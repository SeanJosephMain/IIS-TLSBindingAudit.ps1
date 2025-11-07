<#
.SYNOPSIS
  Enumerate IIS HTTPS bindings on local/remote servers, test TLS (with SNI),
  verify HOSTS file entries, optionally compare HTTP.SYS sslcerts, and export results.

.PARAMETER Computer
  Computer(s) or wildcard(s). Examples: 'localhost', 'WEB01', 'WEB*', 'web-a*-APP?'
  Wildcards expand via ActiveDirectory if available (only Enabled machines are used).

.PARAMETER SkipPing
  Bypass ping filtering. Still records PingOK.

.PARAMETER RevocationOnline
  Perform OCSP/CRL revocation checks (slower, requires outbound access).

.PARAMETER TimeoutSec
  TCP connect timeout in seconds (default 10).

.PARAMETER IncludeHttpSys
  Also parse `netsh http show sslcert` and compare to each binding (hostnameport/ipport).

.PARAMETER Export
  Path to CSV file for export.

.PARAMETER FailsOnly
  If set with -Export, only failures and skipped rows are exported.

.NOTES
  Requires: PowerShell remoting enabled for remote Invoke-Command (WinRM).
  Fixes / Enhancements:
    - TLS validator uses in-scope $RevocationOnline (no $using: inside callback).
    - HOSTS parsing tolerates tabs/multiple spaces and trailing dots.
    - Optional HTTP.SYS compare (hash/store/appid) for quick mismatch triage.
    - Strong validity gate: SAN/CN hostname match, EKU=ServerAuth, dates, key-strength, weak sig alg reject.
#>

[CmdletBinding()]
param(
    [string[]]$Computer = 'localhost',
    [switch]$SkipPing,
    [switch]$RevocationOnline,
    [int]$TimeoutSec = 10,
    [switch]$IncludeHttpSys,
    [Alias('ExportCsv')][string]$Export,
    [switch]$FailsOnly
)

# ----------------------- Helpers -----------------------

function Test-HostReachable {
    param(
        [Parameter(Mandatory)][string]$Name,
        [int]$TimeoutMs = 1000
    )
    $candidates = New-Object System.Collections.Generic.List[string]
    $candidates.Add($Name)

    if ($Name -notlike "*.*" -and $env:USERDNSDOMAIN) {
        $candidates.Add("$Name.$($env:USERDNSDOMAIN.ToLower())")
    }

    try {
        $pds = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -ErrorAction SilentlyContinue).Domain
        if ($pds -and $Name -notlike "*.*") {
            $fq = "$Name.$($pds.ToLower())"
            if (-not $candidates.Contains($fq)) { $candidates.Add($fq) }
        }
    } catch {}

    foreach ($n in ($candidates | Select-Object -Unique)) {
        try {
            $p = New-Object System.Net.NetworkInformation.Ping
            $reply = $p.Send($n, $TimeoutMs)
            if ($reply.Status -eq [System.Net.NetworkInformation.IPStatus]::Success) {
                return @{ PingOK = $true; ResolvedName = $n; IP = $reply.Address.IPAddressToString }
            }
        } catch {}
    }

    return @{ PingOK = $false; ResolvedName = $Name; IP = $null }
}

function Resolve-TargetComputers {
    param(
        [string[]]$ComputerInputs,
        [switch]$SkipPing
    )

    $haveAD = (Get-Module -ListAvailable -Name ActiveDirectory) -ne $null
    $targetsList = New-Object System.Collections.Generic.List[string]

    foreach ($raw in $ComputerInputs) {
        $hasWildcard = [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($raw)
        if ($hasWildcard -and $haveAD) {
            try {
                Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
                $adNames = @( Get-ADComputer -Filter "Name -like '$raw'" -Properties Enabled |
                               Where-Object { $_.Enabled -eq $true } |
                               Select-Object -ExpandProperty Name )

                if ($adNames.Count -gt 0) {
                    foreach ($n in $adNames) { [void]$targetsList.Add([string]$n) }
                } else {
                    [void]$targetsList.Add([string]$raw)
                }
            } catch {
                Write-Warning "AD lookup failed for '$raw': $($_.Exception.Message). Using literal."
                [void]$targetsList.Add([string]$raw)
            }
        } else {
            [void]$targetsList.Add([string]$raw)
        }
    }

    $targets = [System.Linq.Enumerable]::ToArray([System.Linq.Enumerable]::Distinct($targetsList))

    if (-not $targets -or $targets.Count -eq 0) {
        Write-Warning "No target computers resolved from input."
        return @()
    }

    if ($SkipPing) { return $targets }

    $reachable = foreach ($t in $targets) {
        $probe = Test-HostReachable -Name $t
        if ($probe.PingOK) { $t } else { Write-Verbose "Ping failed for '$t' (tried: $($probe.ResolvedName))." }
    }

    if (-not $reachable -or $reachable.Count -eq 0) {
        Write-Warning "No pingable computers after filtering. Use -SkipPing to proceed anyway."
        return @()
    }

    return $reachable
}

# ----------------------- Remote code block -----------------------
$functionBlock = {
    param($RevocationOnline, $TimeoutSec, $IncludeHttpSys)

    Import-Module WebAdministration -ErrorAction Stop

    # script-scoped state from TLS callback
    $script:lastChain = $null
    $script:lastLeaf  = $null
    $script:lastPolicyErrors = $null

    function Test-SslHandshake {
        param(
            [Parameter(Mandatory)] [string]$TargetHost,
            [Parameter(Mandatory)] [int]$Port,
            [switch]$RevocationOnline,
            [int]$TimeoutSec = 10
        )

        $script:lastChain = $null
        $script:lastLeaf  = $null
        $script:lastPolicyErrors = $null

        $result = [ordered]@{
            TargetHost     = $TargetHost
            Port           = $Port
            RemoteIP       = $null
            HandshakeOK    = $false
            ChainOK        = $false
            Errors         = @()
            LeafThumbprint = $null
            LeafSubject    = $null
            LeafNotAfter   = $null
            Issuer         = $null
            Protocol       = $null
            CipherSuite    = $null

            # Deeper validity signals
            HostnameOK     = $false
            EkuServerAuth  = $false
            SanPresent     = $false
            KeyOK          = $false
            SelfSigned     = $false
            NotYetValid    = $false
            Expired        = $false
            WeakSigAlg     = $false
            Valid          = $false
        }

        try {
            $addresses = [System.Net.Dns]::GetHostAddresses($TargetHost) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
            if (-not $addresses) {
                $result.Errors += "DNS: No A record found."
                return $result
            }

            $remote = $addresses[0]
            $result.RemoteIP = $remote.IPAddressToString

            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar = $tcp.BeginConnect($remote, $Port, $null, $null)
            if (-not $ar.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($TimeoutSec))) {
                $tcp.Close()
                $result.Errors += "TCP: Connect timeout."
                return $result
            }
            $tcp.EndConnect($ar)

            $ns = $tcp.GetStream()

            # IMPORTANT: use parameter $RevocationOnline captured in this scope
            $ssl = New-Object System.Net.Security.SslStream($ns, $false, {
                param($sender, [System.Security.Cryptography.X509Certificates.X509Certificate]$cert, $chain, $sslPolicyErrors)
                $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cert

                $ch = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $ch.ChainPolicy.RevocationFlag    = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                $ch.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
                $ch.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(10)
                $ch.ChainPolicy.RevocationMode    = if ($RevocationOnline) {
                    [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                } else {
                    [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                }

                # Enforce EKU Server Authentication
                $null = $ch.ChainPolicy.ApplicationPolicy.Add( (New-Object System.Security.Cryptography.Oid "1.3.6.1.5.5.7.3.1") )

                $ok = $ch.Build($x509)
                $script:lastChain        = $ch
                $script:lastLeaf         = $x509
                $script:lastPolicyErrors = $sslPolicyErrors

                return $ok -and ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
            })

            $ssl.AuthenticateAsClient(
                $TargetHost,
                $null,
                [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13,
                $false
            )

            $result.HandshakeOK = $true

            # --- Extra validations ---
            if ($script:lastLeaf) {
                $leaf = $script:lastLeaf
                $result.LeafThumbprint = $leaf.Thumbprint
                $result.LeafSubject    = $leaf.Subject
                $result.LeafNotAfter   = $leaf.NotAfter

                if ($script:lastChain -and $script:lastChain.ChainElements.Count -gt 1) {
                    $result.Issuer = $script:lastChain.ChainElements[1].Certificate.Subject
                }

                # Dates
                $now = Get-Date
                $result.NotYetValid = ($now -lt $leaf.NotBefore)
                $result.Expired     = ($now -gt $leaf.NotAfter)

                # Self-signed heuristic
                $result.SelfSigned  = ($leaf.Subject -eq $leaf.Issuer) -and ($script:lastChain -and $script:lastChain.ChainElements.Count -eq 1)

                # Weak signature algorithm (reject SHA1)
                try {
                    $sigName = $leaf.SignatureAlgorithm.FriendlyName
                    if ($sigName -match 'sha1') { $result.WeakSigAlg = $true }
                } catch {}

                # SAN presence + hostname coverage
                $sanDns = @()
                try {
                    $sanExt = $leaf.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' } | Select-Object -First 1
                    if ($sanExt) {
                        $sanText = $sanExt.Format($true) # "DNS Name=foo"
                        $sanDns  = ($sanText -split '[\r\n,]') | ForEach-Object {
                            ($_ -replace '^\s*DNS Name\s*=\s*','').Trim()
                        } | Where-Object { $_ -and ($_ -notmatch '^\s*$') }
                        if ($sanDns.Count -gt 0) { $result.SanPresent = $true }
                    }
                } catch {}

                # HostnameOK (prefer SAN; CN fallback)
                $target = $TargetHost.ToLower()
                $hostnameMatches = $false
                if ($sanDns.Count -gt 0) {
                    foreach ($d in $sanDns) {
                        $pat = '^' + [regex]::Escape($d.ToLower()).Replace('\*','.*') + '$'
                        if ($target -match $pat) { $hostnameMatches = $true; break }
                    }
                } else {
                    try {
                        $cn = ($leaf.Subject -split ',') | Where-Object { $_ -match 'CN\s*=' } | Select-Object -First 1
                        $cn = ($cn -replace '.*CN\s*=\s*','').Trim().ToLower()
                        if ($cn) {
                            $pat = '^' + [regex]::Escape($cn).Replace('\*','.*') + '$'
                            if ($target -match $pat) { $hostnameMatches = $true }
                        }
                    } catch {}
                }
                $result.HostnameOK = $hostnameMatches

                # EKU ServerAuth (double-check in leaf)
                $ekuOk = $false
                try {
                    $ekuExt = $leaf.Extensions | Where-Object { $_.Oid.FriendlyName -eq 'Enhanced Key Usage' } | Select-Object -First 1
                    if ($ekuExt) {
                        $ekuText = $ekuExt.Format($true)
                        if ($ekuText -match '(Server Authentication|1\.3\.6\.1\.5\.5\.7\.3\.1)') { $ekuOk = $true }
                    } else {
                        $ekuOk = $false
                    }
                } catch {}
                $result.EkuServerAuth = $ekuOk

                # Key strength
                $keyOK = $false
                try {
                    $rsa   = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($leaf)
                    $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($leaf)
                    if ($rsa) {
                        if ($rsa.KeySize -ge 2048) { $keyOK = $true }
                        $rsa.Dispose()
                    } elseif ($ecdsa) {
                        # Curve presence is enough (e.g., P-256/384/521)
                        $keyOK = $true
                        $ecdsa.Dispose()
                    }
                } catch {}
                $result.KeyOK = $keyOK
            }

            # Preserve platform signals
            $chainOK = ($script:lastPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
            if ($script:lastChain -and $script:lastChain.ChainStatus.Count -gt 0) { $chainOK = $false }
            $result.ChainOK = $chainOK

            # Final validity gate
            $result.Valid = ($result.HandshakeOK -and
                             $result.ChainOK     -and
                             -not $result.NotYetValid -and
                             -not $result.Expired     -and
                             $result.HostnameOK       -and
                             $result.EkuServerAuth    -and
                             $result.KeyOK            -and
                             -not $result.WeakSigAlg)

            if (-not $result.Valid) {
                if (-not $result.HostnameOK) { $result.Errors += 'Name: Hostname does not match SAN/CN.' }
                if (-not $result.EkuServerAuth) { $result.Errors += 'EKU: Missing Server Authentication.' }
                if (-not $result.KeyOK) { $result.Errors += 'Key: RSA<2048 or ECDSA missing.' }
                if ($result.NotYetValid) { $result.Errors += 'Date: Not yet valid.' }
                if ($result.Expired) { $result.Errors += 'Date: Expired.' }
                if ($result.WeakSigAlg) { $result.Errors += 'SigAlg: SHA-1 not allowed.' }
                if ($result.SelfSigned) { $result.Errors += 'Trust: Self-signed.' }
            }

            $ssl.Dispose()
            $tcp.Close()
        }
        catch {
            $err = $_.Exception
            if ($script:lastPolicyErrors) {
                $result.Errors += "TLS Policy: $($script:lastPolicyErrors)"
            }
            if ($script:lastChain) {
                $badStatuses = $script:lastChain.ChainStatus | ForEach-Object { $_.Status.ToString() + ":" + $_.StatusInformation.Trim() }
                if ($badStatuses) {
                    $result.Errors += ("Chain: " + ($badStatuses -join " | "))
                }
            }
            if ($err -and $err.Message -and $result.Errors.Count -eq 0) { $result.Errors += $err.Message }
            elseif ($err -and $err.InnerException -and $err.InnerException.Message -and $result.Errors.Count -eq 0) { $result.Errors += $err.InnerException.Message }
        }

        return $result
    }

    function ShortThumbprint($thumb) {
        if ($thumb -and $thumb.Length -gt 6) { return $thumb.Substring($thumb.Length - 6) }
        return $thumb
    }

    # ---- HOSTS FILE PARSING ----
    $hostsMap = @{}
    try {
        $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
        if (Test-Path $hostsPath) {
            foreach ($line in (Get-Content -Path $hostsPath -ErrorAction Stop)) {
                $t = $line.Trim()
                if (-not $t -or $t.StartsWith('#')) { continue }
                $parts = $t -split '\s+'
                if ($parts.Count -lt 2) { continue }
                $ip = $parts[0]
                for ($i = 1; $i -lt $parts.Count; $i++) {
                    $hn = $parts[$i].ToLower().Trim().TrimEnd('.')
                    if ([string]::IsNullOrWhiteSpace($hn)) { continue }
                    $hostsMap[$hn] = $ip  # last occurrence wins
                }
            }
        }
    } catch {}

    function Get-HostsEntryInfo([string]$HostnameToCheck) {
        if (-not $HostnameToCheck) { return @{ Present = $null; IP = $null } }
        $key = $HostnameToCheck.ToLower().TrimEnd('.')
        if ($hostsMap.ContainsKey($key)) {
            return @{ Present = $true; IP = $hostsMap[$key] }
        } else {
            return @{ Present = $false; IP = $null }
        }
    }

    # ---- HTTP.SYS PARSE (optional) ----
    $httpSys = @{
        ipport       = @{}
        hostnameport = @{}
    }

    if ($IncludeHttpSys) {
        try {
            $raw = (netsh http show sslcert) 2>$null
            $block = @{}
            $mode  = $null
            foreach ($line in $raw) {
                if ($line -match '^\s*IP:port\s*:\s*(.+)$') {
                    $mode = 'ipport'
                    $key = ($Matches[1].Trim())
                    $block = @{ key = $key; hash=$null; store=$null; appid=$null }
                } elseif ($line -match '^\s*Hostname:port\s*:\s*(.+)$') {
                    $mode = 'hostnameport'
                    $key = ($Matches[1].Trim().ToLower())
                    $block = @{ key = $key; hash=$null; store=$null; appid=$null }
                } elseif ($line -match '^\s*Certificate Hash\s*:\s*([0-9A-Fa-f]+)') {
                    $block.hash = $Matches[1].ToUpper()
                } elseif ($line -match '^\s*Application ID\s*:\s*\{?([0-9A-Fa-f\-]+)\}?') {
                    $block.appid = $Matches[1]
                } elseif ($line -match '^\s*Certificate Store Name\s*:\s*(\S+)') {
                    $block.store = $Matches[1]
                    if ($mode -and $block.key) {
                        $httpSys.$mode[$block.key] = @{
                            Hash  = $block.hash
                            Store = $block.store
                            AppId = $block.appid
                        }
                    }
                    $block = @{}
                    $mode = $null
                }
            }
        } catch {
            # ignore parsing failures
        }
    }

    # ---- Enumerate IIS Sites/Bindings ----
    $rows = @()
    $sites = Get-ChildItem IIS:\Sites
    foreach ($site in $sites) {
        $httpsBindings = Get-WebBinding -Name $site.Name -Protocol https
        foreach ($binding in $httpsBindings) {
            $parts = $binding.bindingInformation.Split(':')
            $bindingIP = $parts[0]
            $port = [int]$parts[1]
            $hostName = $parts[2]

            $SniEnabled = ($binding.sslFlags -band 1) -ne 0

            $cert = $null
            if ($binding.certificateHash) {
                $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Thumbprint -eq $binding.certificateHash
            }

            # HOSTS check (even when hostname empty we return nulls)
            $hostsCheckResult = Get-HostsEntryInfo -HostnameToCheck $hostName

            # HTTP.SYS lookup keys
            $httpSysHashShort = $null
            $httpSysStore = $null
            $httpSysAppId = $null
            $httpSysMatch = $null

            if ($IncludeHttpSys) {
                if ([string]::IsNullOrWhiteSpace($hostName)) {
                    $key = "$bindingIP`:$port"
                    if ($httpSys.ipport.ContainsKey($key)) {
                        $httpSysHashShort = ShortThumbprint $httpSys.ipport[$key].Hash
                        $httpSysStore     = $httpSys.ipport[$key].Store
                        $httpSysAppId     = $httpSys.ipport[$key].AppId
                    }
                } else {
                    $key = ($hostName.TrimEnd('.').ToLower() + ":" + $port)
                    if ($httpSys.hostnameport.ContainsKey($key)) {
                        $httpSysHashShort = ShortThumbprint $httpSys.hostnameport[$key].Hash
                        $httpSysStore     = $httpSys.hostnameport[$key].Store
                        $httpSysAppId     = $httpSys.hostnameport[$key].AppId
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($hostName)) {
                $rows += [pscustomobject]@{
                    SiteName      = $site.Name
                    HostName      = "(none)"
                    BindingIP     = $bindingIP
                    Port          = $port
                    Thumbprint    = ShortThumbprint $binding.certificateHash
                    Store         = $binding.certificateStoreName
                    Expiration    = if ($cert) { $cert.NotAfter } else { $null }
                    TestStatus    = "Skipped"
                    SslOK         = $false
                    Errors        = "No hostname in binding (SNI not possible)"
                    RemoteIP      = $null
                    Protocol      = $null
                    CipherSuite   = $null
                    SNI           = $SniEnabled
                    HostsEntry    = $hostsCheckResult.Present
                    HostsEntryIP  = $hostsCheckResult.IP
                    # Validity columns not applicable when skipped:
                    HostnameOK    = $null
                    EkuServerAuth = $null
                    SanPresent    = $null
                    KeyOK         = $null
                    NotYetValid   = $null
                    Expired       = $null
                    WeakSigAlg    = $null
                    SelfSigned    = $null
                    # HTTP.SYS
                    HttpSysHash   = $httpSysHashShort
                    HttpSysStore  = $httpSysStore
                    HttpSysAppId  = $httpSysAppId
                    HttpSysMatch  = $false  # no TLS, cannot assert
                }
                continue
            }

            # TLS test
            $tlsTestResult = Test-SslHandshake -TargetHost $hostName -Port $port -RevocationOnline:$RevocationOnline -TimeoutSec $TimeoutSec

            # Compare to HTTP.SYS if available
            if ($IncludeHttpSys -and $httpSysHashShort) {
                $rowThumb = if ($cert) { ShortThumbprint $cert.Thumbprint } else { ShortThumbprint $tlsTestResult.LeafThumbprint }
                $httpSysMatch = ($rowThumb -ne $null -and $rowThumb -eq $httpSysHashShort)
            }

            $rows += [pscustomobject]@{
                SiteName      = $site.Name
                HostName      = $hostName
                BindingIP     = $bindingIP
                Port          = $port
                Thumbprint    = if ($cert) { ShortThumbprint $cert.Thumbprint } else { ShortThumbprint $tlsTestResult.LeafThumbprint }
                Store         = $binding.certificateStoreName
                Expiration    = if ($cert) { $cert.NotAfter } else { $tlsTestResult.LeafNotAfter }
                TestStatus    = if ($tlsTestResult.Valid) { "OK" } else { "FAIL" }
                SslOK         = $tlsTestResult.Valid
                Errors        = if ($tlsTestResult.Errors) { ($tlsTestResult.Errors -join " || ") } else { "" }
                RemoteIP      = $tlsTestResult.RemoteIP
                Protocol      = $tlsTestResult.Protocol
                CipherSuite   = $tlsTestResult.CipherSuite
                SNI           = $SniEnabled
                HostsEntry    = $hostsCheckResult.Present
                HostsEntryIP  = $hostsCheckResult.IP
                # Validity diagnostics
                HostnameOK    = $tlsTestResult.HostnameOK
                EkuServerAuth = $tlsTestResult.EkuServerAuth
                SanPresent    = $tlsTestResult.SanPresent
                KeyOK         = $tlsTestResult.KeyOK
                NotYetValid   = $tlsTestResult.NotYetValid
                Expired       = $tlsTestResult.Expired
                WeakSigAlg    = $tlsTestResult.WeakSigAlg
                SelfSigned    = $tlsTestResult.SelfSigned
                # HTTP.SYS compare
                HttpSysHash   = $httpSysHashShort
                HttpSysStore  = $httpSysStore
                HttpSysAppId  = $httpSysAppId
                HttpSysMatch  = $httpSysMatch
            }
        }
    }

    return $rows
}

# ----------------------- Run scan -----------------------
$targets = Resolve-TargetComputers -ComputerInputs $Computer -SkipPing:$SkipPing
if (-not $targets -or $targets.Count -eq 0) { return }

$allResults = @()

foreach ($comp in $targets) {
    $probe = Test-HostReachable -Name $comp
    $pingOk = $probe.PingOK
    $resolvedIP = $probe.IP

    Write-Host ">>> Scanning IIS certificates on $comp ..." -ForegroundColor Cyan
    try {
        $res = Invoke-Command -ComputerName $comp -ScriptBlock $functionBlock -ArgumentList $RevocationOnline, $TimeoutSec, $IncludeHttpSys -ErrorAction Stop
    } catch {
        $errMsg = $_.Exception.Message
        $allResults += [pscustomobject]@{
            Computer     = $comp
            ComputerIP   = $resolvedIP
            PingOK       = $pingOk
            SiteName     = "(remote fail)"
            HostName     = "(remote fail)"
            BindingIP    = $null
            Port         = $null
            Thumbprint   = $null
            Store        = $null
            Expiration   = $null
            TestStatus   = "FAIL"
            SslOK        = $false
            SNI          = $null
            Protocol     = $null
            CipherSuite  = $null
            Errors       = "Invoke-Command: $errMsg"
            HostsEntry   = $null
            HostsEntryIP = $null
            HostnameOK   = $null
            EkuServerAuth= $null
            SanPresent   = $null
            KeyOK        = $null
            NotYetValid  = $null
            Expired      = $null
            WeakSigAlg   = $null
            SelfSigned   = $null
            HttpSysHash  = $null
            HttpSysStore = $null
            HttpSysAppId = $null
            HttpSysMatch = $null
        }
        continue
    }

    foreach ($r in $res) {
        $r | Add-Member -NotePropertyName Computer   -NotePropertyValue $comp -Force
        $r | Add-Member -NotePropertyName ComputerIP -NotePropertyValue $resolvedIP -Force
        $r | Add-Member -NotePropertyName PingOK     -NotePropertyValue $pingOk -Force
        if (-not $r.PSObject.Properties.Name.Contains('Store')) {
            $r | Add-Member -NotePropertyName Store -NotePropertyValue $null -Force
        }
    }

    $allResults += $res
}

# ----------------------- Output -----------------------
$allResults = $allResults | Sort-Object { $_.SslOK -eq $false }, Computer, SiteName, HostName

$allResults | Format-Table `
    Computer, ComputerIP, PingOK, SiteName, HostName, BindingIP, Port, Thumbprint, Expiration, TestStatus, SslOK, `
    SNI, Protocol, CipherSuite, HostsEntry, HostsEntryIP, `
    HostnameOK, EkuServerAuth, SanPresent, KeyOK, NotYetValid, Expired, WeakSigAlg, SelfSigned, `
    HttpSysHash, HttpSysMatch, Errors -AutoSize

# ----------------------- Export -----------------------
if ($Export) {
    $toWrite = if ($FailsOnly) {
        $allResults | Where-Object { $_.TestStatus -ne 'OK' }
    } else {
        $allResults
    }

    $toWrite | Export-Csv -Path $Export -Encoding UTF8 -NoTypeInformation
    Write-Host ("CSV saved: {0} ({1} row(s){2})" -f $Export, ($toWrite | Measure-Object | Select-Object -ExpandProperty Count), $(if ($FailsOnly) {", fails only"} else {""})) -ForegroundColor Green
}
