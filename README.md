This PowerShell script scans one or more IIS servers to enumerate all HTTPS bindings, validate TLS connectivity (including SNI support), and verify SSL certificate integrity. 
It can also compare IIS bindings against HTTP.SYS configuration and perform optional online revocation checks. The results can be displayed in the console or exported to a CSV file.

How It Works

Target Resolution:
The script accepts one or more computer names or wildcard patterns. Wildcards are expanded through Active Directory (only enabled computers are used). Each target is optionally ping-tested before processing unless -SkipPing is used.

Remote Execution:
For each reachable host, the script uses PowerShell remoting (WinRM) to execute a remote code block that:
Enumerates all IIS sites and HTTPS bindings.
Extracts binding IPs, ports, and hostnames.
Locates and validates the associated certificates.

TLS Handshake Test:
Each HTTPS binding undergoes a live TLS test to verify:
Successful handshake (TLS 1.2/1.3).
Valid certificate chain (optional OCSP/CRL if -RevocationOnline used).
Hostname-to-SAN/CN match.
Valid key strength, EKU presence, and non-expired dates.
Rejection of SHA-1 and self-signed certificates.

HOSTS File Validation:
The script parses the server’s local hosts file to detect hardcoded hostname entries and record their IP mappings.

HTTP.SYS Comparison (Optional):
When -IncludeHttpSys is used, the script parses netsh http show sslcert output and compares certificate hashes between IIS and HTTP.SYS bindings to detect mismatches.

Output and Export:
Results are displayed in a colorized table showing certificate health and binding details.
Use -Export "C:\Path\Report.csv" to save the results.
Add -FailsOnly to export only failed or skipped entries.

Key Parameters
Parameter	Description
Computer	One or more server names or wildcard patterns (e.g., WEB*, localhost).
SkipPing	Skips ICMP filtering (useful for restricted networks).
RevocationOnline	Enables live OCSP/CRL checks for certificate revocation.
TimeoutSec	TCP/TLS timeout in seconds (default 10).
IncludeHttpSys	Compares HTTP.SYS SSL certificates to IIS bindings.
Export	Exports results to CSV file.
FailsOnly	Exports only failed or skipped validation rows.

Requirements

PowerShell 5.1 or later
PowerShell remoting (WinRM) enabled on target servers
IIS WebAdministration module available
Sufficient permissions to query certificates and IIS configuration

Example Usage
.\iis-tls-audit.ps1

.\iis-tls-audit.ps1 -Computer "WEB01","WEB02" -IncludeHttpSys -Export "C:\Logs\IIS-TLS-Report.csv"

.\iis-tls-audit.ps1 -Computer "WEB-*" -RevocationOnline -FailsOnly -Export "C:\Logs\TLS-Fails.csv"


Output Highlights

Each row includes:
Server and Site/Hostname
Certificate Thumbprint, Expiration
TLS Validity Results (OK/FAIL)
SNI, Protocol, CipherSuite
Hostname, SAN, EKU, Key Strength
HTTP.SYS Match State
Error Summary
