# MalwareCheck.ps1 - Modify the $directoryPath variable to point to the folder containing the PowerShell scripts you want to analyze.

# NetworkScan.rb - Mofify KNOWN_MALICIOUS_IPS, VULNERABLE_PORTS to refine the scan, designed for Linux but works on Windows and MacOS

# ssltls.rb - Ruby script to verify mismatched certificate cn, expiration, weak ciphers and keys, revocation check (CRL or OCSP), TLS compatiblity.


example: ./ssltls.rb <directory> [hostname] [password]  |  ./ssltls.rb /etc/ssl/certs example.com mypassword


