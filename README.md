# MalwareCheck.ps1 - Check PS scripts for possible malware
Modify the $directoryPath variable to the folder containing the PowerShell scripts you want to analyze.

# NetworkScan.rb - Scan system for known vulnerable ports or IP addresses.
Modify KNOWN_MALICIOUS_IPS, VULNERABLE_PORTS to refine the scan, designed for Linux, Windows and MacOS

# ssltls -  Scripts to verify mismatched certificate cn, expiration, weak ciphers and keys, revocation check (CRL or OCSP), TLS compatiblity. Ruby and Powershell.
```
example: ./ssltls.rb <directory> [hostname] [password]  |  ./ssltls.rb /etc/ssl/certs example.com mypassword
```

#ids_middleware_v2.rb
	
IDS Middleware (Advisory + Enforce)
	
#review_tool.rb

for displaying IDS recommendations
