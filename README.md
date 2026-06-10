# MalwareCheck.ps1 - Check PS scripts for possible malware
Modify the $directoryPath variable to the folder containing the PowerShell scripts you want to analyze.

# NetworkScan.rb - Scan system for known vulnerable ports or IP addresses.
Modify KNOWN_MALICIOUS_IPS, VULNERABLE_PORTS to refine the scan, designed for Linux, Windows and MacOS

# ssltls -  Scripts to verify mismatched certificate cn, expiration, weak ciphers and keys, revocation check (CRL or OCSP), TLS compatiblity. Ruby and Powershell.
```
example: ./ssltls.rb <directory> [hostname] [password]  |  ./ssltls.rb /etc/ssl/certs example.com mypassword
```

# pki-iot-infographic.html
The infographic covers all 10 sections in a dark terminal aesthetic suited to the subject matter:

Stat band at the top with key quick-reference numbers
Constraints, Crypto Libraries, Algorithms — the foundational three
Enrollment Protocols & Key Storage — operational details
CA Infrastructure — with cards for each option
Threat Model — 8 threat cards with severity ratings (CRIT / HIGH / MED)
Gov Standards, Post-Quantum Readiness, PKI Ops — the compliance and forward-looking sections
Pipeline footer showing the device identity → PQ migration flow
