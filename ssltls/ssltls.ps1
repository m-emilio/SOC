# ssl and tls check for windows
function Load-Certificate {
    param (
        [string]$filePath,
        [string]$password = $null
    )

    try {
        if ($filePath -match '\.pfx$') {
            # Load a PKCS#12 (.pfx) certificate
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($filePath, $password, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        } elseif ($filePath -match '\.p7b$') {
            # Load PKCS#7 certificates (requires external utility like certutil or OpenSSL)
            return Load-PKCS7Certificate -filePath $filePath
        } else {
            # Load PEM/CRT certificate
            $certContent = Get-Content $filePath -Raw
            return [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certContent)
        }
    }
    catch {
        Write-Warning "Error reading certificate file $filePath: $_"
        return $null
    }
}

# Function to load PKCS#7 certificates
function Load-PKCS7Certificate {
    param (
        [string]$filePath
    )

    try {
        # Use certutil to convert PKCS#7 file and extract the certificates (Requires OpenSSL or certutil)
        $tempPemFile = "$env:TEMP\tempCert.pem"
        & certutil -dump $filePath | Out-File -FilePath $tempPemFile

        # Load each extracted certificate into an array
        $certs = @()
        $lines = Get-Content $tempPemFile
        $currentCert = ""
        foreach ($line in $lines) {
            if ($line -match "^-----BEGIN CERTIFICATE-----") {
                $currentCert = $line
            } elseif ($line -match "^-----END CERTIFICATE-----") {
                $currentCert += "`n$line"
                $certs += [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Text.Encoding]::UTF8.GetBytes($currentCert))
            } else {
                $currentCert += "`n$line"
            }
        }
        return $certs
    }
    catch {
        Write-Warning "Error reading PKCS#7 file: $_"
        return $null
    }
}

# Function to check certificate revocation status using certutil
function Check-CertificateRevocation {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    try {
        $certUtilOutput = & certutil -verify $cert.RawData
        if ($certUtilOutput -match "Revoked") {
            return "Certificate has been revoked."
        }
        return "Certificate is not revoked."
    }
    catch {
        return "Unable to verify revocation status."
    }
}

# Function to check ECC key curve strength
function Check-ECCCurve {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    if ($cert.PublicKey.Oid.FriendlyName -eq "ECC") {
        # Extract ECC curve name from public key parameters (basic implementation)
        $curveName = $cert.PublicKey.Oid.FriendlyName  # Simplified, ECC curve parsing is complex
        $weakCurves = @("secp112r1", "secp128r1", "secp160r1", "prime192v1")
        if ($weakCurves -contains $curveName) {
            return "Weak ECC curve: $curveName"
        }
        return "ECC curve is strong."
    }
    return "Not an ECC certificate."
}

# Function to check TLS compatibility of the certificate
function Check-TLSCompatibility {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert
    )

    $tlsIssues = @()

    # Check for potential use with weak TLS versions (TLS 1.0, TLS 1.1)
    if ($cert.NotBefore -lt (Get-Date -Year 2016 -Month 6 -Day 30)) {
        $tlsIssues += "Certificate was issued before mid-2016. May be used with weak TLS versions (TLS 1.0, TLS 1.1)."
    }

    # Check for strong signature algorithms (for TLS 1.2+)
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    $strongAlgorithms = @("sha256", "sha384", "sha512", "ecdsa")
    if (-not ($strongAlgorithms -contains $signatureAlgorithm.ToLower())) {
        $tlsIssues += "Certificate is using a signature algorithm incompatible with modern TLS versions (e.g., TLS 1.2, TLS 1.3)."
    }

    # Check public key length for TLS 1.2+ compatibility
    $keyLength = $cert.PublicKey.Key.KeySize
    if ($keyLength -lt 2048) {
        $tlsIssues += "RSA key size is too small for TLS 1.2 or TLS 1.3 (minimum 2048 bits)."
    }

    return $tlsIssues
}

# Function to check the certificate for various issues
function Check-Certificate {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$filePath,
        [string]$hostname = $null
    )

    $issues = @()

    # Check if the certificate is expired
    if ($cert.NotAfter -lt (Get-Date)) {
        $issues += "Certificate has expired on $($cert.NotAfter)"
    } elseif ($cert.NotBefore -gt (Get-Date)) {
        $issues += "Certificate is not yet valid (starts on $($cert.NotBefore))"
    }

    # Check if the certificate is self-signed
    if ($cert.Issuer -eq $cert.Subject) {
        $issues += "Certificate is self-signed"
    }

    # Check for weak signature algorithms
    $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
    $weakAlgorithms = @("md5", "sha1", "md2", "md4", "ripemd160", "sha224")
    if ($weakAlgorithms -contains $signatureAlgorithm.ToLower()) {
        $issues += "Weak signature algorithm detected: $signatureAlgorithm"
    }

    # Check for weak public key length
    $keyLength = $cert.PublicKey.Key.KeySize
    if ($keyLength -lt 2048) {
        $issues += "Weak public key ($keyLength bits). Consider 2048-bit or higher."
    }

    # Check for Common Name (CN) mismatch if hostname is provided
    if ($hostname) {
        $subject = $cert.Subject
        $commonName = ($subject -match "CN=([^,]+)") ? $matches[1] : $null
        if ($commonName -and $commonName -ne $hostname) {
            $issues += "Common Name (CN) mismatch: Expected '$hostname', found '$commonName'"
        }
    }

    # TLS compatibility checks
    $tlsIssues = Check-TLSCompatibility -cert $cert
    $issues += $tlsIssues

    # ECC curve validation (if applicable)
    $eccIssues = Check-ECCCurve -cert $cert
    if ($eccIssues) {
        $issues += $eccIssues
    }

    # Certificate revocation check
    $revocationStatus = Check-CertificateRevocation -cert $cert
    $issues += $revocationStatus

    # Return the issues found, along with the file path
    return [PSCustomObject]@{
        File   = $filePath
        Issues = $issues
    }
}

# Function to scan a directory for certificate files and check them
function Check-CertificatesInDirectory {
    param (
        [string]$directory,
        [string]$hostname = $null,
        [string]$password = $null
    )

    # Find all potential certificate files (.pem, .crt, .cer, .pfx, .p7b)
    $certificateFiles = Get-ChildItem -Path $directory -Recurse -Include *.pem, *.crt, *.cer, *.pfx, *.p7b

    if (-not $certificateFiles) {
        Write-Host "No certificate files found in the directory $directory."
        return
    }

    # Check each certificate for potential issues
    foreach ($file in $certificateFiles) {
        $certs = Load-Certificate -filePath $file.FullName -password $password
        if ($certs -is [array]) {
            foreach ($cert in $certs) {
                Process-Certificate -cert $cert -filePath $file.FullName -hostname $hostname
            }
        } else {
            Process-Certificate -cert $certs -filePath $file.FullName -hostname $hostname
        }
    }
}

# Helper function to process each certificate
function Process-Certificate {
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$cert,
        [string]$filePath,
        [string]$hostname = $null
    )

    if ($cert) {
        $results = Check-Certificate -cert $cert -filePath $filePath -hostname $hostname
        Write-Host "Certificate: $($results.File)"
        foreach ($issue in $results.Issues) {
            Write-Host "  Issue: $issue"
        }
        Write-Host ""
    }
}

# Start the certificate scan
$directoryToScan = "C:\path\to\certificates"  # Set the path to the directory containing certificates
$hostname = "example.com"                    # Set the hostname for CN validation (optional)
$certificatePassword = "your_password"        # Set the certificate password for PKCS#12 files if needed

Check-CertificatesInDirectory -directory $directoryToScan -hostname $hostname -password $certificatePassword
