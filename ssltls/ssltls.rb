#!/usr/bin/env ruby
require 'openssl'
require 'socket'
require 'find'
require 'uri'

#tls and ssl check for linux

# Function to load a certificate from a file
def load_certificate(file, password = nil)
  begin
    if file =~ /\.(p12|pfx)$/i
      # Load PKCS#12 (.p12 or .pfx) certificate
      p12 = OpenSSL::PKCS12.new(File.read(file), password)
      return p12.certificate
    elsif file =~ /\.(p7b|p7c)$/i
      # Load PKCS#7 (.p7b or .p7c) certificate
      pkcs7 = OpenSSL::PKCS7.new(File.read(file))
      certs = pkcs7.certificates # Returns an array of certificates
      return certs # Returning all certificates for inspection
    else
      # Load PEM/CRT certificate
      cert_content = File.read(file)
      cert = OpenSSL::X509::Certificate.new(cert_content)
      return [cert]
    end
  rescue OpenSSL::PKCS12::PKCS12Error => e
    puts "Error loading PKCS#12 certificate from #{file}: #{e.message}. Did you provide the correct password?"
    return nil
  rescue => e
    puts "Error reading certificate file #{file}: #{e.message}"
    return nil
  end
end

# Function to check for issues with the SSL certificate
def check_certificate(cert, file, hostname = nil)
  issues = []

  # Check if the certificate is expired
  if cert.not_after < Time.now
    issues << "Certificate has expired on #{cert.not_after}"
  elsif cert.not_before > Time.now
    issues << "Certificate is not yet valid (starts on #{cert.not_before})"
  end

  # Check if the certificate is self-signed
  if cert.issuer == cert.subject
    issues << "Certificate is self-signed"
  end

  # Check for weak signature algorithms
  signature_algorithm = cert.signature_algorithm
  weak_algorithms = ["md5", "sha1", "md2", "md4", "ripemd160", "sha224"]
  if weak_algorithms.any? { |algo| signature_algorithm.downcase.include?(algo) }
    issues << "Weak signature algorithm detected: #{signature_algorithm}"
  end

  # Check for weak public key length
  public_key = cert.public_key
  key_length = public_key.n.num_bytes * 8 rescue 0
  if key_length > 0 && key_length < 2048
    issues << "Weak public key (#{key_length} bits). Consider 2048-bit or higher."
  end

  # Check for weak key algorithms
  case public_key
  when OpenSSL::PKey::RSA
    if public_key.n.num_bytes * 8 < 2048
      issues << "Weak RSA key: #{public_key.n.num_bytes * 8} bits"
    end
  when OpenSSL::PKey::DSA
    if public_key.p.num_bytes * 8 < 2048
      issues << "Weak DSA key: #{public_key.p.num_bytes * 8} bits"
    end
  when OpenSSL::PKey::EC
    curve_name = public_key.group.curve_name
    weak_curves = ["secp112r1", "secp128r1", "secp160r1", "prime192v1"]
    if weak_curves.include?(curve_name)
      issues << "Weak ECDSA curve: #{curve_name}"
    end
  else
    issues << "Unsupported public key type: #{public_key.class}"
  end

  # Check for Common Name (CN) mismatch if hostname is provided
  if hostname
    cn = cert.subject.to_a.find { |name, _, _| name == 'CN' }&.last
    if cn && cn != hostname
      issues << "Common Name (CN) mismatch: Expected '#{hostname}', found '#{cn}'"
    end
  end

  # Placeholder for revocation check (CRL or OCSP)
  crl_distribution_points = cert.extensions.select { |ext| ext.oid == "crlDistributionPoints" }
  if crl_distribution_points.any?
    issues << "Certificate Revocation List (CRL) available, but not yet checked"
  else
    issues << "No CRL (Certificate Revocation List) available"
  end

  # TLS compatibility checks
  issues.concat check_tls_compatibility(cert)

  # Return the issues found, along with the file name
  return { file: file, issues: issues }
end

# Function to check TLS compatibility of the certificate
def check_tls_compatibility(cert)
  tls_issues = []

  # Check for potential use with weak TLS versions
  if cert.not_before < Time.new(2016, 6, 30)
    tls_issues << "Certificate was issued before mid-2016. May be used with weak TLS versions (TLS 1.0, TLS 1.1)."
  end

  # Check for signature algorithms incompatible with TLS 1.2+
  strong_algorithms = ["sha256", "sha384", "sha512", "ecdsa"]
  unless strong_algorithms.any? { |algo| cert.signature_algorithm.downcase.include?(algo) }
    tls_issues << "Certificate is using a signature algorithm incompatible with modern TLS versions (e.g., TLS 1.2, TLS 1.3)."
  end

  # Check for common key types compatible with TLS 1.2+
  public_key = cert.public_key
  key_length = public_key.n.num_bytes * 8 rescue 0
  if public_key.is_a?(OpenSSL::PKey::RSA) && key_length < 2048
    tls_issues << "RSA key size is too small for TLS 1.2 or TLS 1.3 (minimum 2048 bits)."
  elsif public_key.is_a?(OpenSSL::PKey::EC)
    curve_name = public_key.group.curve_name
    strong_curves = ["secp256r1", "secp384r1", "secp521r1"]
    unless strong_curves.include?(curve_name)
      tls_issues << "ECDSA key is using a weak elliptic curve unsuitable for TLS 1.2 or TLS 1.3."
    end
  end

  return tls_issues
end

# Function to display certificate details
def display_certificate_info(cert, file)
  puts "\nCertificate Details for #{file}:"
  puts "  Subject: #{cert.subject}"
  puts "  Issuer: #{cert.issuer}"
  puts "  Valid From: #{cert.not_before}"
  puts "  Valid Until: #{cert.not_after}"
  puts "  Signature Algorithm: #{cert.signature_algorithm}"
  key_length = cert.public_key.n.num_bytes * 8 rescue "Unknown"
  puts "  Public Key Length: #{key_length} bits"
end

# Function to scan a directory for certificate files
def check_certificates_in_directory(directory, hostname = nil, password = nil)
  certificate_files = []

  # Find all potential certificate files (.pem, .crt, .cer, .der, .p12, .pfx, .p7b, .p7c)
  Find.find(directory) do |path|
    if path =~ /\.(pem|crt|cer|der|p12|pfx|p7b|p7c)$/i
      certificate_files << path
    end
  end

  if certificate_files.empty?
    puts "No certificate files found in the directory #{directory}."
    return
  end

  # Check each certificate for potential issues
  certificate_files.each do |file|
    certs = load_certificate(file, password)
    if certs
      certs.each do |cert|
        display_certificate_info(cert, file)
        result = check_certificate(cert, file, hostname)

        # Display any issues with the certificate
        if result[:issues].empty?
          puts "  No major issues detected with this certificate."
        else
          puts "\nPotential issues with the certificate in #{file}:"
          result[:issues].each { |issue| puts "  - #{issue}" }
        end
      end
    else
      puts "Skipping file #{file}: Not a valid certificate."
    end
  end
end

# Main entry point of the script
if ARGV.empty?
  puts "Usage: ./check_certificates.rb <directory> [hostname] [password]"
  exit
end

directory = ARGV[0]
hostname = ARGV[1] # Optional hostname for CN mismatch check
password = ARGV[2] # Optional password for PKCS#12 (P12/PFX) files
check_certificates_in_directory(directory, hostname, password)
