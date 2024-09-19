#!/usr/bin/env ruby

# List of known malicious IP addresses or domains
KNOWN_MALICIOUS_IPS = [
  '198.51.100.23',   # Example of malicious IP address
  '203.0.113.54',    # Another example
  'malicious.com',   # Example malicious domain
  'evil-website.org' # Example malicious domain
]

# List of ports associated with known vulnerabilities
VULNERABLE_PORTS = [
  3389,  # RDP
  22,    # SSH (often attacked)
  445,   # SMB
  1433,  # SQL Server
  1521,  # Oracle DB
  5432,  # PostgreSQL
  5900,  # VNC
  8080,  # Web-based attacks
]

# Function to check platform and run appropriate command
def get_network_connections
  case RUBY_PLATFORM
  when /win32|mingw32/
    # Windows command to check network connections
    puts "Running on Windows: Checking network connections..."
    `netstat -an`
  when /linux/
    # Linux command to check network connections (includes process details)
    puts "Running on Linux: Checking network connections..."
    `ss -tunap`
  when /darwin/
    # macOS command to check network connections
    puts "Running on macOS: Checking network connections..."
    `netstat -an`
  else
    puts "Unsupported platform: #{RUBY_PLATFORM}"
    exit 1
  end
end

# Function to analyze network activity for suspicious connections
def analyze_connections(network_data)
  suspicious_connections = []

  # Check each line of network data
  network_data.each_line do |line|
    # Check for known malicious IPs or domains
    KNOWN_MALICIOUS_IPS.each do |malicious_ip|
      if line.include?(malicious_ip)
        suspicious_connections << "Malicious IP/Domain detected: #{line.strip}"
      end
    end

    # Check for vulnerable ports
    VULNERABLE_PORTS.each do |port|
      if line =~ /:#{port}\b/
        suspicious_connections << "Vulnerable port detected (#{port}): #{line.strip}"
      end
    end

    # Check for any other suspicious patterns
    if line =~ /.*:.*:.*:.*:.*:.*:.*/  # IPv6 addresses (suspicious if the system normally doesn't use IPv6)
      suspicious_connections << "IPv6 connection (may be suspicious): #{line.strip}"
    elsif line =~ /0\.0\.0\.0/         # Listening on all interfaces (could be suspicious)
      suspicious_connections << "Listening on all interfaces (0.0.0.0): #{line.strip}"
    elsif line =~ /127\.0\.0\.1/       # Loopback address, check for unexpected services
      suspicious_connections << "Loopback connection (127.0.0.1): #{line.strip}"
    end
  end

  if suspicious_connections.any?
    puts "\nPotential suspicious connections detected:"
    suspicious_connections.each { |conn| puts conn }
  else
    puts "\nNo suspicious connections detected."
  end
end

# Function to fetch process details (Linux specific)
def analyze_processes(network_data)
  if RUBY_PLATFORM =~ /linux/
    puts "\nAnalyzing processes associated with network connections..."

    # Check for specific suspicious services running on certain ports (Linux only)
    network_data.each_line do |line|
      if line =~ /(\d{1,5})\/(.+)/ # Extract the port number and process name from `ss -tunap` output
        port = $1
        process = $2.strip

        if VULNERABLE_PORTS.include?(port.to_i)
          puts "Suspicious process detected: #{process} running on port #{port}"
        elsif process.downcase.include?("nc") || process.downcase.include?("netcat")
          puts "Potential malicious service (netcat) detected: #{process} running on port #{port}"
        elsif process.downcase.include?("python") || process.downcase.include?("perl")
          puts "Suspicious script-based process detected: #{process} running on port #{port}"
        end
      end
    end
  else
    puts "Process analysis is currently only supported on Linux."
  end
end

# Get network connections
network_data = get_network_connections

# Print all connections (optional)
puts "\n--- Active Network Connections ---"
puts network_data

# Analyze the network connections for suspicious activity
analyze_connections(network_data)

# Optionally analyze processes (Linux specific)
analyze_processes(network_data)
