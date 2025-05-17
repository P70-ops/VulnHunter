# VulnHunter
# Web Server Vulnerability Scanner

  _    __  _____ ___  _   _ ____  _____ ____  
 | |  / / |___ // _ \| | | / ___|| ____|  _ \ 
 | | / /    |_ \ (_) | | | \___ \|  _| | |_) |
 | |/ /_   ___) \__, | |_| |___) | |___|  _ < 
 |_|\_(_) |____/  /_/ \___/|____/|_____|_| \_\
                                              
Web Server Vulnerability Scanner v2.0
====================================

Enter target IP address or hostname (e.g., 192.168.1.1 or example.com): example.com
Enter port number (1-65535): 443

[+] Starting scan for example.com:443...
----------------------------------------
[+] Loaded 25 vulnerability patterns
[+] Performing TLS scan...
    ✓ TLS Version: TLS 1.3
[+] Performing HTTP scan...
    ✓ HTTP Status: 200
[+] Checking for vulnerabilities...
    ! Found: Missing HSTS (High)
    * Missing security header: X-Content-Type-Options
[+] Scan complete. Report saved to results/scan_example.com_1234567890.txt



**VulnScanr** is a comprehensive web server security assessment tool that scans for vulnerabilities in web servers, including TLS misconfigurations, insecure headers, and common web vulnerabilities.

## Features

- 🛡️ **TLS/SSL Scanning**: Checks protocol versions, cipher suites, and certificate validity
- 🔍 **Header Analysis**: Identifies security misconfigurations in HTTP headers
- 📝 **Content Scanning**: Detects exposed sensitive information and common vulnerabilities
- 📊 **Detailed Reporting**: Generates comprehensive vulnerability reports
- 🚀 **Easy-to-Use**: Simple command-line interface with clear output

## Installation

### Prerequisites
- Linux/macOS (Windows support via WSL)
- C++17 compatible compiler (GCC/Clang)
- OpenSSL 3.0+
- libcurl

### Build Instructions

```bash
# Clone the repository
https://github.com/P70-ops/VulnHunter.git
cd web-vulnerability-scanner

# Install dependencies (Ubuntu/Debian)
sudo apt-get install g++ make libcurl4-openssl-dev libssl-dev

# Build the project
make

# Install (optional)
sudo make install
