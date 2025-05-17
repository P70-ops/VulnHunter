#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <regex>
#include <ctime>
#include <iomanip>
#include "include/http_utils.h"
#include "include/tls_utils.h"

using namespace std;

struct Vulnerability {
    string name;
    string type;
    string pattern;
    string description;
    string severity;
};

vector<Vulnerability> load_vulnerabilities(const string& filename) {
    vector<Vulnerability> vulns;
    ifstream file(filename);
    string line;
    
    if (!file.is_open()) {
        throw runtime_error("Failed to open vulnerabilities file: " + filename);
    }
    
    while (getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        vector<string> parts;
        size_t start = 0;
        size_t end = line.find(" | ");
        
        while (end != string::npos) {
            parts.push_back(line.substr(start, end - start));
            start = end + 3;
            end = line.find(" | ", start);
        }
        parts.push_back(line.substr(start));
        
        if (parts.size() >= 5) {
            Vulnerability vuln;
            vuln.name = parts[0];
            vuln.type = parts[1];
            vuln.pattern = parts[2];
            vuln.description = parts[3];
            vuln.severity = parts[4];
            vulns.push_back(vuln);
        }
    }
    
    if (vulns.empty()) {
        cerr << "Warning: No vulnerabilities loaded from " << filename << endl;
    }
    
    return vulns;
}

void save_report(const string& filename, const string& target, 
                const vector<pair<string, string>>& results) {
    ofstream report(filename);
    if (!report.is_open()) {
        throw runtime_error("Failed to create report file: " + filename);
    }
    
    time_t now = time(0);
    report << "========================================\n";
    report << "    Web Server Vulnerability Report\n";
    report << "========================================\n";
    report << "Scan Date: " << ctime(&now);
    report << "Target: " << target << "\n\n";
    
    // Group results by type
    vector<pair<string, string>> info;
    vector<pair<string, string>> warnings;
    vector<pair<string, string>> vulnerabilities;
    vector<pair<string, string>> errors;
    
    for (const auto& result : results) {
        if (result.first == "INFO" || result.first == "TLS Version" || 
            result.first == "Certificate") {
            info.push_back(result);
        } 
        else if (result.first == "WARNING") {
            warnings.push_back(result);
        }
        else if (result.first == "VULNERABILITY") {
            vulnerabilities.push_back(result);
        }
        else if (result.first.find("Error") != string::npos) {
            errors.push_back(result);
        }
        else {
            info.push_back(result);
        }
    }
    
    // Print summary
    report << "=== Summary ==================================\n";
    report << "Vulnerabilities Found: " << vulnerabilities.size() << "\n";
    report << "Warnings: " << warnings.size() << "\n";
    report << "Errors: " << errors.size() << "\n\n";
    
    // Print vulnerabilities first
    if (!vulnerabilities.empty()) {
        report << "=== Vulnerabilities ==========================\n";
        for (const auto& vuln : vulnerabilities) {
            report << "[!] " << vuln.second << "\n";
        }
        report << "\n";
    }
    
    // Then warnings
    if (!warnings.empty()) {
        report << "=== Warnings ================================\n";
        for (const auto& warn : warnings) {
            report << "[*] " << warn.second << "\n";
        }
        report << "\n";
    }
    
    // Then errors
    if (!errors.empty()) {
        report << "=== Errors ==================================\n";
        for (const auto& err : errors) {
            report << "[X] " << err.second << "\n";
        }
        report << "\n";
    }
    
    // Finally general info
    if (!info.empty()) {
        report << "=== Details =================================\n";
        for (const auto& inf : info) {
            report << "[+] " << inf.first << ": " << inf.second << "\n";
        }
    }
    
    report << "\nScan completed at: " << ctime(&now);
    report << "========================================\n";
    report.close();
}

void print_banner() {
    cout << R"(
      _    __  _____ ___  _   _ ____  _____ ____        __  __    _    ____  _   _ _____ ____  
    | |  / / |___ // _ \| | | / ___|| ____|  _ \      |  \/  |  / \  |  _ \| | | | ____|  _ \ 
    | | / /    |_ \ (_) | | | \___ \|  _| | |_) |_____| |\/| | / _ \ | |_) | |_| |  _| | |_) |
    | |/ /_   ___) \__, | |_| |___) | |___|  _ <_____| |  | |/ ___ \|  __/|  _  | |___|  _ < 
    |_|\_(_) |____/  /_/ \___/|____/|_____|_| \_\    |_|  |_/_/   \_\_|   |_| |_|_____|_| \_\

                          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
                          ▓   CYBER RECONNAISSANCE TOOL   ▓
                          ▓   Web Vulnerability Scanner   ▓
                          ▓     Powered by C++ + OpenSSL  ▓
                          ▓     Author: [ YOUR ALIAS ]    ▓
                          ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓

         [++] Target-Based HTTPS Scan Engine     [++] Port & TLS Enumeration
         [++] Header Signature Detection         [++] CVE Pattern Matching
         [++] Live Result Logging                [++] Configurable Signatures

                         Use Responsibly – Code Like a Ghost, Think Like a Hacker

                                              
)" << '\n';
    cout << "Web Server Vulnerability Scanner v2.0\n";
    cout << "====================================\n\n";
}

bool validate_ip(const string& ip) {
    // Validate IP address format
    regex pattern(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9.-]+)");
    if (!regex_match(ip, pattern)) {
        cerr << "Error: Invalid IP/hostname format\n";
        return false;
    }
    return true;
}

bool validate_port(const string& port_str) {
    // Validate port number (1-65535)
    try {
        int port = stoi(port_str);
        if (port < 1 || port > 65535) {
            cerr << "Error: Port must be between 1 and 65535\n";
            return false;
        }
        return true;
    } catch (...) {
        cerr << "Error: Invalid port number\n";
        return false;
    }
}


int main() {
    print_banner();
    
    string host, port_str;
    int port = 0;
    
    // Get IP/hostname
    cout << "Enter target IP address or hostname (e.g., 192.168.1.1 or example.com): ";
    getline(cin, host);
    if (!validate_ip(host)) {
        return 1;
    }
    
    // Get port number
    cout << "Enter port number (1-65535): ";
    getline(cin, port_str);
    if (!validate_port(port_str)) {
        return 1;
    }
    port = stoi(port_str);
    
    string target = host + ":" + port_str;
    
    cout << "\n[+] Starting scan for " << target << "...\n";
    cout << "----------------------------------------\n";
    
    
    try {
        // Load vulnerability definitions
        vector<Vulnerability> vulns;
        try {
            vulns = load_vulnerabilities("vulnerabilities.txt");
            cout << "[+] Loaded " << vulns.size() << " vulnerability patterns\n";
        } catch (const exception& e) {
            cerr << "[!] Warning: " << e.what() << "\n";
            cerr << "[!] Continuing with basic checks only\n";
        }
        
        vector<pair<string, string>> scan_results;
        TLSInfo tls_info;
        
        // Perform TLS scan
        try {
            cout << "[+] Performing TLS scan...\n";
            tls_info = check_tls(host, port);
            scan_results.emplace_back("TLS Version", tls_info.version);
            scan_results.emplace_back("Certificate Info", "\n" + tls_info.cert_info);
            cout << "    ✓ TLS Version: " << tls_info.version << "\n";
        } catch (const exception& e) {
            string err_msg = "TLS scan failed: " + string(e.what());
            scan_results.emplace_back("TLS Error", err_msg);
            cerr << "[!] " << err_msg << "\n";
        }
        
        // Perform HTTP scan
        try {
            cout << "[+] Performing HTTP scan...\n";
            HTTPResponse response = fetch_http_response(host, port);
            scan_results.emplace_back("HTTP Status", to_string(response.status_code));
            cout << "    ✓ HTTP Status: " << response.status_code << "\n";
            
            // Check vulnerabilities
            if (!vulns.empty()) {
                cout << "[+] Checking for vulnerabilities...\n";
                for (const auto& vuln : vulns) {
                    try {
                        bool found = false;
                        
                        if (vuln.type == "HEADER") {
                            for (const auto& header : response.headers) {
                                if (regex_search(header, regex(vuln.pattern))) {
                                    found = true;
                                    break;
                                }
                            }
                        } 
                        else if (vuln.type == "BODY") {
                            found = regex_search(response.body, regex(vuln.pattern));
                        } 
                        else if (vuln.type == "TLS") {
                            found = tls_info.version.find(vuln.pattern) != string::npos;
                        }
                        
                        if (found) {
                            string vuln_msg = vuln.name + " (" + vuln.severity + ") - " + vuln.description;
                            scan_results.emplace_back("VULNERABILITY", vuln_msg);
                            cout << "    ! Found: " << vuln.name << " (" << vuln.severity << ")\n";
                        }
                    } catch (const regex_error& e) {
                        string err_msg = "Regex error in '" + vuln.name + "': " + e.what();
                        scan_results.emplace_back("WARNING", err_msg);
                        cerr << "[*] " << err_msg << "\n";
                    }
                }
            }
            
            // Basic security headers check
            vector<string> security_headers = {
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Content-Security-Policy",
                "X-XSS-Protection"
            };
            
            cout << "[+] Checking security headers...\n";
            for (const auto& header : security_headers) {
                bool found = false;
                for (const auto& h : response.headers) {
                    if (h.find(header) != string::npos) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    string msg = "Missing security header: " + header;
                    scan_results.emplace_back("WARNING", msg);
                    cout << "    * " << msg << "\n";
                }
            }
            
        } catch (const exception& e) {
            string err_msg = "HTTP scan failed: " + string(e.what());
            scan_results.emplace_back("HTTP Error", err_msg);
            cerr << "[!] " << err_msg << "\n";
        }
        
        // Save results
        try {
            string timestamp = to_string(time(0));
            string report_dir = "results";
            string report_file = report_dir + "/scan_" + host + "_" + timestamp + ".txt";
            
            // Create results directory if it doesn't exist
            system(("mkdir -p " + report_dir).c_str());
            
            save_report(report_file, target, scan_results);
            cout << "\n[+] Scan complete. Report saved to " << report_file << "\n";
            
            // Print summary
            cout << "\n=== Scan Summary =========================\n";
            int vuln_count = 0, warn_count = 0, error_count = 0;
            for (const auto& result : scan_results) {
                if (result.first == "VULNERABILITY") vuln_count++;
                else if (result.first == "WARNING") warn_count++;
                else if (result.first.find("Error") != string::npos) error_count++;
            }
            
            cout << "Vulnerabilities found: " << vuln_count << "\n";
            cout << "Warnings: " << warn_count << "\n";
            cout << "Errors: " << error_count << "\n";
            cout << "========================================\n";
            
        } catch (const exception& e) {
            cerr << "[!] Failed to save report: " << e.what() << "\n";
            // Still print results to console
            cout << "\n[+] Scan complete (report not saved). Results:\n";
            for (const auto& result : scan_results) {
                cout << "[" << result.first << "] " << result.second << "\n";
            }
        }
        
    } catch (const exception& e) {
        cerr << "\n[!] Critical error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
