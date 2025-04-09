#!/usr/bin/env python3
"""
CTF Hero - Optimized automation framework for CTF and pentesting.
This tool automates core reconnaissance tasks with a focused approach.
"""

import os
import sys
import time
import json
import argparse
import subprocess
import re
import shutil
import signal
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Set, Any, Optional

# ANSI colors for terminal output
class Colors:
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    RED = '\033[0;31m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'  # No Color

class CTFHero:
    def __init__(self, target_ip: str, options: argparse.Namespace):
        """Initialize CTF Hero with target IP and options"""
        self.target_ip = target_ip
        self.scan_method = "aggressive" if options.aggressive else "normal"
        self.threads = options.threads
        self.quick_mode = options.quick
        self.output_dir = options.output
        
        # Setup paths
        self.setup_paths()
        
        # Initialize other variables
        self.hostname = "target.htb"
        self.hosts_file = "/etc/hosts"
        self.start_time = time.time()
        
        # Lists to store findings
        self.all_ports = []
        self.web_ports = []
        self.domains_found = set()
        self.web_techs = set()
        self.potential_vulns = set()
        
        # Setup wordlists
        self.setup_wordlists()

    def setup_paths(self):
        """Setup directory structure and file paths"""
        self.log_file = os.path.join(self.output_dir, "ctf_hero.log")
        self.ports_file = os.path.join(self.output_dir, "ports.txt")
        self.screenshots_dir = os.path.join(self.output_dir, "screenshots")
        self.scan_dir = os.path.join(self.output_dir, "scans")
        
        # Create required directories
        self.setup_directories()

    def setup_wordlists(self):
        """Setup wordlists paths and create fallbacks if needed"""
        # Default wordlist paths from seclists
        self.wordlist_directories = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
        self.wordlist_directories_small = "/usr/share/seclists/Discovery/Web-Content/common.txt"
        self.wordlist_files = "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
        self.wordlist_quickfiles = "/usr/share/seclists/Discovery/Web-Content/quickhits.txt"
        self.default_wordlist = "/tmp/ctf_wordlist.txt"
        
        # Check if wordlists exist, create fallbacks if needed
        self.check_wordlists()

    def print_banner(self):
        """Print the CTF Hero banner"""
        print(f"{Colors.CYAN}")
        print(" ██████╗████████╗███████╗    ██╗  ██╗███████╗██████╗  ██████╗ ")
        print("██╔════╝╚══██╔══╝██╔════╝    ██║  ██║██╔════╝██╔══██╗██╔═══██╗")
        print("██║        ██║   █████╗      ███████║█████╗  ██████╔╝██║   ██║")
        print("██║        ██║   ██╔══╝      ██╔══██║██╔══╝  ██╔══██╗██║   ██║")
        print("╚██████╗   ██║   ██║         ██║  ██║███████╗██║  ██║╚██████╔╝")
        print(" ╚═════╝   ╚═╝   ╚═╝         ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ")
        print(f"{Colors.NC}")
        print(f"{Colors.GREEN}[+] Optimized automation framework for CTF and pentesting{Colors.NC}")
        print(f"{Colors.YELLOW}[*] Focused on core tools: nmap, ffuf, whatweb, searchsploit{Colors.NC}\n")

    def log(self, level: str, message: str):
        """Log messages to console and log file"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Print to console with color
        if level == "INFO":
            print(f"{Colors.BLUE}[*] {message}{Colors.NC}")
        elif level == "SUCCESS":
            print(f"{Colors.GREEN}[+] {message}{Colors.NC}")
        elif level == "WARNING":
            print(f"{Colors.YELLOW}[!] {message}{Colors.NC}")
        elif level == "ERROR":
            print(f"{Colors.RED}[✗] {message}{Colors.NC}")
        
        # Write to log file
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] [{level}] {message}\n")

    def setup_directories(self):
        """Create the directory structure for output"""
        self.log("INFO", "Creating directory structure...")
        
        directories = [
            self.output_dir,
            self.screenshots_dir,
            self.scan_dir,
            os.path.join(self.scan_dir, "nmap"),
            os.path.join(self.scan_dir, "ffuf"),
            os.path.join(self.scan_dir, "whatweb"),
            os.path.join(self.scan_dir, "exploits"),
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        # Create empty log file if it doesn't exist
        if not os.path.exists(self.log_file):
            open(self.log_file, 'a').close()
            
        self.log("SUCCESS", "Directory structure created successfully")

    def check_requirements(self):
        """Check and install required tools if needed"""
        self.log("INFO", "Checking requirements...")
        
        tools = ["nmap", "ffuf", "whatweb", "curl", "jq", "searchsploit"]
        
        missing_tools = []
        
        for tool in tools:
            if not shutil.which(tool) and not self._is_package_installed(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            self.log("WARNING", f"The following tools are missing: {', '.join(missing_tools)}")
            install_choice = input("Do you want to install the missing tools? (y/n): ")
            
            if install_choice.lower() == 'y':
                self.log("INFO", "Installing missing tools...")
                
                # Check if running as root
                if os.geteuid() != 0:
                    self.log("ERROR", "You need root privileges to install tools. Please run with sudo.")
                    sys.exit(1)
                
                # Update package lists
                subprocess.run(["apt", "update", "-qq"], check=False)
                
                for tool in missing_tools:
                    self.log("INFO", f"Installing {tool}...")
                    result = subprocess.run(["apt", "install", "-y", tool], 
                                          stdout=subprocess.DEVNULL, 
                                          stderr=subprocess.DEVNULL)
                    
                    if result.returncode == 0:
                        self.log("SUCCESS", f"{tool} installed successfully")
                    else:
                        self.log("ERROR", f"Failed to install {tool}")
            else:
                self.log("WARNING", "Some tools are missing. The script may not work correctly.")
        else:
            self.log("SUCCESS", "All required tools are installed")

    def _is_package_installed(self, package: str) -> bool:
        """Check if a package is installed using dpkg"""
        try:
            result = subprocess.run(["dpkg", "-l", package], 
                                   stdout=subprocess.DEVNULL, 
                                   stderr=subprocess.DEVNULL)
            return result.returncode == 0
        except Exception:
            return False

    def check_wordlists(self):
        """Check if wordlists exist and create fallbacks if needed"""
        self.log("INFO", "Checking wordlists...")
        
        # Check directories wordlist
        if not os.path.isfile(self.wordlist_directories):
            self.log("WARNING", "Directories wordlist not found. Creating a temporary list...")
            os.makedirs(os.path.dirname(self.default_wordlist), exist_ok=True)
            
            # Common directories and files
            common_paths = [
                "admin", "login", "wp-login.php", "wp-admin", "administrator", "phpmyadmin",
                "dashboard", "wp-content", "upload", "uploads", "files", "images", "img",
                "css", "js", "javascript", "api", "apis", "v1", "v2", "users", "user",
                "admin.php", "login.php", "portal", "robots.txt", ".git", "backup", "backups",
                "config", "dev", "test", "old", "new", "beta", "prod", "staging", "temp",
                "tmp", "bak", "backup", "xml", "log", "logs", "secret", "private", "hidden",
                "admin_area", "administrator", "webadmin", "siteadmin", "staff", "index.php",
                "index.html", "index", "home", "default", "database", "db", "sql", ".env",
                "config.php", "configuration.php", "settings.php", "setup", "install"
            ]
            
            with open(self.default_wordlist, 'w') as f:
                f.write("\n".join(common_paths))
            
            self.wordlist_directories = self.default_wordlist
            self.wordlist_directories_small = self.default_wordlist
        
        self.log("SUCCESS", "Wordlists check completed")

    def update_hosts_file(self, domain: str) -> bool:
        """Add entries to /etc/hosts file with backup verification"""
        # Create backup of hosts file if it doesn't exist
        if not os.path.exists(f"{self.hosts_file}.bak"):
            try:
                shutil.copy(self.hosts_file, f"{self.hosts_file}.bak")
                self.log("INFO", f"Hosts file backup created at {self.hosts_file}.bak")
            except PermissionError:
                self.log("ERROR", "No permission to backup hosts file. Run with sudo.")
                return False
            except Exception as e:
                self.log("ERROR", f"Failed to backup hosts file: {e}")
                return False
        
        # Check if domain already exists in hosts file
        try:
            with open(self.hosts_file, 'r') as f:
                content = f.read()
                if f"{self.target_ip} {domain}" in content:
                    self.log("INFO", f"Domain {domain} already exists in hosts file")
                    return False
            
            # Add domain to hosts file
            with open(self.hosts_file, 'a') as f:
                f.write(f"{self.target_ip} {domain}\n")
                self.log("SUCCESS", f"Domain {domain} ({self.target_ip}) added to hosts file")
                return True
                
        except PermissionError:
            self.log("ERROR", f"No permission to modify hosts file. Run with sudo.")
            return False
        except Exception as e:
            self.log("ERROR", f"Failed to update hosts file: {e}")
            return False

    def restore_hosts_file(self):
        """Restore hosts file from backup"""
        backup_file = f"{self.hosts_file}.bak"
        if os.path.exists(backup_file):
            try:
                shutil.copy(backup_file, self.hosts_file)
                self.log("SUCCESS", "Hosts file restored from backup")
            except PermissionError:
                self.log("ERROR", "No permission to restore hosts file. Run with sudo.")
            except Exception as e:
                self.log("ERROR", f"Failed to restore hosts file: {e}")
        else:
            self.log("WARNING", "Hosts file backup not found")

    def scan_ports(self) -> bool:
        """Scan open ports on the target"""
        self.log("INFO", f"Starting port scan on target {self.target_ip}...")
        
        nmap_output_file = os.path.join(self.scan_dir, "nmap", "initial_scan.txt")
        
        try:
            self.log("INFO", "Running port scan...")
            
            if self.quick_mode:
                # Quick scan on common ports
                common_ports = "21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,464,587,636,1433,1521,2049,3306,3389,5432,5985,5986,8080,8443,9090"
                cmd = ["nmap", "-sS", "--min-rate=1000", "-T4", "-p", common_ports, self.target_ip, "-oN", nmap_output_file]
            elif self.scan_method == "aggressive":
                cmd = ["nmap", "-p-", "--min-rate=5000", "-T5", self.target_ip, "-oN", nmap_output_file]
            else:
                cmd = ["nmap", "-sS", "-p-", "--min-rate=1000", "-T4", self.target_ip, "-oN", nmap_output_file]
            
            # Run nmap and capture output
            process = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Show real-time output of command
            self.log("INFO", f"nmap command output:")
            for line in process.stdout.split('\n'):
                if line.strip() and not line.startswith('#'):
                    print(f"  {line}")
            
            # Parse open ports
            self._parse_open_ports(nmap_output_file)
            
            return bool(self.all_ports)
            
        except Exception as e:
            self.log("ERROR", f"Port scan failed: {e}")
            return False

    def _parse_open_ports(self, nmap_output_file: str):
        """Parse open ports from nmap output"""
        if not os.path.exists(nmap_output_file):
            self.log("ERROR", f"Nmap output file not found: {nmap_output_file}")
            return
        
        try:
            # Extract open ports
            open_ports = []
            with open(nmap_output_file, 'r') as f:
                for line in f:
                    # Look for lines with open ports
                    match = re.search(r'(\d+)/\w+\s+open', line)
                    if match:
                        open_ports.append(int(match.group(1)))
            
            # Sort ports and save to file
            open_ports.sort()
            with open(self.ports_file, 'w') as f:
                for port in open_ports:
                    f.write(f"{port}\n")
            
            self.all_ports = open_ports
            
            if self.all_ports:
                port_str = ','.join(str(p) for p in self.all_ports)
                self.log("SUCCESS", f"Found {len(self.all_ports)} open ports: {port_str}")
                
                # Identify standard web ports
                web_ports = [p for p in self.all_ports if p in [80, 443, 81, 8000, 8080, 8081, 8443, 3000, 8800, 8888, 8834, 5000, 5001, 9000, 9001, 9090, 9443]]
                
                if web_ports:
                    self.web_ports = web_ports
                    web_ports_str = ','.join(str(p) for p in self.web_ports)
                    self.log("SUCCESS", f"Web ports found: {web_ports_str}")
                else:
                    self.log("WARNING", "No standard web ports found")
                    
                    # Try to identify web services on non-standard ports
                    self.log("INFO", "Trying to identify web services on non-standard ports...")
                    self._identify_non_standard_web_ports()
            else:
                self.log("ERROR", "No open ports found")
                
        except Exception as e:
            self.log("ERROR", f"Failed to parse open ports: {e}")

    def _identify_non_standard_web_ports(self):
        """Identify web services on non-standard ports"""
        non_standard_web_ports = []
        
        for port in self.all_ports:
            # Only check ports below 10000 to avoid excessive scanning
            if port < 10000 and port not in self.web_ports:
                try:
                    url = f"http://{self.target_ip}:{port}"
                    process = subprocess.run(
                        ["curl", "-s", "--connect-timeout", "3", "--max-time", "5", "-I", url],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True
                    )
                    
                    # If it responds with HTTP headers, it's likely a web service
                    if "HTTP/" in process.stdout:
                        non_standard_web_ports.append(port)
                        self.log("SUCCESS", f"Web service detected on non-standard port: {port}")
                        
                        # Display banner info
                        banner_lines = process.stdout.strip().split('\n')[:5]  # First 5 lines
                        for line in banner_lines:
                            if line.strip():
                                self.log("INFO", f"  {line.strip()}")
                except Exception:
                    continue
        
        if non_standard_web_ports:
            # Update web ports
            self.web_ports.extend(non_standard_web_ports)

    def detailed_scan(self):
        """Perform detailed scan on discovered ports"""
        if not self.all_ports:
            self.log("ERROR", "No ports to scan in detail")
            return False
        
        ports_str = ','.join(str(p) for p in self.all_ports)
        self.log("INFO", "Running detailed scan on discovered ports...")
        
        try:
            # Run detailed nmap scan with service detection and scripts
            nmap_output_file = os.path.join(self.scan_dir, "nmap", "detailed")
            process = subprocess.run(
                ["nmap", "-sV", "-sC", "-p", ports_str, self.target_ip, "-oA", nmap_output_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Display important parts of the output
            self.log("INFO", "Detailed scan results:")
            for line in process.stdout.split('\n'):
                # Filter out noise and focus on service detection and script results
                if any(x in line for x in ["open", "SERVICE", "VERSION", "Running", "Script", "|"]):
                    if "|" in line:  # Script output
                        print(f"  {Colors.GREEN}{line}{Colors.NC}")
                    else:
                        print(f"  {line}")
            
            # Extract service versions for later analysis
            self.extract_service_versions()
            
            return True
            
        except Exception as e:
            self.log("ERROR", f"Detailed scan failed: {e}")
            return False

    def extract_service_versions(self):
        """Extract service versions from nmap scan results"""
        self.log("INFO", "Extracting service version information...")
        
        services_file = os.path.join(self.scan_dir, "services_versions.txt")
        nmap_file = os.path.join(self.scan_dir, "nmap", "detailed.nmap")
        
        if not os.path.exists(nmap_file):
            self.log("WARNING", "Detailed nmap scan file not found")
            return
        
        try:
            services = []
            with open(nmap_file, 'r') as f:
                for line in f:
                    # Match lines containing port info with services
                    match = re.search(r'(\d+)/(\w+)\s+(\w+)\s+(.+)', line)
                    if match:
                        port, protocol, state, service_info = match.groups()
                        if state == 'open':
                            services.append(f"{port}/{protocol} {service_info}")
            
            # Save services to file
            with open(services_file, 'w') as f:
                f.write('\n'.join(services))
            
            # Display service versions
            if services:
                self.log("SUCCESS", "Service versions:")
                for service in services:
                    print(f"  {service}")
                
                # Search for exploits based on identified services
                self.search_exploits(services)
                
        except Exception as e:
            self.log("ERROR", f"Failed to extract service versions: {e}")

    def search_exploits(self, services: List[str]):
        """Search for potential exploits for discovered services"""
        if not shutil.which("searchsploit"):
            self.log("WARNING", "searchsploit not found, skipping exploit search")
            return
        
        self.log("INFO", "Searching for potential exploits...")
        exploits_dir = os.path.join(self.scan_dir, "exploits")
        os.makedirs(exploits_dir, exist_ok=True)
        
        try:
            # Update searchsploit database
            subprocess.run(["searchsploit", "-u"], 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
            
            all_results = []
            
            for service_line in services:
                # Try to extract name and version
                match = re.search(r'([a-zA-Z0-9._-]+)\s+([0-9.]+[a-zA-Z0-9._-]*)', service_line)
                if match:
                    service_name, service_version = match.groups()
                    
                    if service_name and service_version:
                        self.log("INFO", f"Looking for exploits for {service_name} {service_version}")
                        
                        process = subprocess.run(
                            ["searchsploit", service_name, service_version],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True
                        )
                        
                        # Save results if any found
                        results = process.stdout.strip()
                        if results and not results.startswith("No"):
                            all_results.append(f"=== {service_name} {service_version} ===\n{results}\n")
                            self.log("SUCCESS", f"Potential exploits found for {service_name} {service_version}")
                            self.potential_vulns.add(f"{service_name} {service_version}")
                            
                            # Display results
                            print(f"\n{Colors.YELLOW}Exploits for {service_name} {service_version}:{Colors.NC}")
                            for line in results.split('\n'):
                                if "|" in line and not line.startswith("Exploit Title"):
                                    print(f"  {line}")
            
            # Save all results to a single file
            if all_results:
                all_exploits_file = os.path.join(exploits_dir, "all_exploits.txt")
                with open(all_exploits_file, 'w') as f:
                    f.write('\n'.join(all_results))
                
                self.log("SUCCESS", f"All potential exploits saved to {all_exploits_file}")
            else:
                self.log("INFO", "No exploits found for the identified services")
                
        except Exception as e:
            self.log("ERROR", f"Failed to search for exploits: {e}")

    def discover_domains(self):
        """Discover domains from web services"""
        if not self.web_ports:
            self.log("WARNING", "No web ports found to discover domains")
            return False
        
        self.log("INFO", "Attempting to discover domains from web services...")
        
        for port in self.web_ports:
            protocol = "https" if port in [443, 8443, 9443] else "http"
            self.log("INFO", f"Analyzing web service on port {port}...")
            
            try:
                url = f"{protocol}://{self.target_ip}:{port}"
                output_file = os.path.join(self.scan_dir, f"domain_discovery_{port}.txt")

                # Try to get server headers
                process = subprocess.run(
                    ["curl", "-s", "--connect-timeout", "5", "--max-time", "10", "-I", url],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

                # Check headers for domain information
                headers = process.stdout.lower()
                domains_found = []

                # Look for common headers that might contain domain info
                for header in ["host:", "location:", "server:", "x-powered-by:"]:
                    if header in headers:
                        lines = headers.split('\n')
                        for line in lines:
                            if header in line.lower():
                                if "://" in line:
                                    domain = line.split("://")[1].split("/")[0].split(":")[0]
                                    domains_found.append(domain)
                                    self.log("SUCCESS", f"Found domain: {domain}")

                # Save unique domains
                if domains_found:
                    with open(output_file, 'w') as f:
                        for domain in set(domains_found):
                            f.write(f"{domain}\n")
                            self.domains_found.add(domain)

                # If no domains found, try to analyze webpage content
                if not domains_found:
                    self.log("INFO", f"No domains found in headers for {url}, analyzing content...")
                    process = subprocess.run(
                        ["curl", "-s", "--connect-timeout", "5", "--max-time", "10", url],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        text=True
                    )

                    content = process.stdout
                    if content:
                        # Look for domain patterns in content
                        domain_patterns = [
                            r'(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})/?',
                            r'//([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})/?',
                            r'href=[\'"]?(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,})/?'
                        ]

                        for pattern in domain_patterns:
                            matches = re.findall(pattern, content)
                            if matches:
                                for domain in matches:
                                    if "." in domain and domain not in ["w3.org", "www.w3.org"]:
                                        self.domains_found.add(domain)
                                        self.log("SUCCESS", f"Found domain in content: {domain}")
            except Exception as e:
                self.log("ERROR", f"Failed to discover domains on port {port}: {e}")

        # Update hosts file with discovered domains
        if self.domains_found:
            self.log("SUCCESS", f"Found {len(self.domains_found)} potential domains")
            domains_file = os.path.join(self.scan_dir, "domains.txt")
            with open(domains_file, 'w') as f:
                for domain in sorted(self.domains_found):
                    f.write(f"{domain}\n")
                    # Update hosts file with discovered domain
                    self.update_hosts_file(domain)

            # Set default hostname if found
            if self.domains_found:
                self.hostname = next(iter(self.domains_found))
                self.log("INFO", f"Setting default hostname to: {self.hostname}")

            return True
        else:
            self.log("WARNING", "No domains discovered")
            # If no domain found, add target.htb to hosts file
            self.update_hosts_file("target.htb")
            return False

    def scan_web_services(self):
        """Scan web services on discovered ports with focused approach"""
        if not self.web_ports:
            self.log("WARNING", "No web ports found to scan")
            return

        self.log("INFO", "Starting optimized web service scanning...")

        # Prepare a list of URLs to scan
        urls_to_scan = []
        for port in self.web_ports:
            protocol = "https" if port in [443, 8443, 9443] else "http"

            # Add IP-based URL
            urls_to_scan.append(f"{protocol}://{self.target_ip}:{port}")

            # Add domain-based URLs if domains were found
            for domain in self.domains_found:
                urls_to_scan.append(f"{protocol}://{domain}:{port}")

        # Add default hostname if we didn't find any domains
        if self.hostname != "target.htb" or not self.domains_found:
            for port in self.web_ports:
                protocol = "https" if port in [443, 8443, 9443] else "http"
                urls_to_scan.append(f"{protocol}://{self.hostname}:{port}")

        # Remove duplicates
        urls_to_scan = list(set(urls_to_scan))

        self.log("INFO", f"Scanning {len(urls_to_scan)} web URLs")

        # Process each URL one at a time for better control
        for url in urls_to_scan:
            self._scan_single_web_service(url)

    def _scan_single_web_service(self, url):
        """Scan a single web service URL with multiple tools"""
        self.log("INFO", f"Scanning web service: {url}")

        # Extract parts from URL for naming files
        parsed_url = url.replace("://", "_").replace(":", "_").replace("/", "_").rstrip("_")

        try:
            # 1. Take screenshot
            self._take_screenshot(url, parsed_url)

            # 2. Identify web technologies
            self._identify_web_technologies(url, parsed_url)

            # 3. Directory and file enumeration
            self._enumerate_directories(url, parsed_url)

        except Exception as e:
            self.log("ERROR", f"Failed to scan {url}: {e}")

    def _take_screenshot(self, url, parsed_url):
        """Take screenshot of web page using cutycapt"""
        screenshot_file = os.path.join(self.screenshots_dir, f"{parsed_url}.png")

        self.log("INFO", f"Taking screenshot of {url}...")

        # Check if cutycapt is installed
        if shutil.which("cutycapt"):
            try:
                subprocess.run(
                    ["cutycapt", "--url=" + url, "--out=" + screenshot_file, "--delay=1000"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=15
                )

                if os.path.exists(screenshot_file) and os.path.getsize(screenshot_file) > 0:
                    self.log("SUCCESS", f"Screenshot saved to {screenshot_file}")
                else:
                    self.log("WARNING", f"Failed to capture screenshot of {url}")
            except subprocess.TimeoutExpired:
                self.log("WARNING", f"Screenshot capture timed out for {url}")
            except Exception as e:
                self.log("ERROR", f"Screenshot error: {e}")
        else:
            self.log("WARNING", "cutycapt not installed, skipping screenshot")

    def _identify_web_technologies(self, url, parsed_url):
        """Identify web technologies using whatweb"""
        whatweb_file = os.path.join(self.scan_dir, "whatweb", f"{parsed_url}.json")

        self.log("INFO", f"Identifying web technologies for {url}...")

        try:
            process = subprocess.run(
                ["whatweb", "-a", "3", "--color=never", "--log-json=" + whatweb_file, url],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=30
            )

            # Parse the results
            if os.path.exists(whatweb_file) and os.path.getsize(whatweb_file) > 0:
                with open(whatweb_file, 'r') as f:
                    try:
                        data = json.load(f)
                        if isinstance(data, list) and data:
                            plugins = data[0].get('plugins', {})
                            if plugins:
                                self.log("SUCCESS", f"Web technologies found for {url}:")
                                for tech, info in plugins.items():
                                    if tech.lower() not in ['title', 'ip', 'script', 'html', 'object', 'meta-author']:
                                        tech_str = f"{tech}"
                                        if isinstance(info, dict) and 'version' in info:
                                            tech_str += f" {info['version']}"
                                            self.web_techs.add(f"{tech} {info['version']}")
                                        else:
                                            self.web_techs.add(tech)
                                        print(f"  {Colors.CYAN}{tech_str}{Colors.NC}")

                                # Search for exploits based on detected technologies
                                self._search_web_exploits()
                    except json.JSONDecodeError:
                        self.log("WARNING", f"Failed to parse whatweb results for {url}")
            else:
                self.log("WARNING", f"No whatweb results for {url}")

        except subprocess.TimeoutExpired:
            self.log("WARNING", f"whatweb scan timed out for {url}")
        except Exception as e:
            self.log("ERROR", f"whatweb scan failed: {e}")

    def _search_web_exploits(self):
        """Search for exploits based on detected web technologies"""
        if not self.web_techs:
            return

        exploits_file = os.path.join(self.scan_dir, "exploits", "web_exploits.txt")

        self.log("INFO", "Searching for exploits for detected web technologies...")

        all_results = []

        for tech in self.web_techs:
            # Skip generic technologies
            if tech.lower() in ['jquery', 'bootstrap', 'css', 'javascript', 'html5', 'html']:
                continue

            try:
                process = subprocess.run(
                    ["searchsploit", tech],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True
                )

                results = process.stdout.strip()
                if results and not results.startswith("No"):
                    all_results.append(f"=== {tech} ===\n{results}\n")
                    self.log("SUCCESS", f"Potential exploits found for {tech}")
                    self.potential_vulns.add(tech)

                    # Display results
                    print(f"\n{Colors.YELLOW}Exploits for {tech}:{Colors.NC}")
                    for line in results.split('\n'):
                        if "|" in line and not line.startswith("Exploit Title"):
                            print(f"  {line}")
            except Exception as e:
                self.log("ERROR", f"Failed to search exploits for {tech}: {e}")

        # Save all results to a single file
        if all_results:
            with open(exploits_file, 'w') as f:
                f.write('\n'.join(all_results))

            self.log("SUCCESS", f"All potential web exploits saved to {exploits_file}")

    def _enumerate_directories(self, url, parsed_url):
        """Enumerate directories and files using ffuf"""
        self.log("INFO", f"Enumerating directories and files for {url}...")

        # Set up ffuf output file
        ffuf_dir = os.path.join(self.scan_dir, "ffuf")
        ffuf_output = os.path.join(ffuf_dir, f"{parsed_url}_dirs.json")

        # Choose wordlist based on quick mode
        wordlist = self.wordlist_quickfiles if self.quick_mode else self.wordlist_directories

        try:
            # Execute ffuf with selected wordlist
            cmd = [
                "ffuf", "-u", f"{url}/FUZZ",
                "-w", wordlist,
                "-mc", "200,204,301,302,307,401,403,405",
                "-c",
                "-t", str(self.threads),
                "-o", ffuf_output,
                "-of", "json"
            ]

            # Add some filtering to reduce false positives
            cmd.extend(["-fs", "0"])

            # Run the command with a timeout
            self.log("INFO", f"Running directory enumeration with ffuf...")
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300 if not self.quick_mode else 120
            )

            # Parse results
            if os.path.exists(ffuf_output) and os.path.getsize(ffuf_output) > 0:
                self._parse_ffuf_results(ffuf_output, url)
            else:
                self.log("WARNING", f"No ffuf results for {url}")

        except subprocess.TimeoutExpired:
            self.log("WARNING", f"ffuf scan timed out for {url}")
        except Exception as e:
            self.log("ERROR", f"ffuf scan failed: {e}")

    def _parse_ffuf_results(self, ffuf_output, base_url):
        """Parse ffuf results and check for interesting files"""
        try:
            with open(ffuf_output, 'r') as f:
                data = json.load(f)
                results = data.get('results', [])

                if results:
                    self.log("SUCCESS", f"Found {len(results)} directories/files")

                    interesting_extensions = ['.php', '.asp', '.aspx', '.jsp', '.git', '.env', '.bak', '.old', '.zip',
                                              '.tar', '.gz', '.sql', '.conf', '.config']
                    interesting_files = []
                    directories = []

                    for result in results:
                        path = result.get('input', {}).get('FUZZ', '')
                        status = result.get('status', 0)
                        size = result.get('length', 0)

                        if not path:
                            continue

                        # Check if it's a directory or file
                        if path.endswith('/') or '.' not in path:
                            directories.append(path)
                        else:
                            # Check for interesting files
                            if any(path.endswith(ext) for ext in interesting_extensions):
                                interesting_files.append((path, status, size))

                            # Check for common sensitive files
                            if path.lower() in ['robots.txt', '.htaccess', 'web.config', '.env', 'config.php',
                                                'wp-config.php']:
                                interesting_files.append((path, status, size))

                    # Print results
                    if directories:
                        self.log("SUCCESS", f"Found {len(directories)} directories")
                        for directory in sorted(directories)[:10]:  # Limit to 10 directories to avoid spam
                            print(f"  {Colors.BLUE}{directory}{Colors.NC}")
                        if len(directories) > 10:
                            print(f"  ... and {len(directories) - 10} more")

                    if interesting_files:
                        self.log("SUCCESS", f"Found {len(interesting_files)} interesting files")
                        for file, status, size in sorted(interesting_files):
                            print(f"  {Colors.GREEN}{file}{Colors.NC} (Status: {status}, Size: {size})")

                            # Try to fetch interesting files for further analysis
                            self._check_interesting_file(base_url, file)
                else:
                    self.log("WARNING", "No directories or files found")

        except Exception as e:
            self.log("ERROR", f"Failed to parse ffuf results: {e}")

    def _check_interesting_file(self, base_url, file_path):
        """Check interesting file for sensitive information"""
        try:
            url = f"{base_url}/{file_path}"
            self.log("INFO", f"Checking interesting file: {url}")

            process = subprocess.run(
                ["curl", "-s", "--connect-timeout", "5", "--max-time", "10", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True
            )

            content = process.stdout
            if content:
                # Save file content
                file_name = file_path.replace('/', '_')
                output_file = os.path.join(self.scan_dir, f"interesting_file_{file_name}")

                with open(output_file, 'w') as f:
                    f.write(content)

                self.log("SUCCESS", f"Saved content to {output_file}")

                # Look for sensitive information
                sensitive_patterns = [
                    r'password\s*=', r'passwd\s*=', r'pass\s*=', r'pwd\s*=',
                    r'username\s*=', r'user\s*=', r'dbuser\s*=', r'db_user\s*=',
                    r'api[_-]key', r'apikey', r'secret[_-]key', r'secretkey',
                    r'admin', r'root', r'config', r'database', r'DB_'
                ]

                for pattern in sensitive_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.log("WARNING", f"Potential sensitive information found in {file_path}: {pattern}")

        except Exception as e:
            self.log("ERROR", f"Failed to check {file_path}: {e}")

    def generate_report(self):
        """Generate a summary report with findings"""
        report_file = os.path.join(self.output_dir, "report.md")

        self.log("INFO", "Generating summary report...")

        try:
            with open(report_file, 'w') as f:
                # Report header
                f.write("# CTF Hero - Target Assessment Report\n\n")
                f.write(f"- **Target:** {self.target_ip}\n")
                f.write(f"- **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"- **Scan Duration:** {self._format_duration(time.time() - self.start_time)}\n\n")

                # Open ports
                f.write("## Open Ports\n\n")
                if self.all_ports:
                    f.write(f"Found {len(self.all_ports)} open ports:\n\n")
                    ports_str = ', '.join(str(p) for p in sorted(self.all_ports))
                    f.write(f"```\n{ports_str}\n```\n\n")
                else:
                    f.write("No open ports found.\n\n")

                # Web services
                f.write("## Web Services\n\n")
                if self.web_ports:
                    f.write(
                        f"Found {len(self.web_ports)} web ports: {', '.join(str(p) for p in sorted(self.web_ports))}\n\n")

                    # Domains
                    if self.domains_found:
                        f.write("### Domains Discovered\n\n")
                        for domain in sorted(self.domains_found):
                            f.write(f"- {domain}\n")
                        f.write("\n")

                    # Web technologies
                    if self.web_techs:
                        f.write("### Web Technologies\n\n")
                        for tech in sorted(self.web_techs):
                            f.write(f"- {tech}\n")
                        f.write("\n")
                else:
                    f.write("No web services found.\n\n")

                # Potential vulnerabilities
                f.write("## Potential Vulnerabilities\n\n")
                if self.potential_vulns:
                    for vuln in sorted(self.potential_vulns):
                        f.write(f"- {vuln}\n")
                    f.write("\n")
                    f.write("Check the exploits directory for more details.\n\n")
                else:
                    f.write("No potential vulnerabilities identified.\n\n")

                # Next steps
                f.write("## Recommended Next Steps\n\n")
                self._generate_next_steps(f)

            self.log("SUCCESS", f"Report generated at {report_file}")

        except Exception as e:
            self.log("ERROR", f"Failed to generate report: {e}")

    def _format_duration(self, seconds):
        """Format duration in seconds to human-readable format"""
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)

        if h > 0:
            return f"{h}h {m}m {s}s"
        elif m > 0:
            return f"{m}m {s}s"
        else:
            return f"{s}s"

    def _generate_next_steps(self, file):
        """Generate recommended next steps based on findings"""
        steps = []

        # Web service recommendations
        if self.web_ports:
            # HTTP-specific recommendations
            if any(p in self.web_ports for p in [80, 8080, 8000]):
                steps.append("- Perform a more thorough web application penetration test")
                steps.append("- Check for common web vulnerabilities (SQL injection, XSS, CSRF, etc.)")

            # HTTPS-specific recommendations
            if any(p in self.web_ports for p in [443, 8443]):
                steps.append("- Verify SSL/TLS configuration")
                steps.append("- Check for SSL/TLS vulnerabilities")

            # If web technologies detected
            if self.web_techs:
                steps.append("- Research specific vulnerabilities for the detected web technologies")

        # SSH-specific recommendations
        if 22 in self.all_ports:
            steps.append("- Check for SSH misconfigurations")
            steps.append("- Try common SSH credentials")

        # FTP-specific recommendations
        if 21 in self.all_ports:
            steps.append("- Check for anonymous FTP access")
            steps.append("- Try common FTP credentials")

        # SMB-specific recommendations
        if any(p in self.all_ports for p in [139, 445]):
            steps.append("- Check for SMB shares and permissions")
            steps.append("- Use tools like enum4linux for further enumeration")

        # Database-specific recommendations
        db_ports = {
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL",
            27017: "MongoDB"
        }
        for port, db_name in db_ports.items():
            if port in self.all_ports:
                steps.append(f"- Check for default {db_name} credentials")
                steps.append(f"- Test for {db_name} misconfigurations")

        # If potential vulnerabilities found
        if self.potential_vulns:
            steps.append("- Review and validate identified potential vulnerabilities")
            steps.append("- Attempt exploitation of promising vulnerabilities")

        # General recommendations
        steps.append("- Perform more targeted fuzzing based on initial findings")
        steps.append("- Try to combine discovered information to identify attack paths")

        # Write steps to file
        if steps:
            file.write("Based on the initial findings, consider these next steps:\n\n")
            for step in steps:
                file.write(f"{step}\n")
        else:
            file.write("No specific recommendations based on current findings.")

    def run(self):
        """Run the CTF Hero scanning process"""
        # Print banner
        self.print_banner()

        # Check requirements
        self.check_requirements()

        # Initial port scanning
        self.log("INFO", f"Starting scan on target {self.target_ip}")

        if not self.scan_ports():
            self.log("ERROR", "Initial port scan failed or found no open ports")
            return False

        # Detailed port scanning
        self.detailed_scan()

        # Web service discovery
        if self.web_ports:
            self.discover_domains()
            self.scan_web_services()

        # Generate report
        self.generate_report()

        # Display scan duration
        duration = self._format_duration(time.time() - self.start_time)
        self.log("SUCCESS", f"Scan completed in {duration}")

        return True


def handle_signal(signum, frame):
    """Handle interruption signals"""
    print(f"\n{Colors.RED}[!] Scan interrupted! Cleaning up...{Colors.NC}")

    # Restore hosts file if backup exists
    if os.path.exists("/etc/hosts.bak"):
        try:
            shutil.copy("/etc/hosts.bak", "/etc/hosts")
            print(f"{Colors.GREEN}[+] Hosts file restored{Colors.NC}")
        except Exception as e:
            print(f"{Colors.RED}[✗] Failed to restore hosts file: {e}{Colors.NC}")

    sys.exit(1)


def main():
    """Main function"""
    # Register signal handlers
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    # Parse arguments
    parser = argparse.ArgumentParser(description="CTF Hero - Optimized automation framework for CTF and pentesting")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Use aggressive scanning")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("-q", "--quick", action="store_true", help="Quick mode - faster but less thorough")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")

    args = parser.parse_args()

    # Create CTF Hero instance
    ctf_hero = CTFHero(args.target, args)

    # Run the scan
    try:
        ctf_hero.run()
    except KeyboardInterrupt:
        ctf_hero.log("WARNING", "Scan interrupted by user")
        ctf_hero.restore_hosts_file()
    except Exception as e:
        ctf_hero.log("ERROR", f"Scan failed: {e}")
        ctf_hero.restore_hosts_file()


if __name__ == "__main__":
    main()