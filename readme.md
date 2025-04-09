# CTF Hero

![CTF Hero Banner](https://img.shields.io/badge/CTF%20Hero-Pentesting%20Framework-blue)
![Python Version](https://img.shields.io/badge/python-3.6%2B-green)
![License](https://img.shields.io/badge/license-MIT-yellow)

CTF Hero is an optimized automation framework for Capture The Flag (CTF) competitions and penetration testing engagements. It streamlines the reconnaissance and enumeration process by focusing on core tools and methodologies that deliver actionable results.

## Features

- **Fast Port Scanning**: Discover open ports with configurable speed options
- **Service Detection**: Identify running services and their versions
- **Web Service Analysis**:
  - Screenshot capture of web pages
  - Web technology identification
  - Directory and file enumeration with intelligent filtering
  - Domain discovery from headers and content
- **Exploit Research**: Automatic searching for potential vulnerabilities based on detected services and technologies
- **Smart Reporting**: Generate comprehensive findings reports with prioritized next steps
- **Multiple Modes**: Choose between normal, aggressive, or quick scan modes depending on your time constraints

## Installation

```bash
# Clone the repository
git clone https://github.com/Guilhermemury/ctf-hero.git
cd ctf-hero

# Ensure dependencies are installed
sudo apt update
sudo apt install -y nmap ffuf whatweb cutycapt curl jq exploitdb
```

## Usage

```bash
# Basic usage
python3 ctf-hero2.py <target_ip>

# Aggressive mode with more threads
python3 ctf-hero2.py <target_ip> -a -t 20

# Quick mode for faster but less thorough scanning
python3 ctf-hero2.py <target_ip> -q

# Custom output directory
python3 ctf-hero2.py <target_ip> -o /path/to/output
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-a, --aggressive` | Use aggressive scanning techniques (faster but noisier) |
| `-t, --threads` | Number of threads for parallel processing (default: 10) |
| `-q, --quick` | Quick mode - faster but less thorough scans |
| `-o, --output` | Output directory (default: ./output) |

## Requirements

- Python 3.6+
- The following tools:
  - nmap: Port scanning and service detection
  - ffuf: Web content discovery
  - whatweb: Web technology identification
  - cutycapt: Website screenshots (optional, but recommended)
  - curl: HTTP requests
  - searchsploit: Vulnerability discovery

The script will attempt to install missing tools if run with root privileges.

## Directory Structure

After a successful scan, your output directory will contain:

```
output/
├── ctf_hero.log         # Detailed log of the scan
├── ports.txt            # List of discovered open ports
├── report.md            # Summary report with findings
├── scans/
│   ├── nmap/            # Nmap scan results
│   ├── ffuf/            # Directory enumeration results
│   ├── whatweb/         # Web technology detection results
│   ├── exploits/        # Potential exploits
│   └── services_versions.txt  # Detected service versions
└── screenshots/         # Web page screenshots
```

## Workflow

1. **Reconnaissance**: The tool begins with port scanning to identify available services
2. **Enumeration**: Based on discovered services, it performs targeted enumeration
3. **Web Analysis**: For web services, it conducts thorough fingerprinting and content discovery
4. **Vulnerability Research**: The tool searches for known vulnerabilities in identified services and technologies
5. **Reporting**: Finally, it generates a comprehensive report with findings and recommended next steps

## How It Helps

- **Time Savings**: Automates repetitive reconnaissance tasks
- **Thoroughness**: Ensures consistent coverage of common attack vectors
- **Focus**: Prioritizes results to help you identify promising attack paths quickly
- **Documentation**: Creates organized reports that can be referenced throughout your engagement

## Example

```bash
# Run a quick scan on a target
sudo python3 ctf-hero2.py 10.10.10.10 -q

# Check the report
cat output/report.md
```

## Disclaimer

This tool is designed for legal use in authorized penetration testing engagements and CTF competitions. Always ensure you have permission before scanning any systems.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request