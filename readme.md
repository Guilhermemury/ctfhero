# CTF Hero 🛡️

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Contributors](https://img.shields.io/github/contributors/Guilhermemury/ctfhero)](https://github.com/Guilhermemury/ctfhero/graphs/contributors)

CTF Hero is an optimized automation framework for CTF challenges and penetration testing. It focuses on core reconnaissance tasks with a streamlined approach, making it perfect for both beginners and experienced security professionals.

## 🌟 Features

- **Smart Port Scanning**: Efficient port discovery with nmap
- **Web Service Analysis**: Automated web technology detection and directory enumeration
- **Domain Discovery**: Intelligent domain enumeration from web services
- **Vulnerability Assessment**: Automated search for known exploits
- **Standardized Output**: Clean and organized reporting
- **Optimized Performance**: Smart resource usage and timeout management
- **Customizable Scanning**: Multiple scanning modes (quick, normal, aggressive)

## 📋 Prerequisites

- Python 3.8 or higher
- Linux/Unix-based system
- Root privileges (for some operations)
- Required tools:
  - nmap
  - ffuf
  - whatweb
  - curl
  - jq
  - searchsploit
  - cutycapt (optional, for screenshots)

## 🚀 Installation

1. Clone the repository:
```bash
git clone https://github.com/Guilhermemury/ctfhero.git
cd ctfhero
```

2. Install required system packages:
```bash
sudo apt update
sudo apt install -y nmap ffuf whatweb curl jq exploitdb cutycapt
```

3. Make the script executable:
```bash
chmod +x ctf-hero2.py
```

## 💻 Usage

Basic usage:
```bash
sudo ./ctf-hero2.py <target_ip>
```

Advanced options:
```bash
sudo ./ctf-hero2.py <target_ip> [options]

Options:
  -a, --aggressive    Use aggressive scanning mode
  -t THREADS, --threads THREADS
                      Number of threads (default: 10)
  -q, --quick         Quick mode - faster but less thorough
  -o OUTPUT, --output OUTPUT
                      Output directory (default: output)
```

## 📁 Project Structure

```
ctfhero/
├── ctf-hero2.py          # Main script
├── requirements.txt      # Python dependencies
├── LICENSE              # MIT License
├── .github/             # GitHub specific files
│   ├── workflows/       # GitHub Actions workflows
│   └── ISSUE_TEMPLATE/  # Issue templates
├── docs/                # Documentation
│   ├── usage.md        # Detailed usage guide
│   └── examples.md     # Usage examples
└── tests/              # Test files
    └── test_*.py       # Unit tests
```

## 📊 Output Structure

```
output/
├── report.md           # Summary report
├── ctf_hero.log       # Detailed log file
├── ports.txt          # Discovered ports
├── domains.txt        # Discovered domains
├── screenshots/       # Web page screenshots
└── scans/             # Detailed scan results
    ├── nmap/         # Nmap scan results
    ├── ffuf/         # Directory enumeration results
    ├── whatweb/      # Web technology detection
    └── exploits/     # Potential exploits
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational and authorized security testing purposes only. Always ensure you have permission to test the target system. The authors are not responsible for any misuse or damage caused by this program.

## 🙏 Acknowledgments

- Inspired by various CTF challenges and penetration testing methodologies
- Thanks to all contributors and the security community
- Special thanks to the developers of the tools used in this project

## 📞 Contact

Guilherme Mury - [@kilserv](https://twitter.com/kilserv)

Project Link: [https://github.com/Guilhermemury/ctfhero](https://github.com/Guilhermemury/ctfhero)
