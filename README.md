# Linux Privilege Escalation Scanner

A comprehensive Python tool for identifying potential privilege escalation vulnerabilities and misconfigurations on Linux systems. This scanner helps security professionals, system administrators, and penetration testers discover attack vectors for privilege escalation in a controlled and educational manner.

## Overview

Linux privilege escalation is a critical security concern where attackers exploit vulnerabilities to gain elevated privileges (root/sudo). This scanner systematically checks for common privilege escalation vectors including:

- Vulnerable SUID binaries
- Kernel exploits and vulnerabilities
- Misconfigured sudo permissions
- Insecure file permissions
- Writable system directories
- Cron job vulnerabilities
- PATH manipulation opportunities
- Shared library loading issues
- Docker/container escape vectors
- Capability misconfigurations

## Features

### Comprehensive Scanning
- Automated detection of privilege escalation vectors
- Multiple scanning modes (quick, thorough, custom)
- Parallel scanning for improved performance
- Detailed vulnerability assessment and analysis

### User-Friendly Interface
- Command-line interface with clear output
- Color-coded vulnerability severity levels (Critical, High, Medium, Low, Info)
- Structured report generation
- Export capabilities (JSON, HTML, plain text)

### Security & Compliance
- Non-intrusive passive scanning
- No system modifications required
- Safe for production environments
- Compliance reporting for security audits

### Educational Value
- Detailed explanations of each vulnerability
- Remediation recommendations
- References to security best practices
- Learning resources for system hardening

## Installation

### Prerequisites
- Python 3.8 or higher
- Linux operating system
- Basic system access (user-level minimum for basic scans)
- Root access (recommended for comprehensive scanning)

### Setup

```bash
# Clone the repository
git clone https://github.com/gauravmalhotra3300-hub/linux-privesc-scanner.git
cd linux-privesc-scanner

# Create virtual environment (optional but recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\\Scripts\\activate

# Install dependencies (if any)
pip install -r requirements.txt

# Make scanner executable
chmod +x privesc_scanner.py
```

## Usage

### Basic Scanning

```bash
# Quick scan for high-priority vulnerabilities
python3 privesc_scanner.py

# Comprehensive scan of all vectors
python3 privesc_scanner.py --thorough

# Scan specific categories
python3 privesc_scanner.py --category suid
python3 privesc_scanner.py --category sudo
python3 privesc_scanner.py --category kernel
```

### Advanced Options

```bash
# Generate detailed HTML report
python3 privesc_scanner.py --output report.html --format html

# Export results to JSON
python3 privesc_scanner.py --output results.json --format json

# Verbose output with debugging information
python3 privesc_scanner.py --verbose

# Custom severity threshold
python3 privesc_scanner.py --severity high critical

# Parallel scanning with thread count
python3 privesc_scanner.py --threads 4
```

## Scanning Categories

### SUID Binaries
Identifies SUID binaries that may be exploitable for privilege escalation. Checks against known vulnerable binaries and analyzes custom binaries.

### Sudo Permissions
Analyzes sudoers configuration for misconfigurations and dangerous permissions that could allow privilege escalation without passwords.

### Kernel Vulnerabilities
Detects system kernel version and checks against known privilege escalation exploits.

### File Permissions
Scans for world-writable files, insecure permissions on sensitive files, and permission-based attack vectors.

### Cron Jobs
Analyzes cron configuration for world-writable scripts and insecure job scheduling.

### Environment Variables
Checks for PATH manipulation opportunities and insecure environment variable configurations.

### Capabilities
Identifies dangerous Linux capability assignments that could enable privilege escalation.

### Docker
Detects Docker socket access, container misconfigurations, and containerization escape vectors.

## Report Output

The scanner generates detailed reports including:

```
=== Linux Privilege Escalation Scanner Report ===

System Information:
  - Hostname: [hostname]
  - Kernel: [version]
  - Distribution: [distro]
  - Scan Date: [date]

Vulnerabilities Found: [count]
  - Critical: [X]
  - High: [X]
  - Medium: [X]
  - Low: [X]
  - Info: [X]

[Detailed findings with remediation guidance]
```

## Remediation Guide

Each identified vulnerability includes:
1. **Description**: What the vulnerability is
2. **Impact**: Potential impact if exploited
3. **Detection Details**: How it was detected
4. **Remediation**: Steps to fix the issue
5. **References**: Links to security documentation

## Example Scenarios

### Scenario 1: Vulnerable SUID Binary
```
[!] CRITICAL: SUID Binary Vulnerability
Found vulnerable SUID binary: /usr/bin/find
Potential Impact: Privilege escalation to root
Remediation: Update or remove vulnerable binary
```

### Scenario 2: Misconfigured Sudo
```
[!] HIGH: Sudo Misconfiguration
User can run: /bin/cat /etc/shadow NOPASSWD
Potential Impact: Read sensitive system files
Remediation: Review sudoers configuration
```

### Scenario 3: World-Writable Script
```
[!] HIGH: World-Writable Script
File: /usr/local/bin/backup.sh (Permissions: 777)
Potential Impact: Arbitrary code execution
Remediation: Restrict file permissions to 755
```

## Requirements

The scanner requires the following system utilities:
- `find` - File searching
- `grep` - Pattern matching
- `awk` - Text processing
- `sed` - Stream editing
- `sudo` - Privilege checking
- `id` - User information

## System Requirements

- **OS**: Linux (tested on Ubuntu, Debian, CentOS, Red Hat)
- **Python**: 3.8+
- **Disk Space**: ~10 MB
- **Memory**: ~100 MB
- **Runtime**: 30 seconds to 5 minutes depending on system and scan type

## Legal & Ethical Considerations

### ⚠️ Important Disclaimer

This tool is provided for **authorized security testing only**. Unauthorized access to computer systems is illegal.

**Permitted Uses:**
- ✅ Auditing your own systems
- ✅ Authorized penetration testing with written permission
- ✅ Security research and education
- ✅ DevOps and system hardening
- ✅ Incident response and forensics

**Prohibited Uses:**
- ❌ Unauthorized system scanning
- ❌ Identifying vulnerabilities without permission
- ❌ Gaining unauthorized access
- ❌ Any illegal activity

**User Responsibility**: You are solely responsible for your actions. Ensure you have explicit written authorization before scanning any system you do not own.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit your changes (`git commit -am 'Add improvement'`)
4. Push to the branch (`git push origin feature/improvement`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Comment complex code sections

## Testing

Run the test suite:

```bash
# Run all tests
python3 -m pytest tests/

# Run with coverage
python3 -m pytest --cov=. tests/

# Run specific test category
python3 -m pytest tests/test_suid.py
```

## Troubleshooting

### Common Issues

**Issue**: Permission denied errors
```bash
# Solution: Run with appropriate privileges
sudo python3 privesc_scanner.py
```

**Issue**: Module import errors
```bash
# Solution: Install dependencies
pip install -r requirements.txt
```

**Issue**: Slow scanning
```bash
# Solution: Use quick scan or limit threads
python3 privesc_scanner.py --threads 2
```

## Performance Metrics

- Quick Scan: ~30 seconds
- Standard Scan: ~2 minutes
- Thorough Scan: ~5 minutes
- Memory Usage: 50-150 MB

## References & Resources

- [Linux Privilege Escalation Guide - HackTricks](https://book.hacktricks.xyz/linux-unix/privilege-escalation)
- [MITRE ATT&CK - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/)
- [GTFOBins - Unix Binaries Exploitation](https://gtfobins.github.io/)
- [Linux Security Hardening Guide](https://www.kernel.org/doc/html/latest/)
- [CIS Linux Security Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

## Learning Resources

- **Books**: The Art of Linux Kernel Exploitation
- **Courses**: Offensive Security Training (OSCP)
- **Certifications**: Certified Ethical Hacker (CEH), OSCP

## License

MIT License - See LICENSE file for details

## Author

Created by Gaurav Malhotra for cybersecurity education and research.

## Support & Questions

For issues, questions, or suggestions:
- Open an issue on GitHub
- Check existing documentation
- Review the FAQ section

## Version History

**v1.0.0** (January 2026)
- Initial release
- Core privilege escalation scanning
- Multiple output formats
- Comprehensive vulnerability database

## Disclaimer

This tool is provided as-is without warranty. Use at your own risk. The authors assume no responsibility for misuse or damage caused by this tool.

---

**Last Updated**: January 2026
**Status**: Active Development
**Maintainer**: gauravmalhotra3300-hub
