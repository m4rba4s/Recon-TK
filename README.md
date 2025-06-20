# 🚀 RTK Elite v3.0 - Professional Penetration Testing Framework

[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.23+-00ADD8.svg?style=for-the-badge&logo=go)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20windows%20%7C%20macOS-lightgrey.svg?style=for-the-badge)](https://github.com/m4rba4s/Recon-TK)
[![Security](https://img.shields.io/badge/security-hardened-green.svg?style=for-the-badge)](https://github.com/m4rba4s/Recon-TK)

```
██████╗ ████████╗██╗  ██╗    ███████╗██╗     ██╗████████╗███████╗
██╔══██╗╚══██╔══╝██║ ██╔╝    ██╔════╝██║     ██║╚══██╔══╝██╔════╝
██████╔╝   ██║   █████╔╝     █████╗  ██║     ██║   ██║   █████╗  
██╔══██╗   ██║   ██╔═██╗     ██╔══╝  ██║     ██║   ██║   ██╔══╝  
██║  ██║   ██║   ██║  ██╗    ███████╗███████╗██║   ██║   ███████╗
╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝    ╚══════╝╚══════╝╚═╝   ╚═╝   ╚══════╝

Professional Reconnaissance & Penetration Testing Framework
```

**RTK Elite** is a cutting-edge, enterprise-grade penetration testing framework built with Go. Designed for authorized security assessments, red team operations, and vulnerability research with zero false-positive architecture.

## 🎯 Core Features

### 🔍 **Zero False-Positive Scanning**
- **CVE Intelligence**: Real-time OSV.dev integration with validated vulnerability data
- **ASN Verification**: Accurate CDN detection with Cloudflare/Akamai range validation  
- **Content-Based Validation**: Reality-checker engine for precise vulnerability confirmation
- **Professional Exit Codes**: CI/CD integration with standardized error reporting

### ⚡ **Advanced Performance**
- **Adaptive Threading**: EWMA-based dynamic thread optimization
- **Time-boxed Operations**: Professional timeout handling with resume capabilities
- **Memory Efficient**: Optimized resource usage for large-scale assessments
- **Concurrent Architecture**: High-performance parallel processing

### 🛡️ **Enterprise Security**
- **GDPR Compliant**: Zero telemetry, local data storage only
- **Supply Chain Security**: SBOM generation and dependency validation
- **Audit Transparency**: Comprehensive logging and compliance reporting
- **Secure Configuration**: Encrypted storage with secure defaults

### 🌐 **Comprehensive Coverage**
- **Network Reconnaissance**: Port scanning, service detection, protocol analysis
- **Web Application Testing**: WAF detection, bypass techniques, vulnerability assessment
- **DNS Intelligence**: Subdomain enumeration, wildcard detection, certificate transparency
- **Cloud Security**: Container escape detection, Kubernetes assessment, cloud metadata analysis

## 🏗️ Architecture

### 🧱 **Modular Design**
```
rtk-elite/
├── cmd/                 # Command-line interface
├── internal/           # Core modules
│   ├── scan/          # Scanning engines
│   ├── validate/      # Reality-checker validation
│   ├── origin/        # Origin discovery
│   ├── cve/           # CVE intelligence
│   └── reporting/     # SARIF/JSON reporting
├── pkg/               # Public APIs
└── docs/              # Documentation
```

### 🔧 **Professional Modules**

#### 🎯 **Scanning Engine**
- **SYN-RTT Fingerprinting**: Advanced TCP stack analysis
- **Adaptive Port Discovery**: Intelligent port selection algorithms
- **Service Banner Analysis**: Deep protocol inspection
- **Performance Monitoring**: Real-time metrics and optimization

#### 🔍 **Reality-Checker Validation**
- **Content Diff Analysis**: Levenshtein distance-based validation
- **Response Code Correlation**: Multi-layer verification
- **Payload Effectiveness**: Dynamic exploit validation
- **False Positive Elimination**: Professional accuracy standards

#### 🌍 **Origin Discovery**
- **Certificate Transparency**: Real-time CT log monitoring
- **ASN-Based Filtering**: Cloudflare/Akamai edge detection
- **DNS History Analysis**: Historical resolution tracking
- **Network Path Validation**: Route verification and analysis

#### 💼 **CVE Intelligence**
- **OSV.dev Integration**: Official vulnerability database access
- **BoltDB Caching**: High-performance local storage
- **Future CVE Filtering**: Temporal validation for accuracy
- **Exploit Correlation**: Weaponization status tracking

## 🚀 Installation

### Prerequisites
```bash
# System Requirements
Go 1.23+ (latest stable)
Git 2.0+
Linux/Windows/macOS
Minimum 2GB RAM, 1GB disk space
```

### Quick Start
```bash
# Clone repository
git clone https://github.com/m4rba4s/Recon-TK.git
cd Recon-TK

# Build from source
make build

# Install (optional)
make install

# Run diagnostics
./rtk doctor
```

### Package Installation
```bash
# Debian/Ubuntu
wget https://github.com/m4rba4s/Recon-TK/releases/download/v3.0.0/rtk-elite_3.0.0_linux_amd64.deb
sudo dpkg -i rtk-elite_3.0.0_linux_amd64.deb

# RHEL/CentOS
wget https://github.com/m4rba4s/Recon-TK/releases/download/v3.0.0/rtk-elite_3.0.0_linux_amd64.rpm
sudo rpm -i rtk-elite_3.0.0_linux_amd64.rpm

# macOS Homebrew
brew tap m4rba4s/recon-tk
brew install rtk-elite
```

## 📖 Usage Examples

### Basic Operations
```bash
# System diagnostics and configuration
rtk doctor

# Target reconnaissance
rtk scan --target example.com --ports 1-65535

# DNS enumeration
rtk dns --target example.com --recursive

# CVE assessment
rtk cve-new --target example.com --severity HIGH
```

### Advanced Testing
```bash
# Cloudflare bypass assessment
rtk cfbypass example.com --debug

# Comprehensive security assessment
rtk advanced example.com --bypass-mode aggressive

# Time-boxed operation with resume
rtk scan --target example.com --timebox 3600

# Resume interrupted operation
rtk resume session_abc123
```

### Professional Reporting
```bash
# SARIF output for IDE integration
rtk scan --target example.com --output results.sarif --format sarif

# Comprehensive HTML report
rtk advanced example.com --report --format html

# JSON output for automation
rtk cve-new --target example.com --output cve-results.json
```

### CI/CD Integration
```bash
# Automated security pipeline
rtk scan --target $TARGET --silent --exit-code-mode

# Configuration validation
rtk audit --target $TARGET --compliance-mode

# Update vulnerability database
rtk cidr update && rtk cve-new --update-db
```

## 🔧 Configuration

### Environment Variables
```bash
export RTK_DATA_HOME="/opt/rtk-elite/data"
export RTK_CONFIG_HOME="/etc/rtk-elite"
export RTK_LOG_LEVEL="INFO"
export RTK_THREADS="100"
```

### Configuration File
```yaml
# ~/.rtk-elite/config.yaml
scan:
  threads: 100
  timeout: 5s
  adaptive_threading: true

cve:
  update_interval: "24h"
  min_severity: "MEDIUM"
  auto_update: true

reporting:
  format: "json"
  include_metadata: true
  compliance_mode: false

network:
  user_agent: "RTK-Elite/3.0"
  max_retries: 3
  rate_limit: "100/s"
```

## 🛡️ Security & Compliance

### Data Privacy
- **Local Storage Only**: All data remains on your system
- **No Telemetry**: Zero analytics or usage tracking
- **GDPR Compliant**: Full privacy protection
- **Audit Trail**: Comprehensive logging for compliance

### Security Features
- **Supply Chain Protection**: SBOM generation and validation
- **Secure Defaults**: Hardened configuration out-of-the-box
- **Dependency Scanning**: Automated vulnerability checks
- **Code Signing**: Digital signatures for integrity verification

### Compliance Standards
- **OWASP Guidelines**: Following security testing best practices
- **NIST Framework**: Aligned with cybersecurity standards
- **ISO 27001**: Supporting information security management
- **PCI DSS**: Payment card industry compliance support

## 🔄 Update Management

### CIDR Range Updates
```bash
# Update CDN IP ranges
rtk cidr update

# Check update status
rtk cidr status

# Verify IP classification
rtk cidr verify 172.67.68.228
```

### CVE Database Updates
```bash
# Update vulnerability database
rtk cve-new --update-db

# Check database status
rtk cve-new --db-status

# Force refresh
rtk cve-new --update-db --force
```

## 📊 Professional Reporting

### Output Formats
- **SARIF**: Static analysis results interchange format
- **JSON**: Machine-readable structured data
- **HTML**: Executive-friendly reports with visualizations
- **CSV**: Spreadsheet-compatible data export
- **XML**: Structured markup for integration

### Integration Support
- **IDE Integration**: SARIF format for VS Code, IntelliJ
- **SIEM Platforms**: JSON/XML export for Splunk, ELK
- **Ticketing Systems**: CSV export for Jira, ServiceNow
- **CI/CD Pipelines**: Exit codes and JSON for automation

## 🤝 Contributing

We welcome contributions from security professionals and developers:

### Development Setup
```bash
# Clone and setup
git clone https://github.com/m4rba4s/Recon-TK.git
cd Recon-TK

# Install dependencies
make deps

# Run tests
make test

# Code quality checks
make lint
```

### Contribution Guidelines
1. **Fork** the repository
2. **Create** a feature branch
3. **Write** tests for new features
4. **Ensure** all tests pass
5. **Submit** a pull request

### Code Standards
- **Go 1.23+** with modules
- **Test Coverage**: Minimum 80%
- **Documentation**: Comprehensive godoc comments
- **Security**: No hardcoded secrets or credentials

## 📝 Version History

### v3.0.0 - "Professional Edge" (Current)
```
🚀 Major release focused on enterprise readiness
✅ Zero false-positive CVE validation
✅ Professional exit codes and CI/CD integration
✅ CIDR auto-refresh with fallback support
✅ Time-boxed operations with resume capability
✅ Comprehensive audit and compliance features
✅ Enhanced SARIF reporting
✅ Supply chain security improvements
```

### v2.2.0 - "Zero-FalsePos Edge"
```
🔧 Critical accuracy improvements
✅ OSV.dev CVE integration
✅ ASN-based origin verification
✅ Verbose EWMA logging
✅ Static analysis integration
```

### v2.1.0 - "Reality-Checker"
```
🛡️ Enhanced validation engine
✅ Content-based verification
✅ Advanced Cloudflare detection
✅ Professional reporting
```

## 📞 Support & Resources

### Documentation
- **User Guide**: [docs/user-guide.md](docs/user-guide.md)
- **API Reference**: [docs/api-reference.md](docs/api-reference.md)
- **Configuration**: [docs/configuration.md](docs/configuration.md)
- **Troubleshooting**: [docs/troubleshooting.md](docs/troubleshooting.md)

### Community
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Community support and questions
- **Security Issues**: security@your-org.com
- **Documentation**: docs@your-org.com

### Professional Support
- **Enterprise Licensing**: Available for commercial use
- **Custom Development**: Professional services available
- **Training Programs**: Security assessment training
- **Compliance Consulting**: Regulatory requirement support

## ⚖️ Legal & Ethics

### Authorized Use Only
```
⚠️  IMPORTANT: This tool is designed for authorized security testing only.

✅ Authorized Use:
   • Testing your own systems and networks
   • Client-authorized penetration testing
   • Security research with proper permissions
   • Educational purposes in controlled environments

❌ Prohibited Use:
   • Unauthorized access to systems
   • Malicious activities or attacks
   • Violation of computer crime laws
   • Testing without explicit permission
```

### Disclaimer
```
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT RESPONSIBLE FOR ANY MISUSE OR ILLEGAL ACTIVITIES.
USERS ARE RESPONSIBLE FOR COMPLIANCE WITH APPLICABLE LAWS AND REGULATIONS.
```

## 📄 License

**MIT License** - See [LICENSE](LICENSE) for full terms.

```
Copyright (c) 2025 RTK Elite Development Team

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 🎯 Quick Reference

```bash
# Essential Commands
rtk doctor              # System diagnostics
rtk scan -t host.com    # Basic port scan
rtk dns -t host.com     # DNS enumeration
rtk cve-new -t host.com # Vulnerability assessment
rtk cfbypass host.com   # CDN bypass testing
rtk audit -t host.com   # Compliance audit
rtk cidr update         # Update IP ranges
rtk resume              # List resumable sessions

# Professional Options
--debug                 # Verbose logging
--timebox 3600         # 1-hour timeout
--output results.json  # Save results
--format sarif         # SARIF output
--silent               # Minimal output
--resume session_id    # Resume operation
```

**🔥 RTK Elite v3.0 - Where professional security testing meets enterprise reliability.**

---
*Made with ⚡ by security professionals, for security professionals.*