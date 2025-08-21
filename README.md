# Network Security Monitor

A comprehensive real-time network traffic analysis and threat detection system with an intuitive web dashboard. Monitor network packets, detect suspicious activities, and visualize threats in real-time.

## 🌟 Features

### Real-time Network Monitoring
- **Live packet capture** with protocol analysis (TCP, UDP, ICMP, ARP, IPv6)
- **Real-time dashboard** with WebSocket communication
- **Interactive traffic visualization** with geographical mapping
- **Protocol statistics** and connection tracking

### Advanced Threat Detection
- **Multi-layered security analysis** with customizable rules
- **Signature-based detection** for common attack patterns:
  - SQL Injection attempts
  - Cross-Site Scripting (XSS)
  - Remote Code Execution (RCE)
  - Path Traversal attacks
  - LDAP & NoSQL injection
- **Behavioral analysis** including:
  - Port scan detection
  - Suspicious IP tracking
  - Traffic pattern anomalies
  - Amplification attack detection

### Intelligence & Analytics
- **GeoIP location tracking** for external connections
- **Risk scoring system** with threat prioritization
- **IP frequency analysis** and reputation tracking
- **Customizable blacklists** for known threats
- **Statistical analysis** with trend visualization

### User Interface
- **Modern responsive dashboard** built with Bootstrap 5
- **Real-time data streaming** with live updates
- **Interactive world map** showing traffic origins
- **Advanced filtering system** by location, port, protocol, and alert status
- **Data export capabilities** (CSV format)
- **Comprehensive logging system** with automatic rotation

## 📋 Prerequisites

### System Requirements
- **Operating System**: Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+ recommended)
- **Python**: 3.7 or higher
- **Memory**: Minimum 512MB RAM (2GB+ recommended for high traffic)
- **Network**: Administrator/root privileges for packet capture

### Dependencies
- Flask 2.0+
- Flask-SocketIO 5.0+
- Scapy 2.4+
- Requests 2.25+
- Additional Python packages (see requirements.txt)

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/network-security-monitor.git
cd network-security-monitor
```

### 2. Create Virtual Environment (Recommended)
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Install Scapy Dependencies

#### Windows
```bash
# Install Npcap (required for Windows packet capture)
# Download from: https://nmap.org/npcap/
# Run installer with "Install Npcap in WinPcap API-compatible Mode" checked
```

#### macOS
```bash
# No additional setup required
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install python3-dev libpcap-dev
```

#### Linux (CentOS/RHEL)
```bash
sudo yum install python3-devel libpcap-devel
# or for newer versions:
sudo dnf install python3-devel libpcap-devel
```

## 🎯 Quick Start

### 1. Basic Usage
```bash
# Run with administrator/root privileges
sudo python app.py

# Windows (Run PowerShell/CMD as Administrator)
python app.py
```

### 2. Access Dashboard
Open your web browser and navigate to:
```
http://localhost:5000
```

### 3. Configure Settings
- **Blacklist Management**: Add suspicious IPs/domains via the API
- **Filter Configuration**: Use the dashboard filters for focused monitoring
- **Export Data**: Download captured data in CSV format

## ⚙️ Configuration

### Environment Variables
Create a `.env` file in the project root:
```env
# Flask Configuration
FLASK_ENV=development
SECRET_KEY=your-super-secret-key-change-this

# Network Interface (optional)
NETWORK_INTERFACE=eth0

# Logging Level
LOG_LEVEL=INFO

# GeoIP Configuration (optional)
GEOIP_API_KEY=your-api-key
```

### Blacklist Configuration
Edit `blacklist.txt` to add known malicious IPs/domains:
```
# Format: one entry per line
192.168.1.100
malicious-domain.com
suspicious-ip-range.net
```

### Custom Filter Rules
Modify `analyzer.py` to add custom detection patterns:
```python
# Add to suspicious_patterns dictionary
'Custom Attack': [
    r"your-custom-regex-pattern",
    r"another-pattern"
]
```

## 🖥️ Usage Examples

### Basic Network Monitoring
```python
# Start monitoring with default settings
python app.py
```

### Advanced Configuration
```python
# Monitor specific interface with custom filters
python app.py --interface eth0 --filter "port 80 or port 443"
```

### API Usage
```bash
# Get current statistics
curl http://localhost:5000/api/stats

# Add IP to blacklist
curl -X POST http://localhost:5000/api/blacklist \
  -H "Content-Type: application/json" \
  -d '{"entry": "192.168.1.100"}'

# Get suspicious IPs
curl http://localhost:5000/api/suspicious_ips
```

## 📊 Dashboard Features

### Main Dashboard
- **Live packet stream** with real-time updates
- **Security alert counters** with threat categorization
- **Protocol statistics** (TCP, UDP, ICMP, Others)
- **Geographic traffic visualization**

### Filtering System
- **Location-based filtering** by country/city
- **Port-specific filtering** for targeted analysis
- **Protocol filtering** (TCP, UDP, ICMP, etc.)
- **Alert status filtering** (alerts only, safe only)

### Data Export
- **CSV export** of filtered packet data
- **Historical log access** with date range selection
- **Statistical reports** generation

## 🛡️ Security Analysis Features

### Threat Detection Categories
1. **Network-based Attacks**
   - Port scanning detection
   - DDoS/amplification attacks
   - Suspicious connection patterns

2. **Application-layer Attacks**
   - SQL injection attempts
   - Cross-site scripting (XSS)
   - Remote code execution (RCE)
   - Path traversal attacks

3. **Protocol Anomalies**
   - Malformed packets
   - Unusual packet sizes
   - Protocol violations

### Risk Scoring System
- **Low Risk (1-4)**: Minimal threat indicators
- **Medium Risk (5-9)**: Moderate suspicious activity
- **High Risk (10-14)**: Significant threat indicators
- **Critical Risk (15+)**: Immediate attention required

## 📁 Project Structure

```
network-security-monitor/
├── app.py                 # Main Flask application
├── sniffer.py            # Packet capture and processing
├── analyzer.py           # Security analysis engine
├── logger.py             # Logging and data persistence
├── geoip.py             # Geographic location services
├── templates/
│   └── dashboard.html    # Web dashboard interface
├── static/              # CSS, JS, and assets
├── logs/               # Log files and backups
├── blacklist.txt       # Known malicious IPs/domains
├── requirements.txt    # Python dependencies
└── README.md          # Project documentation
```

## 🔧 API Reference

### Statistics Endpoint
```http
GET /api/stats
```
Returns current system statistics including packet counts and threat metrics.

### Packet Data Endpoint
```http
GET /api/packets?count=100
```
Retrieve recent packet captures with optional count parameter.

### Blacklist Management
```http
GET /api/blacklist
POST /api/blacklist
```
View or modify the blacklist of known malicious entries.

### Suspicious IP Tracking
```http
GET /api/suspicious_ips
```
Get list of IPs flagged for suspicious activity.

## 🤝 Contributing

We welcome contributions! Please follow these guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature-name`
3. **Make your changes** with proper documentation
4. **Add tests** for new functionality
5. **Submit a pull request** with detailed description

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black *.py
flake8 *.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for legitimate network security monitoring and educational purposes only. Users are responsible for:

- **Compliance** with local laws and regulations
- **Proper authorization** before monitoring network traffic
- **Ethical use** of the software and collected data
- **Privacy protection** and data handling practices

The authors are not responsible for any misuse of this software.

## 🙏 Acknowledgments

- **Scapy** - Powerful packet manipulation library
- **Flask & Flask-SocketIO** - Web framework and real-time communication
- **Bootstrap** - Modern UI components
- **Leaflet** - Interactive mapping functionality
- **Open source community** - Various security research and threat intelligence

---

**Made with ❤️ by the Network Security Community**
