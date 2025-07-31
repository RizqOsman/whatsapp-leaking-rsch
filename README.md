# WhatsApp IP Leak Detector

A comprehensive network monitoring tool designed to detect potential IP address leaks during WhatsApp calls and other real-time communications. This tool captures STUN (Session Traversal Utilities for NAT) packets and analyzes network traffic to identify public IP addresses that may be exposed during peer-to-peer communications.

## 🎯 Purpose

This tool is designed for:
- **Network Security Research**: Understanding how real-time communication apps handle IP exposure
- **Privacy Analysis**: Detecting potential IP leaks during VoIP calls
- **Network Monitoring**: Comprehensive traffic analysis for security assessments
- **Educational Purposes**: Learning about STUN protocol and WebRTC implementations

## ✨ Features

- **Multi-Mode Capture**: STUN-specific, comprehensive, WhatsApp-focused, and debug modes
- **Real-time Monitoring**: Live packet capture and analysis
- **IP Classification**: Automatic detection of public, private, multicast, and reserved IPs
- **WHOIS Integration**: Detailed IP ownership and organization information
- **GeoIP Lookup**: Geographical location data for detected IPs
- **Meta Server Filtering**: Automatic filtering of Facebook/Meta/WhatsApp servers
- **Comprehensive Logging**: Detailed results saved to log files
- **Auto-Interface Detection**: Automatic network interface detection and testing
- **Cross-Platform**: Works on Linux, macOS, and Windows

## 🛠️ Requirements

### System Requirements
- **Python 3.7+**
- **tshark/Wireshark** (for packet capture)
- **Root/Administrator privileges** (for packet capture)

### Python Dependencies
```bash
pip3 install -r requirements.txt
```

### System Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install tshark

# CentOS/RHEL
sudo yum install wireshark

# macOS
brew install wireshark
```

## 📦 Installation

1. **Clone the repository:**
```bash
git clone https://github.com/RizqOsman/whatsapp-leaking-rsch.git
cd whatsapp-leaking-rsch
```

2. **Install Python dependencies:**
```bash
pip3 install -r requirements.txt
```

3. **Install GeoIP tool (optional):**
```bash
git clone https://github.com/maldevel/IPGeoLocation.git
```

4. **Verify tshark installation:**
```bash
tshark --version
```

## 📖 Usage

### Basic Usage
```bash
# Auto-detect interface and start STUN monitoring
sudo python3 whatsapp-leak-detector.py

# Specify interface
sudo python3 whatsapp-leak-detector.py -i eth0

# Monitor ALL traffic (TCP/UDP/STUN) - RECOMMENDED
sudo python3 whatsapp-leak-detector.py -i eth0 -c

# Monitor WhatsApp-focused traffic patterns
sudo python3 whatsapp-leak-detector.py -i eth0 -w

# Simple UDP capture (all UDP traffic)
sudo python3 whatsapp-leak-detector.py -i eth0 -s

# Custom output file
sudo python3 whatsapp-leak-detector.py -o my_results.log
```

### List Available Interfaces
```bash
sudo python3 whatsapp-leak-detector.py -l
```

### Command Line Options
```
-i, --interface     Network interface (auto-detect if not specified)
-c, --comprehensive Monitor ALL traffic (TCP/UDP/STUN) - RECOMMENDED
-w, --whatsapp      Monitor WhatsApp-focused traffic patterns
-s, --simple        Use simple UDP capture instead of STUN-specific
-d, --debug         DEBUG mode - show ALL traffic without filtering
-o, --output        Output log file (default: leak_results.log)
-l, --list          List available interfaces
```

### Monitoring Modes

#### 1. **Comprehensive Mode (-c)** - RECOMMENDED
```bash
sudo python3 whatsapp-leak-detector.py -c
```
- **Monitors ALL traffic** (TCP, UDP, STUN)
- **Captures all IPs** that communicate
- **Ideal for comprehensive research**
- **Shows all traffic patterns**

#### 2. **WhatsApp Mode (-w)**
```bash
sudo python3 whatsapp-leak-detector.py -w
```
- **Focuses on WhatsApp traffic**
- **Monitors TCP and UDP** relevant patterns
- **Shows WhatsApp traffic patterns**

#### 3. **STUN Mode (Default)**
```bash
sudo python3 whatsapp-leak-detector.py
```
- **Monitors only STUN packets**
- **Specific to WebRTC**
- **Less noise**

#### 4. **Simple Mode (-s)**
```bash
sudo python3 whatsapp-leak-detector.py -s
```
- **Monitors all UDP traffic**
- **Filters private IPs**
- **Similar to original bash script**

#### 5. **Debug Mode (-d)**
```bash
sudo python3 whatsapp-leak-detector.py -d
```
- **Shows ALL traffic without filtering**
- **Displays detailed packet information**
- **Useful for troubleshooting**

## 🔍 How It Works

### 1. **Packet Capture**
- Uses `tshark` for high-performance packet capture
- Monitors network interface in real-time
- Captures STUN, TCP, and UDP packets

### 2. **STUN Detection**
- Identifies STUN Binding Requests (message type 0x0001)
- Detects WebRTC peer-to-peer communication attempts
- Filters for NAT traversal packets

### 3. **IP Analysis**
- Classifies IP addresses (Public, Private, Multicast, etc.)
- Validates IP address ranges
- Filters out private and reserved IPs

### 4. **Information Gathering**
- **WHOIS Lookup**: Organization, network, and country information
- **GeoIP Lookup**: City, ISP, latitude, longitude
- **Meta Filtering**: Excludes Facebook/Meta/WhatsApp servers

### 5. **Logging and Reporting**
- Saves detailed results to log files
- Provides real-time console output
- Generates comprehensive reports

## 📊 Sample Output

```
[*] Starting COMPREHENSIVE capture on eth0
[*] Monitoring ALL IP traffic (TCP/UDP/STUN)...
[*] This will capture everything - WhatsApp, web traffic, etc.
[*] Press Ctrl+C to stop
--------------------------------------------------

[TCP] 192.168.1.100:54321 -> 8.8.8.8:443
  [SRC] 192.168.1.100 - Type: Private
  [DST] 8.8.8.8 - Type: Public

[STUN] Binding Request (1) - 192.168.1.100:54321 -> 203.0.113.1:3478
  [SRC] 192.168.1.100 - Type: Private
  [DST] 203.0.113.1 - Type: Public

[PACKET #1] IP: 8.8.8.8 - Type: Public
[STUN] Public IP detected: 8.8.8.8
─ WHOIS ─
OrgName:        Google LLC
NetName:        GOOGLE
Country:        US
─ GEOIP ─
IP: 8.8.8.8
Country: United States
City: Mountain View
ISP: Google LLC
──────────────────────────────────────────────────
```

## 🔒 Security & Privacy Considerations

### Legal and Ethical Use
- **Educational Purpose Only**: This tool is for research and educational purposes
- **Authorized Testing**: Only use on networks you own or have explicit permission to test
- **Privacy Respect**: Do not use to invade others' privacy
- **Compliance**: Ensure compliance with local laws and regulations

### Data Handling
- **Local Processing**: All analysis is performed locally
- **No Data Transmission**: No captured data is sent to external servers
- **Temporary Storage**: Packet data is not permanently stored
- **Log Files**: Only IP analysis results are logged

## 🐛 Troubleshooting

### Common Issues

#### 1. **No Packets Captured**
```bash
# Check interface status
sudo python3 whatsapp-leak-detector.py -l

# Test with debug mode
sudo python3 whatsapp-leak-detector.py -d

# Generate test traffic
ping 8.8.8.8
```

#### 2. **tshark Not Found**
```bash
# Install tshark
sudo apt-get install tshark  # Ubuntu/Debian
sudo yum install wireshark    # CentOS/RHEL
brew install wireshark        # macOS
```

#### 3. **Permission Denied**
```bash
# Run with sudo
sudo python3 whatsapp-leak-detector.py

# Or add user to wireshark group
sudo usermod -a -G wireshark $USER
```

#### 4. **No Public IPs Detected**
- Check network connectivity
- Generate external traffic (browse web, make calls)
- Use comprehensive mode (-c) instead of STUN-only

### Debug Mode
Use debug mode to see all traffic:
```bash
sudo python3 whatsapp-leak-detector.py -d
```

## 📁 File Structure

```
whatsapp-leaking-rsch/
├── whatsapp-leak-detector.py    # Main detection script
├── debug_capture.py             # Debug and testing script
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── leak_results.log             # Output log file
└── IPGeoLocation/               # GeoIP tool (optional)
    ├── ipgeolocation.py
    ├── core/
    └── ...
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is provided for **educational and research purposes only**. The authors are not responsible for any misuse of this software. Users must ensure they have proper authorization before testing on any network.

## 👨‍💻 Author

**RizqOsman**  
*Backend, DevOps & Network Pentester*

- **GitHub**: [@RizqOsman](https://github.com/RizqOsman)
- **Specializations**: Backend Development, DevOps, Network Security Testing
- **Focus**: Network security research, penetration testing, privacy analysis

## 🙏 Acknowledgments

- **IPGeoLocation**: [@maldevel](https://github.com/maldevel) for the GeoIP tool
- **Wireshark**: For the excellent packet analysis capabilities
- **STUN Protocol**: RFC 5389 for NAT traversal specifications
- **WebRTC Community**: For real-time communication protocols

---

**⚠️ Important**: This tool is for educational purposes only. Always ensure you have proper authorization before testing on any network. 