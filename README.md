# WhatsApp IP Leak Detection Tool

Tool untuk mendeteksi kebocoran IP real saat menggunakan WhatsApp melalui analisis paket STUN.

## 🎯 Tujuan

Mendeteksi dan menganalisis IP publik yang terungkap saat melakukan panggilan WhatsApp, untuk penelitian keamanan privasi.

## ✨ Fitur

- **STUN Detection** - Mendeteksi STUN Binding Requests secara spesifik
- **Auto Interface Detection** - Otomatis mendeteksi interface yang bekerja
- **GeoIP Integration** - Informasi geolokasi lengkap
- **WHOIS Lookup** - Informasi organisasi dan pemilik IP
- **Meta Filtering** - Mengabaikan server Facebook/Meta/WhatsApp
- **Logging** - Menyimpan hasil ke file
- **High Performance** - Menggunakan tshark yang sangat cepat

## 📋 Requirements

### System Requirements
- Linux/macOS/Windows
- Python 3.6+
- tshark (Wireshark CLI)

### Python Dependencies
```
scapy>=2.4.5
requests>=2.25.1
colorama>=0.4.4
termcolor>=1.1.0
```

## 🚀 Instalasi

### 1. Install tshark
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install tshark

# CentOS/RHEL
sudo yum install wireshark

# macOS
brew install wireshark
```

### 2. Install Python Dependencies
```bash
pip3 install -r requirements.txt
```

### 3. Optional: Install IPGeoLocation Tool
```bash
git clone https://github.com/maldevel/IPGeoLocation.git
cd IPGeoLocation
pip3 install -r requirements.txt
```

## 📖 Penggunaan

### Basic Usage
```bash
# Auto-detect interface dan mulai monitoring
sudo python3 whatsapp-leak-detector.py

# Specify interface
sudo python3 whatsapp-leak-detector.py -i eth0

# Simple UDP capture (semua UDP traffic)
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
-i, --interface    Network interface (auto-detect if not specified)
-s, --simple       Use simple UDP capture instead of STUN-specific
-o, --output       Output log file (default: leak_results.log)
-l, --list         List available interfaces
```

## 🔍 Cara Kerja

1. **Packet Capture** - Menggunakan tshark untuk capture paket UDP
2. **STUN Detection** - Mendeteksi STUN Binding Requests (message type 0x0001)
3. **IP Validation** - Memvalidasi apakah IP adalah public IP
4. **WHOIS Lookup** - Mendapatkan informasi organisasi
5. **GeoIP Lookup** - Mendapatkan informasi geolokasi
6. **Meta Filtering** - Mengabaikan server legitimate WhatsApp
7. **Logging** - Menyimpan hasil ke file

## 📊 Output Example

```
[*] Starting STUN capture on eth0
[*] Monitoring for STUN Binding Requests...
[*] Press Ctrl+C to stop
--------------------------------------------------

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

## 🛡️ Keamanan dan Privasi

### Legal Considerations
- Tool ini hanya untuk **penelitian keamanan**
- Pastikan mendapat **persetujuan** sebelum monitoring
- Ikuti **regulasi privasi** yang berlaku (GDPR, CCPA, dll)
- Jangan gunakan untuk **aktivitas ilegal**

### Ethical Guidelines
- Hanya monitor **traffic sendiri**
- Jangan monitor **orang lain** tanpa izin
- Gunakan untuk **penelitian akademis** atau **security testing**
- Hormati **privasi pengguna**

## 🔧 Troubleshooting

### Interface Not Found
```bash
# List available interfaces
sudo python3 whatsapp-leak-detector.py -l

# Test specific interface
sudo tshark -i eth0 -c 5
```

### No STUN Packets Detected
- Pastikan melakukan **panggilan WhatsApp aktif**
- STUN packets hanya muncul saat panggilan berlangsung
- Coba dengan aplikasi lain yang menggunakan WebRTC

### Permission Denied
```bash
# Run with sudo
sudo python3 whatsapp-leak-detector.py
```

### tshark Not Found
```bash
# Install tshark
sudo apt-get install tshark
```

## 📁 File Structure

```
whatsapp-leak-detector/
├── whatsapp-leak-detector.py    # Main script
├── requirements.txt             # Python dependencies
├── README.md                    # Documentation
├── leak_results.log             # Output log (generated)
└── IPGeoLocation/              # Optional GeoIP tool
```

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

Tool ini dibuat untuk tujuan penelitian dan edukasi. Pengguna bertanggung jawab penuh atas penggunaan tool ini. Penulis tidak bertanggung jawab atas penyalahgunaan tool ini.

## 📞 Support

Jika ada pertanyaan atau masalah, silakan buat issue di repository ini.

---

**Happy Researching! 🔬** 