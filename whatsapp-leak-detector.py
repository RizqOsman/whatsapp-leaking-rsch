import subprocess
import ipaddress
import os
import socket
from datetime import datetime
import time
import signal
import sys

class WhatsAppLeakDetector:
    def __init__(self, interface="eth0", output_file="leak_results.log"):
        self.interface = interface
        self.output_file = output_file
        self.checked_ips = set()
        self.running = False
        self.packet_count = 0
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n[!] Received signal {signum}, shutting down...")
        self.stop()
        sys.exit(0)
    
    def is_valid_public_ip(self, ip):
        """Check if IP is a valid public IPv4 address"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if it's IPv4
            if ip_obj.version != 4:
                return False
                
            # Check if it's private using ipaddress module
            if ip_obj.is_private:
                return False
                
            # Check if it's multicast
            if ip_obj.is_multicast:
                return False
                
            # Check if it's reserved
            if ip_obj.is_reserved:
                return False
                
            # Check if it's loopback
            if ip_obj.is_loopback:
                return False
                
            # Check if it's link-local
            if ip_obj.is_link_local:
                return False
                
            # Check if it's documentation/test
            if ip_obj.is_unspecified:
                return False
                
            # Additional manual checks for edge cases
            ip_str = str(ip_obj)
            
            # Check for 172.15.x.x specifically (this should be private)
            if ip_str.startswith('172.15.'):
                return False
                
            # Check for other private ranges that might be missed
            private_ranges = [
                '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
                '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
                '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.'
            ]
            
            for private_range in private_ranges:
                if ip_str.startswith(private_range):
                    return False
                    
            return True
            
        except Exception as e:
            print(f"[DEBUG] IP validation error for {ip}: {e}")
            return False
    
    def whois_lookup(self, ip):
        """Perform WHOIS lookup"""
        try:
            result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
            return result.stdout
        except Exception as e:
            return f"WHOIS failed: {e}"
    
    def find_geoip_script(self):
        """Find IPGeoLocation script in common locations"""
        possible_paths = [
            "/home/kali/IPGeoLocation/ipgeolocation.py",
            "./IPGeoLocation/ipgeolocation.py",
            "../IPGeoLocation/ipgeolocation.py",
            "/opt/IPGeoLocation/ipgeolocation.py",
            "/usr/local/bin/ipgeolocation.py"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        return None
    
    def geoip_lookup(self, ip):
        """Perform GeoIP lookup with dynamic path detection"""
        try:
            ipgeo_script = self.find_geoip_script()
            if not ipgeo_script:
                return "[GeoIP] IPGeoLocation tool not found. Install it first."
            
            result = subprocess.run(['python3', ipgeo_script, '-t', ip, '--noprint'], 
                                  capture_output=True, text=True, timeout=15)
            return result.stdout
        except Exception as e:
            return f"[GeoIP Error] {e}"
    
    def is_meta_server(self, whois_info):
        """Check if IP belongs to Meta/Facebook/WhatsApp"""
        meta_keywords = ["facebook", "meta", "whatsapp", "instagram", "messenger"]
        whois_lower = whois_info.lower()
        return any(keyword in whois_lower for keyword in meta_keywords)
    
    def process_ip(self, ip):
        """Process detected IP address"""
        if ip in self.checked_ips:
            return
        
        self.checked_ips.add(ip)
        self.packet_count += 1
        
        # Debug: Show IP classification
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_type = "Public"
            if ip_obj.is_private:
                ip_type = "Private"
            elif ip_obj.is_multicast:
                ip_type = "Multicast"
            elif ip_obj.is_loopback:
                ip_type = "Loopback"
            elif ip_obj.is_link_local:
                ip_type = "Link-Local"
            elif ip_obj.is_reserved:
                ip_type = "Reserved"
                
            print(f"\n[PACKET #{self.packet_count}] IP: {ip} - Type: {ip_type}")
        except:
            print(f"\n[PACKET #{self.packet_count}] IP: {ip} - Type: Unknown")
        
        if not self.is_valid_public_ip(ip):
            print(f"[INFO] Skipping {ip} - not a public IP")
            return
        
        print(f"[STUN] Public IP detected: {ip}")
        
        # Perform lookups
        whois_info = self.whois_lookup(ip)
        geo_info = self.geoip_lookup(ip)
        
        # Check if it's a Meta server
        if self.is_meta_server(whois_info):
            print("[META RELAY DETECTED] Ignoring Meta server")
            return
        
        # Extract relevant WHOIS information
        whois_lines = whois_info.split('\n')
        relevant_whois = []
        for line in whois_lines:
            if any(keyword in line.lower() for keyword in ['orgname', 'netname', 'country', 'city', 'state']):
                relevant_whois.append(line.strip())
        
        # Display results
        print("─ WHOIS ─")
        for line in relevant_whois:
            print(line)
        print("─ GEOIP ─")
        print(geo_info)
        print("─" * 50)
        
        # Log to file
        self.log_to_file(ip, whois_info, geo_info)
    
    def log_to_file(self, ip, whois_info, geo_info):
        """Log results to file"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"""
[{timestamp}] IP: {ip}
WHOIS:
{whois_info}
GEOIP:
{geo_info}
{'='*60}
"""
        
        try:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"[ERROR] Failed to log: {e}")
    
    def get_available_interfaces(self):
        """Get list of available network interfaces"""
        interfaces = []
        try:
            # Method 1: Using ip command
            result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if ':' in line and 'lo:' not in line:
                        interface = line.split(':')[1].strip()
                        if interface and not interface.startswith('lo'):
                            interfaces.append(interface)
        except:
            pass
        
        # Method 2: Using ifconfig (fallback)
        if not interfaces:
            try:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        if ':' in line and 'lo:' not in line:
                            interface = line.split(':')[0].strip()
                            if interface and not interface.startswith('lo'):
                                interfaces.append(interface)
            except:
                pass
        
        # Method 3: Common interface names
        if not interfaces:
            common_interfaces = ['eth0', 'wlan0', 'en0', 'en1', 'wlan1', 'eth1']
            for interface in common_interfaces:
                try:
                    subprocess.run(['ip', 'link', 'show', interface], 
                                 capture_output=True, check=True)
                    interfaces.append(interface)
                except:
                    continue
        
        return interfaces
    
    def test_interface(self, interface):
        """Test if interface is available and working"""
        try:
            result = subprocess.run([
                'tshark', '-i', interface, '-c', '1', '-w', '/dev/null'
            ], capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            return False
    
    def select_interface(self):
        """Let user select interface or auto-detect"""
        interfaces = self.get_available_interfaces()
        
        if not interfaces:
            print("[ERROR] No network interfaces found!")
            print("[INFO] Common interfaces: eth0, wlan0, en0, en1")
            return None
        
        print(f"[INFO] Available interfaces: {', '.join(interfaces)}")
        
        # Test each interface
        working_interfaces = []
        for interface in interfaces:
            if self.test_interface(interface):
                working_interfaces.append(interface)
                print(f"[✓] {interface} - Working")
            else:
                print(f"[✗] {interface} - Not working")
        
        if not working_interfaces:
            print("[ERROR] No working interfaces found!")
            return None
        
        # Auto-select first working interface
        selected = working_interfaces[0]
        print(f"[INFO] Auto-selected: {selected}")
        
        return selected
    
    def start_stun_capture(self):
        """Start tshark capture for STUN packets"""
        cmd = [
            'tshark',
            '-i', self.interface,
            '-T', 'fields',
            '-e', 'ip.dst',
            '-f', 'udp',
            '-Y', 'stun and stun.message_type == 1',  # STUN Binding Requests only
            '-l'
        ]
        
        print(f"[*] Starting STUN capture on {self.interface}")
        print(f"[*] Monitoring for STUN Binding Requests...")
        print(f"[*] Press Ctrl+C to stop")
        print(f"[*] Results will be logged to: {self.output_file}")
        print("-" * 50)
        
        self.running = True
        start_time = time.time()
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in process.stdout:
                if not self.running:
                    break
                
                ip = line.strip()
                if ip and ip not in ['', 'ip.dst']:
                    self.process_ip(ip)
                    
        except KeyboardInterrupt:
            print("\n[!] Stopping capture...")
        except Exception as e:
            print(f"[ERROR] Capture failed: {e}")
        finally:
            self.stop()
            if 'process' in locals():
                process.terminate()
            
            duration = time.time() - start_time
            print(f"\n[*] Capture duration: {duration:.1f} seconds")
            print(f"[*] Total packets processed: {self.packet_count}")
            print(f"[*] Total unique IPs detected: {len(self.checked_ips)}")
    
    def start_simple_capture(self):
        """Simple capture - all UDP traffic (like bash script)"""
        cmd = [
            'tshark',
            '-i', self.interface,
            '-T', 'fields',
            '-e', 'ip.dst',
            '-f', 'udp',
            '-Y', 'ip.dst!=192.168.0.0/16 and ip.dst!=10.0.0.0/8 and ip.dst!=172.16.0.0/12',
            '-l'
        ]
        
        print(f"[*] Starting simple UDP capture on {self.interface}")
        print(f"[*] Monitoring all UDP traffic (excluding private IPs)...")
        print(f"[*] Press Ctrl+C to stop")
        print(f"[*] Results will be logged to: {self.output_file}")
        print("-" * 50)
        
        self.running = True
        start_time = time.time()
        
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in process.stdout:
                if not self.running:
                    break
                
                ip = line.strip()
                if ip and ip not in ['', 'ip.dst']:
                    # Skip multicast and broadcast
                    if (ip.startswith('224.') or ip.startswith('239.') or ip.startswith('255.')):
                        continue
                    
                    self.process_ip(ip)
                    
        except KeyboardInterrupt:
            print("\n[!] Stopping capture...")
        except Exception as e:
            print(f"[ERROR] Capture failed: {e}")
        finally:
            self.stop()
            if 'process' in locals():
                process.terminate()
            
            duration = time.time() - start_time
            print(f"\n[*] Capture duration: {duration:.1f} seconds")
            print(f"[*] Total packets processed: {self.packet_count}")
            print(f"[*] Total unique IPs detected: {len(self.checked_ips)}")
    
    def stop(self):
        """Stop the capture process"""
        self.running = False
    
    def get_statistics(self):
        """Get capture statistics"""
        return {
            'total_ips_detected': len(self.checked_ips),
            'unique_ips': list(self.checked_ips),
            'output_file': self.output_file,
            'packet_count': self.packet_count
        }

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='WhatsApp IP Leak Detection Tool')
    parser.add_argument('-i', '--interface', help='Network interface (auto-detect if not specified)')
    parser.add_argument('-s', '--simple', action='store_true', help='Use simple UDP capture')
    parser.add_argument('-o', '--output', default='leak_results.log', help='Output log file')
    parser.add_argument('-l', '--list', action='store_true', help='List available interfaces')
    
    args = parser.parse_args()
    
    # Check tshark availability
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] tshark not found. Install Wireshark/tshark first.")
        print("[INFO] Ubuntu/Debian: sudo apt-get install tshark")
        print("[INFO] CentOS/RHEL: sudo yum install wireshark")
        print("[INFO] macOS: brew install wireshark")
        return
    
    # List interfaces if requested
    if args.list:
        detector = WhatsAppLeakDetector()
        interfaces = detector.get_available_interfaces()
        if interfaces:
            print(f"Available interfaces: {', '.join(interfaces)}")
            for interface in interfaces:
                status = "Working" if detector.test_interface(interface) else "Not working"
                print(f"  {interface}: {status}")
        else:
            print("No interfaces found!")
        return
    
    # Determine interface to use
    interface = args.interface
    if not interface:
        detector = WhatsAppLeakDetector()
        interface = detector.select_interface()
        if not interface:
            print("[ERROR] Could not determine interface to use!")
            print("[INFO] Use -l to list available interfaces")
            print("[INFO] Use -i <interface> to specify interface manually")
            return
    
    # Test interface before starting
    detector = WhatsAppLeakDetector(interface, args.output)
    if not detector.test_interface(interface):
        print(f"[ERROR] Interface {interface} is not working!")
        print("[INFO] Use -l to list available interfaces")
        return
    
    # Setup signal handler
    signal.signal(signal.SIGINT, detector.signal_handler)
    signal.signal(signal.SIGTERM, detector.signal_handler)
    
    # Check GeoIP tool
    geoip_script = detector.find_geoip_script()
    if geoip_script:
        print(f"[INFO] GeoIP tool found: {geoip_script}")
    else:
        print("[WARNING] GeoIP tool not found. WHOIS only will be available.")
    
    try:
        if args.simple:
            detector.start_simple_capture()
        else:
            detector.start_stun_capture()
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        return
    
    stats = detector.get_statistics()
    print(f"\n[*] Final Statistics:")
    print(f"    Total IPs detected: {stats['total_ips_detected']}")
    print(f"    Output file: {stats['output_file']}")

if __name__ == "__main__":
    main() 