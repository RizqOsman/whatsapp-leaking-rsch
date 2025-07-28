#!/usr/bin/env python3
"""
WhatsApp IP Leak Detection using tshark + Python
Combines tshark performance with Python flexibility
"""

import subprocess
import ipaddress
import os
import socket
from datetime import datetime

def get_available_interfaces():
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
                # Test if interface exists
                subprocess.run(['ip', 'link', 'show', interface], 
                             capture_output=True, check=True)
                interfaces.append(interface)
            except:
                continue
    
    return interfaces

def test_interface(interface):
    """Test if interface is available and working"""
    try:
        # Test with tshark
        result = subprocess.run([
            'tshark', '-i', interface, '-c', '1', '-w', '/dev/null'
        ], capture_output=True, timeout=5)
        return result.returncode == 0
    except:
        return False

def select_interface():
    """Let user select interface or auto-detect"""
    interfaces = get_available_interfaces()
    
    if not interfaces:
        print("[ERROR] No network interfaces found!")
        print("[INFO] Common interfaces: eth0, wlan0, en0, en1")
        return None
    
    print(f"[INFO] Available interfaces: {', '.join(interfaces)}")
    
    # Test each interface
    working_interfaces = []
    for interface in interfaces:
        if test_interface(interface):
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

def is_valid_public_ip(ip):
    """Check if IP is a valid public IPv4 address"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return (ip_obj.version == 4 and 
               not ip_obj.is_private and 
               not ip_obj.is_multicast and 
               not ip_obj.is_reserved and 
               not ip_obj.is_loopback and 
               not ip_obj.is_link_local)
    except:
        return False

def whois_lookup(ip):
    """Perform WHOIS lookup"""
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        return result.stdout
    except:
        return "WHOIS failed"

def geoip_lookup(ip):
    """Perform GeoIP lookup"""
    try:
        ipgeo_script = "/home/kali/IPGeoLocation/ipgeolocation.py"
        if not os.path.exists(ipgeo_script):
            return "[GeoIP] ipgeolocation.py not found"
        
        result = subprocess.run(['python3', ipgeo_script, '-t', ip, '--noprint'], 
                              capture_output=True, text=True, timeout=15)
        return result.stdout
    except:
        return "[GeoIP Error]"

def is_meta_server(whois_info):
    """Check if IP belongs to Meta/Facebook/WhatsApp"""
    meta_keywords = ["facebook", "meta", "whatsapp", "instagram"]
    whois_lower = whois_info.lower()
    return any(keyword in whois_lower for keyword in meta_keywords)

def process_ip(ip, checked_ips):
    """Process detected IP address"""
    if ip in checked_ips:
        return checked_ips
    
    checked_ips.add(ip)
    
    if not is_valid_public_ip(ip):
        return checked_ips
    
    print(f"\n[STUN] Public IP detected: {ip}")
    
    # Perform lookups
    whois_info = whois_lookup(ip)
    geo_info = geoip_lookup(ip)
    
    # Check if it's a Meta server
    if is_meta_server(whois_info):
        print("[META RELAY DETECTED] Ignoring Meta server")
        return checked_ips
    
    # Extract relevant WHOIS information
    whois_lines = whois_info.split('\n')
    relevant_whois = []
    for line in whois_lines:
        if any(keyword in line.lower() for keyword in ['orgname', 'netname', 'country', 'city']):
            relevant_whois.append(line.strip())
    
    # Display results
    print("─ WHOIS ─")
    for line in relevant_whois:
        print(line)
    print("─ GEOIP ─")
    print(geo_info)
    print("─" * 50)
    
    # Log to file
    log_to_file(ip, whois_info, geo_info)
    
    return checked_ips

def log_to_file(ip, whois_info, geo_info):
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
        with open('leak_results.log', 'a', encoding='utf-8') as f:
            f.write(log_entry)
    except Exception as e:
        print(f"[ERROR] Failed to log: {e}")

def start_stun_capture(interface):
    """Start tshark capture for STUN packets"""
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'ip.dst',
        '-f', 'udp',
        '-Y', 'stun and stun.message_type == 1',  # STUN Binding Requests only
        '-l'
    ]
    
    print(f"[*] Starting STUN capture on {interface}")
    print(f"[*] Monitoring for STUN Binding Requests...")
    print(f"[*] Press Ctrl+C to stop")
    print("-" * 50)
    
    checked_ips = set()
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            ip = line.strip()
            if ip and ip not in ['', 'ip.dst']:
                checked_ips = process_ip(ip, checked_ips)
                
    except KeyboardInterrupt:
        print("\n[!] Stopping capture...")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
    finally:
        if 'process' in locals():
            process.terminate()
    
    return checked_ips

def start_simple_capture(interface):
    """Simple capture - all UDP traffic (like bash script)"""
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'ip.dst',
        '-f', 'udp',
        '-Y', 'ip.dst!=192.168.0.0/16 and ip.dst!=10.0.0.0/8 and ip.dst!=172.16.0.0/12',
        '-l'
    ]
    
    print(f"[*] Starting simple UDP capture on {interface}")
    print(f"[*] Monitoring all UDP traffic (excluding private IPs)...")
    print(f"[*] Press Ctrl+C to stop")
    print("-" * 50)
    
    checked_ips = set()
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            ip = line.strip()
            if ip and ip not in ['', 'ip.dst']:
                # Skip multicast and broadcast
                if (ip.startswith('224.') or ip.startswith('239.') or ip.startswith('255.')):
                    continue
                
                checked_ips = process_ip(ip, checked_ips)
                
    except KeyboardInterrupt:
        print("\n[!] Stopping capture...")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
    finally:
        if 'process' in locals():
            process.terminate()
    
    return checked_ips

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='WhatsApp IP Leak Detection using tshark')
    parser.add_argument('-i', '--interface', help='Network interface (auto-detect if not specified)')
    parser.add_argument('-s', '--simple', action='store_true', help='Use simple UDP capture')
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
        interfaces = get_available_interfaces()
        if interfaces:
            print(f"Available interfaces: {', '.join(interfaces)}")
            for interface in interfaces:
                status = "Working" if test_interface(interface) else "Not working"
                print(f"  {interface}: {status}")
        else:
            print("No interfaces found!")
        return
    
    # Determine interface to use
    interface = args.interface
    if not interface:
        interface = select_interface()
        if not interface:
            print("[ERROR] Could not determine interface to use!")
            print("[INFO] Use -l to list available interfaces")
            print("[INFO] Use -i <interface> to specify interface manually")
            return
    
    # Test interface before starting
    if not test_interface(interface):
        print(f"[ERROR] Interface {interface} is not working!")
        print("[INFO] Use -l to list available interfaces")
        return
    
    try:
        if args.simple:
            checked_ips = start_simple_capture(interface)
        else:
            checked_ips = start_stun_capture(interface)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        return
    
    print(f"\n[*] Total unique IPs detected: {len(checked_ips)}")

if __name__ == "__main__":
    main() 