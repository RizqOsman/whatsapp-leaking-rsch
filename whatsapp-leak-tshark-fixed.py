#!/usr/bin/env python3
"""
WhatsApp IP Leak Detection using tshark + Python
Fixed version with better IP validation and dynamic GeoIP path
"""

import subprocess
import ipaddress
import os
import socket
from datetime import datetime

def is_valid_public_ip(ip):
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

def find_geoip_script():
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

def whois_lookup(ip):
    """Perform WHOIS lookup"""
    try:
        result = subprocess.run(['whois', ip], capture_output=True, text=True, timeout=10)
        return result.stdout
    except Exception as e:
        return f"WHOIS failed: {e}"

def geoip_lookup(ip):
    """Perform GeoIP lookup with dynamic path detection"""
    try:
        ipgeo_script = find_geoip_script()
        if not ipgeo_script:
            return "[GeoIP] IPGeoLocation tool not found. Install it first."
        
        result = subprocess.run(['python3', ipgeo_script, '-t', ip, '--noprint'], 
                              capture_output=True, text=True, timeout=15)
        return result.stdout
    except Exception as e:
        return f"[GeoIP Error] {e}"

def is_meta_server(whois_info):
    """Check if IP belongs to Meta/Facebook/WhatsApp"""
    meta_keywords = ["facebook", "meta", "whatsapp", "instagram", "messenger"]
    whois_lower = whois_info.lower()
    return any(keyword in whois_lower for keyword in meta_keywords)

def process_ip(ip, checked_ips):
    """Process detected IP address"""
    if ip in checked_ips:
        return checked_ips
    
    checked_ips.add(ip)
    
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
            
        print(f"\n[DEBUG] IP: {ip} - Type: {ip_type}")
    except:
        print(f"\n[DEBUG] IP: {ip} - Type: Unknown")
    
    if not is_valid_public_ip(ip):
        print(f"[INFO] Skipping {ip} - not a public IP")
        return checked_ips
    
    print(f"[STUN] Public IP detected: {ip}")
    
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

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='WhatsApp IP Leak Detection - Fixed Version')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-s', '--simple', action='store_true', help='Use simple UDP capture')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Check tshark availability
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] tshark not found. Install Wireshark/tshark first.")
        return
    
    # Test interface before starting
    if not test_interface(args.interface):
        print(f"[ERROR] Interface {args.interface} is not working!")
        return
    
    # Check GeoIP tool
    geoip_script = find_geoip_script()
    if geoip_script:
        print(f"[INFO] GeoIP tool found: {geoip_script}")
    else:
        print("[WARNING] GeoIP tool not found. WHOIS only will be available.")
    
    try:
        if args.simple:
            checked_ips = start_simple_capture(args.interface)
        else:
            checked_ips = start_stun_capture(args.interface)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        return
    
    print(f"\n[*] Total unique IPs detected: {len(checked_ips)}")

if __name__ == "__main__":
    main() 