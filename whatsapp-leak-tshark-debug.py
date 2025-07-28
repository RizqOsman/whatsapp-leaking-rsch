#!/usr/bin/env python3
"""
WhatsApp IP Leak Detection using tshark + Python
Debug version with enhanced monitoring
"""

import subprocess
import ipaddress
import os
import socket
from datetime import datetime
import time

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

def process_ip(ip, checked_ips, packet_count):
    """Process detected IP address"""
    if ip in checked_ips:
        return checked_ips, packet_count
    
    checked_ips.add(ip)
    packet_count += 1
    
    print(f"\n[PACKET #{packet_count}] IP detected: {ip}")
    
    if not is_valid_public_ip(ip):
        print(f"[INFO] {ip} is not a public IP (private/multicast/etc)")
        return checked_ips, packet_count
    
    print(f"[STUN] Public IP detected: {ip}")
    
    # Perform lookups
    whois_info = whois_lookup(ip)
    geo_info = geoip_lookup(ip)
    
    # Check if it's a Meta server
    if is_meta_server(whois_info):
        print("[META RELAY DETECTED] Ignoring Meta server")
        return checked_ips, packet_count
    
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
    
    return checked_ips, packet_count

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

def start_debug_capture(interface):
    """Start debug capture - show all UDP traffic"""
    print(f"[*] Starting DEBUG capture on {interface}")
    print(f"[*] Monitoring ALL UDP traffic for debugging...")
    print(f"[*] Press Ctrl+C to stop")
    print("-" * 50)
    
    checked_ips = set()
    packet_count = 0
    start_time = time.time()
    
    # Command to capture all UDP traffic
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'udp.length',
        '-f', 'udp',
        '-l'
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            if not line.strip():
                continue
                
            parts = line.strip().split('\t')
            if len(parts) >= 6:
                timestamp, src_ip, dst_ip, src_port, dst_port, length = parts
                
                # Show all UDP packets for debugging
                print(f"[UDP] {src_ip}:{src_port} -> {dst_ip}:{dst_port} (len: {length})")
                
                # Process destination IP
                if dst_ip and dst_ip != 'ip.dst':
                    checked_ips, packet_count = process_ip(dst_ip, checked_ips, packet_count)
                
                # Also process source IP if it's public
                if src_ip and src_ip != 'ip.src':
                    checked_ips, packet_count = process_ip(src_ip, checked_ips, packet_count)
                    
    except KeyboardInterrupt:
        print("\n[!] Stopping capture...")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
    finally:
        if 'process' in locals():
            process.terminate()
    
    duration = time.time() - start_time
    print(f"\n[*] Capture duration: {duration:.1f} seconds")
    print(f"[*] Total packets processed: {packet_count}")
    print(f"[*] Total unique IPs detected: {len(checked_ips)}")
    
    return checked_ips

def start_stun_capture(interface):
    """Start STUN capture with enhanced debugging"""
    print(f"[*] Starting STUN capture on {interface}")
    print(f"[*] Monitoring for STUN packets...")
    print(f"[*] Press Ctrl+C to stop")
    print("-" * 50)
    
    checked_ips = set()
    packet_count = 0
    start_time = time.time()
    
    # Command to capture STUN packets
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'stun.message_type',
        '-e', 'stun.message_type_name',
        '-f', 'udp',
        '-Y', 'stun',
        '-l'
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            if not line.strip():
                continue
                
            parts = line.strip().split('\t')
            if len(parts) >= 7:
                timestamp, src_ip, dst_ip, src_port, dst_port, msg_type, msg_name = parts
                
                print(f"[STUN] {msg_name} ({msg_type}) - {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                
                # Process destination IP
                if dst_ip and dst_ip != 'ip.dst':
                    checked_ips, packet_count = process_ip(dst_ip, checked_ips, packet_count)
                    
    except KeyboardInterrupt:
        print("\n[!] Stopping capture...")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
    finally:
        if 'process' in locals():
            process.terminate()
    
    duration = time.time() - start_time
    print(f"\n[*] Capture duration: {duration:.1f} seconds")
    print(f"[*] Total STUN packets: {packet_count}")
    print(f"[*] Total unique IPs detected: {len(checked_ips)}")
    
    return checked_ips

def start_simple_capture(interface):
    """Simple capture with debugging"""
    print(f"[*] Starting simple UDP capture on {interface}")
    print(f"[*] Monitoring UDP traffic (excluding private IPs)...")
    print(f"[*] Press Ctrl+C to stop")
    print("-" * 50)
    
    checked_ips = set()
    packet_count = 0
    start_time = time.time()
    
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'ip.dst',
        '-f', 'udp',
        '-Y', 'ip.dst!=192.168.0.0/16 and ip.dst!=10.0.0.0/8 and ip.dst!=172.16.0.0/12',
        '-l'
    ]
    
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in process.stdout:
            ip = line.strip()
            if ip and ip not in ['', 'ip.dst']:
                # Skip multicast and broadcast
                if (ip.startswith('224.') or ip.startswith('239.') or ip.startswith('255.')):
                    continue
                
                checked_ips, packet_count = process_ip(ip, checked_ips, packet_count)
                
    except KeyboardInterrupt:
        print("\n[!] Stopping capture...")
    except Exception as e:
        print(f"[ERROR] Capture failed: {e}")
    finally:
        if 'process' in locals():
            process.terminate()
    
    duration = time.time() - start_time
    print(f"\n[*] Capture duration: {duration:.1f} seconds")
    print(f"[*] Total packets processed: {packet_count}")
    print(f"[*] Total unique IPs detected: {len(checked_ips)}")
    
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
    
    parser = argparse.ArgumentParser(description='WhatsApp IP Leak Detection - Debug Version')
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-s', '--simple', action='store_true', help='Use simple UDP capture')
    parser.add_argument('-d', '--debug', action='store_true', help='Show all UDP traffic for debugging')
    parser.add_argument('-t', '--test', action='store_true', help='Test interface only')
    
    args = parser.parse_args()
    
    # Check tshark availability
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] tshark not found. Install Wireshark/tshark first.")
        return
    
    # Test interface if requested
    if args.test:
        print(f"[*] Testing interface: {args.interface}")
        if test_interface(args.interface):
            print(f"[✓] Interface {args.interface} is working")
        else:
            print(f"[✗] Interface {args.interface} is not working")
        return
    
    # Test interface before starting
    if not test_interface(args.interface):
        print(f"[ERROR] Interface {args.interface} is not working!")
        return
    
    print(f"[*] Using interface: {args.interface}")
    print(f"[*] Make sure to start a WhatsApp call to generate STUN traffic")
    print(f"[*] Waiting 3 seconds before starting capture...")
    time.sleep(3)
    
    try:
        if args.debug:
            checked_ips = start_debug_capture(args.interface)
        elif args.simple:
            checked_ips = start_simple_capture(args.interface)
        else:
            checked_ips = start_stun_capture(args.interface)
    except KeyboardInterrupt:
        print("\n[!] Stopping...")
        return

if __name__ == "__main__":
    main() 