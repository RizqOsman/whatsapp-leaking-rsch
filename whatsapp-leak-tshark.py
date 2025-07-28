import subprocess
import ipaddress
import os
from datetime import datetime

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

def start_stun_capture(interface="eth0"):
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

def start_simple_capture(interface="eth0"):
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
    parser.add_argument('-i', '--interface', default='eth0', help='Network interface')
    parser.add_argument('-s', '--simple', action='store_true', help='Use simple UDP capture')
    
    args = parser.parse_args()
    
    # Check tshark availability
    try:
        subprocess.run(['tshark', '--version'], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("[ERROR] tshark not found. Install Wireshark/tshark first.")
        return
    
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