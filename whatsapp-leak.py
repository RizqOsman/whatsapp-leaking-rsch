import scapy.all as scapy
import ipaddress
import subprocess
import os
import datetime
import socket
import struct

INTERFACE = "eth0"
IPGEO_SCRIPT = "/home/kali/IPGeoLocation/ipgeolocation.py"
checked_ips = set()

def is_valid_public_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version == 4 and not (
            ip_obj.is_private or ip_obj.is_multicast or ip_obj.is_reserved or
            ip_obj.is_loopback or ip_obj.is_link_local
        )
    except:
        return False

def whois_lookup(ip):
    try:
        return subprocess.check_output(['whois', ip], timeout=5).decode()
    except:
        return "WHOIS failed"

def geoip_lookup(ip):
    try:
        if not os.path.exists(IPGEO_SCRIPT):
            return "[GeoIP] ipgeolocation.py not found."
        result = subprocess.check_output(['python3', IPGEO_SCRIPT, '-t', ip], timeout=8)
        return result.decode()
    except:
        return "[GeoIP Error]"

def is_stun_binding(packet):
    # STUN uses UDP with specific format (first 2 bytes == 0x0001)
    try:
        data = bytes(packet[scapy.UDP].payload)
        if len(data) >= 2:
            msg_type = struct.unpack('!H', data[0:2])[0]
            return msg_type == 0x0001
    except:
        pass
    return False

def packet_callback(packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
        dst_ip = packet[scapy.IP].dst
        if dst_ip not in checked_ips and is_stun_binding(packet):
            checked_ips.add(dst_ip)
            print(f"\n[STUN] Binding Request Detected to {dst_ip}")
            if is_valid_public_ip(dst_ip):
                print("[+] Public IP detected from STUN: ", dst_ip)
                whois_info = whois_lookup(dst_ip)
                geo_info = geoip_lookup(dst_ip)

                if any(x in whois_info.lower() for x in ["facebook", "meta", "whatsapp"]):
                    print("[META RELAY DETECTED] Ignoring Meta server")
                    return

                print("─ WHOIS ─")
                for line in whois_info.splitlines():
                    if any(k in line.lower() for k in ['orgname', 'netname', 'country']):
                        print(line)
                print("─ GEOIP ─")
                print(geo_info)
                print("─────────────────────────────\n")

print(f"[*] Sniffing STUN packets on {INTERFACE}...")
scapy.sniff(iface=INTERFACE, filter="udp", prn=packet_callback, store=0)
