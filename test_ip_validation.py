#!/usr/bin/env python3
"""
Test IP validation function
"""

import ipaddress

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

def test_ip(ip):
    """Test an IP address"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        is_public = is_valid_public_ip(ip)
        
        print(f"IP: {ip}")
        print(f"  Version: IPv{ip_obj.version}")
        print(f"  Is Private: {ip_obj.is_private}")
        print(f"  Is Public: {is_public}")
        print(f"  Is Multicast: {ip_obj.is_multicast}")
        print(f"  Is Loopback: {ip_obj.is_loopback}")
        print(f"  Is Link-Local: {ip_obj.is_link_local}")
        print(f"  Is Reserved: {ip_obj.is_reserved}")
        print("-" * 30)
        
        return is_public
    except Exception as e:
        print(f"Error testing {ip}: {e}")
        return False

def main():
    # Test IPs
    test_ips = [
        "172.15.1.1",      # Should be private
        "172.15.2.109",    # Should be private
        "172.16.1.1",      # Should be private
        "192.168.1.1",     # Should be private
        "10.0.0.1",        # Should be private
        "8.8.8.8",         # Should be public
        "1.1.1.1",         # Should be public
        "127.0.0.1",       # Should be private (loopback)
        "224.0.0.1",       # Should be private (multicast)
        "169.254.1.1",     # Should be private (link-local)
    ]
    
    print("=== IP VALIDATION TEST ===")
    
    for ip in test_ips:
        test_ip(ip)
    
    print("\n=== SUMMARY ===")
    print("IPs that should be PUBLIC:")
    for ip in test_ips:
        if is_valid_public_ip(ip):
            print(f"  ✓ {ip}")
    
    print("\nIPs that should be PRIVATE:")
    for ip in test_ips:
        if not is_valid_public_ip(ip):
            print(f"  ✗ {ip}")

if __name__ == "__main__":
    main() 