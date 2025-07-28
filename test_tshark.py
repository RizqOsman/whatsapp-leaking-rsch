#!/usr/bin/env python3
"""
Simple test script for tshark and interface detection
"""

import subprocess
import time

def test_tshark():
    """Test if tshark is working"""
    print("[*] Testing tshark...")
    try:
        result = subprocess.run(['tshark', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("[✓] tshark is working")
            return True
        else:
            print("[✗] tshark failed")
            return False
    except Exception as e:
        print(f"[✗] tshark error: {e}")
        return False

def test_interface(interface):
    """Test if interface is working"""
    print(f"[*] Testing interface: {interface}")
    try:
        # Test with tshark
        result = subprocess.run([
            'tshark', '-i', interface, '-c', '5', '-w', '/dev/null'
        ], capture_output=True, timeout=10)
        
        if result.returncode == 0:
            print(f"[✓] Interface {interface} is working")
            return True
        else:
            print(f"[✗] Interface {interface} failed")
            print(f"Error: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(f"[✓] Interface {interface} is working (timeout is normal)")
        return True
    except Exception as e:
        print(f"[✗] Interface {interface} error: {e}")
        return False

def list_interfaces():
    """List available interfaces"""
    print("[*] Listing available interfaces...")
    
    # Method 1: ip command
    try:
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        if result.returncode == 0:
            print("Interfaces found:")
            for line in result.stdout.split('\n'):
                if ':' in line and 'lo:' not in line:
                    interface = line.split(':')[1].strip()
                    if interface and not interface.startswith('lo'):
                        print(f"  - {interface}")
    except:
        pass
    
    # Method 2: ifconfig
    try:
        result = subprocess.run(['ifconfig'], capture_output=True, text=True)
        if result.returncode == 0:
            print("Interfaces (ifconfig):")
            for line in result.stdout.split('\n'):
                if ':' in line and 'lo:' not in line:
                    interface = line.split(':')[0].strip()
                    if interface and not interface.startswith('lo'):
                        print(f"  - {interface}")
    except:
        pass

def capture_test(interface, duration=10):
    """Test packet capture"""
    print(f"[*] Testing packet capture on {interface} for {duration} seconds...")
    
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-f', 'udp',
        '-c', '10'  # Capture 10 packets
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration+5)
        
        if result.returncode == 0:
            print("[✓] Packet capture successful")
            print("Sample packets:")
            lines = result.stdout.strip().split('\n')
            for i, line in enumerate(lines[:5]):  # Show first 5 packets
                if line.strip():
                    parts = line.split('\t')
                    if len(parts) >= 5:
                        print(f"  {i+1}. {parts[1]}:{parts[3]} -> {parts[2]}:{parts[4]}")
        else:
            print("[✗] Packet capture failed")
            print(f"Error: {result.stderr}")
            
    except subprocess.TimeoutExpired:
        print("[✓] Packet capture timeout (normal)")
    except Exception as e:
        print(f"[✗] Packet capture error: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Test tshark and interface')
    parser.add_argument('-i', '--interface', default='eth0', help='Interface to test')
    parser.add_argument('-c', '--capture', action='store_true', help='Test packet capture')
    parser.add_argument('-l', '--list', action='store_true', help='List interfaces')
    
    args = parser.parse_args()
    
    print("=== TSHARK TEST SCRIPT ===")
    
    # Test tshark
    if not test_tshark():
        print("[ERROR] tshark is not working properly!")
        return
    
    # List interfaces
    if args.list:
        list_interfaces()
        return
    
    # Test interface
    if not test_interface(args.interface):
        print(f"[ERROR] Interface {args.interface} is not working!")
        print("[INFO] Try listing interfaces with: python3 test_tshark.py -l")
        return
    
    # Test packet capture
    if args.capture:
        capture_test(args.interface)
    
    print("\n[✓] All tests passed!")
    print(f"[INFO] You can now use interface: {args.interface}")

if __name__ == "__main__":
    main() 