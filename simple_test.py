#!/usr/bin/env python3
"""
Simple test for tshark and interface
"""

import subprocess
import time

def main():
    print("=== SIMPLE TSHARK TEST ===")
    
    # Test 1: Check tshark
    print("1. Testing tshark...")
    try:
        result = subprocess.run(['tshark', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print("   ✓ tshark is working")
        else:
            print("   ✗ tshark failed")
            return
    except Exception as e:
        print(f"   ✗ tshark error: {e}")
        return
    
    # Test 2: Check interface
    interface = "eth0"
    print(f"2. Testing interface {interface}...")
    try:
        result = subprocess.run(['tshark', '-i', interface, '-c', '1'], 
                              capture_output=True, timeout=5)
        print("   ✓ Interface is working")
    except:
        print("   ✗ Interface failed")
        return
    
    # Test 3: Capture some packets
    print("3. Capturing packets for 10 seconds...")
    print("   Start a WhatsApp call now!")
    
    cmd = [
        'tshark',
        '-i', interface,
        '-T', 'fields',
        '-e', 'ip.dst',
        '-f', 'udp',
        '-c', '20'  # Capture 20 packets
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0:
            print("   ✓ Capture successful")
            print("   Packets captured:")
            
            lines = result.stdout.strip().split('\n')
            for i, line in enumerate(lines):
                if line.strip() and line.strip() != 'ip.dst':
                    print(f"   {i+1}. {line.strip()}")
        else:
            print("   ✗ Capture failed")
            print(f"   Error: {result.stderr}")
            
    except Exception as e:
        print(f"   ✗ Capture error: {e}")

if __name__ == "__main__":
    main() 