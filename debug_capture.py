#!/usr/bin/env python3
"""
Debug script untuk menguji packet capture di interface eth0
"""

import subprocess
import time
import sys

def test_basic_capture():
    """Test basic tshark capture"""
    print("[*] Testing basic tshark capture...")
    
    cmd = ['tshark', '-i', 'eth0', '-c', '10', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        
        if result.stdout.strip():
            print("✓ Basic capture working")
            return True
        else:
            print("✗ No packets captured")
            return False
    except subprocess.TimeoutExpired:
        print("✗ Timeout - no packets in 10 seconds")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def test_interface_status():
    """Test interface status"""
    print("\n[*] Testing interface status...")
    
    # Check if interface exists
    cmd = ['ip', 'link', 'show', 'eth0']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            print("✓ Interface eth0 exists")
            print(f"Status: {result.stdout}")
        else:
            print("✗ Interface eth0 not found")
            return False
    except Exception as e:
        print(f"✗ Error checking interface: {e}")
        return False
    
    # Check if interface is UP
    cmd = ['ip', 'addr', 'show', 'eth0']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0 and 'state UP' in result.stdout:
            print("✓ Interface eth0 is UP")
            return True
        else:
            print("✗ Interface eth0 is not UP")
            return False
    except Exception as e:
        print(f"✗ Error checking interface status: {e}")
        return False

def test_network_connectivity():
    """Test network connectivity"""
    print("\n[*] Testing network connectivity...")
    
    # Ping test
    cmd = ['ping', '-c', '3', '8.8.8.8']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✓ Network connectivity OK (ping 8.8.8.8)")
            return True
        else:
            print("✗ No network connectivity")
            return False
    except Exception as e:
        print(f"✗ Error testing connectivity: {e}")
        return False

def test_tshark_permissions():
    """Test tshark permissions"""
    print("\n[*] Testing tshark permissions...")
    
    # Test without sudo
    cmd = ['tshark', '-i', 'eth0', '-c', '1']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✓ tshark works without sudo")
            return True
        else:
            print("✗ tshark needs sudo")
            print(f"Error: {result.stderr}")
            return False
    except Exception as e:
        print(f"✗ Error testing tshark: {e}")
        return False

def test_promiscuous_mode():
    """Test promiscuous mode capture"""
    print("\n[*] Testing promiscuous mode...")
    
    cmd = ['tshark', '-i', 'eth0', '-p', '-c', '10', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        print(f"Return code: {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        
        if result.stdout.strip():
            print("✓ Promiscuous mode working")
            return True
        else:
            print("✗ No packets in promiscuous mode")
            return False
    except subprocess.TimeoutExpired:
        print("✗ Timeout - no packets in 10 seconds")
        return False
    except Exception as e:
        print(f"✗ Error: {e}")
        return False

def generate_traffic():
    """Generate some traffic to test capture"""
    print("\n[*] Generating test traffic...")
    
    # Start ping in background
    ping_cmd = ['ping', '-c', '5', '8.8.8.8']
    try:
        ping_process = subprocess.Popen(ping_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)  # Wait for ping to start
        
        # Try to capture during ping
        capture_cmd = ['tshark', '-i', 'eth0', '-c', '5', '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst']
        result = subprocess.run(capture_cmd, capture_output=True, text=True, timeout=5)
        
        ping_process.terminate()
        
        if result.stdout.strip():
            print("✓ Captured packets during ping")
            print(f"Packets: {result.stdout}")
            return True
        else:
            print("✗ No packets captured during ping")
            return False
    except Exception as e:
        print(f"✗ Error generating traffic: {e}")
        return False

def main():
    print("🔍 WhatsApp Leak Detector - Debug Script")
    print("=" * 50)
    
    tests = [
        ("Interface Status", test_interface_status),
        ("Network Connectivity", test_network_connectivity),
        ("tshark Permissions", test_tshark_permissions),
        ("Basic Capture", test_basic_capture),
        ("Promiscuous Mode", test_promiscuous_mode),
        ("Traffic Generation", generate_traffic),
    ]
    
    results = []
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"✗ Test failed with exception: {e}")
            results.append((test_name, False))
    
    print(f"\n{'='*50}")
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 50)
    
    for test_name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{test_name}: {status}")
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Your setup should work.")
    else:
        print("⚠️  Some tests failed. Check the issues above.")
        print("\n💡 Troubleshooting tips:")
        print("1. Make sure you're running as root/sudo")
        print("2. Check if eth0 is the correct interface")
        print("3. Verify network connectivity")
        print("4. Try different interface (wlan0, en0, etc.)")

if __name__ == "__main__":
    main() 