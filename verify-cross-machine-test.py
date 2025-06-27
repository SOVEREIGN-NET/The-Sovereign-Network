#!/usr/bin/env python3
"""
ZHTP Cross-Machine Test Verification Script
This script helps verify that both machines are ready for cross-machine testing
"""

import json
import requests
import sys
import time
from datetime import datetime

def test_api_endpoint(url, description):
    """Test an API endpoint and return the result"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            return True, response.json()
        else:
            return False, f"HTTP {response.status_code}"
    except Exception as e:
        return False, str(e)

def main():
    print("🧪 ZHTP Cross-Machine Test Verification")
    print("=" * 40)
    print(f"📅 Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    base_url = "http://localhost:8000"
    tests = [
        ("/api/status", "System Status"),
        ("/api/messages/inbox", "Message Inbox"),
        ("/browser", "Browser Interface"),
        ("/whisper", "Whisper DApp"),
    ]
    
    results = {}
    all_passed = True
    
    print("🔍 Running API Tests...")
    print("-" * 25)
    
    for endpoint, description in tests:
        url = base_url + endpoint
        print(f"Testing {description:.<20} ", end="", flush=True)
        
        success, data = test_api_endpoint(url, description)
        results[endpoint] = {"success": success, "data": data}
        
        if success:
            print("✅ PASS")
        else:
            print(f"❌ FAIL ({data})")
            all_passed = False
        
        time.sleep(0.5)  # Small delay between tests
    
    print()
    print("📊 Test Results Summary")
    print("-" * 25)
    
    # System status details
    if results["/api/status"]["success"]:
        status_data = results["/api/status"]["data"]
        print(f"🌐 Network Status: {status_data.get('status', 'unknown')}")
        print(f"🔗 Connected Nodes: {status_data.get('connected_nodes', 0)}")
        print(f"🔒 Zero Knowledge: {status_data.get('zero_knowledge', False)}")
        print(f"🛡️  Quantum Resistant: {status_data.get('quantum_resistant', False)}")
        print(f"💰 ZK Transactions: {status_data.get('zk_transactions', 0)}")
        print(f"🔄 Consensus Rounds: {status_data.get('consensus_rounds', 0)}")
    
    # Message inbox details
    if results["/api/messages/inbox"]["success"]:
        inbox_data = results["/api/messages/inbox"]["data"]
        message_count = len(inbox_data.get('messages', []))
        print(f"📬 Messages in Inbox: {message_count}")
    
    print()
    
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ This machine is ready for cross-machine testing")
        print()
        print("📋 Next Steps:")
        print("1. Run this script on the second machine")
        print("2. Ensure both machines show 'Connected Nodes: 2+' in status")
        print("3. Open http://localhost:8000/ in browsers on both machines")
        print("4. Follow the Cross-Machine Testing Guide")
    else:
        print("⚠️  Some tests failed!")
        print("❌ This machine may not be ready for testing")
        print()
        print("🔧 Troubleshooting:")
        print("1. Ensure ZHTP node is running (./run-zhtp.sh or run-zhtp.bat)")
        print("2. Check for error messages in the terminal")
        print("3. Verify firewall settings allow port 8000")
        print("4. Wait a few minutes for the node to fully initialize")
    
    print()
    
    # Save results to file
    try:
        import socket
        machine_name = socket.gethostname()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"test-results/verification_{machine_name}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                'machine': machine_name,
                'timestamp': timestamp,
                'results': results,
                'all_passed': all_passed
            }, f, indent=2)
        
        print(f"📁 Results saved to: {filename}")
    except Exception as e:
        print(f"⚠️  Could not save results: {e}")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
        sys.exit(1)
    except ImportError as e:
        if "requests" in str(e):
            print("❌ Error: 'requests' library not found")
            print("Install with: pip install requests")
            sys.exit(1)
        else:
            raise
