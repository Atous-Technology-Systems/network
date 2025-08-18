#!/usr/bin/env python3
"""Test script for the identity management system.

This script tests all the new identity and CA functionality.
"""

import sys
import os
import requests
import json
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def test_identity_system(base_url: str = "http://127.0.0.1:8000"):
    """Test the identity management system."""
    print("🧪 Testing Identity Management System...")
    print(f"📍 Base URL: {base_url}")
    
    # Test data
    test_user = {
        "username": "testuser",
        "password": "testpass123",
        "email": "test@example.com"
    }
    
    session_token = None
    
    try:
        # 1. Test health endpoints
        print("\n🔍 Testing health endpoints...")
        
        # Identity health
        response = requests.get(f"{base_url}/v1/identity/health")
        print(f"   Identity health: {response.status_code}")
        if response.status_code == 200:
            print(f"   Status: {response.json().get('status')}")
        
        # CA health
        response = requests.get(f"{base_url}/v1/ca/health")
        print(f"   CA health: {response.status_code}")
        if response.status_code == 200:
            print(f"   Status: {response.json().get('status')}")
        
        # 2. Test user creation (requires admin)
        print("\n👤 Testing user creation...")
        
        # First, try to create a user without auth (should fail)
        response = requests.post(f"{base_url}/v1/identity/users", json=test_user)
        print(f"   Create user without auth: {response.status_code} (expected: 401)")
        
        # 3. Test login
        print("\n🔐 Testing login...")
        
        login_data = {
            "username": "admin",
            "password": "admin123456"
        }
        
        response = requests.post(f"{base_url}/v1/identity/auth/login", json=login_data)
        print(f"   Admin login: {response.status_code}")
        
        if response.status_code == 200:
            login_response = response.json()
            session_token = login_response["session_token"]
            print(f"   ✅ Login successful, session token obtained")
            print(f"   User: {login_response['user']['username']} (Role: {login_response['user']['role']})")
        else:
            print(f"   ❌ Login failed: {response.text}")
            return False
        
        # 4. Test user creation with admin auth
        print("\n👤 Testing user creation with admin auth...")
        
        headers = {"Authorization": f"Bearer {session_token}"}
        response = requests.post(f"{base_url}/v1/identity/users", json=test_user, headers=headers)
        print(f"   Create user with admin auth: {response.status_code}")
        
        if response.status_code == 200:
            print(f"   ✅ User created successfully")
        else:
            print(f"   ❌ User creation failed: {response.text}")
        
        # 5. Test agent creation
        print("\n🤖 Testing agent creation...")
        
        test_agent = {
            "agent_id": "test-agent-001",
            "name": "Test Agent 001",
            "agent_type": "service",
            "metadata": {
                "test": True,
                "version": "1.0.0"
            }
        }
        
        response = requests.post(f"{base_url}/v1/identity/agents", json=test_agent, headers=headers)
        print(f"   Create agent: {response.status_code}")
        
        if response.status_code == 200:
            print(f"   ✅ Agent created successfully")
        else:
            print(f"   ❌ Agent creation failed: {response.text}")
        
        # 6. Test agent listing
        print("\n📋 Testing agent listing...")
        
        response = requests.get(f"{base_url}/v1/identity/agents", headers=headers)
        print(f"   List agents: {response.status_code}")
        
        if response.status_code == 200:
            agents = response.json()
            print(f"   ✅ Found {len(agents)} agents")
            for agent in agents[:3]:  # Show first 3
                print(f"     - {agent['agent_id']}: {agent['name']}")
        else:
            print(f"   ❌ Agent listing failed: {response.text}")
        
        # 7. Test CA functionality
        print("\n🔐 Testing CA functionality...")
        
        # Get CA info
        response = requests.get(f"{base_url}/v1/ca/info", headers=headers)
        print(f"   Get CA info: {response.status_code}")
        
        if response.status_code == 200:
            ca_info = response.json()
            print(f"   ✅ CA info retrieved")
            print(f"     Subject: {ca_info['ca_subject']}")
            print(f"     Total certificates: {ca_info['total_certificates']}")
        else:
            print(f"   ❌ CA info failed: {response.text}")
        
        # Get CA policy
        response = requests.get(f"{base_url}/v1/ca/policy", headers=headers)
        print(f"   Get CA policy: {response.status_code}")
        
        if response.status_code == 200:
            policy = response.json()
            print(f"   ✅ CA policy retrieved")
            print(f"     Key type: {policy['key_type']}")
            print(f"     Key size: {policy['key_size']} bits")
            print(f"     Validity: {policy['validity_days']} days")
        else:
            print(f"   ❌ CA policy failed: {response.text}")
        
        # 8. Test certificate listing
        print("\n📜 Testing certificate listing...")
        
        response = requests.get(f"{base_url}/v1/ca/certificates", headers=headers)
        print(f"   List certificates: {response.status_code}")
        
        if response.status_code == 200:
            certs = response.json()
            print(f"   ✅ Found {certs['total']} certificates")
        else:
            print(f"   ❌ Certificate listing failed: {response.text}")
        
        # 9. Test user listing
        print("\n👥 Testing user listing...")
        
        response = requests.get(f"{base_url}/v1/identity/users", headers=headers)
        print(f"   List users: {response.status_code}")
        
        if response.status_code == 200:
            users = response.json()
            print(f"   ✅ Found {len(users)} users")
            for user in users:
                print(f"     - {user['username']} (Role: {user['role']}, Status: {user['status']})")
        else:
            print(f"   ❌ User listing failed: {response.text}")
        
        # 10. Test current user info
        print("\n👤 Testing current user info...")
        
        response = requests.get(f"{base_url}/v1/identity/users/me", headers=headers)
        print(f"   Get current user: {response.status_code}")
        
        if response.status_code == 200:
            user_info = response.json()
            print(f"   ✅ Current user: {user_info['username']} (Role: {user_info['role']})")
        else:
            print(f"   ❌ Current user failed: {response.text}")
        
        # 11. Test audit log
        print("\n📝 Testing audit log...")
        
        response = requests.get(f"{base_url}/v1/identity/audit", headers=headers)
        print(f"   Get audit log: {response.status_code}")
        
        if response.status_code == 200:
            audit_entries = response.json()
            print(f"   ✅ Found {len(audit_entries)} audit entries")
            for entry in audit_entries[:3]:  # Show first 3
                print(f"     - {entry['action']}: {entry['details']}")
        else:
            print(f"   ❌ Audit log failed: {response.text}")
        
        # 12. Test system stats
        print("\n📊 Testing system stats...")
        
        response = requests.get(f"{base_url}/v1/identity/stats", headers=headers)
        print(f"   Get system stats: {response.status_code}")
        
        if response.status_code == 200:
            stats = response.json()
            print(f"   ✅ System stats retrieved")
            print(f"     Users: {stats['users']['total']}")
            print(f"     Agents: {stats['agents']['total']}")
            print(f"     Active sessions: {stats['sessions']['active']}")
        else:
            print(f"   ❌ System stats failed: {response.text}")
        
        # 13. Test logout
        print("\n🚪 Testing logout...")
        
        response = requests.post(f"{base_url}/v1/identity/auth/logout", headers=headers)
        print(f"   Logout: {response.status_code}")
        
        if response.status_code == 200:
            print(f"   ✅ Logout successful")
        else:
            print(f"   ❌ Logout failed: {response.text}")
        
        print("\n🎉 All tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Main test function."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Test the identity management system")
    parser.add_argument("--url", default="http://127.0.0.1:8000", 
                       help="Base URL for the API (default: http://127.0.0.1:8000)")
    
    args = parser.parse_args()
    
    success = test_identity_system(args.url)
    
    if success:
        print("\n✅ All tests passed!")
        sys.exit(0)
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
