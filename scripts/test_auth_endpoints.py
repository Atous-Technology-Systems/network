#!/usr/bin/env python3
"""
Test Authentication Endpoints

This script tests the updated authentication endpoints to ensure they work
with the new database-backed authentication system.
"""

import sys
import os
import tempfile
import shutil
import requests
import json
import time

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atous_sec_network.database.database import DatabaseManager
from atous_sec_network.database.init_db import initialize_database
from atous_sec_network.api.server import create_app


def test_auth_endpoints():
    """Test the authentication endpoints"""
    print("🧪 Testing Authentication Endpoints")
    print("=" * 50)
    
    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_auth_api.db")
    db_url = f"sqlite:///{db_path}"
    
    try:
        print(f"📁 Creating temporary database: {db_path}")
        
        # Initialize database
        db_manager = DatabaseManager(db_url)
        db_manager.initialize()
        
        # Initialize with default data
        print("🔧 Setting up default roles and admin user...")
        initialize_database(db_manager)
        
        # Create FastAPI app
        app = create_app()
        
        # Override database URL for testing
        app.state.db_url = db_url
        
        # Start test server
        import uvicorn
        import threading
        
        def run_server():
            uvicorn.run(app, host="127.0.0.1", port=8001, log_level="error")
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Wait for server to start
        time.sleep(2)
        
        base_url = "http://127.0.0.1:8001"
        
        print("\n🔐 Testing User Registration")
        print("-" * 30)
        
        # Test user registration
        register_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "TestPassword123!",
            "roles": ["operator"]
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/auth/register",
                json=register_data,
                timeout=10
            )
            
            if response.status_code == 201:
                print("✅ User registration successful")
                user_data = response.json()
                print(f"   User ID: {user_data['user_id']}")
                print(f"   Username: {user_data['username']}")
                print(f"   Roles: {user_data['roles']}")
            else:
                print(f"❌ User registration failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            return False
        
        print("\n🔑 Testing User Login")
        print("-" * 30)
        
        # Test user login
        login_data = {
            "username": "testuser",
            "password": "TestPassword123!"
        }
        
        try:
            response = requests.post(
                f"{base_url}/api/auth/login",
                json=login_data,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ User login successful")
                login_response = response.json()
                print(f"   Access Token: {login_response['access_token'][:20]}...")
                print(f"   Token Type: {login_response['token_type']}")
                print(f"   Expires In: {login_response['expires_in']} seconds")
                
                # Store token for further tests
                access_token = login_response['access_token']
                
            else:
                print(f"❌ User login failed: {response.status_code}")
                print(f"   Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            return False
        
        print("\n🔒 Testing Protected Endpoint")
        print("-" * 30)
        
        # Test accessing a protected endpoint
        headers = {"Authorization": f"Bearer {access_token}"}
        
        try:
            response = requests.get(
                f"{base_url}/api/auth/me",
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                print("✅ Protected endpoint access successful")
                user_info = response.json()
                print(f"   Username: {user_info['username']}")
                print(f"   Email: {user_info['email']}")
                print(f"   Roles: {user_info['roles']}")
            else:
                print(f"❌ Protected endpoint access failed: {response.status_code}")
                print(f"   Response: {response.text}")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
        
        print("\n🎉 All tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Clean up
        print(f"\n🧹 Cleaning up...")
        try:
            db_manager.close()
            shutil.rmtree(temp_dir)
            print("✅ Cleanup completed")
        except Exception as e:
            print(f"⚠️  Cleanup warning: {e}")


if __name__ == "__main__":
    success = test_auth_endpoints()
    sys.exit(0 if success else 1)
