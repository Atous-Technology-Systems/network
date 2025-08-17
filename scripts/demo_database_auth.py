#!/usr/bin/env python3
"""
Database Authentication System Demo

This script demonstrates the new database-backed authentication system
for ATous Secure Network.
"""

import sys
import os
import tempfile
import shutil

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atous_sec_network.database.database import DatabaseManager
from atous_sec_network.database.auth_service import DatabaseAuthService
from atous_sec_network.database.init_db import initialize_database
from atous_sec_network.database.models import User, Role, Session, AuditLog


def demo_database_auth():
    """Demonstrate the database authentication system"""
    print("🚀 ATous Secure Network - Database Authentication Demo")
    print("=" * 60)
    
    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "demo_auth.db")
    db_url = f"sqlite:///{db_path}"
    
    try:
        print(f"📁 Creating temporary database: {db_path}")
        
        # Initialize database
        db_manager = DatabaseManager(db_url)
        db_manager.initialize()
        
        print("✅ Database initialized successfully")
        
        # Initialize with default data
        print("🔧 Setting up default roles and admin user...")
        initialize_database(db_manager)
        
        print("✅ Default data created successfully")
        
        # Create auth service
        auth_service = DatabaseAuthService()
        auth_service.db_manager = db_manager
        
        print("\n👥 User Management Demo")
        print("-" * 30)
        
        # Create a test user
        print("Creating test user 'demo_user'...")
        user_id = auth_service.create_user(
            username="demo_user",
            email="demo@atous.network",
            password_hash="demo_password_hash",
            roles=["operator"]
        )
        print(f"✅ User created with ID: {user_id}")
        
        # Authenticate user
        print("\n🔐 Authentication Demo")
        print("-" * 30)
        
        print("Authenticating user...")
        user_data = auth_service.authenticate_user("demo_user", "demo_password_hash")
        
        if user_data:
            print("✅ Authentication successful!")
            print(f"   Username: {user_data['username']}")
            print(f"   User ID: {user_data['user_id']}")
            print(f"   Roles: {', '.join(user_data['roles'])}")
            print(f"   Active: {user_data['is_active']}")
        else:
            print("❌ Authentication failed!")
            return
        
        # Session management
        print("\n🔄 Session Management Demo")
        print("-" * 30)
        
        print("Creating user session...")
        session_id = auth_service.create_session(
            user_id=user_id,
            ip_address="192.168.1.100",
            user_agent="Demo Browser"
        )
        print(f"✅ Session created: {session_id}")
        
        print("Validating session...")
        session_user = auth_service.validate_session(session_id)
        if session_user:
            print("✅ Session valid!")
            print(f"   Session user: {session_user['username']}")
        else:
            print("❌ Session invalid!")
        
        # Permission checking
        print("\n🔒 Permission System Demo")
        print("-" * 30)
        
        permissions_to_check = [
            "api:read",
            "monitor:read", 
            "admin:read",
            "security:write"
        ]
        
        for permission in permissions_to_check:
            has_perm = auth_service.check_user_permission(user_id, permission)
            status = "✅" if has_perm else "❌"
            print(f"   {status} {permission}: {has_perm}")
        
        # Audit logging
        print("\n📝 Audit Logging Demo")
        print("-" * 30)
        
        with db_manager.get_session() as session:
            audit_logs = session.query(AuditLog).filter(
                AuditLog.user_id == int(user_id)
            ).all()
            
            print(f"Found {len(audit_logs)} audit log entries:")
            for log in audit_logs:
                print(f"   📋 {log.event_type}: {log.event_description}")
        
        # Clean up session
        print("\n🧹 Cleanup Demo")
        print("-" * 30)
        
        print("Revoking session...")
        if auth_service.revoke_session(session_id):
            print("✅ Session revoked successfully")
        else:
            print("❌ Failed to revoke session")
        
        print("Validating revoked session...")
        revoked_session = auth_service.validate_session(session_id)
        if revoked_session is None:
            print("✅ Session properly invalidated")
        else:
            print("❌ Session still valid after revocation")
        
        # Database statistics
        print("\n📊 Database Statistics")
        print("-" * 30)
        
        with db_manager.get_session() as session:
            user_count = session.query(User).count()
            role_count = session.query(Role).count()
            session_count = session.query(Session).count()
            audit_count = session.query(AuditLog).count()
            
            print(f"   Users: {user_count}")
            print(f"   Roles: {role_count}")
            print(f"   Sessions: {session_count}")
            print(f"   Audit Logs: {audit_count}")
        
        print("\n🎉 Demo completed successfully!")
        print("\nThis demonstrates:")
        print("  ✅ Database schema implementation")
        print("  ✅ User creation and management")
        print("  ✅ Authentication and authorization")
        print("  ✅ Session management")
        print("  ✅ Role-based access control")
        print("  ✅ Audit logging")
        print("  ✅ Database transaction integrity")
        
    except Exception as e:
        print(f"❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        print(f"\n🧹 Cleaning up temporary database...")
        db_manager.close()
        shutil.rmtree(temp_dir)
        print("✅ Cleanup completed")


if __name__ == "__main__":
    demo_database_auth()
