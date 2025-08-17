#!/usr/bin/env python3
"""
Authentication Integration Demo

This script demonstrates the complete integration between the database
authentication system and the existing access control system.
"""

import sys
import os
import tempfile
import shutil

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atous_sec_network.database.database import DatabaseManager
from atous_sec_network.database.init_db import initialize_database
from atous_sec_network.security.auth_integration import AuthIntegrationService
from atous_sec_network.security.access_control import Permission, Role as SecurityRole


def demo_auth_integration():
    """Demonstrate the authentication integration system"""
    print("🚀 ATous Secure Network - Authentication Integration Demo")
    print("=" * 70)
    
    # Create temporary database
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "demo_integration.db")
    db_url = f"sqlite:///{db_path}"
    
    try:
        print(f"📁 Creating temporary database: {db_path}")
        
        # Initialize database
        db_manager = DatabaseManager(db_url)
        db_manager.initialize()
        
        # Initialize with default data
        print("🔧 Setting up default roles and admin user...")
        initialize_database(db_manager)
        
        print("✅ Default data created successfully")
        
        # Create auth integration service
        auth_integration = AuthIntegrationService()
        auth_integration.db_auth_service.db_manager = db_manager
        
        print("\n👥 User Management Demo")
        print("-" * 30)
        
        # Create users with different roles
        print("Creating users with different roles...")
        
        # Create operator user
        operator_id = auth_integration.create_user(
            username="operator_user",
            email="operator@atous.network",
            password="OperatorPass123!",
            roles={SecurityRole.OPERATOR}
        )
        print(f"✅ Operator user created: {operator_id}")
        
        # Create admin user
        admin_id = auth_integration.create_user(
            username="admin_user",
            email="admin_demo@atous.network",
            password="AdminPass123!",
            roles={SecurityRole.ADMIN}
        )
        print(f"✅ Admin user created: {admin_id}")
        
        # Create security analyst user
        security_id = auth_integration.create_user(
            username="security_user",
            email="security_demo@atous.network",
            password="SecurityPass123!",
            roles={SecurityRole.SECURITY_ANALYST}
        )
        print(f"✅ Security analyst user created: {security_id}")
        
        print("\n🔐 Authentication Demo")
        print("-" * 30)
        
        # Authenticate operator user
        print("Authenticating operator user...")
        operator_auth = auth_integration.authenticate_user(
            username="operator_user",
            password="OperatorPass123!",
            ip_address="192.168.1.100",
            user_agent="Demo Browser"
        )
        
        if operator_auth:
            print("✅ Operator authentication successful!")
            print(f"   Username: {operator_auth['username']}")
            print(f"   User ID: {operator_auth['user_id']}")
            print(f"   Roles: {', '.join(operator_auth['roles'])}")
            print(f"   Session ID: {operator_auth['session_id']}")
            print(f"   Token: {operator_auth['token'][:30]}...")
        else:
            print("❌ Operator authentication failed!")
            return
        
        # Authenticate admin user
        print("\nAuthenticating admin user...")
        admin_auth = auth_integration.authenticate_user(
            username="admin_user",
            password="AdminPass123!",
            ip_address="192.168.1.101",
            user_agent="Admin Browser"
        )
        
        if admin_auth:
            print("✅ Admin authentication successful!")
            print(f"   Username: {admin_auth['username']}")
            print(f"   User ID: {admin_auth['user_id']}")
            print(f"   Roles: {', '.join(admin_auth['roles'])}")
            print(f"   Session ID: {admin_auth['session_id']}")
        else:
            print("❌ Admin authentication failed!")
            return
        
        print("\n🔒 Permission System Demo")
        print("-" * 30)
        
        # Test permissions for operator user
        print("Testing operator user permissions...")
        operator_permissions = [
            ("api:read", Permission.API_READ),
            ("monitor:read", Permission.MONITOR_READ),
            ("admin:read", Permission.ADMIN_READ),  # Should fail
            ("security:write", Permission.SECURITY_WRITE)  # Should fail
        ]
        
        for perm_name, permission in operator_permissions:
            has_perm = auth_integration.check_permission(operator_id, permission)
            status = "✅" if has_perm else "❌"
            print(f"   {status} {perm_name}: {has_perm}")
        
        # Test permissions for admin user
        print("\nTesting admin user permissions...")
        admin_permissions = [
            ("api:read", Permission.API_READ),
            ("admin:read", Permission.ADMIN_READ),
            ("admin:users", Permission.ADMIN_USERS),
            ("security:read", Permission.SECURITY_READ),
            ("security:write", Permission.SECURITY_WRITE)  # Should succeed
        ]
        
        for perm_name, permission in admin_permissions:
            has_perm = auth_integration.check_permission(admin_id, permission)
            status = "✅" if has_perm else "❌"
            print(f"   {status} {perm_name}: {has_perm}")
        
        print("\n🔄 Session Management Demo")
        print("-" * 30)
        
        # Validate operator session
        print("Validating operator session...")
        operator_session = auth_integration.validate_token(operator_auth["token"])
        
        if operator_session:
            print("✅ Operator session valid!")
            print(f"   Username: {operator_session['username']}")
            print(f"   User ID: {operator_session['user_id']}")
        else:
            print("❌ Operator session invalid!")
        
        # Validate admin session
        print("\nValidating admin session...")
        admin_session = auth_integration.validate_token(admin_auth["token"])
        
        if admin_session:
            print("✅ Admin session valid!")
            print(f"   Username: {admin_session['username']}")
            print(f"   User ID: {admin_session['user_id']}")
        else:
            print("❌ Admin session invalid!")
        
        print("\n🧹 Session Cleanup Demo")
        print("-" * 30)
        
        # Revoke operator session
        print("Revoking operator session...")
        if auth_integration.revoke_session(operator_auth["session_id"]):
            print("✅ Operator session revoked successfully")
        else:
            print("❌ Failed to revoke operator session")
        
        # Verify session is no longer valid
        print("Verifying revoked session...")
        revoked_session = auth_integration.validate_token(operator_auth["token"])
        if revoked_session is None:
            print("✅ Session properly invalidated after revocation")
        else:
            print("❌ Session still valid after revocation")
        
        print("\n📊 Database Statistics")
        print("-" * 30)
        
        with db_manager.get_session() as session:
            from atous_sec_network.database.models import User, Role, Session, AuditLog
            
            user_count = session.query(User).count()
            role_count = session.query(Role).count()
            session_count = session.query(Session).count()
            audit_count = session.query(AuditLog).count()
            
            print(f"   Users: {user_count}")
            print(f"   Roles: {role_count}")
            print(f"   Sessions: {session_count}")
            print(f"   Audit Logs: {audit_count}")
        
        print("\n🎉 Integration Demo completed successfully!")
        print("\nThis demonstrates:")
        print("  ✅ Database-backed user management")
        print("  ✅ Secure password hashing with bcrypt")
        print("  ✅ JWT token generation and validation")
        print("  ✅ Session management with database persistence")
        print("  ✅ Role-based access control (RBAC)")
        print("  ✅ Permission checking against database")
        print("  ✅ Audit logging for all operations")
        print("  ✅ Seamless integration with existing API")
        
    except Exception as e:
        print(f"❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Clean up
        print(f"\n🧹 Cleaning up temporary database...")
        try:
            db_manager.close()
            shutil.rmtree(temp_dir)
            print("✅ Cleanup completed")
        except Exception as e:
            print(f"⚠️  Cleanup warning: {e}")


if __name__ == "__main__":
    demo_auth_integration()
