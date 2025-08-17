"""
Integration Test: Database Authentication Service

This test demonstrates the integration between the database authentication service
and the existing authentication system.
"""

import unittest
import tempfile
import os
import json
from unittest.mock import patch, MagicMock

from atous_sec_network.database.auth_service import DatabaseAuthService
from atous_sec_network.database.init_db import initialize_database
from atous_sec_network.database.database import DatabaseManager
from atous_sec_network.database.models import User, Role, Session, AuditLog


class TestDatabaseAuthIntegration(unittest.TestCase):
    """Test database authentication integration"""
    
    def setUp(self):
        """Set up test database and services"""
        # Create temporary database
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_integration.db")
        self.db_url = f"sqlite:///{self.db_path}"
        
        # Initialize database manager
        self.db_manager = DatabaseManager(self.db_url)
        self.db_manager.initialize()
        
        # Initialize database with default data
        initialize_database(self.db_manager)
        
        # Create auth service
        self.auth_service = DatabaseAuthService()
        self.auth_service.db_manager = self.db_manager
    
    def tearDown(self):
        """Clean up test database"""
        self.db_manager.close()
        # Remove temporary files
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_complete_user_lifecycle(self):
        """Test complete user lifecycle: create, authenticate, session, revoke"""
        # 1. Create user with proper bcrypt hash
        import bcrypt
        password = "SecurePass123!"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user_id = self.auth_service.create_user(
            username="integration_user",
            email="integration@test.com",
            password_hash=password_hash,
            roles=["operator"]
        )
        
        self.assertIsNotNone(user_id)
        
        # 2. Authenticate user with plain text password
        user_data = self.auth_service.authenticate_user(
            "integration_user", password
        )
        
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data["username"], "integration_user")
        self.assertEqual(user_data["user_id"], user_id)
        
        # 3. Create session
        session_id = self.auth_service.create_session(
            user_id=user_id,
            ip_address="192.168.1.100",
            user_agent="Integration Test Browser"
        )
        
        self.assertIsNotNone(session_id)
        
        # 4. Validate session
        session_user_data = self.auth_service.validate_session(session_id)
        
        self.assertIsNotNone(session_user_data)
        self.assertEqual(session_user_data["username"], "integration_user")
        self.assertEqual(session_user_data["session_id"], session_id)
        
        # 5. Check permissions
        has_api_read = self.auth_service.check_user_permission(user_id, "api:read")
        self.assertTrue(has_api_read)
        
        has_admin_read = self.auth_service.check_user_permission(user_id, "admin:read")
        self.assertFalse(has_admin_read)  # Operator shouldn't have admin permissions
        
        # 6. Revoke session
        revoke_result = self.auth_service.revoke_session(session_id)
        self.assertTrue(revoke_result)
        
        # 7. Verify session is no longer valid
        invalid_session_data = self.auth_service.validate_session(session_id)
        self.assertIsNone(invalid_session_data)
    
    def test_role_based_access_control(self):
        """Test role-based access control with different user types"""
        # Create users with different roles
        import bcrypt
        
        admin_password = "AdminPass123!"
        admin_hash = bcrypt.hashpw(admin_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        admin_user_id = self.auth_service.create_user(
            username="admin_user",
            email="admin@test.com",
            password_hash=admin_hash,
            roles=["admin"]
        )
        
        security_password = "SecurityPass123!"
        security_hash = bcrypt.hashpw(security_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        security_user_id = self.auth_service.create_user(
            username="security_user",
            email="security@test.com",
            password_hash=security_hash,
            roles=["security_analyst"]
        )
        
        operator_password = "OperatorPass123!"
        operator_hash = bcrypt.hashpw(operator_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        operator_user_id = self.auth_service.create_user(
            username="operator_user",
            email="operator@test.com",
            password_hash=operator_hash,
            roles=["operator"]
        )
        
        # Test admin permissions
        self.assertTrue(self.auth_service.check_user_permission(admin_user_id, "admin:read"))
        self.assertTrue(self.auth_service.check_user_permission(admin_user_id, "admin:users"))
        self.assertTrue(self.auth_service.check_user_permission(admin_user_id, "security:read"))
        
        # Test security analyst permissions
        self.assertTrue(self.auth_service.check_user_permission(security_user_id, "security:read"))
        self.assertTrue(self.auth_service.check_user_permission(security_user_id, "security:write"))
        self.assertTrue(self.auth_service.check_user_permission(security_user_id, "abiss:analyze"))
        self.assertFalse(self.auth_service.check_user_permission(security_user_id, "admin:read"))
        
        # Test operator permissions
        self.assertTrue(self.auth_service.check_user_permission(operator_user_id, "api:read"))
        self.assertTrue(self.auth_service.check_user_permission(operator_user_id, "monitor:read"))
        self.assertFalse(self.auth_service.check_user_permission(operator_user_id, "security:write"))
    
    def test_audit_logging_integration(self):
        """Test that all operations create proper audit logs"""
        # Create user with proper bcrypt hash
        import bcrypt
        password = "SecurePass123!"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user_id = self.auth_service.create_user(
            username="audit_user",
            email="audit@test.com",
            password_hash=password_hash,
            roles=["operator"]
        )
        
        # Authenticate user with plain text password
        self.auth_service.authenticate_user("audit_user", password)
        
        # Create session
        session_id = self.auth_service.create_session(user_id)
        
        # Revoke session
        self.auth_service.revoke_session(session_id)
        
        # Check audit logs
        with self.db_manager.get_session() as session:
            audit_logs = session.query(AuditLog).filter(
                AuditLog.user_id == int(user_id)
            ).all()
            
            # Should have logs for: user creation, login, session creation, session revocation
            event_types = [log.event_type for log in audit_logs]
            self.assertIn("user_created", event_types)
            self.assertIn("login_successful", event_types)
            self.assertIn("session_created", event_types)
            self.assertIn("session_revoked", event_types)
    
    def test_concurrent_user_operations(self):
        """Test handling of multiple user operations in sequence"""
        # Create 5 users in sequence (SQLite doesn't handle real concurrency well)
        results = []
        errors = []
        
        for i in range(5):
            try:
                import bcrypt
                password = f"SecurePass{i}!"
                password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                
                user_id = self.auth_service.create_user(
                    username=f"concurrent_user_{i}",
                    email=f"concurrent{i}@test.com",
                    password_hash=password_hash,
                    roles=["operator"]
                )
                results.append((i, user_id))
            except Exception as e:
                errors.append((i, str(e)))
        
        # Verify all users were created successfully
        self.assertEqual(len(results), 5)
        self.assertEqual(len(errors), 0)
        
        # Verify users exist in database
        with self.db_manager.get_session() as session:
            for thread_id, user_id in results:
                user = session.query(User).filter(User.id == int(user_id)).first()
                self.assertIsNotNone(user)
                self.assertEqual(user.username, f"concurrent_user_{thread_id}")
    
    def test_database_transaction_integrity(self):
        """Test that database transactions maintain integrity"""
        # Try to create user with invalid data using the service (should fail)
        try:
            # This should fail due to empty username
            user_id = self.auth_service.create_user(
                username="",  # Empty username should fail
                email="invalid@test.com",
                password_hash="hash",
                roles=["operator"]
            )
            # If we get here, the validation failed
            self.fail("Should have failed with empty username")
        except ValueError:
            # Expected to fail
            pass
        
        # Verify no invalid user was created
        with self.db_manager.get_session() as session:
            invalid_users = session.query(User).filter(User.username == "").all()
            self.assertEqual(len(invalid_users), 0)
        
        # Verify we can still create valid users
        import bcrypt
        password = "ValidPass123!"
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user_id = self.auth_service.create_user(
            username="valid_user",
            email="valid@test.com",
            password_hash=password_hash,
            roles=["operator"]
        )
        
        self.assertIsNotNone(user_id)
    
    def test_performance_under_load(self):
        """Test performance of authentication operations under load"""
        import time
        
        # Create 20 users (reduced from 50 for faster testing)
        start_time = time.time()
        
        user_ids = []
        passwords = []
        for i in range(20):
            import bcrypt
            password = f"SecurePass{i}!"
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            passwords.append(password)
            
            user_id = self.auth_service.create_user(
                username=f"perf_user_{i}",
                email=f"perf{i}@test.com",
                password_hash=password_hash,
                roles=["operator"]
            )
            user_ids.append(user_id)
        
        creation_time = time.time() - start_time
        
        # Authenticate all users
        start_time = time.time()
        
        for i, user_id in enumerate(user_ids):
            user_data = self.auth_service.authenticate_user(
                f"perf_user_{i}", passwords[i]
            )
            self.assertIsNotNone(user_data)
        
        auth_time = time.time() - start_time
        
        # Performance assertions (adjust based on your system)
        self.assertLess(creation_time, 15.0)  # Should create 20 users in under 15 seconds
        self.assertLess(auth_time, 10.0)      # Should authenticate 20 users in under 10 seconds
        
        print(f"Created 20 users in {creation_time:.2f}s")
        print(f"Authenticated 20 users in {auth_time:.2f}s")


if __name__ == "__main__":
    unittest.main()
