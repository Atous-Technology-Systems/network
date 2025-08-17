"""
Test Authentication Integration Service

Tests the integration between database authentication and access control system.
"""

import unittest
import tempfile
import os
import shutil
from unittest.mock import patch, MagicMock

from atous_sec_network.security.auth_integration import AuthIntegrationService
from atous_sec_network.database.database import DatabaseManager
from atous_sec_network.database.models import User, Role, Session, AuditLog
from atous_sec_network.security.access_control import Permission, Role as SecurityRole


class TestAuthIntegration(unittest.TestCase):
    """Test authentication integration service"""
    
    def setUp(self):
        """Set up test database"""
        # Create temporary database
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_integration.db")
        self.db_url = f"sqlite:///{self.db_path}"
        
        # Initialize database manager
        self.db_manager = DatabaseManager(self.db_url)
        self.db_manager.initialize()
        
        # Create auth integration service
        self.auth_integration = AuthIntegrationService()
        self.auth_integration.db_auth_service.db_manager = self.db_manager
        
        # Create test roles
        self._create_test_roles()
    
    def tearDown(self):
        """Clean up test database"""
        self.db_manager.close()
        shutil.rmtree(self.temp_dir)
    
    def _create_test_roles(self):
        """Create test roles in database"""
        with self.db_manager.get_session() as session:
            # Create operator role
            operator_role = Role(
                name="operator",
                description="Test operator role",
                permissions='["api:read", "monitor:read"]',
                is_active=True
            )
            session.add(operator_role)
            
            # Create admin role
            admin_role = Role(
                name="admin",
                description="Test admin role",
                permissions='["admin:read", "admin:users", "security:read"]',
                is_active=True
            )
            session.add(admin_role)
            
            session.commit()
    
    def test_password_hashing_and_verification(self):
        """Test password hashing and verification"""
        password = "test_password_123"
        
        # Hash password
        password_hash = self.auth_integration.hash_password(password)
        
        # Verify password
        self.assertTrue(self.auth_integration.verify_password(password, password_hash))
        self.assertFalse(self.auth_integration.verify_password("wrong_password", password_hash))
    
    def test_create_user_success(self):
        """Test successful user creation"""
        user_id = self.auth_integration.create_user(
            username="testuser",
            email="test@example.com",
            password="secure_password_123",
            roles={SecurityRole.OPERATOR}
        )
        
        self.assertIsNotNone(user_id)
        self.assertTrue(user_id.isdigit())
        
        # Verify user was created in database
        with self.db_manager.get_session() as session:
            user = session.query(User).filter(User.id == int(user_id)).first()
            self.assertIsNotNone(user)
            self.assertEqual(user.username, "testuser")
            self.assertEqual(user.email, "test@example.com")
            self.assertEqual(len(user.roles), 1)
            self.assertEqual(user.roles[0].name, "operator")
    
    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        # Create user first
        user_id = self.auth_integration.create_user(
            username="authuser",
            email="auth@example.com",
            password="auth_password_123",
            roles={SecurityRole.OPERATOR}
        )
        
        # Authenticate user
        auth_result = self.auth_integration.authenticate_user(
            username="authuser",
            password="auth_password_123",
            ip_address="192.168.1.100",
            user_agent="Test Browser"
        )
        
        self.assertIsNotNone(auth_result)
        self.assertEqual(auth_result["username"], "authuser")
        self.assertEqual(auth_result["user_id"], user_id)
        self.assertIn("operator", auth_result["roles"])
        self.assertIn("token", auth_result)
        self.assertIn("session_id", auth_result)
    
    def test_authenticate_user_invalid_password(self):
        """Test user authentication with invalid password"""
        # Create user first
        self.auth_integration.create_user(
            username="invaliduser",
            email="invalid@example.com",
            password="correct_password",
            roles={SecurityRole.OPERATOR}
        )
        
        # Try to authenticate with wrong password
        auth_result = self.auth_integration.authenticate_user(
            username="invaliduser",
            password="wrong_password"
        )
        
        self.assertIsNone(auth_result)
    
    def test_validate_token_success(self):
        """Test successful token validation"""
        # Create and authenticate user
        user_id = self.auth_integration.create_user(
            username="tokenuser",
            email="token@example.com",
            password="token_password_123",
            roles={SecurityRole.OPERATOR}
        )
        
        auth_result = self.auth_integration.authenticate_user(
            username="tokenuser",
            password="token_password_123"
        )
        
        # Validate token
        user_info = self.auth_integration.validate_token(auth_result["token"])
        
        self.assertIsNotNone(user_info)
        self.assertEqual(user_info["username"], "tokenuser")
        self.assertEqual(user_info["user_id"], user_id)
    
    def test_validate_token_invalid(self):
        """Test token validation with invalid token"""
        user_info = self.auth_integration.validate_token("invalid_token")
        self.assertIsNone(user_info)
    
    def test_check_permission_success(self):
        """Test successful permission check"""
        # Create user with admin role
        user_id = self.auth_integration.create_user(
            username="permuser",
            email="perm@example.com",
            password="perm_password_123",
            roles={SecurityRole.ADMIN}
        )
        
        # Check permission
        has_permission = self.auth_integration.check_permission(
            user_id, Permission.ADMIN_READ
        )
        
        self.assertTrue(has_permission)
    
    def test_check_permission_failure(self):
        """Test failed permission check"""
        # Create user with operator role only
        user_id = self.auth_integration.create_user(
            username="nopermuser",
            email="noperm@example.com",
            password="noperm_password_123",
            roles={SecurityRole.OPERATOR}
        )
        
        # Check permission that operator doesn't have
        has_permission = self.auth_integration.check_permission(
            user_id, Permission.ADMIN_READ
        )
        
        self.assertFalse(has_permission)
    
    def test_get_user_success(self):
        """Test successful user retrieval"""
        # Create user
        user_id = self.auth_integration.create_user(
            username="getuser",
            email="get@example.com",
            password="get_password_123",
            roles={SecurityRole.OPERATOR}
        )
        
        # Get user
        user = self.auth_integration.get_user(user_id)
        
        self.assertIsNotNone(user)
        self.assertEqual(user.username, "getuser")
        self.assertEqual(user.email, "get@example.com")
        self.assertEqual(len(user.roles), 1)
        self.assertIn(SecurityRole.OPERATOR, user.roles)
    
    def test_revoke_session_success(self):
        """Test successful session revocation"""
        # Create and authenticate user
        user_id = self.auth_integration.create_user(
            username="sessionuser",
            email="session@example.com",
            password="session_password_123",
            roles={SecurityRole.OPERATOR}
        )
        
        auth_result = self.auth_integration.authenticate_user(
            username="sessionuser",
            password="session_password_123"
        )
        
        # Revoke session
        result = self.auth_integration.revoke_session(auth_result["session_id"])
        
        self.assertTrue(result)
        
        # Verify session is no longer valid
        user_info = self.auth_integration.validate_token(auth_result["token"])
        self.assertIsNone(user_info)


if __name__ == "__main__":
    unittest.main()
