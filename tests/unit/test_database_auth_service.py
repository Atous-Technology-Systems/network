"""
Test Database Authentication Service

Tests the database-backed authentication service integration.
"""

import unittest
import tempfile
import os
from unittest.mock import patch, MagicMock

from atous_sec_network.database.auth_service import DatabaseAuthService
from atous_sec_network.database.models import User, Role, Session, AuditLog
from atous_sec_network.database.database import DatabaseManager


class TestDatabaseAuthService(unittest.TestCase):
    """Test database authentication service"""
    
    def setUp(self):
        """Set up test database"""
        # Create temporary database
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_auth.db")
        self.db_url = f"sqlite:///{self.db_path}"
        
        # Initialize database manager
        self.db_manager = DatabaseManager(self.db_url)
        self.db_manager.initialize()
        
        # Create auth service
        self.auth_service = DatabaseAuthService()
        self.auth_service.db_manager = self.db_manager
        
        # Create test roles
        self._create_test_roles()
    
    def tearDown(self):
        """Clean up test database"""
        self.db_manager.close()
        # Remove temporary files
        import shutil
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
    
    def test_create_user_success(self):
        """Test successful user creation"""
        # Create user first
        import bcrypt
        password = "testpassword"
        # Usar um hash bcrypt válido e conhecido
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Verificar se o hash é válido antes de criar o usuário
        assert bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')), "Hash bcrypt inválido"
        
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash=password_hash,
            roles=["operator"]
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
    
    def test_create_user_duplicate_username(self):
        """Test user creation with duplicate username"""
        # Create first user
        self.auth_service.create_user(
            username="testuser",
            email="test1@example.com",
            password_hash="hashed_password_123"
        )
        
        # Try to create second user with same username
        with self.assertRaises(ValueError, msg="Username already exists"):
            self.auth_service.create_user(
                username="testuser",
                email="test2@example.com",
                password_hash="hashed_password_456"
            )
    
    def test_create_user_duplicate_email(self):
        """Test user creation with duplicate email"""
        # Create first user
        self.auth_service.create_user(
            username="user1",
            email="test@example.com",
            password_hash="hashed_password_123"
        )
        
        # Try to create second user with same email
        with self.assertRaises(ValueError, msg="Email already exists"):
            self.auth_service.create_user(
                username="user2",
                email="test@example.com",
                password_hash="hashed_password_456"
            )
    
    def test_authenticate_user_success(self):
        """Test successful user authentication"""
        # Create user first
        import bcrypt
        password = "testpassword"
        # Usar um hash bcrypt válido e conhecido
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        # Verificar se o hash é válido antes de criar o usuário
        assert bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')), "Hash bcrypt inválido"
        
        user_id = self.auth_service.create_user(
            username="testuser_success",  # Nome único para evitar conflitos
            email="test_success@example.com",
            password_hash=password_hash,
            roles=["operator"]
        )
        
        # Authenticate user
        user_data = self.auth_service.authenticate_user("testuser_success", "testpassword")
        
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data["username"], "testuser_success")
        self.assertEqual(user_data["user_id"], user_id)
        self.assertEqual(user_data["roles"], ["operator"])
        self.assertTrue(user_data["is_active"])
        self.assertFalse(user_data["is_locked"])
    
    def test_authenticate_user_invalid_password(self):
        """Test user authentication with invalid password"""
        # Create user first
        self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="correct_hash",
            roles=["operator"]
        )
        
        # Try to authenticate with wrong password
        user_data = self.auth_service.authenticate_user("testuser", "wrong_hash")
        
        self.assertIsNone(user_data)
    
    def test_authenticate_user_nonexistent(self):
        """Test authentication of non-existent user"""
        user_data = self.auth_service.authenticate_user("nonexistent", "any_hash")
        
        self.assertIsNone(user_data)
    
    def test_create_session_success(self):
        """Test successful session creation"""
        # Create user first
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["operator"]
        )
        
        # Create session
        session_id = self.auth_service.create_session(
            user_id=user_id,
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            duration_minutes=60
        )
        
        self.assertIsNotNone(session_id)
        
        # Verify session was created in database
        with self.db_manager.get_session() as session:
            session_model = session.query(Session).filter(
                Session.session_id == session_id
            ).first()
            self.assertIsNotNone(session_model)
            self.assertEqual(session_model.user_id, int(user_id))
            self.assertEqual(session_model.ip_address, "192.168.1.1")
            self.assertEqual(session_model.user_agent, "Test Browser")
    
    def test_validate_session_success(self):
        """Test successful session validation"""
        # Create user and session
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["operator"]
        )
        
        session_id = self.auth_service.create_session(user_id=user_id)
        
        # Validate session
        user_data = self.auth_service.validate_session(session_id)
        
        self.assertIsNotNone(user_data)
        self.assertEqual(user_data["username"], "testuser")
        self.assertEqual(user_data["session_id"], session_id)
    
    def test_validate_session_invalid(self):
        """Test session validation with invalid session ID"""
        user_data = self.auth_service.validate_session("invalid_session_id")
        
        self.assertIsNone(user_data)
    
    def test_revoke_session_success(self):
        """Test successful session revocation"""
        # Create user and session
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["operator"]
        )
        
        session_id = self.auth_service.create_session(user_id=user_id)
        
        # Revoke session
        result = self.auth_service.revoke_session(session_id)
        
        self.assertTrue(result)
        
        # Verify session is no longer active
        with self.db_manager.get_session() as session:
            session_model = session.query(Session).filter(
                Session.session_id == session_id
            ).first()
            self.assertFalse(session_model.is_active)
    
    def test_get_user_roles(self):
        """Test getting user roles"""
        # Create user with roles
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["operator", "admin"]
        )
        
        # Get user roles
        roles = self.auth_service.get_user_roles(user_id)
        
        self.assertIn("operator", roles)
        self.assertIn("admin", roles)
        self.assertEqual(len(roles), 2)
    
    def test_check_user_permission_success(self):
        """Test successful permission check"""
        # Create user with admin role
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["admin"]
        )
        
        # Check permission
        has_permission = self.auth_service.check_user_permission(
            user_id, "admin:read"
        )
        
        self.assertTrue(has_permission)
    
    def test_check_user_permission_failure(self):
        """Test failed permission check"""
        # Create user with operator role only
        user_id = self.auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            roles=["operator"]
        )
        
        # Check permission that operator doesn't have
        has_permission = self.auth_service.check_user_permission(
            user_id, "admin:read"
        )
        
        self.assertFalse(has_permission)


if __name__ == "__main__":
    unittest.main()
