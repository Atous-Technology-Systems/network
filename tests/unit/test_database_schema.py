"""
Test Database Schema Implementation

Tests the database models and database manager for the authentication system
"""

import unittest
import tempfile
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from atous_sec_network.database.models import Base, User, Role, Session, AuditLog
from atous_sec_network.database.database import DatabaseManager


class TestDatabaseSchema(unittest.TestCase):
    """Test database schema implementation"""
    
    def setUp(self):
        """Set up test database"""
        # Create temporary database file
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.temp_db.close()
        
        # Create database manager with temporary database
        self.db_url = f"sqlite:///{self.temp_db.name}"
        self.db_manager = DatabaseManager(self.db_url)
        self.db_manager.initialize()
        
        # Create test session
        self.session = self.db_manager.get_session_sync()
    
    def tearDown(self):
        """Clean up test database"""
        if self.session:
            self.session.close()
        if self.db_manager:
            self.db_manager.close()
        
        # Remove temporary database file
        if os.path.exists(self.temp_db.name):
            os.unlink(self.temp_db.name)
    
    def test_create_tables(self):
        """Test that all tables are created successfully"""
        # Verify tables exist
        from sqlalchemy import inspect
        inspector = inspect(self.db_manager.engine)
        tables = inspector.get_table_names()
        
        expected_tables = ['users', 'roles', 'user_roles', 'user_roles_metadata', 'sessions', 'audit_logs']
        for table in expected_tables:
            self.assertIn(table, tables, f"Table {table} should exist")
    
    def test_user_creation(self):
        """Test user creation and basic operations"""
        # Create a test user
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password_123",
            first_name="Test",
            last_name="User"
        )
        
        self.session.add(user)
        self.session.commit()
        
        # Verify user was created
        retrieved_user = self.session.query(User).filter_by(username="testuser").first()
        self.assertIsNotNone(retrieved_user)
        self.assertEqual(retrieved_user.email, "test@example.com")
        self.assertEqual(retrieved_user.full_name, "Test User")
        self.assertTrue(retrieved_user.is_active)
        self.assertFalse(retrieved_user.is_verified)
    
    def test_role_creation(self):
        """Test role creation and permissions"""
        # Create a test role
        role = Role(
            name="admin",
            description="Administrator role",
            permissions='["read", "write", "delete", "admin"]'
        )
        
        self.session.add(role)
        self.session.commit()
        
        # Verify role was created
        retrieved_role = self.session.query(Role).filter_by(name="admin").first()
        self.assertIsNotNone(retrieved_role)
        self.assertEqual(retrieved_role.description, "Administrator role")
        self.assertTrue(retrieved_role.has_permission("read"))
        self.assertTrue(retrieved_role.has_permission("admin"))
        self.assertFalse(retrieved_role.has_permission("nonexistent"))
    
    def test_user_role_assignment(self):
        """Test user-role assignment"""
        # Create user and role
        user = User(
            username="roleuser",
            email="role@example.com",
            password_hash="hashed_password_456"
        )
        
        role = Role(
            name="user",
            description="Regular user role",
            permissions='["read", "write"]'
        )
        
        self.session.add_all([user, role])
        self.session.commit()
        
        # Assign role to user
        user.roles.append(role)
        self.session.commit()
        
        # Verify assignment
        retrieved_user = self.session.query(User).filter_by(username="roleuser").first()
        self.assertEqual(len(retrieved_user.roles), 1)
        self.assertEqual(retrieved_user.roles[0].name, "user")
    
    def test_session_creation(self):
        """Test session creation and management"""
        # Create user first
        user = User(
            username="sessionuser",
            email="session@example.com",
            password_hash="hashed_password_789"
        )
        self.session.add(user)
        self.session.commit()
        
        # Create session
        session = Session(
            session_id=Session.generate_session_id(),
            user_id=user.id,
            ip_address="192.168.1.100",
            user_agent="Test Browser/1.0",
            expires_at=user.created_at.replace(year=user.created_at.year + 1)
        )
        
        self.session.add(session)
        self.session.commit()
        
        # Verify session
        retrieved_session = self.session.query(Session).filter_by(user_id=user.id).first()
        self.assertIsNotNone(retrieved_session)
        self.assertEqual(retrieved_session.ip_address, "192.168.1.100")
        self.assertFalse(retrieved_session.is_expired())
    
    def test_audit_log_creation(self):
        """Test audit log creation"""
        # Create audit log entry
        audit_entry = AuditLog(
            event_type="user_login",
            event_description="User logged in successfully",
            ip_address="192.168.1.100",
            user_agent="Test Browser/1.0"
        )
        
        self.session.add(audit_entry)
        self.session.commit()
        
        # Verify audit log
        retrieved_audit = self.session.query(AuditLog).filter_by(event_type="user_login").first()
        self.assertIsNotNone(retrieved_audit)
        self.assertEqual(retrieved_audit.event_description, "User logged in successfully")
        self.assertEqual(retrieved_audit.ip_address, "192.168.1.100")


if __name__ == '__main__':
    unittest.main()
