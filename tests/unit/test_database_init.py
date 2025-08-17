"""
Test Database Initialization

Tests the database initialization script that sets up default roles and admin user.
"""

import unittest
import tempfile
import os
import json

from atous_sec_network.database.init_db import initialize_database, create_test_data
from atous_sec_network.database.database import DatabaseManager
from atous_sec_network.database.models import User, Role, AuditLog


class TestDatabaseInit(unittest.TestCase):
    """Test database initialization"""
    
    def setUp(self):
        """Set up test database"""
        # Create temporary database
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_init.db")
        self.db_url = f"sqlite:///{self.db_path}"
        
        # Initialize database manager
        self.db_manager = DatabaseManager(self.db_url)
        self.db_manager.initialize()
    
    def tearDown(self):
        """Clean up test database"""
        self.db_manager.close()
        # Remove temporary files
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_initialize_database_success(self):
        """Test successful database initialization"""
        # Initialize database
        initialize_database(self.db_manager)
        
        # Verify roles were created
        with self.db_manager.get_session() as session:
            roles = session.query(Role).all()
            self.assertGreater(len(roles), 0)
            
            # Check for specific roles
            role_names = [role.name for role in roles]
            self.assertIn("super_admin", role_names)
            self.assertIn("admin", role_names)
            self.assertIn("operator", role_names)
            self.assertIn("monitor", role_names)
            self.assertIn("guest", role_names)
    
    def test_default_roles_permissions(self):
        """Test that default roles have correct permissions"""
        # Initialize database
        initialize_database(self.db_manager)
        
        with self.db_manager.get_session() as session:
            # Check super_admin role permissions
            super_admin = session.query(Role).filter(Role.name == "super_admin").first()
            self.assertIsNotNone(super_admin)
            
            permissions = json.loads(super_admin.permissions)
            self.assertIn("admin:full", permissions)
            self.assertIn("security:read", permissions)
            self.assertIn("abiss:read", permissions)
            self.assertIn("nnis:read", permissions)
            
            # Check operator role permissions
            operator = session.query(Role).filter(Role.name == "operator").first()
            self.assertIsNotNone(operator)
            
            permissions = json.loads(operator.permissions)
            self.assertIn("api:read", permissions)
            self.assertIn("monitor:read", permissions)
            self.assertNotIn("admin:read", permissions)  # Should not have admin permissions
    
    def test_admin_user_creation(self):
        """Test that admin user is created with correct role"""
        # Initialize database
        initialize_database(self.db_manager)
        
        with self.db_manager.get_session() as session:
            # Check admin user exists
            admin_user = session.query(User).filter(User.username == "admin").first()
            self.assertIsNotNone(admin_user)
            self.assertEqual(admin_user.email, "admin@atous.network")
            self.assertTrue(admin_user.is_active)
            self.assertTrue(admin_user.is_verified)
            
            # Check admin user has admin role
            admin_roles = [role.name for role in admin_user.roles]
            self.assertIn("admin", admin_roles)
    
    def test_audit_log_creation(self):
        """Test that audit logs are created during initialization"""
        # Initialize database
        initialize_database(self.db_manager)
        
        with self.db_manager.get_session() as session:
            # Check for initialization audit log
            init_log = session.query(AuditLog).filter(
                AuditLog.event_type == "database_initialized"
            ).first()
            self.assertIsNotNone(init_log)
            
            # Check for admin user creation audit log
            admin_log = session.query(AuditLog).filter(
                AuditLog.event_type == "admin_user_created"
            ).first()
            self.assertIsNotNone(admin_log)
    
    def test_create_test_data(self):
        """Test test data creation"""
        # Initialize database first
        initialize_database(self.db_manager)
        
        # Create test data
        create_test_data(self.db_manager)
        
        with self.db_manager.get_session() as session:
            # Check test user exists
            test_user = session.query(User).filter(User.username == "testuser").first()
            self.assertIsNotNone(test_user)
            self.assertEqual(test_user.email, "test@example.com")
            
            # Check test user has operator role
            test_roles = [role.name for role in test_user.roles]
            self.assertIn("operator", test_roles)
    
    def test_duplicate_initialization(self):
        """Test that re-initialization doesn't create duplicates"""
        # Initialize database twice
        initialize_database(self.db_manager)
        initialize_database(self.db_manager)
        
        with self.db_manager.get_session() as session:
            # Should still have only one admin user
            admin_users = session.query(User).filter(User.username == "admin").all()
            self.assertEqual(len(admin_users), 1)
            
            # Should still have only one set of roles
            roles = session.query(Role).all()
            role_names = [role.name for role in roles]
            self.assertEqual(len(role_names), len(set(role_names)))  # No duplicates
    
    def test_role_permissions_format(self):
        """Test that role permissions are stored in correct JSON format"""
        # Initialize database
        initialize_database(self.db_manager)
        
        with self.db_manager.get_session() as session:
            roles = session.query(Role).all()
            
            for role in roles:
                if role.permissions:
                    # Verify permissions can be parsed as JSON
                    try:
                        permissions = json.loads(role.permissions)
                        self.assertIsInstance(permissions, list)
                        
                        # Verify each permission is a string
                        for permission in permissions:
                            self.assertIsInstance(permission, str)
                            
                    except json.JSONDecodeError:
                        self.fail(f"Role {role.name} has invalid JSON permissions: {role.permissions}")


if __name__ == "__main__":
    unittest.main()
