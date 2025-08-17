"""
Database Initialization Script for ATous Secure Network

This script initializes the database with:
- Default roles and permissions
- Admin user account
- Basic security policies
"""

import logging
import json
from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError

from .database import get_database_manager
from .models import Role, User, AuditLog
from ..security.access_control import Permission, Role as SecurityRole

logger = logging.getLogger(__name__)


def initialize_database(db_manager=None):
    """Initialize database with default data"""
    try:
        if db_manager is None:
            db_manager = get_database_manager()
        
        with db_manager.get_session() as session:
            # Create default roles
            create_default_roles(session)
            
            # Create admin user
            create_admin_user(session)
            
            # Create audit log entry
            audit_log = AuditLog(
                user_id=None,
                event_type="database_initialized",
                event_description="Database initialized with default data",
                event_metadata='{"timestamp": "' + datetime.now(timezone.utc).isoformat() + '"}'
            )
            session.add(audit_log)
            
            session.commit()
            logger.info("Database initialized successfully")
            
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        raise


def create_default_roles(session):
    """Create default system roles"""
    default_roles = [
        {
            "name": "super_admin",
            "description": "Super Administrator with full system access",
            "permissions": [
                Permission.ADMIN_FULL.value,
                Permission.SECURITY_READ.value,
                Permission.SECURITY_WRITE.value,
                Permission.SECURITY_BLOCK_IP.value,
                Permission.SECURITY_UNBLOCK_IP.value,
                Permission.SECURITY_VIEW_LOGS.value,
                Permission.SECURITY_MANAGE_RULES.value,
                Permission.ABISS_READ.value,
                Permission.ABISS_WRITE.value,
                Permission.ABISS_CONFIGURE.value,
                Permission.ABISS_ANALYZE.value,
                Permission.NNIS_READ.value,
                Permission.NNIS_WRITE.value,
                Permission.NNIS_CONFIGURE.value,
                Permission.NNIS_TRAIN.value,
                Permission.API_READ.value,
                Permission.API_WRITE.value,
                Permission.API_DELETE.value,
                Permission.MONITOR_READ.value,
                Permission.MONITOR_WRITE.value,
                Permission.MONITOR_ALERTS.value
            ]
        },
        {
            "name": "admin",
            "description": "Administrator with system management access",
            "permissions": [
                Permission.ADMIN_READ.value,
                Permission.ADMIN_USERS.value,
                Permission.SECURITY_READ.value,
                Permission.SECURITY_WRITE.value,
                Permission.ABISS_READ.value,
                Permission.ABISS_WRITE.value,
                Permission.NNIS_READ.value,
                Permission.NNIS_WRITE.value,
                Permission.API_READ.value,
                Permission.API_WRITE.value,
                Permission.MONITOR_READ.value,
                Permission.MONITOR_WRITE.value
            ]
        },
        {
            "name": "security_analyst",
            "description": "Security analyst with security operations access",
            "permissions": [
                Permission.SECURITY_READ.value,
                Permission.SECURITY_WRITE.value,
                Permission.SECURITY_VIEW_LOGS.value,
                Permission.ABISS_READ.value,
                Permission.ABISS_ANALYZE.value,
                Permission.NNIS_READ.value,
                Permission.MONITOR_READ.value,
                Permission.MONITOR_ALERTS.value
            ]
        },
        {
            "name": "operator",
            "description": "System operator with basic access",
            "permissions": [
                Permission.API_READ.value,
                Permission.MONITOR_READ.value,
                Permission.SECURITY_READ.value
            ]
        },
        {
            "name": "monitor",
            "description": "System monitor with read-only access",
            "permissions": [
                Permission.MONITOR_READ.value,
                Permission.API_READ.value
            ]
        },
        {
            "name": "guest",
            "description": "Guest user with minimal access",
            "permissions": [
                Permission.API_READ.value
            ]
        }
    ]
    
    for role_data in default_roles:
        try:
            # Check if role already exists
            existing_role = session.query(Role).filter(Role.name == role_data["name"]).first()
            if existing_role:
                logger.info(f"Role {role_data['name']} already exists, skipping")
                continue
            
            # Create new role
            role = Role(
                name=role_data["name"],
                description=role_data["description"],
                permissions=json.dumps(role_data["permissions"]),
                is_active=True
            )
            session.add(role)
            logger.info(f"Created role: {role_data['name']}")
            
        except IntegrityError:
            logger.warning(f"Role {role_data['name']} already exists")
            session.rollback()
        except Exception as e:
            logger.error(f"Error creating role {role_data['name']}: {e}")
            session.rollback()
            raise
    
    session.commit()


def create_admin_user(session):
    """Create default admin user"""
    try:
        # Check if admin user already exists
        existing_admin = session.query(User).filter(User.username == "admin").first()
        if existing_admin:
            logger.info("Admin user already exists, skipping")
            return
        
        # Get admin role
        admin_role = session.query(Role).filter(Role.name == "admin").first()
        if not admin_role:
            logger.error("Admin role not found, cannot create admin user")
            return
        
        # Create admin user (password: Admin123!)
        # In production, this should be changed on first login
        admin_user = User(
            username="admin",
            email="admin@atous.network",
            password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/vHhHwqG",  # Admin123!
            first_name="System",
            last_name="Administrator",
            is_active=True,
            is_verified=True
        )
        
        session.add(admin_user)
        session.flush()  # Get the ID
        
        # Assign admin role
        admin_user.roles.append(admin_role)
        
        # Create audit log
        audit_log = AuditLog(
            user_id=admin_user.id,
            event_type="admin_user_created",
            event_description="Default admin user created during initialization",
            event_metadata='{"username": "admin", "role": "admin"}'
        )
        session.add(audit_log)
        
        session.commit()
        logger.info("Admin user created successfully")
        
    except IntegrityError:
        logger.warning("Admin user already exists")
        session.rollback()
    except Exception as e:
        logger.error(f"Error creating admin user: {e}")
        session.rollback()
        raise


def create_test_data(db_manager=None):
    """Create test data for development"""
    try:
        if db_manager is None:
            db_manager = get_database_manager()
        
        with db_manager.get_session() as session:
            # Create test user
            test_role = session.query(Role).filter(Role.name == "operator").first()
            if not test_role:
                logger.error("Operator role not found")
                return
            
            existing_test = session.query(User).filter(User.username == "testuser").first()
            if existing_test:
                logger.info("Test user already exists")
                return
            
            test_user = User(
                username="testuser",
                email="test@example.com",
                password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/vHhHwqG",  # Admin123!
                first_name="Test",
                last_name="User",
                is_active=True,
                is_verified=True
            )
            
            session.add(test_user)
            session.flush()
            test_user.roles.append(test_role)
            
            session.commit()
            logger.info("Test user created successfully")
            
    except Exception as e:
        logger.error(f"Error creating test data: {e}")


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Initialize database
    initialize_database()
    
    # Create test data in development
    create_test_data()
