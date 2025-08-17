"""
Database Authentication Service for ATous Secure Network

This module provides database-backed authentication services that integrate
with the existing access control system.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone
import logging
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.exc import IntegrityError, NoResultFound

from .models import User as DBUser, Role as DBRole, Session as DBSessionModel, AuditLog
from .database import get_database_manager
from ..security.access_control import Permission, Role as SecurityRole

logger = logging.getLogger(__name__)


class DatabaseAuthService:
    """Database-backed authentication service"""
    
    def __init__(self):
        self.db_manager = get_database_manager()
    
    def create_user(self, username: str, email: str, password_hash: str, 
                   roles: Optional[List[str]] = None) -> str:
        """
        Create a new user in the database
        
        Args:
            username: Username for the new user
            email: Email address for the new user
            password_hash: Hashed password
            roles: List of role names to assign
            
        Returns:
            User ID of the created user
            
        Raises:
            ValueError: If username or email already exists
        """
        # Validate input parameters
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        if not email or not email.strip():
            raise ValueError("Email cannot be empty")
        if not password_hash:
            raise ValueError("Password hash cannot be empty")
        
        try:
            with self.db_manager.get_session() as session:
                # Check if user already exists
                existing_user = session.query(DBUser).filter(
                    (DBUser.username == username) | (DBUser.email == email)
                ).first()
                
                if existing_user:
                    if existing_user.username == username:
                        raise ValueError("Username already exists")
                    else:
                        raise ValueError("Email already exists")
                
                # Create user
                db_user = DBUser(
                    username=username,
                    email=email,
                    password_hash=password_hash,
                    is_active=True,
                    is_verified=False
                )
                
                session.add(db_user)
                session.flush()  # Get the ID
                
                # Assign default role if none specified
                if not roles:
                    roles = ["operator"]
                
                # Assign roles
                for role_name in roles:
                    role = session.query(DBRole).filter(DBRole.name == role_name).first()
                    if role:
                        db_user.roles.append(role)
                
                # Create audit log
                audit_log = AuditLog(
                    user_id=db_user.id,
                    event_type="user_created",
                    event_description=f"User {username} created",
                    event_metadata=f'{{"username": "{username}", "email": "{email}"}}'
                )
                session.add(audit_log)
                
                session.commit()
                
                logger.info(f"User created in database: {username} (ID: {db_user.id})")
                return str(db_user.id)
                
        except IntegrityError as e:
            logger.error(f"Database integrity error creating user: {e}")
            raise ValueError("Database error creating user")
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            raise ValueError(f"Failed to create user: {str(e)}")
    
    def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """
        Authenticate a user with username and plain text password
        
        Args:
            username: Username to authenticate
            password: Plain text password to verify
            
        Returns:
            User data if authentication successful, None otherwise
        """
        try:
            with self.db_manager.get_session() as session:
                user = session.query(DBUser).filter(DBUser.username == username).first()
                
                if not user:
                    return None
                
                # Check if account is locked
                if user.is_locked():
                    logger.warning(f"Login attempt for locked account: {username}")
                    return None
                
                # Verify password using bcrypt
                import bcrypt
                try:
                    logger.debug(f"Verificando senha para usuário {username}")
                    logger.debug(f"Hash armazenado: {user.password_hash}")
                    logger.debug(f"Tipo do hash: {type(user.password_hash)}")
                    
                    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
                        # Increment failed login attempts
                        user.increment_failed_login()
                        session.commit()
                        
                        # Log failed attempt
                        audit_log = AuditLog(
                            user_id=user.id,
                            event_type="login_failed",
                            event_description=f"Failed login attempt for user {username}",
                            event_metadata='{"reason": "invalid_password"}'
                        )
                        session.add(audit_log)
                        session.commit()
                        
                        return None
                except Exception as e:
                    logger.error(f"Password verification error for user {username}: {e}")
                    logger.error(f"Hash que causou erro: {user.password_hash}")
                    logger.error(f"Senha fornecida: {password}")
                    return None
                
                # Reset failed login attempts on successful login
                user.reset_failed_login()
                user.last_login = datetime.now(timezone.utc)
                session.commit()
                
                # Log successful login
                audit_log = AuditLog(
                    user_id=user.id,
                    event_type="login_successful",
                    event_description=f"Successful login for user {username}",
                    event_metadata='{"ip_address": "unknown"}'
                )
                session.add(audit_log)
                session.commit()
                
                # Return user data
                return {
                    "user_id": str(user.id),
                    "username": user.username,
                    "email": user.email,
                    "roles": [role.name for role in user.roles],
                    "is_active": user.is_active,
                    "is_locked": user.is_locked(),
                    "last_login": user.last_login
                }
                
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user data by ID
        
        Args:
            user_id: User ID to retrieve
            
        Returns:
            User data if found, None otherwise
        """
        try:
            with self.db_manager.get_session() as session:
                user = session.query(DBUser).filter(DBUser.id == int(user_id)).first()
                
                if not user:
                    return None
                
                return {
                    "user_id": str(user.id),
                    "username": user.username,
                    "email": user.email,
                    "roles": [role.name for role in user.roles],
                    "is_active": user.is_active,
                    "is_locked": user.is_locked(),
                    "last_login": user.last_login,
                    "created_at": user.created_at,
                    "updated_at": user.updated_at
                }
                
        except Exception as e:
            logger.error(f"Error retrieving user: {e}")
            return None
    
    def create_session(self, user_id: str, ip_address: Optional[str] = None, 
                      user_agent: Optional[str] = None, duration_minutes: int = 60) -> Optional[str]:
        """
        Create a new user session
        
        Args:
            user_id: ID of the user
            ip_address: IP address of the client
            user_agent: User agent string
            duration_minutes: Session duration in minutes
            
        Returns:
            Session ID if created successfully, None otherwise
        """
        try:
            with self.db_manager.get_session() as session:
                # Verify user exists
                user = session.query(DBUser).filter(DBUser.id == int(user_id)).first()
                if not user:
                    return None
                
                # Create session
                session_model = DBSessionModel(
                    session_id=DBSessionModel.generate_session_id(),
                    user_id=int(user_id),
                    ip_address=ip_address,
                    user_agent=user_agent,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
                )
                
                session.add(session_model)
                
                # Create audit log for session creation
                audit_log = AuditLog(
                    user_id=int(user_id),
                    event_type="session_created",
                    event_description=f"Session created for user {user_id}",
                    event_metadata=f'{{"session_id": "{session_model.session_id}", "ip_address": "{ip_address}", "user_agent": "{user_agent}"}}'
                )
                session.add(audit_log)
                
                session.commit()
                
                logger.info(f"Session created for user {user_id}: {session_model.session_id}")
                return session_model.session_id
                
        except Exception as e:
            logger.error(f"Error creating session: {e}")
            return None
    
    def validate_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """
        Validate a session and return user data if valid
        
        Args:
            session_id: Session ID to validate
            
        Returns:
            User data if session valid, None otherwise
        """
        try:
            with self.db_manager.get_session() as session:
                session_model = session.query(DBSessionModel).filter(
                    DBSessionModel.session_id == session_id,
                    DBSessionModel.is_active == True
                ).first()
                
                if not session_model:
                    return None
                
                # Check if session is expired
                if session_model.is_expired():
                    session_model.is_active = False
                    session.commit()
                    return None
                
                # Refresh activity
                session_model.refresh_activity()
                session.commit()
                
                # Get user data
                user = session.query(DBUser).filter(DBUser.id == session_model.user_id).first()
                if not user or not user.is_active:
                    return None
                
                return {
                    "user_id": str(user.id),
                    "username": user.username,
                    "email": user.email,
                    "roles": [role.name for role in user.roles],
                    "is_active": user.is_active,
                    "session_id": session_id
                }
                
        except Exception as e:
            logger.error(f"Error validating session: {e}")
            return None
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a user session
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if session revoked successfully, False otherwise
        """
        try:
            with self.db_manager.get_session() as session:
                session_model = session.query(DBSessionModel).filter(
                    DBSessionModel.session_id == session_id
                ).first()
                
                if not session_model:
                    return False
                
                session_model.is_active = False
                
                # Create audit log for session revocation
                audit_log = AuditLog(
                    user_id=session_model.user_id,
                    event_type="session_revoked",
                    event_description=f"Session revoked: {session_id}",
                    event_metadata=f'{{"session_id": "{session_id}"}}'
                )
                session.add(audit_log)
                
                session.commit()
                
                logger.info(f"Session revoked: {session_id}")
                return True
                
        except Exception as e:
            logger.error(f"Error revoking session: {e}")
            return False
    
    def get_user_roles(self, user_id: str) -> List[str]:
        """
        Get roles for a specific user
        
        Args:
            user_id: User ID
            
        Returns:
            List of role names
        """
        try:
            with self.db_manager.get_session() as session:
                user = session.query(DBUser).filter(DBUser.id == int(user_id)).first()
                
                if not user:
                    return []
                
                return [role.name for role in user.roles]
                
        except Exception as e:
            logger.error(f"Error getting user roles: {e}")
            return []
    
    def check_user_permission(self, user_id: str, permission: str) -> bool:
        """
        Check if a user has a specific permission
        
        Args:
            user_id: User ID
            permission: Permission to check
            
        Returns:
            True if user has permission, False otherwise
        """
        try:
            with self.db_manager.get_session() as session:
                user = session.query(DBUser).filter(DBUser.id == int(user_id)).first()
                
                if not user:
                    return False
                
                # Check roles for permission
                for role in user.roles:
                    if role.has_permission(permission):
                        return True
                
                return False
                
        except Exception as e:
            logger.error(f"Error checking user permission: {e}")
            return False


# Global instance
auth_service = DatabaseAuthService()
