"""
Authentication Integration Layer for ATous Secure Network

This module integrates the database authentication service with the existing
access control system, providing a hybrid approach that maintains API compatibility
while adding database persistence.
"""

from typing import Dict, List, Optional, Set, Any, Union
from datetime import datetime, timedelta, UTC
import bcrypt
import jwt
import secrets
import logging
from dataclasses import dataclass, field

from .access_control import Permission, Role, User as AccessControlUser
from ..database.auth_service import DatabaseAuthService
from ..database.models import User as DBUser, Role as DBRole

logger = logging.getLogger(__name__)


class AuthIntegrationService:
    """Integration service between database auth and access control"""
    
    def __init__(self, secret_key: str = None):
        self.secret_key = secret_key or secrets.token_urlsafe(32)
        self.db_auth_service = DatabaseAuthService()
        self.token_expiry_minutes = 60  # 1 hour default
        
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)
        return password_hash.decode('utf-8')
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False
    
    def create_user(self, username: str, email: str, password: str, 
                   roles: Optional[Set[str]] = None) -> str:
        """
        Create user in database with proper password hashing
        
        Args:
            username: Username for new user
            email: Email address
            password: Plain text password
            roles: Set of roles to assign
            
        Returns:
            User ID of created user
            
        Raises:
            ValueError: If user creation fails
        """
        try:
            # Hash password
            password_hash = self.hash_password(password)
            
            # Use roles directly (already strings)
            role_names = list(roles) if roles else None
            
            # Create user in database
            user_id = self.db_auth_service.create_user(
                username=username,
                email=email,
                password_hash=password_hash,
                roles=role_names
            )
            
            logger.info(f"User created successfully: {username} (ID: {user_id})")
            return user_id
            
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            raise ValueError(f"Failed to create user: {str(e)}")
    
    def authenticate_user(self, username: str, password: str, 
                        ip_address: str = None, user_agent: str = None) -> Optional[Dict[str, Any]]:
        """
        Authenticate user with username and password
        
        Args:
            username: Username to authenticate
            password: Plain text password
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            User data if authentication successful, None otherwise
        """
        try:
            # Get user from database
            user_data = self.db_auth_service.authenticate_user(username, password)
            
            if not user_data:
                return None
            
            # Create session
            session_id = self.db_auth_service.create_session(
                user_id=user_data["user_id"],
                ip_address=ip_address,
                user_agent=user_agent,
                duration_minutes=self.token_expiry_minutes
            )
            
            if not session_id:
                logger.error(f"Failed to create session for user {username}")
                return None
            
            # Generate JWT token
            token_data = {
                "user_id": user_data["user_id"],
                "username": user_data["username"],
                "email": user_data["email"],
                "roles": user_data["roles"],
                "session_id": session_id,
                "exp": datetime.now(UTC) + timedelta(minutes=self.token_expiry_minutes)
            }
            
            token = jwt.encode(token_data, self.secret_key, algorithm="HS256")
            
            # Return authentication result
            return {
                "user_id": user_data["user_id"],
                "username": user_data["username"],
                "email": user_data["email"],
                "roles": user_data["roles"],
                "token": token,
                "session_id": session_id,
                "expires_at": token_data["exp"].isoformat()
            }
            
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            return None
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validate JWT token and return user data
        
        Args:
            token: JWT token to validate
            
        Returns:
            User data if token valid, None otherwise
        """
        try:
            # Decode token
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
            
            # Validate session
            session_data = self.db_auth_service.validate_session(payload["session_id"])
            
            if not session_data:
                logger.warning(f"Invalid session for token: {payload['session_id']}")
                return None
            
            # Return user data
            return {
                "user_id": payload["user_id"],
                "username": payload["username"],
                "email": payload["email"],
                "roles": payload["roles"],
                "session_id": payload["session_id"]
            }
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None
    
    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """
        Check if user has specific permission
        
        Args:
            user_id: User ID to check
            permission: Permission to verify
            
        Returns:
            True if user has permission, False otherwise
        """
        try:
            return self.db_auth_service.check_user_permission(user_id, permission.value)
        except Exception as e:
            logger.error(f"Permission check error: {e}")
            return False
    
    def get_user(self, user_id: str) -> Optional[AccessControlUser]:
        """
        Get user data as AccessControlUser object for compatibility
        
        Args:
            user_id: User ID to retrieve
            
        Returns:
            AccessControlUser object if found, None otherwise
        """
        try:
            user_data = self.db_auth_service.get_user_by_id(user_id)
            
            if not user_data:
                return None
            
            # Convert to AccessControlUser format
            roles = {Role(role_name) for role_name in user_data["roles"]}
            
            return AccessControlUser(
                user_id=user_data["user_id"],
                username=user_data["username"],
                email=user_data["email"],
                password_hash="",  # Not needed for access control
                roles=roles,
                is_active=user_data["is_active"],
                is_locked=user_data["is_locked"],
                last_login=user_data.get("last_login"),
                created_at=user_data.get("created_at", datetime.now(UTC)),
                updated_at=user_data.get("updated_at", datetime.now(UTC))
            )
            
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {e}")
            return None
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke user session
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if session revoked successfully, False otherwise
        """
        try:
            return self.db_auth_service.revoke_session(session_id)
        except Exception as e:
            logger.error(f"Session revocation error: {e}")
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
            return self.db_auth_service.get_user_roles(user_id)
        except Exception as e:
            logger.error(f"Error getting user roles: {e}")
            return []


# Global instance for compatibility
auth_integration = AuthIntegrationService()
