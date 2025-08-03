"""Access Control System for ATous Secure Network

Implements Role-Based Access Control (RBAC) with:
- User authentication and authorization
- Role and permission management
- Session management
- Access logging and monitoring
- JWT token validation
- Rate limiting per user/role
"""

from typing import Dict, List, Optional, Set, Any, Union
from datetime import datetime, timedelta, UTC
from enum import Enum
import hashlib
import secrets
import jwt
import bcrypt
from pydantic import BaseModel, Field
from dataclasses import dataclass, field
import logging
from collections import defaultdict, deque
import threading
import time

# Configure logging
logger = logging.getLogger(__name__)

class Permission(Enum):
    """System permissions"""
    # System administration
    ADMIN_FULL = "admin:full"
    ADMIN_READ = "admin:read"
    ADMIN_USERS = "admin:users"
    ADMIN_SECURITY = "admin:security"
    
    # Security operations
    SECURITY_READ = "security:read"
    SECURITY_WRITE = "security:write"
    SECURITY_BLOCK_IP = "security:block_ip"
    SECURITY_UNBLOCK_IP = "security:unblock_ip"
    SECURITY_VIEW_LOGS = "security:view_logs"
    SECURITY_MANAGE_RULES = "security:manage_rules"
    
    # ABISS operations
    ABISS_READ = "abiss:read"
    ABISS_WRITE = "abiss:write"
    ABISS_CONFIGURE = "abiss:configure"
    ABISS_ANALYZE = "abiss:analyze"
    
    # NNIS operations
    NNIS_READ = "nnis:read"
    NNIS_WRITE = "nnis:write"
    NNIS_CONFIGURE = "nnis:configure"
    NNIS_TRAIN = "nnis:train"
    
    # API access
    API_READ = "api:read"
    API_WRITE = "api:write"
    API_DELETE = "api:delete"
    
    # Monitoring
    MONITOR_READ = "monitor:read"
    MONITOR_WRITE = "monitor:write"
    MONITOR_ALERTS = "monitor:alerts"

class Role(Enum):
    """System roles with predefined permissions"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    OPERATOR = "operator"
    MONITOR = "monitor"
    GUEST = "guest"

class SessionStatus(Enum):
    """Session status enumeration"""
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    SUSPENDED = "suspended"

@dataclass
class User:
    """User model"""
    user_id: str
    username: str
    email: str
    password_hash: str
    roles: Set[Role] = field(default_factory=set)
    custom_permissions: Set[Permission] = field(default_factory=set)
    is_active: bool = True
    is_locked: bool = False
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    
    def get_all_permissions(self) -> Set[Permission]:
        """Get all permissions for this user (from roles + custom)"""
        permissions = set(self.custom_permissions)
        for role in self.roles:
            permissions.update(ROLE_PERMISSIONS.get(role, set()))
        return permissions
    
    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission"""
        return permission in self.get_all_permissions()
    
    def has_any_permission(self, permissions: List[Permission]) -> bool:
        """Check if user has any of the specified permissions"""
        user_permissions = self.get_all_permissions()
        return any(perm in user_permissions for perm in permissions)
    
    def has_all_permissions(self, permissions: List[Permission]) -> bool:
        """Check if user has all of the specified permissions"""
        user_permissions = self.get_all_permissions()
        return all(perm in user_permissions for perm in permissions)

@dataclass
class Session:
    """User session model"""
    session_id: str
    user_id: str
    token: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    status: SessionStatus = SessionStatus.ACTIVE
    
    def is_valid(self) -> bool:
        """Check if session is valid"""
        return (
            self.status == SessionStatus.ACTIVE and
            datetime.now(UTC) < self.expires_at
        )
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.now(UTC) >= self.expires_at

@dataclass
class AccessAttempt:
    """Access attempt logging"""
    timestamp: datetime
    user_id: Optional[str]
    ip_address: str
    endpoint: str
    method: str
    success: bool
    failure_reason: Optional[str] = None
    user_agent: Optional[str] = None

# Role-Permission mapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.SUPER_ADMIN: {
        Permission.ADMIN_FULL,
        Permission.ADMIN_READ,
        Permission.ADMIN_USERS,
        Permission.ADMIN_SECURITY,
        Permission.SECURITY_READ,
        Permission.SECURITY_WRITE,
        Permission.SECURITY_BLOCK_IP,
        Permission.SECURITY_UNBLOCK_IP,
        Permission.SECURITY_VIEW_LOGS,
        Permission.SECURITY_MANAGE_RULES,
        Permission.ABISS_READ,
        Permission.ABISS_WRITE,
        Permission.ABISS_CONFIGURE,
        Permission.ABISS_ANALYZE,
        Permission.NNIS_READ,
        Permission.NNIS_WRITE,
        Permission.NNIS_CONFIGURE,
        Permission.NNIS_TRAIN,
        Permission.API_READ,
        Permission.API_WRITE,
        Permission.API_DELETE,
        Permission.MONITOR_READ,
        Permission.MONITOR_WRITE,
        Permission.MONITOR_ALERTS,
    },
    Role.ADMIN: {
        Permission.ADMIN_READ,
        Permission.ADMIN_USERS,
        Permission.SECURITY_READ,
        Permission.SECURITY_WRITE,
        Permission.SECURITY_BLOCK_IP,
        Permission.SECURITY_UNBLOCK_IP,
        Permission.SECURITY_VIEW_LOGS,
        Permission.ABISS_READ,
        Permission.ABISS_WRITE,
        Permission.ABISS_ANALYZE,
        Permission.NNIS_READ,
        Permission.NNIS_WRITE,
        Permission.API_READ,
        Permission.API_WRITE,
        Permission.MONITOR_READ,
        Permission.MONITOR_WRITE,
        Permission.MONITOR_ALERTS,
    },
    Role.SECURITY_ANALYST: {
        Permission.SECURITY_READ,
        Permission.SECURITY_WRITE,
        Permission.SECURITY_BLOCK_IP,
        Permission.SECURITY_UNBLOCK_IP,
        Permission.SECURITY_VIEW_LOGS,
        Permission.ABISS_READ,
        Permission.ABISS_ANALYZE,
        Permission.NNIS_READ,
        Permission.API_READ,
        Permission.MONITOR_READ,
        Permission.MONITOR_ALERTS,
    },
    Role.OPERATOR: {
        Permission.SECURITY_READ,
        Permission.ABISS_READ,
        Permission.NNIS_READ,
        Permission.API_READ,
        Permission.MONITOR_READ,
    },
    Role.MONITOR: {
        Permission.SECURITY_READ,
        Permission.ABISS_READ,
        Permission.NNIS_READ,
        Permission.MONITOR_READ,
    },
    Role.GUEST: {
        Permission.API_READ,
    }
}

class AccessControlSystem:
    """Comprehensive access control system with RBAC"""
    
    def __init__(self, jwt_secret: str, session_timeout_hours: int = 24):
        self.jwt_secret = jwt_secret
        self.session_timeout_hours = session_timeout_hours
        
        # Storage (in production, use database)
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.access_attempts: deque = deque(maxlen=10000)  # Keep last 10k attempts
        
        # Rate limiting
        self.login_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.api_requests: Dict[str, List[datetime]] = defaultdict(list)
        
        # Configuration
        self.max_login_attempts = 5
        self.login_lockout_duration = timedelta(minutes=30)
        self.max_api_requests_per_minute = 60
        self.max_api_requests_per_hour = 1000
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Create default admin user
        self._create_default_admin()
        
        logger.info("Access Control System initialized")
    
    def _create_default_admin(self):
        """Create default admin user if none exists"""
        admin_id = "admin-001"
        if admin_id not in self.users:
            password_hash = self._hash_password("admin123!@#")
            admin_user = User(
                user_id=admin_id,
                username="admin",
                email="admin@atous-sec.local",
                password_hash=password_hash,
                roles={Role.SUPER_ADMIN}
            )
            self.users[admin_id] = admin_user
            logger.info("Default admin user created")
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    
    def _generate_token(self, user_id: str, session_id: str) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'session_id': session_id,
            'iat': datetime.now(UTC),
            'exp': datetime.now(UTC) + timedelta(hours=self.session_timeout_hours)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def _verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None
    
    def _is_rate_limited(self, identifier: str, max_attempts: int, time_window: timedelta) -> bool:
        """Check if identifier is rate limited"""
        now = datetime.now(UTC)
        cutoff = now - time_window
        
        # Clean old attempts
        attempts = [attempt for attempt in self.login_attempts[identifier] if attempt > cutoff]
        self.login_attempts[identifier] = attempts
        
        return len(attempts) >= max_attempts
    
    def _record_login_attempt(self, identifier: str):
        """Record a login attempt"""
        self.login_attempts[identifier].append(datetime.now(UTC))
    
    def _log_access_attempt(self, user_id: Optional[str], ip_address: str, endpoint: str, 
                           method: str, success: bool, failure_reason: Optional[str] = None,
                           user_agent: Optional[str] = None):
        """Log access attempt"""
        attempt = AccessAttempt(
            timestamp=datetime.now(UTC),
            user_id=user_id,
            ip_address=ip_address,
            endpoint=endpoint,
            method=method,
            success=success,
            failure_reason=failure_reason,
            user_agent=user_agent
        )
        self.access_attempts.append(attempt)
    
    def create_user(self, username: str, email: str, password: str, 
                   roles: Optional[Set[Role]] = None) -> str:
        """Create a new user"""
        with self._lock:
            # Check if username already exists
            for user in self.users.values():
                if user.username == username:
                    raise ValueError("Username already exists")
                if user.email == email:
                    raise ValueError("Email already exists")
            
            user_id = f"user-{secrets.token_hex(8)}"
            password_hash = self._hash_password(password)
            
            user = User(
                user_id=user_id,
                username=username,
                email=email,
                password_hash=password_hash,
                roles=roles or {Role.GUEST}
            )
            
            self.users[user_id] = user
            logger.info(f"User created: {username} ({user_id})")
            return user_id
    
    def authenticate(self, username: str, password: str, ip_address: str, 
                    user_agent: str) -> Optional[Dict[str, Any]]:
        """Authenticate user and create session"""
        with self._lock:
            # Check rate limiting
            if self._is_rate_limited(ip_address, self.max_login_attempts, self.login_lockout_duration):
                self._log_access_attempt(None, ip_address, "/auth/login", "POST", False, "Rate limited")
                raise ValueError("Too many login attempts. Please try again later.")
            
            # Find user
            user = None
            for u in self.users.values():
                if u.username == username:
                    user = u
                    break
            
            if not user:
                self._record_login_attempt(ip_address)
                self._log_access_attempt(None, ip_address, "/auth/login", "POST", False, "User not found")
                raise ValueError("Invalid credentials")
            
            # Check if user is active and not locked
            if not user.is_active:
                self._log_access_attempt(user.user_id, ip_address, "/auth/login", "POST", False, "User inactive")
                raise ValueError("Account is inactive")
            
            if user.is_locked:
                self._log_access_attempt(user.user_id, ip_address, "/auth/login", "POST", False, "User locked")
                raise ValueError("Account is locked")
            
            # Verify password
            if not self._verify_password(password, user.password_hash):
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= self.max_login_attempts:
                    user.is_locked = True
                    logger.warning(f"User {username} locked due to failed login attempts")
                
                self._record_login_attempt(ip_address)
                self._log_access_attempt(user.user_id, ip_address, "/auth/login", "POST", False, "Invalid password")
                raise ValueError("Invalid credentials")
            
            # Reset failed attempts on successful login
            user.failed_login_attempts = 0
            user.last_login = datetime.now(UTC)
            
            # Create session
            session_id = f"session-{secrets.token_hex(16)}"
            token = self._generate_token(user.user_id, session_id)
            
            session = Session(
                session_id=session_id,
                user_id=user.user_id,
                token=token,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=self.session_timeout_hours),
                last_activity=datetime.now(UTC),
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            self.sessions[session_id] = session
            
            self._log_access_attempt(user.user_id, ip_address, "/auth/login", "POST", True)
            logger.info(f"User {username} authenticated successfully")
            
            return {
                "token": token,
                "session_id": session_id,
                "user_id": user.user_id,
                "username": user.username,
                "roles": [role.value for role in user.roles],
                "permissions": [perm.value for perm in user.get_all_permissions()],
                "expires_at": session.expires_at.isoformat()
            }
    
    def validate_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Validate token and return user info"""
        with self._lock:
            payload = self._verify_token(token)
            if not payload:
                return None
            
            session_id = payload.get('session_id')
            user_id = payload.get('user_id')
            
            if not session_id or not user_id:
                return None
            
            session = self.sessions.get(session_id)
            if not session or not session.is_valid():
                return None
            
            user = self.users.get(user_id)
            if not user or not user.is_active:
                return None
            
            # Update last activity
            session.last_activity = datetime.now(UTC)
            
            return {
                "user_id": user.user_id,
                "username": user.username,
                "roles": [role.value for role in user.roles],
                "permissions": [perm.value for perm in user.get_all_permissions()],
                "session_id": session_id
            }
    
    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has specific permission"""
        with self._lock:
            user = self.users.get(user_id)
            if not user or not user.is_active:
                return False
            return user.has_permission(permission)
    
    def logout(self, session_id: str):
        """Logout user by revoking session"""
        with self._lock:
            session = self.sessions.get(session_id)
            if session:
                session.status = SessionStatus.REVOKED
                logger.info(f"Session {session_id} revoked")
    
    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        with self._lock:
            now = datetime.now(UTC)
            expired_sessions = []
            
            for session_id, session in self.sessions.items():
                if session.is_expired():
                    session.status = SessionStatus.EXPIRED
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                del self.sessions[session_id]
            
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        with self._lock:
            sessions = []
            for session in self.sessions.values():
                if session.user_id == user_id and session.is_valid():
                    sessions.append({
                        "session_id": session.session_id,
                        "created_at": session.created_at.isoformat(),
                        "last_activity": session.last_activity.isoformat(),
                        "ip_address": session.ip_address,
                        "user_agent": session.user_agent
                    })
            return sessions
    
    def get_access_logs(self, limit: int = 100, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get access logs"""
        with self._lock:
            logs = list(self.access_attempts)
            
            if user_id:
                logs = [log for log in logs if log.user_id == user_id]
            
            # Sort by timestamp (newest first) and limit
            logs.sort(key=lambda x: x.timestamp, reverse=True)
            logs = logs[:limit]
            
            return [{
                "timestamp": log.timestamp.isoformat(),
                "user_id": log.user_id,
                "ip_address": log.ip_address,
                "endpoint": log.endpoint,
                "method": log.method,
                "success": log.success,
                "failure_reason": log.failure_reason,
                "user_agent": log.user_agent
            } for log in logs]
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        with self._lock:
            now = datetime.now(UTC)
            last_24h = now - timedelta(hours=24)
            
            # Count attempts in last 24h
            recent_attempts = [a for a in self.access_attempts if a.timestamp > last_24h]
            successful_logins = [a for a in recent_attempts if a.success and a.endpoint == "/auth/login"]
            failed_logins = [a for a in recent_attempts if not a.success and a.endpoint == "/auth/login"]
            
            return {
                "total_users": len(self.users),
                "active_sessions": len([s for s in self.sessions.values() if s.is_valid()]),
                "locked_users": len([u for u in self.users.values() if u.is_locked]),
                "inactive_users": len([u for u in self.users.values() if not u.is_active]),
                "successful_logins_24h": len(successful_logins),
                "failed_logins_24h": len(failed_logins),
                "total_access_attempts_24h": len(recent_attempts),
                "unique_ips_24h": len(set(a.ip_address for a in recent_attempts)),
                "timestamp": now.isoformat()
            }

# Global access control instance
access_control = AccessControlSystem(
    jwt_secret=secrets.token_hex(32),  # In production, use environment variable
    session_timeout_hours=24
)