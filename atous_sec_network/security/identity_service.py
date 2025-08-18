"""Identity management service for users and agents.

This service provides comprehensive identity management including:
- User/agent registration and authentication
- Role-based access control (RBAC)
- Identity lifecycle management
- Multi-factor authentication support
- Audit logging for compliance
"""

from __future__ import annotations

import os
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, UTC
from typing import Dict, List, Optional, Tuple, Union
from contextlib import contextmanager
from enum import Enum
import jwt

from ..core.logging_config import get_logger

logger = get_logger('security.identity_service')


class IdentityType(Enum):
    """Types of identities supported by the system."""
    USER = "user"
    AGENT = "agent"
    SERVICE = "service"
    DEVICE = "device"


class IdentityStatus(Enum):
    """Status of an identity."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    DELETED = "deleted"


class Role(Enum):
    """System roles for access control."""
    ADMIN = "admin"
    OPERATOR = "operator"
    USER = "user"
    AGENT = "agent"
    READONLY = "readonly"


class IdentityService:
    """Comprehensive identity management service."""
    
    def __init__(self, db_path: str = "identity_database.db"):
        self.db_path = db_path
        self.jwt_secret = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
        self.jwt_algorithm = "HS256"
        self.jwt_expiry_hours = int(os.getenv("JWT_EXPIRY_HOURS", "24"))
        
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """Initialize SQLite database for identity management."""
        try:
            with self._get_db_connection() as conn:
                # Users table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE,
                        password_hash TEXT NOT NULL,
                        salt TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'user',
                        status TEXT NOT NULL DEFAULT 'active',
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_login TEXT,
                        mfa_enabled BOOLEAN DEFAULT FALSE,
                        mfa_secret TEXT
                    )
                """)
                
                # Agents table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS agents (
                        id INTEGER PRIMARY KEY,
                        agent_id TEXT UNIQUE NOT NULL,
                        name TEXT NOT NULL,
                        type TEXT NOT NULL DEFAULT 'agent',
                        status TEXT NOT NULL DEFAULT 'active',
                        public_key TEXT,
                        certificate_serial INTEGER,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        last_heartbeat TEXT,
                        metadata TEXT
                    )
                """)
                
                # Sessions table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER NOT NULL,
                        session_token TEXT UNIQUE NOT NULL,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        expires_at TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                
                # Audit log table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        resource TEXT,
                        details TEXT,
                        ip_address TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                
                # Create indexes
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_log(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
                
                conn.commit()
                logger.info("Identity database initialized")
        except Exception as e:
            logger.error(f"Failed to initialize identity database: {e}")
            raise
    
    @contextmanager
    def _get_db_connection(self):
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
        finally:
            conn.close()
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash a password with salt."""
        if salt is None:
            salt = secrets.token_hex(16)
        
        # Use PBKDF2-like approach with multiple iterations
        hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return hash_obj.hex(), salt
    
    def _verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify a password against its hash."""
        try:
            computed_hash, _ = self._hash_password(password, salt)
            return secrets.compare_digest(computed_hash, password_hash)
        except Exception:
            return False
    
    def create_user(self, username: str, password: str, email: Optional[str] = None, 
                   role: str = "user") -> Dict:
        """Create a new user account."""
        try:
            # Validate input
            if not username or len(username) < 3:
                raise ValueError("Username must be at least 3 characters")
            if not password or len(password) < 8:
                raise ValueError("Password must be at least 8 characters")
            if role not in [r.value for r in Role]:
                raise ValueError(f"Invalid role: {role}")
            
            # Hash password
            password_hash, salt = self._hash_password(password)
            
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO users (username, email, password_hash, salt, role)
                    VALUES (?, ?, ?, ?, ?)
                """, (username, email, password_hash, salt, role))
                
                user_id = cursor.lastrowid
                conn.commit()
                
                # Log the action
                self._log_audit_event(user_id, "user_created", "users", f"Created user {username}")
                
                logger.info(f"Created user: {username} with role: {role}")
                return {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "role": role,
                    "status": "active"
                }
        except Exception as e:
            logger.error(f"Failed to create user {username}: {e}")
            raise
    
    def authenticate_user(self, username: str, password: str, ip_address: Optional[str] = None) -> Optional[Dict]:
        """Authenticate a user and return session info."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    SELECT id, username, password_hash, salt, role, status, mfa_enabled
                    FROM users WHERE username = ?
                """, (username,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                user_id, username, password_hash, salt, role, status, mfa_enabled = row
                
                # Check status
                if status != "active":
                    logger.warning(f"Login attempt for inactive user: {username}")
                    return None
                
                # Verify password
                if not self._verify_password(password, password_hash, salt):
                    logger.warning(f"Failed login attempt for user: {username}")
                    return None
                
                # Update last login
                conn.execute("""
                    UPDATE users SET last_login = ? WHERE id = ?
                """, (datetime.now(UTC).isoformat(), user_id))
                
                # Create session
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now(UTC) + timedelta(hours=self.jwt_expiry_hours)
                
                conn.execute("""
                    INSERT INTO sessions (user_id, session_token, expires_at, ip_address)
                    VALUES (?, ?, ?, ?)
                """, (user_id, session_token, expires_at.isoformat(), ip_address))
                
                conn.commit()
                
                # Log successful login
                self._log_audit_event(user_id, "user_login", "auth", f"User {username} logged in")
                
                logger.info(f"User {username} authenticated successfully")
                return {
                    "user_id": user_id,
                    "username": username,
                    "role": role,
                    "session_token": session_token,
                    "expires_at": expires_at.isoformat(),
                    "mfa_enabled": mfa_enabled
                }
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            return None
    
    def validate_session(self, session_token: str) -> Optional[Dict]:
        """Validate a session token and return user info."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    SELECT s.user_id, s.expires_at, u.username, u.role, u.status
                    FROM sessions s
                    JOIN users u ON s.user_id = u.id
                    WHERE s.session_token = ?
                """, (session_token,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                user_id, expires_at, username, role, status = row
                
                # Check if session expired
                if datetime.fromisoformat(expires_at) < datetime.now(UTC):
                    # Clean up expired session
                    conn.execute("DELETE FROM sessions WHERE session_token = ?", (session_token,))
                    conn.commit()
                    return None
                
                # Check user status
                if status != "active":
                    return None
                
                return {
                    "user_id": user_id,
                    "username": username,
                    "role": role
                }
        except Exception as e:
            logger.error(f"Session validation error: {e}")
            return None
    
    def create_agent(self, agent_id: str, name: str, agent_type: str = "agent", 
                    public_key: Optional[str] = None, metadata: Optional[Dict] = None) -> Dict:
        """Create a new agent identity."""
        try:
            # Validate input
            if not agent_id or len(agent_id) < 3:
                raise ValueError("Agent ID must be at least 3 characters")
            if not name:
                raise ValueError("Agent name is required")
            
            metadata_json = None
            if metadata:
                import json
                metadata_json = json.dumps(metadata)
            
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    INSERT INTO agents (agent_id, name, type, public_key, metadata)
                    VALUES (?, ?, ?, ?, ?)
                """, (agent_id, name, agent_type, public_key, metadata_json))
                
                agent_db_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"Created agent: {agent_id} ({name})")
                return {
                    "id": agent_db_id,
                    "agent_id": agent_id,
                    "name": name,
                    "type": agent_type,
                    "status": "active",
                    "public_key": public_key,
                    "metadata": metadata
                }
        except Exception as e:
            logger.error(f"Failed to create agent {agent_id}: {e}")
            raise
    
    def update_agent_heartbeat(self, agent_id: str, metadata: Optional[Dict] = None) -> bool:
        """Update agent heartbeat and metadata."""
        try:
            metadata_json = None
            if metadata:
                import json
                metadata_json = json.dumps(metadata)
            
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    UPDATE agents 
                    SET last_heartbeat = ?, metadata = ?
                    WHERE agent_id = ? AND status = 'active'
                """, (datetime.now(UTC).isoformat(), metadata_json, agent_id))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to update agent heartbeat {agent_id}: {e}")
            return False
    
    def get_agent_info(self, agent_id: str) -> Optional[Dict]:
        """Get agent information."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM agents WHERE agent_id = ?
                """, (agent_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                columns = [desc[0] for desc in cursor.description]
                agent_data = dict(zip(columns, row))
                
                # Parse metadata JSON
                if agent_data.get("metadata"):
                    import json
                    try:
                        agent_data["metadata"] = json.loads(agent_data["metadata"])
                    except json.JSONDecodeError:
                        agent_data["metadata"] = None
                
                return agent_data
        except Exception as e:
            logger.error(f"Failed to get agent info {agent_id}: {e}")
            return None
    
    def list_agents(self, status: Optional[str] = None, limit: int = 100) -> List[Dict]:
        """List agents with optional filtering."""
        try:
            with self._get_db_connection() as conn:
                query = "SELECT * FROM agents"
                params = []
                
                if status:
                    query += " WHERE status = ?"
                    params.append(status)
                
                query += " ORDER BY created_at DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                
                agents = []
                for row in cursor.fetchall():
                    agent_data = dict(zip(columns, row))
                    
                    # Parse metadata JSON
                    if agent_data.get("metadata"):
                        import json
                        try:
                            agent_data["metadata"] = json.loads(agent_data["metadata"])
                        except json.JSONDecodeError:
                            agent_data["metadata"] = None
                    
                    agents.append(agent_data)
                
                return agents
        except Exception as e:
            logger.error(f"Failed to list agents: {e}")
            return []
    
    def update_user_role(self, user_id: int, new_role: str, admin_user_id: int) -> bool:
        """Update a user's role (admin only)."""
        try:
            if new_role not in [r.value for r in Role]:
                raise ValueError(f"Invalid role: {new_role}")
            
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    UPDATE users SET role = ? WHERE id = ?
                """, (new_role, user_id))
                
                if cursor.rowcount > 0:
                    conn.commit()
                    
                    # Log the action
                    self._log_audit_event(admin_user_id, "role_updated", "users", 
                                        f"Updated user {user_id} role to {new_role}")
                    
                    logger.info(f"Updated user {user_id} role to {new_role}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to update user role {user_id}: {e}")
            return False
    
    def suspend_user(self, user_id: int, reason: str, admin_user_id: int) -> bool:
        """Suspend a user account (admin only)."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    UPDATE users SET status = 'suspended' WHERE id = ?
                """, (user_id,))
                
                if cursor.rowcount > 0:
                    # Invalidate all sessions
                    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
                    conn.commit()
                    
                    # Log the action
                    self._log_audit_event(admin_user_id, "user_suspended", "users", 
                                        f"Suspended user {user_id}: {reason}")
                    
                    logger.info(f"Suspended user {user_id}: {reason}")
                    return True
                return False
        except Exception as e:
            logger.error(f"Failed to suspend user {user_id}: {e}")
            return False
    
    def _log_audit_event(self, user_id: Optional[int], action: str, resource: str, 
                         details: str, ip_address: Optional[str] = None) -> None:
        """Log an audit event."""
        try:
            with self._get_db_connection() as conn:
                conn.execute("""
                    INSERT INTO audit_log (user_id, action, resource, details, ip_address)
                    VALUES (?, ?, ?, ?, ?)
                """, (user_id, action, resource, details, ip_address))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to log audit event: {e}")
    
    def get_audit_log(self, user_id: Optional[int] = None, action: Optional[str] = None,
                       limit: int = 100) -> List[Dict]:
        """Get audit log entries."""
        try:
            with self._get_db_connection() as conn:
                query = "SELECT * FROM audit_log"
                params = []
                
                if user_id or action:
                    query += " WHERE"
                    if user_id:
                        query += " user_id = ?"
                        params.append(user_id)
                    if action:
                        if user_id:
                            query += " AND"
                        query += " action = ?"
                        params.append(action)
                
                query += " ORDER BY timestamp DESC LIMIT ?"
                params.append(limit)
                
                cursor = conn.execute(query, params)
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to get audit log: {e}")
            return []
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions and return count of cleaned sessions."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    DELETE FROM sessions WHERE expires_at < ?
                """, (datetime.now(UTC).isoformat(),))
                
                cleaned_count = cursor.rowcount
                conn.commit()
                
                if cleaned_count > 0:
                    logger.info(f"Cleaned up {cleaned_count} expired sessions")
                
                return cleaned_count
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    def get_system_stats(self) -> Dict:
        """Get system statistics."""
        try:
            with self._get_db_connection() as conn:
                # User counts
                cursor = conn.execute("SELECT status, COUNT(*) FROM users GROUP BY status")
                user_status_counts = dict(cursor.fetchall())
                
                # Agent counts
                cursor = conn.execute("SELECT status, COUNT(*) FROM agents GROUP BY status")
                agent_status_counts = dict(cursor.fetchall())
                
                # Active sessions
                cursor = conn.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?")
                active_sessions = cursor.fetchone()[0]
                
                # Recent audit events
                cursor = conn.execute("""
                    SELECT action, COUNT(*) FROM audit_log 
                    WHERE timestamp > ? GROUP BY action
                """, ((datetime.now(UTC) - timedelta(hours=24)).isoformat(),))
                recent_actions = dict(cursor.fetchall())
                
                return {
                    "users": {
                        "total": sum(user_status_counts.values()),
                        "by_status": user_status_counts
                    },
                    "agents": {
                        "total": sum(agent_status_counts.values()),
                        "by_status": agent_status_counts
                    },
                    "sessions": {
                        "active": active_sessions
                    },
                    "audit": {
                        "recent_actions": recent_actions
                    },
                    "timestamp": datetime.now(UTC).isoformat()
                }
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return {"error": str(e)}

    def get_user_info(self, user_id: int) -> Optional[Dict]:
        """Get user information by ID."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM users WHERE id = ?
                """, (user_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, row))
        except Exception as e:
            logger.error(f"Failed to get user info {user_id}: {e}")
            return None
    
    def list_users(self, limit: int = 100) -> List[Dict]:
        """List users with optional filtering."""
        try:
            with self._get_db_connection() as conn:
                cursor = conn.execute("""
                    SELECT * FROM users ORDER BY created_at DESC LIMIT ?
                """, (limit,))
                
                columns = [desc[0] for desc in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Failed to list users: {e}")
            return []
