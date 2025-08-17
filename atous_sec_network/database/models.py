"""
Database Models for ATous Secure Network

This module defines the SQLAlchemy models for:
- User management
- Role-based access control
- Session management
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, ForeignKey, Table
from sqlalchemy.orm import DeclarativeBase, relationship
from sqlalchemy.sql import func
from datetime import datetime, timedelta, timezone
import uuid

class Base(DeclarativeBase):
    pass

# Association table for many-to-many relationship between users and roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id'), primary_key=True),
    Column('role_id', Integer, ForeignKey('roles.id'), primary_key=True)
)


class User(Base):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(120), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(50), nullable=True)
    last_name = Column(String(50), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    
    # Relationships
    roles = relationship('Role', secondary=user_roles, back_populates='users')
    sessions = relationship('Session', back_populates='user', cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<User {self.username}>'
    
    @property
    def full_name(self):
        """Get user's full name"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.username
    
    def is_locked(self):
        """Check if user account is locked"""
        if self.locked_until:
            # Ensure both datetimes are timezone-aware for comparison
            current_time = datetime.now(timezone.utc)
            if self.locked_until.tzinfo is None:
                # If locked_until is naive, assume it's UTC
                locked_until_utc = self.locked_until.replace(tzinfo=timezone.utc)
            else:
                locked_until_utc = self.locked_until
            return current_time < locked_until_utc
        return False
    
    def increment_failed_login(self):
        """Increment failed login attempts and lock if necessary"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:
            # Lock account for 30 minutes
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=30)
    
    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        self.locked_until = None


class Role(Base):
    """Role model for role-based access control"""
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=True)
    permissions = Column(Text, nullable=True)  # JSON string of permissions
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now(), nullable=False)
    
    # Relationships
    users = relationship('User', secondary=user_roles, back_populates='roles')
    
    def __repr__(self):
        return f'<Role {self.name}>'
    
    
    def has_permission(self, permission):
        """Check if role has specific permission"""
        if not self.permissions:
            return False
        try:
            import json
            permissions = json.loads(self.permissions)
            return permission in permissions
        except (json.JSONDecodeError, TypeError):
            return False


class UserRole(Base):
    """User-Role association model for additional metadata"""
    __tablename__ = 'user_roles_metadata'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'), nullable=False)
    assigned_at = Column(DateTime, default=func.now(), nullable=False)
    assigned_by = Column(Integer, ForeignKey('users.id'), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    
    def __repr__(self):
        return f'<UserRole {self.user_id}:{self.role_id}>'


class Session(Base):
    """Session model for managing user sessions"""
    __tablename__ = 'sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String(255), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=func.now(), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    user = relationship('User', back_populates='sessions')
    
    def __repr__(self):
        return f'<Session {self.session_id}>'
    
    @classmethod
    def generate_session_id(cls):
        """Generate a unique session ID"""
        return str(uuid.uuid4())
    
    def is_expired(self):
        """Check if session is expired"""
        # Ensure both datetimes are timezone-aware for comparison
        current_time = datetime.now(timezone.utc)
        if self.expires_at.tzinfo is None:
            # If expires_at is naive, assume it's UTC
            expires_at_utc = self.expires_at.replace(tzinfo=timezone.utc)
        else:
            expires_at_utc = self.expires_at
        return current_time > expires_at_utc
    
    def refresh_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now(timezone.utc)
    
    def extend_session(self, duration_minutes=30):
        """Extend session expiration"""
        self.expires_at = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)


class AuditLog(Base):
    """Audit log model for tracking security events"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    event_type = Column(String(100), nullable=False, index=True)
    event_description = Column(Text, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=func.now(), nullable=False)
    event_metadata = Column(Text, nullable=True)  # JSON string of additional data
    
    def __repr__(self):
        return f'<AuditLog {self.event_type}:{self.timestamp}>'
