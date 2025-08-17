"""
Security Policy Implementation for ATous Secure Network

This module implements comprehensive security policies including:
- Password policies (complexity, history, expiration)
- Session management policies (timeout, limits, monitoring)
- Account lockout mechanisms
- Security policy enforcement
"""

from typing import Dict, List, Optional, Set, Any, Union
from datetime import datetime, timedelta, UTC
from enum import Enum
import re
import hashlib
import logging
from dataclasses import dataclass, field
from collections import defaultdict, deque
import threading
import time

logger = logging.getLogger(__name__)


class PasswordComplexity(Enum):
    """Password complexity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AccountStatus(Enum):
    """Account status enumeration"""
    ACTIVE = "active"
    LOCKED = "locked"
    SUSPENDED = "suspended"
    EXPIRED = "expired"
    PENDING_VERIFICATION = "pending_verification"


@dataclass
class PasswordPolicy:
    """Password policy configuration"""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    min_special_chars: int = 1
    max_consecutive_chars: int = 3
    max_repeated_chars: int = 2
    complexity_level: PasswordComplexity = PasswordComplexity.MEDIUM
    history_size: int = 5  # Number of previous passwords to remember
    expiration_days: Optional[int] = 90  # Password expiration in days
    lockout_threshold: int = 5  # Failed attempts before lockout
    lockout_duration_minutes: int = 30  # Lockout duration
    progressive_lockout: bool = True  # Increase lockout duration with each violation


@dataclass
class SessionPolicy:
    """Session management policy configuration"""
    max_sessions_per_user: int = 5  # Maximum concurrent sessions
    session_timeout_minutes: int = 60  # Session timeout
    idle_timeout_minutes: int = 30  # Idle timeout
    absolute_timeout_hours: int = 24  # Maximum session duration
    require_reauthentication: bool = True  # Require re-auth for sensitive operations
    session_rotation: bool = True  # Rotate session IDs periodically
    concurrent_ip_limit: int = 3  # Maximum sessions from same IP


@dataclass
class SecurityPolicy:
    """Overall security policy configuration"""
    password_policy: PasswordPolicy = field(default_factory=PasswordPolicy)
    session_policy: SessionPolicy = field(default_factory=SessionPolicy)
    enable_audit_logging: bool = True
    enable_rate_limiting: bool = True
    enable_geolocation_tracking: bool = False
    require_mfa_for_admin: bool = True
    require_mfa_for_sensitive_ops: bool = True
    max_login_attempts_per_hour: int = 10
    suspicious_activity_threshold: int = 3


class PasswordValidator:
    """Password validation and policy enforcement"""
    
    def __init__(self, policy: PasswordPolicy):
        self.policy = policy
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for password validation"""
        self.uppercase_pattern = re.compile(r'[A-Z]')
        self.lowercase_pattern = re.compile(r'[a-z]')
        self.digit_pattern = re.compile(r'\d')
        self.special_pattern = re.compile(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>/?]')
    
    def validate_password(self, password: str, username: str = None, 
                         email: str = None, previous_passwords: List[str] = None) -> tuple[bool, List[str]]:
        """
        Validate password against policy
        
        Args:
            password: Password to validate
            username: Username (for similarity check)
            email: Email (for similarity check)
            previous_passwords: List of previous passwords to check against
            
        Returns:
            Tuple of (is_valid, list_of_violations)
        """
        violations = []
        
        # Length validation
        if len(password) < self.policy.min_length:
            violations.append(f"Password must be at least {self.policy.min_length} characters long")
        
        if len(password) > self.policy.max_length:
            violations.append(f"Password must be no more than {self.policy.max_length} characters long")
        
        # Character type validation
        if self.policy.require_uppercase and not self.uppercase_pattern.search(password):
            violations.append("Password must contain at least one uppercase letter")
        
        if self.policy.require_lowercase and not self.lowercase_pattern.search(password):
            violations.append("Password must contain at least one lowercase letter")
        
        if self.policy.require_digits and not self.digit_pattern.search(password):
            violations.append("Password must contain at least one digit")
        
        if self.policy.require_special_chars:
            special_chars = self.special_pattern.findall(password)
            if len(special_chars) < self.policy.min_special_chars:
                violations.append(f"Password must contain at least {self.policy.min_special_chars} special characters")
        
        # Consecutive character validation
        if self.policy.max_consecutive_chars > 0:
            for i in range(len(password) - self.policy.max_consecutive_chars):
                if len(set(password[i:i + self.policy.max_consecutive_chars + 1])) == 1:
                    violations.append(f"Password cannot contain more than {self.policy.max_consecutive_chars} consecutive identical characters")
                    break
        
        # Repeated character validation
        if self.policy.max_repeated_chars > 0:
            char_counts = defaultdict(int)
            for char in password:
                char_counts[char] += 1
                if char_counts[char] > self.policy.max_repeated_chars:
                    violations.append(f"Password cannot contain character '{char}' more than {self.policy.max_repeated_chars} times")
                    break
        
        # Similarity checks - only if username is provided
        if username and self._is_similar_to_username(password, username):
            violations.append("Password cannot be similar to username")
        
        if email and self._is_similar_to_email(password, email):
            violations.append("Password cannot be similar to email")
        
        # Previous password check - only if previous passwords are provided
        if previous_passwords and password in previous_passwords:
            violations.append("Password cannot be the same as previous passwords")
        
        # Complexity level validation - only check if policy requires it
        if self.policy.complexity_level != PasswordComplexity.LOW:
            if not self._meets_complexity_level(password):
                violations.append(f"Password does not meet {self.policy.complexity_level.value} complexity requirements")
        
        return len(violations) == 0, violations
    
    def _is_similar_to_username(self, password: str, username: str) -> bool:
        """Check if password is too similar to username"""
        username_lower = username.lower()
        password_lower = password.lower()
        
        # Check for exact match
        if username_lower in password_lower or password_lower in username_lower:
            return True
        
        # Check for common variations
        variations = [
            username_lower + "123",
            username_lower + "!",
            username_lower + "2024",
            "123" + username_lower,
            "!" + username_lower
        ]
        
        return password_lower in variations
    
    def _is_similar_to_email(self, password: str, email: str) -> bool:
        """Check if password is too similar to email"""
        email_local = email.split('@')[0].lower()
        password_lower = password.lower()
        
        return email_local in password_lower or password_lower in email_local
    
    def _meets_complexity_level(self, password: str) -> bool:
        """Check if password meets complexity level requirements"""
        if self.policy.complexity_level == PasswordComplexity.LOW:
            return len(password) >= 6
        
        elif self.policy.complexity_level == PasswordComplexity.MEDIUM:
            return (
                len(password) >= 8 and
                bool(self.uppercase_pattern.search(password)) and
                bool(self.lowercase_pattern.search(password)) and
                bool(self.digit_pattern.search(password))
                # Note: MEDIUM complexity doesn't require special characters by default
            )
        
        elif self.policy.complexity_level == PasswordComplexity.HIGH:
            return (
                len(password) >= 10 and
                bool(self.uppercase_pattern.search(password)) and
                bool(self.lowercase_pattern.search(password)) and
                bool(self.digit_pattern.search(password)) and
                bool(self.special_pattern.search(password))
            )
        
        elif self.policy.complexity_level == PasswordComplexity.CRITICAL:
            return (
                len(password) >= 12 and
                bool(self.uppercase_pattern.search(password)) and
                bool(self.lowercase_pattern.search(password)) and
                bool(self.digit_pattern.search(password)) and
                bool(self.special_pattern.search(password)) and
                len(set(password)) >= len(password) * 0.8  # 80% unique characters
            )
        
        return False
    
    def calculate_password_strength(self, password: str) -> float:
        """Calculate password strength score (0.0 to 1.0)"""
        score = 0.0
        
        # Length score (0-25 points)
        length_score = min(len(password) / 20.0, 1.0) * 25
        score += length_score
        
        # Character variety score (0-25 points)
        char_types = 0
        if self.uppercase_pattern.search(password):
            char_types += 1
        if self.lowercase_pattern.search(password):
            char_types += 1
        if self.digit_pattern.search(password):
            char_types += 1
        if self.special_pattern.search(password):
            char_types += 1
        
        variety_score = (char_types / 4.0) * 25
        score += variety_score
        
        # Entropy score (0-25 points)
        unique_chars = len(set(password))
        entropy_score = min(unique_chars / 20.0, 1.0) * 25
        score += entropy_score
        
        # Pattern avoidance score (0-25 points)
        pattern_score = 25
        if self._has_common_patterns(password):
            pattern_score -= 10
        if self._has_keyboard_patterns(password):
            pattern_score -= 10
        if self._has_sequential_patterns(password):
            pattern_score -= 5
        
        score += max(0, pattern_score)
        
        # Ensure minimum score for passwords that meet basic requirements
        if len(password) >= 8 and char_types >= 3:
            score = max(score, 60.0)  # Minimum 0.6 for basic strong passwords
        
        return min(score / 100.0, 1.0)
    
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common password patterns"""
        common_patterns = [
            "password", "123456", "qwerty", "admin", "letmein",
            "welcome", "monkey", "dragon", "master", "football"
        ]
        
        password_lower = password.lower()
        return any(pattern in password_lower for pattern in common_patterns)
    
    def _has_keyboard_patterns(self, password: str) -> bool:
        """Check for keyboard patterns"""
        keyboard_rows = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm",
            "1234567890"
        ]
        
        password_lower = password.lower()
        for row in keyboard_rows:
            for i in range(len(row) - 2):
                pattern = row[i:i+3]
                if pattern in password_lower:
                    return True
        
        return False
    
    def _has_sequential_patterns(self, password: str) -> bool:
        """Check for sequential patterns"""
        sequences = [
            "abcdefghijklmnopqrstuvwxyz",
            "zyxwvutsrqponmlkjihgfedcba",
            "0123456789",
            "9876543210"
        ]
        
        password_lower = password.lower()
        for seq in sequences:
            for i in range(len(seq) - 2):
                pattern = seq[i:i+3]
                if pattern in password_lower:
                    return True
        
        return False


class SessionManager:
    """Session management and policy enforcement"""
    
    def __init__(self, policy: SessionPolicy):
        self.policy = policy
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.session_history: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.ip_session_counts: Dict[str, int] = defaultdict(int)
        self.lock = threading.RLock()
    
    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> Optional[str]:
        """
        Create a new session for user
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Session ID if created successfully, None otherwise
        """
        with self.lock:
            # Check session limits
            if not self._can_create_session(user_id, ip_address):
                return None
            
            # Generate session ID
            session_id = self._generate_session_id()
            
            # Create session
            session = {
                "session_id": session_id,
                "user_id": user_id,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": datetime.now(UTC),
                "last_activity": datetime.now(UTC),
                "expires_at": datetime.now(UTC) + timedelta(minutes=self.policy.session_timeout_minutes),
                "absolute_expires_at": datetime.now(UTC) + timedelta(hours=self.policy.absolute_timeout_hours),
                "is_active": True
            }
            
            # Store session
            self.active_sessions[session_id] = session
            self.session_history[user_id].append(session.copy())
            
            # Update IP session count
            self.ip_session_counts[ip_address] += 1
            
            # Clean up old sessions if needed
            self._cleanup_old_sessions(user_id)
            
            logger.info(f"Session created for user {user_id}: {session_id}")
            return session_id
    
    def _can_create_session(self, user_id: str, ip_address: str) -> bool:
        """Check if user can create a new session"""
        # Check user session limit
        user_sessions = [s for s in self.active_sessions.values() if s["user_id"] == user_id and s["is_active"]]
        if len(user_sessions) >= self.policy.max_sessions_per_user:
            logger.warning(f"User {user_id} has reached maximum session limit")
            return False
        
        # Check IP session limit
        if self.ip_session_counts[ip_address] >= self.policy.concurrent_ip_limit:
            logger.warning(f"IP {ip_address} has reached maximum session limit")
            return False
        
        return True
    
    def validate_session(self, session_id: str, ip_address: str = None) -> Optional[Dict[str, Any]]:
        """
        Validate session and return session data if valid
        
        Args:
            session_id: Session ID to validate
            ip_address: Client IP address for validation
            
        Returns:
            Session data if valid, None otherwise
        """
        with self.lock:
            if session_id not in self.active_sessions:
                return None
            
            session = self.active_sessions[session_id]
            
            # Check if session is active
            if not session["is_active"]:
                return None
            
            # Check if session is expired
            if self._is_session_expired(session):
                self._deactivate_session(session_id)
                return None
            
            # Check IP address if provided
            if ip_address and session["ip_address"] != ip_address:
                logger.warning(f"Session {session_id} IP mismatch: expected {session['ip_address']}, got {ip_address}")
                return None
            
            # Check idle timeout
            if self._is_session_idle(session):
                self._deactivate_session(session_id)
                return None
            
            # Update last activity
            session["last_activity"] = datetime.now(UTC)
            
            return session
    
    def _is_session_expired(self, session: Dict[str, Any]) -> bool:
        """Check if session is expired"""
        now = datetime.now(UTC)
        return (
            now >= session["expires_at"] or
            now >= session["absolute_expires_at"]
        )
    
    def _is_session_idle(self, session: Dict[str, Any]) -> bool:
        """Check if session is idle"""
        if self.policy.idle_timeout_minutes <= 0:
            return False
        
        idle_timeout = timedelta(minutes=self.policy.idle_timeout_minutes)
        return datetime.now(UTC) - session["last_activity"] >= idle_timeout
    
    def extend_session(self, session_id: str, duration_minutes: int = None) -> bool:
        """
        Extend session duration
        
        Args:
            session_id: Session ID to extend
            duration_minutes: Extension duration in minutes
            
        Returns:
            True if extended successfully, False otherwise
        """
        with self.lock:
            if session_id not in self.active_sessions:
                return False
            
            session = self.active_sessions[session_id]
            
            if not session["is_active"]:
                return False
            
            # Calculate new expiration
            extension = timedelta(minutes=duration_minutes or self.policy.session_timeout_minutes)
            new_expires_at = datetime.now(UTC) + extension
            
            # Check absolute timeout
            if new_expires_at > session["absolute_expires_at"]:
                new_expires_at = session["absolute_expires_at"]
            
            session["expires_at"] = new_expires_at
            session["last_activity"] = datetime.now(UTC)
            
            logger.info(f"Session {session_id} extended until {new_expires_at}")
            return True
    
    def revoke_session(self, session_id: str) -> bool:
        """
        Revoke a session
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if revoked successfully, False otherwise
        """
        with self.lock:
            if session_id not in self.active_sessions:
                return False
            
            session = self.active_sessions[session_id]
            ip_address = session["ip_address"]
            
            # Deactivate session
            self._deactivate_session(session_id)
            
            # Update IP session count
            self.ip_session_counts[ip_address] = max(0, self.ip_session_counts[ip_address] - 1)
            
            logger.info(f"Session {session_id} revoked")
            return True
    
    def _deactivate_session(self, session_id: str):
        """Deactivate a session"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id]["is_active"] = False
    
    def _cleanup_old_sessions(self, user_id: str):
        """Clean up old sessions for user"""
        if user_id not in self.session_history:
            return
        
        # Keep only recent sessions
        max_history = 10
        if len(self.session_history[user_id]) > max_history:
            self.session_history[user_id] = self.session_history[user_id][-max_history:]
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        import secrets
        return secrets.token_urlsafe(32)
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        with self.lock:
            return [
                session for session in self.active_sessions.values()
                if session["user_id"] == user_id and session["is_active"]
            ]
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up all expired sessions and return count of cleaned sessions"""
        with self.lock:
            expired_sessions = []
            
            for session_id, session in self.active_sessions.items():
                if self._is_session_expired(session) or self._is_session_idle(session):
                    expired_sessions.append(session_id)
            
            # Remove expired sessions
            for session_id in expired_sessions:
                session = self.active_sessions[session_id]
                ip_address = session["ip_address"]
                
                # Remove from active sessions
                del self.active_sessions[session_id]
                
                # Update IP session count
                self.ip_session_counts[ip_address] = max(0, self.ip_session_counts[ip_address] - 1)
            
            if expired_sessions:
                logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
            
            return len(expired_sessions)
    
    def get_session_stats(self) -> Dict[str, Any]:
        """Get session statistics"""
        with self.lock:
            active_count = sum(1 for s in self.active_sessions.values() if s["is_active"])
            total_count = len(self.active_sessions)
            
            return {
                "active_sessions": active_count,
                "total_sessions": total_count,
                "unique_users": len(set(s["user_id"] for s in self.active_sessions.values() if s["is_active"])),
                "unique_ips": len(set(s["ip_address"] for s in self.active_sessions.values() if s["is_active"]))
            }


class AccountLockoutManager:
    """Account lockout and security policy enforcement"""
    
    def __init__(self, policy: PasswordPolicy):
        self.policy = policy
        self.failed_attempts: Dict[str, List[datetime]] = defaultdict(list)
        self.locked_accounts: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.RLock()
    
    def record_failed_attempt(self, user_id: str, ip_address: str) -> bool:
        """
        Record a failed login attempt
        
        Args:
            user_id: User ID
            ip_address: IP address of failed attempt
            
        Returns:
            True if account should be locked, False otherwise
        """
        with self.lock:
            now = datetime.now(UTC)
            
            # Add failed attempt
            self.failed_attempts[user_id].append(now)
            
            # Clean old attempts (older than 1 hour)
            cutoff = now - timedelta(hours=1)
            self.failed_attempts[user_id] = [
                attempt for attempt in self.failed_attempts[user_id]
                if attempt > cutoff
            ]
            
            # Check if lockout threshold reached
            if len(self.failed_attempts[user_id]) >= self.policy.lockout_threshold:
                self._lock_account(user_id, ip_address)
                return True
            
            return False
    
    def record_successful_attempt(self, user_id: str):
        """Record a successful login attempt and reset failed attempts"""
        with self.lock:
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
            
            if user_id in self.locked_accounts:
                del self.locked_accounts[user_id]
    
    def is_account_locked(self, user_id: str) -> bool:
        """Check if account is locked"""
        with self.lock:
            if user_id not in self.locked_accounts:
                return False
            
            lock_info = self.locked_accounts[user_id]
            
            # Check if lockout period has expired
            if datetime.now(UTC) >= lock_info["unlock_time"]:
                del self.locked_accounts[user_id]
                return False
            
            return True
    
    def get_lockout_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get lockout information for user"""
        with self.lock:
            if user_id not in self.locked_accounts:
                return None
            
            lock_info = self.locked_accounts[user_id]
            remaining_time = lock_info["unlock_time"] - datetime.now(UTC)
            
            return {
                "locked_until": lock_info["unlock_time"],
                "remaining_seconds": max(0, int(remaining_time.total_seconds())),
                "reason": lock_info["reason"],
                "failed_attempts": len(self.failed_attempts.get(user_id, [])),
                "duration_minutes": lock_info["duration_minutes"]
            }
    
    def _lock_account(self, user_id: str, ip_address: str):
        """Lock an account"""
        now = datetime.now(UTC)
        
        # Calculate lockout duration
        if self.policy.progressive_lockout:
            # Progressive lockout: increase duration with each violation
            violation_count = len(self.failed_attempts[user_id])
            base_duration = self.policy.lockout_duration_minutes
            progressive_multiplier = min(violation_count - self.policy.lockout_threshold + 1, 5)
            lockout_minutes = base_duration * progressive_multiplier
        else:
            lockout_minutes = self.policy.lockout_duration_minutes
        
        unlock_time = now + timedelta(minutes=lockout_minutes)
        
        self.locked_accounts[user_id] = {
            "locked_at": now,
            "unlock_time": unlock_time,
            "ip_address": ip_address,
            "reason": f"Too many failed login attempts ({len(self.failed_attempts[user_id])})",
            "duration_minutes": lockout_minutes
        }
        
        logger.warning(f"Account {user_id} locked until {unlock_time} due to failed attempts")
    
    def force_unlock_account(self, user_id: str, admin_user_id: str) -> bool:
        """
        Force unlock an account (admin only)
        
        Args:
            user_id: User ID to unlock
            admin_user_id: Admin user ID performing the unlock
            
        Returns:
            True if unlocked successfully, False otherwise
        """
        with self.lock:
            if user_id not in self.locked_accounts:
                return False
            
            # Remove lockout
            del self.locked_accounts[user_id]
            
            # Reset failed attempts
            if user_id in self.failed_attempts:
                del self.failed_attempts[user_id]
            
            logger.info(f"Account {user_id} force unlocked by admin {admin_user_id}")
            return True
    
    def cleanup_expired_lockouts(self) -> int:
        """Clean up expired lockouts and return count of cleaned accounts"""
        with self.lock:
            expired_accounts = []
            
            for user_id, lock_info in self.locked_accounts.items():
                if datetime.now(UTC) >= lock_info["unlock_time"]:
                    expired_accounts.append(user_id)
            
            # Remove expired lockouts
            for user_id in expired_accounts:
                del self.locked_accounts[user_id]
            
            if expired_accounts:
                logger.info(f"Cleaned up {len(expired_accounts)} expired account lockouts")
            
            return len(expired_accounts)
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get security statistics"""
        with self.lock:
            return {
                "locked_accounts": len(self.locked_accounts),
                "accounts_with_failed_attempts": len(self.failed_attempts),
                "total_failed_attempts": sum(len(attempts) for attempts in self.failed_attempts.values()),
                "lockout_policy": {
                    "threshold": self.policy.lockout_threshold,
                    "base_duration_minutes": self.policy.lockout_duration_minutes,
                    "progressive_lockout": self.policy.progressive_lockout
                }
            }


class SecurityPolicyManager:
    """Main security policy manager that coordinates all security components"""
    
    def __init__(self, config: SecurityPolicy = None):
        self.config = config or SecurityPolicy()
        self.password_validator = PasswordValidator(self.config.password_policy)
        self.session_manager = SessionManager(self.config.session_policy)
        self.lockout_manager = AccountLockoutManager(self.config.password_policy)
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def validate_password(self, password: str, username: str = None, 
                         email: str = None, previous_passwords: List[str] = None) -> tuple[bool, List[str]]:
        """Validate password against security policy"""
        return self.password_validator.validate_password(password, username, email, previous_passwords)
    
    def calculate_password_strength(self, password: str) -> float:
        """Calculate password strength score"""
        return self.password_validator.calculate_password_strength(password)
    
    def create_session(self, user_id: str, ip_address: str, user_agent: str) -> Optional[str]:
        """Create a new session for user"""
        return self.session_manager.create_session(user_id, ip_address, user_agent)
    
    def validate_session(self, session_id: str, ip_address: str = None) -> Optional[Dict[str, Any]]:
        """Validate session and return session data if valid"""
        return self.session_manager.validate_session(session_id, ip_address)
    
    def extend_session(self, session_id: str, duration_minutes: int = None) -> bool:
        """Extend session duration"""
        return self.session_manager.extend_session(session_id, duration_minutes)
    
    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session"""
        return self.session_manager.revoke_session(session_id)
    
    def record_failed_login(self, user_id: str, ip_address: str) -> bool:
        """Record a failed login attempt and check if account should be locked"""
        return self.lockout_manager.record_failed_attempt(user_id, ip_address)
    
    def record_successful_login(self, user_id: str):
        """Record a successful login attempt"""
        self.lockout_manager.record_successful_attempt(user_id)
    
    def is_account_locked(self, user_id: str) -> bool:
        """Check if account is locked"""
        return self.lockout_manager.is_account_locked(user_id)
    
    def get_lockout_info(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get lockout information for user"""
        return self.lockout_manager.get_lockout_info(user_id)
    
    def force_unlock_account(self, user_id: str, admin_user_id: str) -> bool:
        """Force unlock an account (admin only)"""
        return self.lockout_manager.force_unlock_account(user_id, admin_user_id)
    
    def get_user_sessions(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all active sessions for a user"""
        return self.session_manager.get_user_sessions(user_id)
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get comprehensive security statistics"""
        stats = {
            "password_policy": {
                "min_length": self.config.password_policy.min_length,
                "complexity_level": self.config.password_policy.complexity_level.value,
                "expiration_days": self.config.password_policy.expiration_days,
                "history_size": self.config.password_policy.history_size
            },
            "session_policy": {
                "max_sessions_per_user": self.config.session_policy.max_sessions_per_user,
                "session_timeout_minutes": self.config.session_policy.session_timeout_minutes,
                "idle_timeout_minutes": self.config.session_policy.idle_timeout_minutes
            },
            "sessions": self.session_manager.get_session_stats(),
            "lockouts": self.lockout_manager.get_security_stats()
        }
        
        return stats
    
    def _start_cleanup_thread(self):
        """Start background cleanup thread"""
        def cleanup_worker():
            while True:
                try:
                    # Clean up expired sessions
                    expired_sessions = self.session_manager.cleanup_expired_sessions()
                    
                    # Clean up expired lockouts
                    expired_lockouts = self.lockout_manager.cleanup_expired_lockouts()
                    
                    # Log cleanup results
                    if expired_sessions > 0 or expired_lockouts > 0:
                        logger.info(f"Cleanup: {expired_sessions} sessions, {expired_lockouts} lockouts")
                    
                    # Sleep for 5 minutes
                    time.sleep(300)
                    
                except Exception as e:
                    logger.error(f"Error in cleanup thread: {e}")
                    time.sleep(60)  # Wait 1 minute on error
        
        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()
        logger.info("Security policy cleanup thread started")


# Default security policy configurations
DEFAULT_SECURITY_POLICY = SecurityPolicy()

# Global security policy manager instance
security_policy_manager = SecurityPolicyManager(DEFAULT_SECURITY_POLICY)
