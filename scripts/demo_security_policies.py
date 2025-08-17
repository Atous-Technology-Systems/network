#!/usr/bin/env python3
"""
Security Policy Implementation Demo

This script demonstrates the comprehensive security policy system including:
- Password validation and complexity requirements
- Session management policies
- Account lockout mechanisms
- Security policy enforcement
"""

import sys
import os
import time
from datetime import datetime, timedelta, UTC

# Add the project root to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from atous_sec_network.security.security_policies import (
    SecurityPolicyManager, PasswordValidator, SessionManager, AccountLockoutManager,
    PasswordPolicy, SessionPolicy, SecurityPolicy, PasswordComplexity
)


def demo_password_policies():
    """Demonstrate password policy validation"""
    print("🔐 Password Policy Demonstration")
    print("=" * 50)
    
    # Create different password policies
    basic_policy = PasswordPolicy(
        min_length=8,
        require_uppercase=True,
        require_lowercase=True,
        require_digits=True,
        require_special_chars=False,
        complexity_level=PasswordComplexity.MEDIUM
    )
    
    strict_policy = PasswordPolicy(
        min_length=12,
        require_uppercase=True,
        require_lowercase=True,
        require_digits=True,
        require_special_chars=True,
        min_special_chars=2,
        max_consecutive_chars=2,
        max_repeated_chars=2,
        complexity_level=PasswordComplexity.HIGH
    )
    
    basic_validator = PasswordValidator(basic_policy)
    strict_validator = PasswordValidator(strict_policy)
    
    # Test basic policy
    print("\n📋 Basic Password Policy (8+ chars, uppercase, lowercase, digits)")
    test_passwords = [
        "SecurePass123",
        "weak",
        "nouppercase123",
        "NOLOWERCASE123",
        "NoDigits"
    ]
    
    for password in test_passwords:
        is_valid, violations = basic_validator.validate_password(password)
        status = "✅" if is_valid else "❌"
        print(f"   {status} '{password}': {'Valid' if is_valid else ', '.join(violations)}")
    
    # Test strict policy
    print("\n🔒 Strict Password Policy (12+ chars, special chars, pattern checks)")
    test_passwords = [
        "VerySecurePass123!@",
        "SecurePass123!@",
        "SecurePass11123!@",  # Too many consecutive chars
        "SecurePassss123!@",  # Too many repeated chars
        "admin123"  # Too similar to username
    ]
    
    for password in test_passwords:
        is_valid, violations = strict_validator.validate_password(password, username="admin")
        status = "✅" if is_valid else "❌"
        print(f"   {status} '{password}': {'Valid' if is_valid else ', '.join(violations)}")
    
    # Test password strength calculation
    print("\n📊 Password Strength Analysis")
    test_passwords = ["123456", "SecurePass123", "VerySecurePass123!@#"]
    
    for password in test_passwords:
        strength = basic_validator.calculate_password_strength(password)
        strength_bar = "█" * int(strength * 20)
        print(f"   '{password}': {strength:.2f} [{strength_bar:<20}]")


def demo_session_management():
    """Demonstrate session management policies"""
    print("\n🔄 Session Management Demonstration")
    print("=" * 50)
    
    # Create session policy
    session_policy = SessionPolicy(
        max_sessions_per_user=3,
        session_timeout_minutes=60,
        idle_timeout_minutes=30,
        absolute_timeout_hours=2,
        concurrent_ip_limit=2
    )
    
    session_manager = SessionManager(session_policy)
    
    # Create multiple sessions
    print("\n📱 Creating user sessions...")
    session1 = session_manager.create_session("user1", "192.168.1.100", "Chrome Browser")
    session2 = session_manager.create_session("user1", "192.168.1.101", "Firefox Browser")
    session3 = session_manager.create_session("user1", "192.168.1.102", "Safari Browser")
    
    print(f"   Session 1: {session1}")
    print(f"   Session 2: {session2}")
    print(f"   Session 3: {session3}")
    
    # Try to create fourth session (should fail due to limit)
    session4 = session_manager.create_session("user1", "192.168.1.103", "Edge Browser")
    if session4 is None:
        print("   ❌ Session 4: Failed (user session limit reached)")
    
    # Test IP-based limits
    print("\n🌐 Testing IP-based session limits...")
    ip_session1 = session_manager.create_session("user2", "192.168.1.100", "Mobile App")
    ip_session2 = session_manager.create_session("user3", "192.168.1.100", "Tablet App")
    ip_session3 = session_manager.create_session("user4", "192.168.1.100", "Desktop App")
    
    print(f"   IP 192.168.1.100 - Session 1: {ip_session1}")
    print(f"   IP 192.168.1.100 - Session 2: {ip_session2}")
    if ip_session3 is None:
        print("   ❌ IP 192.168.1.100 - Session 3: Failed (IP session limit reached)")
    
    # Session validation
    print("\n✅ Testing session validation...")
    valid_session = session_manager.validate_session(session1)
    if valid_session:
        print(f"   Session {session1}: Valid")
    else:
        print(f"   Session {session1}: Invalid")
    
    # Session statistics
    stats = session_manager.get_session_stats()
    print(f"\n📊 Session Statistics:")
    print(f"   Active Sessions: {stats['active_sessions']}")
    print(f"   Total Sessions: {stats['total_sessions']}")
    print(f"   Unique Users: {stats['unique_users']}")
    print(f"   Unique IPs: {stats['unique_ips']}")


def demo_account_lockout():
    """Demonstrate account lockout mechanisms"""
    print("\n🚫 Account Lockout Demonstration")
    print("=" * 50)
    
    # Create lockout policy
    lockout_policy = PasswordPolicy(
        lockout_threshold=3,
        lockout_duration_minutes=5,  # Short duration for demo
        progressive_lockout=True
    )
    
    lockout_manager = AccountLockoutManager(lockout_policy)
    
    # Simulate failed login attempts
    print("\n🔓 Simulating failed login attempts...")
    for attempt in range(1, 4):
        should_lock = lockout_manager.record_failed_attempt("user1", "192.168.1.100")
        print(f"   Failed attempt {attempt}: {'🔒 Account locked!' if should_lock else '⚠️  Warning'}")
    
    # Check account status
    if lockout_manager.is_account_locked("user1"):
        print("   ✅ Account is now locked")
        
        # Get lockout information
        lockout_info = lockout_manager.get_lockout_info("user1")
        if lockout_info:
            print(f"   🔒 Locked until: {lockout_info['locked_until']}")
            print(f"   ⏰ Remaining time: {lockout_info['remaining_seconds']} seconds")
            print(f"   📝 Reason: {lockout_info['reason']}")
            print(f"   🔢 Failed attempts: {lockout_info['failed_attempts']}")
    
    # Test progressive lockout
    print("\n📈 Testing progressive lockout...")
    
    # Force unlock and try again
    lockout_manager.force_unlock_account("user1", "admin")
    print("   🔓 Account force unlocked by admin")
    
    # Try to lock again
    for attempt in range(1, 4):
        should_lock = lockout_manager.record_failed_attempt("user1", "192.168.1.100")
        if should_lock:
            print(f"   🔒 Account locked again after {attempt} attempts")
            break
    
    # Check progressive duration
    lockout_info = lockout_manager.get_lockout_info("user1")
    if lockout_info:
        print(f"   ⏰ Progressive lockout duration: {lockout_info['duration_minutes']} minutes")
    
    # Successful login should reset everything
    print("\n✅ Simulating successful login...")
    lockout_manager.record_successful_attempt("user1")
    
    if not lockout_manager.is_account_locked("user1"):
        print("   ✅ Account unlocked after successful login")
    
    # Security statistics
    stats = lockout_manager.get_security_stats()
    print(f"\n📊 Lockout Statistics:")
    print(f"   Locked Accounts: {stats['locked_accounts']}")
    print(f"   Accounts with Failed Attempts: {stats['accounts_with_failed_attempts']}")
    print(f"   Total Failed Attempts: {stats['total_failed_attempts']}")
    print(f"   Lockout Threshold: {stats['lockout_policy']['threshold']}")
    print(f"   Progressive Lockout: {stats['lockout_policy']['progressive_lockout']}")


def demo_security_policy_manager():
    """Demonstrate the integrated security policy manager"""
    print("\n🛡️  Security Policy Manager Integration")
    print("=" * 50)
    
    # Create comprehensive security policy
    security_policy = SecurityPolicy(
        password_policy=PasswordPolicy(
            min_length=8,
            lockout_threshold=3,
            lockout_duration_minutes=5,
            progressive_lockout=True
        ),
        session_policy=SessionPolicy(
            max_sessions_per_user=3,
            session_timeout_minutes=60,
            idle_timeout_minutes=30
        )
    )
    
    policy_manager = SecurityPolicyManager(security_policy)
    
    # Test password validation
    print("\n🔐 Testing password validation...")
    is_valid, violations = policy_manager.validate_password(
        "SecurePass123", username="admin"
    )
    print(f"   Password 'SecurePass123': {'✅ Valid' if is_valid else '❌ Invalid'}")
    if violations:
        print(f"      Violations: {', '.join(violations)}")
    
    # Test session management
    print("\n📱 Testing session management...")
    session_id = policy_manager.create_session("user1", "192.168.1.100", "Demo Browser")
    if session_id:
        print(f"   ✅ Session created: {session_id}")
        
        # Validate session
        session = policy_manager.validate_session(session_id)
        if session:
            print(f"   ✅ Session validated successfully")
        
        # Revoke session
        if policy_manager.revoke_session(session_id):
            print(f"   ✅ Session revoked successfully")
    
    # Test account lockout
    print("\n🚫 Testing account lockout...")
    for attempt in range(1, 4):
        should_lock = policy_manager.record_failed_login("user1", "192.168.1.100")
        print(f"   Failed attempt {attempt}: {'🔒 Account locked!' if should_lock else '⚠️  Warning'}")
    
    if policy_manager.is_account_locked("user1"):
        print("   ✅ Account lockout working")
        
        # Force unlock
        if policy_manager.force_unlock_account("user1", "admin"):
            print("   ✅ Account force unlocked by admin")
    
    # Get comprehensive security statistics
    print("\n📊 Comprehensive Security Statistics:")
    stats = policy_manager.get_security_stats()
    
    print(f"   Password Policy:")
    print(f"     - Min Length: {stats['password_policy']['min_length']}")
    print(f"     - Complexity: {stats['password_policy']['complexity_level']}")
    print(f"     - Expiration: {stats['password_policy']['expiration_days']} days")
    
    print(f"   Session Policy:")
    print(f"     - Max Sessions per User: {stats['session_policy']['max_sessions_per_user']}")
    print(f"     - Session Timeout: {stats['session_policy']['session_timeout_minutes']} minutes")
    print(f"     - Idle Timeout: {stats['session_policy']['idle_timeout_minutes']} minutes")
    
    print(f"   Current Status:")
    print(f"     - Active Sessions: {stats['sessions']['active_sessions']}")
    print(f"     - Locked Accounts: {stats['lockouts']['locked_accounts']}")
    print(f"     - Failed Login Attempts: {stats['lockouts']['total_failed_attempts']}")


def main():
    """Main demonstration function"""
    print("🚀 ATous Secure Network - Security Policy Implementation Demo")
    print("=" * 70)
    print("This demo showcases the comprehensive security policy system including:")
    print("  • Password validation and complexity requirements")
    print("  • Session management policies")
    print("  • Account lockout mechanisms")
    print("  • Security policy enforcement")
    print("=" * 70)
    
    try:
        # Run all demonstrations
        demo_password_policies()
        demo_session_management()
        demo_account_lockout()
        demo_security_policy_manager()
        
        print("\n🎉 Security Policy Demo completed successfully!")
        print("\nThis demonstrates:")
        print("  ✅ Comprehensive password policy enforcement")
        print("  ✅ Advanced session management with limits")
        print("  ✅ Progressive account lockout mechanisms")
        print("  ✅ Integrated security policy management")
        print("  ✅ Real-time security monitoring and statistics")
        
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
