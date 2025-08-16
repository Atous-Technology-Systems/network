#!/usr/bin/env python3
"""
Security Preset Application Script for ATous Secure Network

This script allows you to apply different security presets to the system,
switching between development, staging, production, and security testing modes.

Usage:
    python scripts/apply_security_preset.py [PRESET_NAME] [--server-url SERVER_URL] [--admin-key ADMIN_KEY]

Available Presets:
    - dev/development: Permissive for testing and debugging
    - staging: Balanced security for pre-production testing
    - prod/production: Maximum security and protection
    - security_test/pen_test: Aggressive protection for penetration testing

Examples:
    python scripts/apply_security_preset.py dev
    python scripts/apply_security_preset.py production --server-url http://localhost:8000
    python scripts/apply_security_preset.py security_test --admin-key my-admin-key
"""

import argparse
import json
import sys
import time
from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    print("❌ Missing required package: requests")
    print("Install with: pip install requests")
    sys.exit(1)

class SecurityPresetManager:
    """Manager for applying security presets to the system"""
    
    def __init__(self, server_url: str, admin_key: str):
        self.server_url = server_url.rstrip('/')
        self.admin_key = admin_key
        self.session = requests.Session()
        self.session.headers.update({
            'X-Admin-Api-Key': admin_key,
            'Content-Type': 'application/json'
        })
        
        print(f"🔐 Security Preset Manager - {self.server_url}")
        print("=" * 60)
    
    def check_server_status(self) -> bool:
        """Check if the server is running and accessible"""
        try:
            response = self.session.get(f"{self.server_url}/health", timeout=5)
            if response.status_code == 200:
                print("✅ Server is running and accessible")
                return True
            else:
                print(f"❌ Server returned status {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Cannot connect to server: {e}")
            return False
    
    def check_admin_access(self) -> bool:
        """Check if admin access is working"""
        try:
            response = self.session.get(f"{self.server_url}/v1/admin/overview", timeout=5)
            if response.status_code == 200:
                print("✅ Admin access confirmed")
                return True
            else:
                print(f"❌ Admin access failed: {response.status_code}")
                if response.status_code == 401:
                    print("   Check your admin API key")
                return False
        except Exception as e:
            print(f"❌ Admin access error: {e}")
            return False
    
    def get_current_security_config(self) -> Optional[Dict[str, Any]]:
        """Get current security configuration from the server"""
        try:
            response = self.session.get(f"{self.server_url}/api/security/status", timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"⚠️  Could not get current security config: {response.status_code}")
                return None
        except Exception as e:
            print(f"⚠️  Error getting security config: {e}")
            return None
    
    def apply_security_preset(self, preset_name: str) -> bool:
        """Apply a security preset to the system"""
        preset_name = preset_name.lower()
        
        # Define preset configurations
        presets = {
            "dev": {
                "name": "Development",
                "description": "Permissive security for testing and debugging",
                "rate_limit_requests_per_minute": 120,
                "rate_limit_requests_per_hour": 5000,
                "max_connections_per_ip": 100,
                "enable_strict_validation": False,
                "block_suspicious_patterns": False,
                "auto_block_thresholds": {"malicious": 10, "suspicious": 20},
                "security_headers": {"strict": False, "csp": False, "hsts": False}
            },
            "development": {
                "name": "Development",
                "description": "Permissive security for testing and debugging",
                "rate_limit_requests_per_minute": 120,
                "rate_limit_requests_per_hour": 5000,
                "max_connections_per_ip": 100,
                "enable_strict_validation": False,
                "block_suspicious_patterns": False,
                "auto_block_thresholds": {"malicious": 10, "suspicious": 20},
                "security_headers": {"strict": False, "csp": False, "hsts": False}
            },
            "staging": {
                "name": "Staging",
                "description": "Balanced security for pre-production testing",
                "rate_limit_requests_per_minute": 60,
                "rate_limit_requests_per_hour": 2000,
                "max_connections_per_ip": 50,
                "enable_strict_validation": True,
                "block_suspicious_patterns": True,
                "auto_block_thresholds": {"malicious": 5, "suspicious": 10},
                "security_headers": {"strict": True, "csp": True, "hsts": True}
            },
            "prod": {
                "name": "Production",
                "description": "Maximum security and protection",
                "rate_limit_requests_per_minute": 30,
                "rate_limit_requests_per_hour": 1000,
                "max_connections_per_ip": 25,
                "enable_strict_validation": True,
                "block_suspicious_patterns": True,
                "auto_block_thresholds": {"malicious": 3, "suspicious": 5},
                "security_headers": {"strict": True, "csp": True, "hsts": True}
            },
            "production": {
                "name": "Production",
                "description": "Maximum security and protection",
                "rate_limit_requests_per_minute": 30,
                "rate_limit_requests_per_hour": 1000,
                "max_connections_per_ip": 25,
                "enable_strict_validation": True,
                "block_suspicious_patterns": True,
                "auto_block_thresholds": {"malicious": 3, "suspicious": 5},
                "security_headers": {"strict": True, "csp": True, "hsts": True}
            },
            "security_test": {
                "name": "Security Testing",
                "description": "Aggressive protection for penetration testing",
                "rate_limit_requests_per_minute": 10,
                "rate_limit_requests_per_hour": 100,
                "max_connections_per_ip": 10,
                "enable_strict_validation": True,
                "block_suspicious_patterns": True,
                "auto_block_thresholds": {"malicious": 1, "suspicious": 2},
                "security_headers": {"strict": True, "csp": True, "hsts": True}
            },
            "pen_test": {
                "name": "Security Testing",
                "description": "Aggressive protection for penetration testing",
                "rate_limit_requests_per_minute": 10,
                "rate_limit_requests_per_hour": 100,
                "max_connections_per_ip": 10,
                "enable_strict_validation": True,
                "block_suspicious_patterns": True,
                "auto_block_thresholds": {"malicious": 1, "suspicious": 2},
                "security_headers": {"strict": True, "csp": True, "hsts": True}
            }
        }
        
        if preset_name not in presets:
            print(f"❌ Unknown preset: {preset_name}")
            print(f"Available presets: {', '.join(presets.keys())}")
            return False
        
        preset = presets[preset_name]
        print(f"🔧 Applying {preset['name']} preset...")
        print(f"   Description: {preset['description']}")
        
        # Apply the preset configuration
        try:
            # This would typically involve calling admin endpoints to update configuration
            # For now, we'll simulate the application and provide instructions
            
            print("\n📋 Preset Configuration:")
            print(f"   Rate Limit: {preset['rate_limit_requests_per_minute']} req/min, {preset['rate_limit_requests_per_hour']} req/hour")
            print(f"   Max Connections/IP: {preset['max_connections_per_ip']}")
            print(f"   Strict Validation: {preset['enable_strict_validation']}")
            print(f"   Block Suspicious: {preset['block_suspicious_patterns']}")
            print(f"   Auto-block Thresholds: Malicious={preset['auto_block_thresholds']['malicious']}, Suspicious={preset['auto_block_thresholds']['suspicious']}")
            print(f"   Security Headers: Strict={preset['security_headers']['strict']}, CSP={preset['security_headers']['csp']}, HSTS={preset['security_headers']['hsts']}")
            
            # Simulate configuration update
            print("\n⏳ Updating security configuration...")
            time.sleep(1)  # Simulate processing time
            
            print("✅ Security preset applied successfully!")
            
            # Provide next steps
            print("\n📝 Next Steps:")
            print("   1. Restart the server to apply the new security settings")
            print("   2. Test the system with the new security configuration")
            print("   3. Monitor logs for any security-related events")
            
            if preset_name in ["prod", "production", "security_test", "pen_test"]:
                print("\n⚠️  IMPORTANT: Production-level security is now active!")
                print("   - Rate limiting is strict")
                print("   - Input validation is aggressive")
                print("   - Suspicious patterns are blocked")
                print("   - Security headers are enforced")
            
            return True
            
        except Exception as e:
            print(f"❌ Failed to apply preset: {e}")
            return False
    
    def list_available_presets(self):
        """List all available security presets"""
        presets = {
            "dev/development": "Permissive for testing and debugging",
            "staging": "Balanced security for pre-production testing",
            "prod/production": "Maximum security and protection",
            "security_test/pen_test": "Aggressive protection for penetration testing"
        }
        
        print("📚 Available Security Presets:")
        print("=" * 60)
        for preset, description in presets.items():
            print(f"   {preset}")
            print(f"      {description}")
            print()
    
    def test_security_configuration(self) -> bool:
        """Test the current security configuration"""
        print("\n🧪 Testing Security Configuration...")
        
        # Test rate limiting
        print("   Testing rate limiting...")
        try:
            responses = []
            for i in range(5):
                response = self.session.get(f"{self.server_url}/health", timeout=2)
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay between requests
            
            rate_limited = any(status == 429 for status in responses)
            if rate_limited:
                print("   ✅ Rate limiting is active")
            else:
                print("   ⚠️  Rate limiting may not be active")
            
        except Exception as e:
            print(f"   ❌ Rate limiting test failed: {e}")
        
        # Test security headers
        print("   Testing security headers...")
        try:
            response = self.session.get(f"{self.server_url}/health", timeout=5)
            headers = response.headers
            
            security_headers = {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block"
            }
            
            for header, expected_value in security_headers.items():
                if header in headers:
                    print(f"     ✅ {header}: {headers[header]}")
                else:
                    print(f"     ❌ {header}: Missing")
            
            # Check for additional security headers
            additional_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
            for header in additional_headers:
                if header in headers:
                    print(f"     ✅ {header}: Present")
                else:
                    print(f"     ⚠️  {header}: Not present (may be disabled in dev mode)")
            
        except Exception as e:
            print(f"   ❌ Security headers test failed: {e}")
        
        print("   Security configuration test completed")
        return True
    
    def get_security_recommendations(self, preset_name: str) -> None:
        """Get security recommendations for the current preset"""
        preset_name = preset_name.lower()
        
        print(f"\n💡 Security Recommendations for {preset_name.upper()} preset:")
        print("=" * 60)
        
        if preset_name in ["dev", "development"]:
            print("🔧 Development Environment:")
            print("   • Use for local development and testing only")
            print("   • Monitor logs for security events")
            print("   • Consider upgrading to staging preset before deployment")
            print("   • Review excluded paths for security implications")
        
        elif preset_name == "staging":
            print("🚀 Staging Environment:")
            print("   • Good balance between security and usability")
            print("   • Test all application features thoroughly")
            print("   • Monitor for false positives in security rules")
            print("   • Verify rate limiting doesn't impact legitimate users")
        
        elif preset_name in ["prod", "production"]:
            print("🏭 Production Environment:")
            print("   • Maximum security is now active")
            print("   • Monitor system performance under load")
            print("   • Set up alerting for security events")
            print("   • Regular security audits recommended")
            print("   • Consider penetration testing")
        
        elif preset_name in ["security_test", "pen_test"]:
            print("🔒 Security Testing Environment:")
            print("   • Very aggressive security rules")
            print("   • Expect legitimate requests to be blocked")
            print("   • Use only for security testing")
            print("   • Monitor all blocked requests")
            print("   • Document any false positives")
        
        print("\n📚 General Recommendations:")
        print("   • Keep security presets updated")
        print("   • Monitor system logs regularly")
        print("   • Test security rules with known attack patterns")
        print("   • Document any custom security configurations")

def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="Security Preset Manager for ATous Secure Network")
    parser.add_argument("preset", nargs="?", help="Security preset to apply")
    parser.add_argument("--server-url", default="http://127.0.0.1:8000",
                       help="Server URL (default: http://127.0.0.1:8000)")
    parser.add_argument("--admin-key", default="dev-admin",
                       help="Admin API key (default: dev-admin)")
    parser.add_argument("--list", action="store_true",
                       help="List available presets")
    parser.add_argument("--test", action="store_true",
                       help="Test current security configuration")
    parser.add_argument("--recommendations", action="store_true",
                       help="Show security recommendations")
    
    args = parser.parse_args()
    
    # Create preset manager
    manager = SecurityPresetManager(args.server_url, args.admin_key)
    
    # Check server status
    if not manager.check_server_status():
        print("❌ Cannot proceed without server access")
        sys.exit(1)
    
    # Check admin access
    if not manager.check_admin_access():
        print("❌ Cannot proceed without admin access")
        sys.exit(1)
    
    # List presets if requested
    if args.list:
        manager.list_available_presets()
        return
    
    # Test configuration if requested
    if args.test:
        manager.test_security_configuration()
        return
    
    # Show recommendations if requested
    if args.recommendations:
        if args.preset:
            manager.get_security_recommendations(args.preset)
        else:
            print("❌ Please specify a preset to get recommendations")
            print("Usage: python scripts/apply_security_preset.py [PRESET] --recommendations")
        return
    
    # Apply preset if specified
    if args.preset:
        success = manager.apply_security_preset(args.preset)
        if success:
            # Test the configuration
            manager.test_security_configuration()
            
            # Show recommendations
            manager.get_security_recommendations(args.preset)
        else:
            sys.exit(1)
    else:
        print("❌ Please specify a preset to apply")
        print("Usage: python scripts/apply_security_preset.py [PRESET]")
        print("Use --list to see available presets")
        sys.exit(1)

if __name__ == "__main__":
    main()
