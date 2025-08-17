"""Security Presets for ATous Secure Network

This module provides pre-configured security settings for different environments,
allowing easy switching between development, staging, and production security levels.
"""

from dataclasses import dataclass
from typing import List, Optional
from .config import RateLimitConfig, SecurityPreset



# Development preset - More permissive for testing
DEV_PRESET = SecurityPreset(
    name="development",
    description="Development environment - permissive for testing and debugging",
    rate_limit_config=RateLimitConfig(
        requests_per_minute=120,      # 2 req/sec
        requests_per_hour=5000,       # ~1.4 req/sec average
        burst_limit=20,               # Allow bursts
        block_duration_minutes=5      # Short blocks
    ),
    max_connections_per_ip=100,       # Higher for testing
    connection_timeout_seconds=2,
    enable_input_validation=True,
    strict_validation=False,          # Allow some suspicious patterns
    block_suspicious_patterns=False,  # Don't block immediately
    max_request_size_mb=10,          # 10MB for file uploads
    max_query_params=50,
    max_header_size=8192,            # 8KB headers
    auto_block_malicious_threshold=10,  # Higher threshold
    auto_block_suspicious_threshold=20, # Higher threshold
    block_duration_hours=1,
    excluded_paths=[
        "/health", "/docs", "/redoc", "/openapi.json", "/",
        "/api/crypto/encrypt", "/api/security/encrypt", "/encrypt",
        "/api/info", "/api/security/status", "/api/metrics"
    ],
    strict_security_headers=False,    # Less strict for dev
    enable_csp=False,                 # Disable CSP in dev
    enable_hsts=False                 # Disable HSTS in dev
)

# Staging preset - Balanced security
STAGING_PRESET = SecurityPreset(
    name="staging",
    description="Staging environment - balanced security for pre-production testing",
    rate_limit_config=RateLimitConfig(
        requests_per_minute=60,       # 1 req/sec
        requests_per_hour=2000,       # ~0.6 req/sec average
        burst_limit=10,               # Moderate bursts
        block_duration_minutes=15     # Medium blocks
    ),
    max_connections_per_ip=50,        # Moderate limit
    connection_timeout_seconds=1,
    enable_input_validation=True,
    strict_validation=True,           # Strict validation
    block_suspicious_patterns=True,   # Block suspicious patterns
    max_request_size_mb=5,           # 5MB limit
    max_query_params=25,
    max_header_size=4096,            # 4KB headers
    auto_block_malicious_threshold=5,   # Lower threshold
    auto_block_suspicious_threshold=10, # Lower threshold
    block_duration_hours=2,
    excluded_paths=[
        "/health", "/docs", "/redoc", "/openapi.json", "/",
        "/api/info", "/api/security/status", "/api/metrics"
    ],
    strict_security_headers=True,     # Strict headers
    enable_csp=True,                  # Enable CSP
    enable_hsts=True                  # Enable HSTS
)

# Production preset - Maximum security
PRODUCTION_PRESET = SecurityPreset(
    name="production",
    description="Production environment - maximum security and protection",
    rate_limit_config=RateLimitConfig(
        requests_per_minute=30,       # 0.5 req/sec
        requests_per_hour=1000,       # ~0.3 req/sec average
        burst_limit=5,                # Minimal bursts
        block_duration_minutes=30     # Long blocks
    ),
    max_connections_per_ip=25,        # Low limit
    connection_timeout_seconds=1,
    enable_input_validation=True,
    strict_validation=True,           # Maximum validation
    block_suspicious_patterns=True,   # Block all suspicious
    max_request_size_mb=2,           # 2MB limit
    max_query_params=15,
    max_header_size=2048,            # 2KB headers
    auto_block_malicious_threshold=3,    # Very low threshold
    auto_block_suspicious_threshold=5,   # Very low threshold
    block_duration_hours=6,          # Long blocks
    excluded_paths=[
        "/health", "/api/info", "/api/security/status", "/api/metrics"
    ],
    strict_security_headers=True,     # Maximum headers
    enable_csp=True,                  # Strict CSP
    enable_hsts=True                  # Strict HSTS
)

# Security testing preset - Aggressive for penetration testing
SECURITY_TEST_PRESET = SecurityPreset(
    name="security_test",
    description="Security testing environment - aggressive protection for penetration testing",
    rate_limit_config=RateLimitConfig(
        requests_per_minute=10,       # Very low rate
        requests_per_hour=100,        # Very low rate
        burst_limit=2,                # Minimal bursts
        block_duration_minutes=60     # Very long blocks
    ),
    max_connections_per_ip=10,        # Very low limit
    connection_timeout_seconds=1,
    enable_input_validation=True,
    strict_validation=True,           # Maximum validation
    block_suspicious_patterns=True,   # Block all suspicious
    max_request_size_mb=1,           # 1MB limit
    max_query_params=10,
    max_header_size=1024,            # 1KB headers
    auto_block_malicious_threshold=1,    # Immediate blocking
    auto_block_suspicious_threshold=2,   # Very low threshold
    block_duration_hours=24,         # 24-hour blocks
    excluded_paths=[
        "/health"                     # Only health check
    ],
    strict_security_headers=True,     # Maximum headers
    enable_csp=True,                  # Strict CSP
    enable_hsts=True                  # Strict HSTS
)

# Preset registry
SECURITY_PRESETS = {
    "dev": DEV_PRESET,
    "development": DEV_PRESET,
    "staging": STAGING_PRESET,
    "prod": PRODUCTION_PRESET,
    "production": PRODUCTION_PRESET,
    "security_test": SECURITY_TEST_PRESET,
    "pen_test": SECURITY_TEST_PRESET
}

def get_security_preset(preset_name: str) -> SecurityPreset:
    """Get a security preset by name"""
    preset_name = preset_name.lower()
    if preset_name not in SECURITY_PRESETS:
        raise ValueError(f"Unknown security preset: {preset_name}. Available: {list(SECURITY_PRESETS.keys())}")
    return SECURITY_PRESETS[preset_name]

def list_available_presets() -> List[str]:
    """List all available security presets"""
    return list(SECURITY_PRESETS.keys())

def get_preset_description(preset_name: str) -> str:
    """Get description of a security preset"""
    preset = get_security_preset(preset_name)
    return f"{preset.name}: {preset.description}"

def create_custom_preset(
    base_preset: str,
    customizations: dict
) -> SecurityPreset:
    """Create a custom preset based on an existing one with customizations"""
    base = get_security_preset(base_preset)
    
    # Create a copy with customizations
    custom_preset = SecurityPreset(
        name=f"custom_{base.name}",
        description=f"Custom preset based on {base.name}",
        rate_limit_config=base.rate_limit_config,
        max_connections_per_ip=base.max_connections_per_ip,
        connection_timeout_seconds=base.connection_timeout_seconds,
        enable_input_validation=base.enable_input_validation,
        strict_validation=base.strict_validation,
        block_suspicious_patterns=base.block_suspicious_patterns,
        max_request_size_mb=base.max_request_size_mb,
        max_query_params=base.max_query_params,
        max_header_size=base.max_header_size,
        auto_block_malicious_threshold=base.auto_block_malicious_threshold,
        auto_block_suspicious_threshold=base.auto_block_suspicious_threshold,
        block_duration_hours=base.block_duration_hours,
        excluded_paths=base.excluded_paths.copy(),
        strict_security_headers=base.strict_security_headers,
        enable_csp=base.enable_csp,
        enable_hsts=base.enable_hsts
    )
    
    # Apply customizations
    for key, value in customizations.items():
        if hasattr(custom_preset, key):
            setattr(custom_preset, key, value)
    
    return custom_preset
