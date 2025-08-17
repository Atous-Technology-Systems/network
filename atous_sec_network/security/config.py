"""Security Configuration for ATous Secure Network

This module contains shared configuration classes to avoid circular imports.
"""

from dataclasses import dataclass
from typing import List

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_minute: int = 10000  # Muito mais permissivo para desenvolvimento
    requests_per_hour: int = 100000   # Muito mais permissivo para desenvolvimento
    burst_limit: int = 1000           # Muito mais permissivo para desenvolvimento
    block_duration_minutes: int = 1   # Mantido baixo para testes

@dataclass
class SecurityPreset:
    """Security configuration preset for a specific environment"""
    name: str
    description: str
    
    # Rate limiting
    rate_limit_config: RateLimitConfig
    
    # DDoS protection
    max_connections_per_ip: int
    connection_timeout_seconds: int
    
    # Input validation
    enable_input_validation: bool
    strict_validation: bool
    block_suspicious_patterns: bool
    
    # Request limits
    max_request_size_mb: int
    max_query_params: int
    max_header_size: int
    
    # Auto-blocking
    auto_block_malicious_threshold: int
    auto_block_suspicious_threshold: int
    block_duration_hours: int
    
    # Excluded paths (paths that bypass strict validation)
    excluded_paths: List[str]
    
    # Security headers
    strict_security_headers: bool
    enable_csp: bool
    enable_hsts: bool
