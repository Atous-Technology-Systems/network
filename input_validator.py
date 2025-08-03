"""Input Validation System for ATous Secure Network

This module provides comprehensive input validation and sanitization
to prevent various types of injection attacks and security vulnerabilities.
"""

import re
import html
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass

class ValidationResult(Enum):
    """Enumeration for validation results"""
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    BLOCKED = "blocked"

@dataclass
class ValidationResponse:
    """Response object for validation results"""
    result: ValidationResult
    sanitized_value: str
    threats_detected: List[str]
    confidence_score: float
    original_value: str

class InputValidator:
    """Comprehensive input validator for security threats"""
    
    def __init__(self):
        """Initialize the validator with security patterns"""
        self._initialize_patterns()
        self._initialize_safe_chars()
        self.compiled_patterns = self._compile_patterns()
    
    def _initialize_patterns(self):
        """Initialize security threat detection patterns"""
        
        # SQL Injection patterns
        self.sql_patterns = [
            r"(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)",
            r"(?i)(or|and)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            r"(?i)(or|and)\s+['\"]?[a-z]+['\"]?\s*=\s*['\"]?[a-z]+['\"]?",
            r"['\"];.*--",
            r"(?i)\bxp_cmdshell\b",
            r"(?i)\bsp_executesql\b",
            r"(?i)\bdbms_pipe\b",
            r"(?i)\butl_file\b"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:\s*[^\s]",
            r"on\w+\s*=\s*['\"][^'\"]*['\"]?",
            r"<iframe[^>]*>.*?</iframe>",
            r"<object[^>]*>.*?</object>",
            r"<embed[^>]*>.*?</embed>",
            r"<link[^>]*>.*?</link>",
            r"<meta[^>]*>.*?</meta>",
            r"vbscript:\s*[^\s]",
            r"expression\s*\("
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r"[;&|`$(){}\[\]]",
            r"(?i)(cmd|command|exec|system|shell|bash|sh|powershell|pwsh)",
            r"(?i)(rm|del|format|fdisk|mkfs)",
            r"(?i)(wget|curl|nc|netcat|telnet|ssh)",
            r"(?i)(cat|type|more|less|head|tail)"
        ]
        
        # Path traversal patterns
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c",
            r"\.\.%2f",
            r"\.\.%5c",
            r"file://",
            r"/etc/passwd",
            r"\\windows\\system32"
        ]
        
        self.xxe_patterns = [
            r"<!ENTITY",
            r"SYSTEM\s+['\"]file:",
            r"SYSTEM\s+['\"]http:",
            r"<!DOCTYPE[^>]*\[",
            r"&[a-zA-Z][a-zA-Z0-9]*;"
        ]
        
        # LDAP injection patterns
        self.ldap_patterns = [
            r"[()&|!*]",
            r"(?i)(objectclass|cn|uid|ou|dc)\s*[=~]",
            r"\*\)\(.*=",
            r"\)\(.*=.*\*"
        ]
        
        # NoSQL injection patterns
        self.nosql_patterns = [
            r"(?i)\$where",
            r"(?i)\$ne",
            r"(?i)\$gt",
            r"(?i)\$lt",
            r"(?i)\$regex",
            r"(?i)\$or",
            r"(?i)\$and",
            r"(?i)\$not",
            r"(?i)\$in",
            r"(?i)\$nin"
        ]
    
    def _initialize_safe_chars(self):
        """Initialize safe character sets for different contexts"""
        self.safe_chars = {
            "general": r"[a-zA-Z0-9\s\-_.,!?@#%^&*()+=\[\]{}|;:'\"/\\<>~`]",
            "html": r"[a-zA-Z0-9\s\-_.,!?@#%^&*()+=\[\]{}|;:'\"/\\~`]",
            "web": r"[a-zA-Z0-9\s\-_.,!?@#%^&*()+=\[\]{}|;:'\"/\\<>~`]",
            "url": r"[a-zA-Z0-9\-_.~:/?#\[\]@!$&'()*+,;=%]",
            "database": r"[a-zA-Z0-9\s\-_.,@#%^&*()+=\[\]{}|:~`]",
            "system": r"[a-zA-Z0-9\s\-_.,@#%^&*()+=\[\]{}:~`]",
            "ldap": r"[a-zA-Z0-9\s\-_.,@#%^+=:~`]",
            "xml": r"[a-zA-Z0-9\s\-_.,!?@#%^&*()+=\[\]{}|;:~`]",
            "json": r"[a-zA-Z0-9\s\-_.,!?@#%^&*()+=\[\]{}|;:'\"~`]"
        }
    
    def _compile_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Compile all regex patterns for better performance"""
        compiled = {}
        
        pattern_groups = {
            "sql": self.sql_patterns,
            "xss": self.xss_patterns,
            "command": self.command_patterns,
            "path_traversal": self.path_traversal_patterns,
            "xxe": self.xxe_patterns,
            "ldap": self.ldap_patterns,
            "nosql": self.nosql_patterns
        }
        
        for group_name, patterns in pattern_groups.items():
            compiled[group_name] = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
        
        return compiled
    
    def sanitize_input(self, data: Any, context: str = "general") -> str:
        """Sanitize input data based on context"""
        if data is None:
            return ""
        
        if not isinstance(data, str):
            data = str(data)
        
        if isinstance(data, str):
            if context == "html":
                return html.escape(data)
            elif context == "sql":
                # Escapar caracteres especiais SQL
                return data.replace("'", "''").replace("\\", "\\\\")
            elif context == "url":
                # Validar URL
                try:
                    parsed = urlparse(data)
                    if parsed.scheme in ['http', 'https', 'ftp']:
                        return data
                    else:
                        return ""
                except:
                    return ""
            elif context == "xml":
                # Remover caracteres perigosos para XML
                return re.sub(r'[<>"\'\/\\&;]', '', data)
            elif context == "json":
                # Escapar para JSON
                try:
                    return json.dumps(data)[1:-1]  # Remove aspas externas
                except:
                    return ""
            else:
                # Sanitização geral
                safe_pattern = self.safe_chars.get(context, self.safe_chars["general"])
                return re.sub(f"[^{safe_pattern[1:-1]}]", "", data)
        
        return str(data)
    
    def detect_threats(self, data: str) -> List[str]:
        """Detect security threats in input data"""
        threats = []
        
        for threat_type, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                if pattern.search(data):
                    threats.append(threat_type)
                    break  # One match per threat type is enough
        
        return threats
    
    def calculate_threat_score(self, threats: List[str], data: str) -> float:
        """Calculate threat confidence score"""
        if not threats:
            return 0.0
        
        # Base score based on number of threat types
        base_score = len(threats) * 0.2
        
        # Additional scoring based on specific threats
        threat_weights = {
            "sql": 0.3,
            "xss": 0.25,
            "command": 0.35,
            "path_traversal": 0.2,
            "xxe": 0.3,
            "ldap": 0.15,
            "nosql": 0.25
        }
        
        weighted_score = sum(threat_weights.get(threat, 0.1) for threat in threats)
        
        # Length factor (longer suspicious strings are more likely to be attacks)
        length_factor = min(len(data) / 1000, 0.2)
        
        total_score = min(base_score + weighted_score + length_factor, 1.0)
        return round(total_score, 3)
    
    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))
    
    def validate_filename(self, filename: str) -> bool:
        """Validate filename for security"""
        # Check for dangerous characters
        invalid_chars = r'[<>:"/\\|?*]'
        if re.search(invalid_chars, filename):
            return False
        
        # Check for reserved names (Windows)
        reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 
                         'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 
                         'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
        
        name_without_ext = filename.split('.')[0].upper()
        if name_without_ext in reserved_names:
            return False
        
        return True
    
    def validate_url(self, url: str, allow_private: bool = False) -> bool:
        """Validate URL and check for SSRF"""
        try:
            parsed = urlparse(url)
            
            # Check scheme
            if parsed.scheme not in ['http', 'https']:
                return False
            
            # Check for SSRF attempts
            if not allow_private:
                hostname = parsed.hostname
                if hostname:
                    # Block localhost, private IPs, etc.
                    private_patterns = [
                        r'^localhost$',
                        r'^127\.',
                        r'^10\.',
                        r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
                        r'^192\.168\.',
                        r'^169\.254\.',
                        r'^::1$',
                        r'^fc00:',
                        r'^fe80:'
                    ]
                    
                    for pattern in private_patterns:
                        if re.match(pattern, hostname, re.IGNORECASE):
                            return False
            
            return True
        except:
            return False
    
    def validate_json(self, data: str) -> bool:
        """Validate JSON format"""
        try:
            json.loads(data)
            return True
        except:
            return False
    
    def validate_xml(self, data: str) -> bool:
        """Validate XML format and check for XXE"""
        try:
            # Check for XXE patterns first
            xxe_threats = []
            for pattern in self.compiled_patterns["xxe"]:
                if pattern.search(data):
                    xxe_threats.append("xxe")
            
            if xxe_threats:
                return False
            
            # Try to parse XML
            ET.fromstring(data)
            return True
        except:
            return False
    
    def validate(self, data: Any, context: str = "general") -> ValidationResponse:
        """Main validation method"""
        if data is None:
            return ValidationResponse(
                result=ValidationResult.SAFE,
                sanitized_value="",
                threats_detected=[],
                confidence_score=0.0,
                original_value=""
            )
        
        original_value = str(data)
        threats = self.detect_threats(original_value)
        confidence_score = self.calculate_threat_score(threats, original_value)
        sanitized_value = self.sanitize_input(data, context)
        
        # Determine result based on threats and confidence
        if confidence_score >= 0.8:
            result = ValidationResult.BLOCKED
        elif confidence_score >= 0.5:
            result = ValidationResult.MALICIOUS
        elif confidence_score >= 0.2:
            result = ValidationResult.SUSPICIOUS
        else:
            result = ValidationResult.SAFE
        
        return ValidationResponse(
            result=result,
            sanitized_value=sanitized_value,
            threats_detected=threats,
            confidence_score=confidence_score,
            original_value=original_value
        )

# Global validator instance
validator = InputValidator()

def validate_request_data(data: Dict[str, Any], context: str = "general") -> Dict[str, ValidationResponse]:
    """Validate all fields in request data"""
    results = {}
    
    for key, value in data.items():
        if isinstance(value, (str, int, float)):
            results[key] = validator.validate(value, context)
        elif isinstance(value, dict):
            # Recursively validate nested dictionaries
            nested_results = validate_request_data(value, context)
            results[key] = nested_results
        elif isinstance(value, list):
            # Validate list items
            list_results = []
            for item in value:
                if isinstance(item, (str, int, float)):
                    list_results.append(validator.validate(item, context))
                elif isinstance(item, dict):
                    list_results.append(validate_request_data(item, context))
            results[key] = list_results
    
    return results