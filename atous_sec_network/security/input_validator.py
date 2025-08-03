"""Input validation module for ATous Secure Network."""

import re
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    threats: List[str]
    risk_score: float
    message: str = ""
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}

class InputValidator:
    """Comprehensive input validation for security threats."""
    
    def __init__(self):
        # SQL Injection patterns
        self.sql_patterns = [
            r"('|(\-\-)|(;)|(\||\|)|(\*|\*))",
            r"(union|select|insert|delete|update|drop|create|alter|exec|execute)",
            r"(script|javascript|vbscript|onload|onerror|onclick)",
            r"(\<|\>|\&|\#)"
        ]
        
        # XSS patterns
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe[^>]*>",
            r"<object[^>]*>",
            r"<embed[^>]*>"
        ]
        
        # Command injection patterns
        self.command_patterns = [
            r"[;&|`$(){}\[\]]",
            r"(cat|ls|dir|type|copy|del|rm|mv|cp)",
            r"(wget|curl|nc|netcat|telnet|ssh)"
        ]
        
        # Path traversal patterns
        self.path_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%2e%2e%5c"
        ]
    
    def validate_input(self, input_data: str, validation_type: str = "general") -> Dict[str, Any]:
        """Validate input against various security threats."""
        if not input_data:
            return {"valid": True, "threats": [], "sanitized": ""}
        
        threats = []
        
        # Check for SQL injection
        if self._check_sql_injection(input_data):
            threats.append("sql_injection")
        
        # Check for XSS
        if self._check_xss(input_data):
            threats.append("xss")
        
        # Check for command injection
        if self._check_command_injection(input_data):
            threats.append("command_injection")
        
        # Check for path traversal
        if self._check_path_traversal(input_data):
            threats.append("path_traversal")
        
        is_valid = len(threats) == 0
        sanitized = self._sanitize_input(input_data) if not is_valid else input_data
        
        return {
            "valid": is_valid,
            "threats": threats,
            "sanitized": sanitized,
            "original_length": len(input_data),
            "sanitized_length": len(sanitized)
        }
    
    def _check_sql_injection(self, data: str) -> bool:
        """Check for SQL injection patterns."""
        data_lower = data.lower()
        for pattern in self.sql_patterns:
            if re.search(pattern, data_lower, re.IGNORECASE):
                return True
        return False
    
    def _check_xss(self, data: str) -> bool:
        """Check for XSS patterns."""
        for pattern in self.xss_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False
    
    def _check_command_injection(self, data: str) -> bool:
        """Check for command injection patterns."""
        for pattern in self.command_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False
    
    def _check_path_traversal(self, data: str) -> bool:
        """Check for path traversal patterns."""
        for pattern in self.path_patterns:
            if re.search(pattern, data, re.IGNORECASE):
                return True
        return False
    
    def _sanitize_input(self, data: str) -> str:
        """Sanitize input by removing dangerous characters."""
        # Remove HTML tags
        data = re.sub(r'<[^>]+>', '', data)
        
        # Remove SQL keywords
        sql_keywords = ['union', 'select', 'insert', 'delete', 'update', 'drop', 'create', 'alter']
        for keyword in sql_keywords:
            data = re.sub(keyword, '', data, flags=re.IGNORECASE)
        
        # Remove dangerous characters
        data = re.sub(r'[<>"\';\-\-]', '', data)
        
        return data.strip()
    
    def validate_email(self, email: str) -> bool:
        """Validate email format."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def validate_url(self, url: str) -> bool:
        """Validate URL format."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def validate_json(self, json_str: str) -> Dict[str, Any]:
        """Validate JSON format."""
        try:
            data = json.loads(json_str)
            return {"valid": True, "data": data, "error": None}
        except json.JSONDecodeError as e:
            return {"valid": False, "data": None, "error": str(e)}
    
    def validate_filename(self, filename: str) -> bool:
        """Validate filename for security."""
        # Check for path traversal
        if self._check_path_traversal(filename):
            return False
        
        # Check for dangerous characters
        dangerous_chars = ['<', '>', ':', '"', '|', '?', '*']
        for char in dangerous_chars:
            if char in filename:
                return False
        
        return True

# Global validator instance
validator = InputValidator()

def validate_input(data: str, validation_type: str = "general") -> Dict[str, Any]:
    """Global function for input validation."""
    return validator.validate_input(data, validation_type)

def validate_email(email: str) -> bool:
    """Global function for email validation."""
    return validator.validate_email(email)

def validate_url(url: str) -> bool:
    """Global function for URL validation."""
    return validator.validate_url(url)

def validate_json(json_str: str) -> Dict[str, Any]:
    """Global function for JSON validation."""
    return validator.validate_json(json_str)

def validate_filename(filename: str) -> bool:
    """Global function for filename validation."""
    return validator.validate_filename(filename)

def validate_request_data(data: Any, validation_type: str = "general") -> ValidationResult:
    """Validate request data and return ValidationResult."""
    if isinstance(data, str):
        result = validator.validate_input(data, validation_type)
        return ValidationResult(
            is_valid=result["is_valid"],
            threats=result["threats"],
            risk_score=result["risk_score"],
            message=result.get("message", ""),
            details=result
        )
    elif isinstance(data, dict):
        # Validate all string values in the dictionary
        all_threats = []
        max_risk_score = 0.0
        is_valid = True
        
        for key, value in data.items():
            if isinstance(value, str):
                result = validator.validate_input(value, validation_type)
                if not result["is_valid"]:
                    is_valid = False
                all_threats.extend(result["threats"])
                max_risk_score = max(max_risk_score, result["risk_score"])
        
        return ValidationResult(
            is_valid=is_valid,
            threats=list(set(all_threats)),
            risk_score=max_risk_score,
            message="Request data validation completed",
            details={"validated_fields": len(data)}
        )
    else:
        return ValidationResult(
            is_valid=True,
            threats=[],
            risk_score=0.0,
            message="Non-string data passed validation",
            details={"data_type": type(data).__name__}
        )