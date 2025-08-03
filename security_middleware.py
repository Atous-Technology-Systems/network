"""Security Middleware for ATous Secure Network

This module provides comprehensive security middleware that integrates
with FastAPI to automatically validate and sanitize all incoming requests,
implement rate limiting, and provide DDoS protection.
"""

import time
import json
import asyncio
from typing import Dict, List, Any, Optional, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from input_validator import validator, ValidationResult, validate_request_data

logger = logging.getLogger(__name__)

@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_limit: int = 10
    block_duration_minutes: int = 15

@dataclass
class ClientInfo:
    """Information about a client for rate limiting and monitoring"""
    ip_address: str
    request_times: deque = field(default_factory=deque)
    blocked_until: Optional[datetime] = None
    total_requests: int = 0
    malicious_requests: int = 0
    suspicious_requests: int = 0
    last_request_time: datetime = field(default_factory=datetime.now)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware for input validation and rate limiting"""
    
    def __init__(
        self,
        app: ASGIApp,
        rate_limit_config: Optional[RateLimitConfig] = None,
        enable_input_validation: bool = True,
        enable_rate_limiting: bool = True,
        enable_ddos_protection: bool = True,
        max_request_size: int = 1024 * 1024,  # 1MB
        blocked_ips: Optional[List[str]] = None
    ):
        super().__init__(app)
        self.rate_limit_config = rate_limit_config or RateLimitConfig()
        self.enable_input_validation = enable_input_validation
        self.enable_rate_limiting = enable_rate_limiting
        self.enable_ddos_protection = enable_ddos_protection
        self.max_request_size = max_request_size
        self.blocked_ips = set(blocked_ips or [])
        
        # Client tracking for rate limiting
        self.clients: Dict[str, ClientInfo] = {}
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
        
        # DDoS protection
        self.connection_counts: Dict[str, int] = defaultdict(int)
        self.max_connections_per_ip = 50
        
        # Request size tracking
        self.large_request_threshold = 100 * 1024  # 100KB
        
        logger.info("Security middleware initialized with comprehensive protection")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Main middleware dispatch method"""
        start_time = time.time()
        client_ip = self._get_client_ip(request)
        
        try:
            # Check if IP is blocked
            if client_ip in self.blocked_ips:
                logger.warning(f"Blocked IP attempted access: {client_ip}")
                return JSONResponse(
                    status_code=403,
                    content={"error": "Access denied", "code": "IP_BLOCKED"}
                )
            
            # Rate limiting check
            if self.enable_rate_limiting:
                rate_limit_result = await self._check_rate_limit(client_ip)
                if rate_limit_result:
                    return rate_limit_result
            
            # DDoS protection
            if self.enable_ddos_protection:
                ddos_result = await self._check_ddos_protection(client_ip)
                if ddos_result:
                    return ddos_result
            
            # Request size validation
            content_length = request.headers.get('content-length')
            if content_length and int(content_length) > self.max_request_size:
                logger.warning(f"Request too large from {client_ip}: {content_length} bytes")
                return JSONResponse(
                    status_code=413,
                    content={"error": "Request too large", "code": "REQUEST_TOO_LARGE"}
                )
            
            # Input validation
            if self.enable_input_validation:
                validation_result = await self._validate_request(request)
                if validation_result:
                    return validation_result
            
            # Process the request
            response = await call_next(request)
            
            # Update client statistics
            await self._update_client_stats(client_ip, 'safe')
            
            # Add security headers
            self._add_security_headers(response)
            
            # Log successful request
            processing_time = time.time() - start_time
            logger.info(f"Request processed successfully for {client_ip} in {processing_time:.3f}s")
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error for {client_ip}: {str(e)}")
            await self._update_client_stats(client_ip, 'error')
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error", "code": "MIDDLEWARE_ERROR"}
            )
        finally:
            # Cleanup old client data periodically
            if time.time() - self.last_cleanup > self.cleanup_interval:
                await self._cleanup_old_clients()
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP address from request"""
        # Check for forwarded headers (proxy/load balancer)
        forwarded_for = request.headers.get('x-forwarded-for')
        if forwarded_for:
            return forwarded_for.split(',')[0].strip()
        
        real_ip = request.headers.get('x-real-ip')
        if real_ip:
            return real_ip
        
        # Fallback to direct connection IP
        return request.client.host if request.client else 'unknown'
    
    async def _check_rate_limit(self, client_ip: str) -> Optional[Response]:
        """Check if client has exceeded rate limits"""
        now = datetime.now()
        
        # Get or create client info
        if client_ip not in self.clients:
            self.clients[client_ip] = ClientInfo(ip_address=client_ip)
        
        client = self.clients[client_ip]
        
        # Check if client is currently blocked
        if client.blocked_until and now < client.blocked_until:
            remaining_time = (client.blocked_until - now).total_seconds()
            logger.warning(f"Rate limited client {client_ip} attempted access, {remaining_time:.0f}s remaining")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded",
                    "code": "RATE_LIMITED",
                    "retry_after": int(remaining_time)
                },
                headers={"Retry-After": str(int(remaining_time))}
            )
        
        # Clean old request times
        minute_ago = now - timedelta(minutes=1)
        hour_ago = now - timedelta(hours=1)
        
        while client.request_times and client.request_times[0] < hour_ago:
            client.request_times.popleft()
        
        # Count recent requests
        requests_last_minute = sum(1 for t in client.request_times if t > minute_ago)
        requests_last_hour = len(client.request_times)
        
        # Check rate limits
        if requests_last_minute >= self.rate_limit_config.requests_per_minute:
            client.blocked_until = now + timedelta(minutes=self.rate_limit_config.block_duration_minutes)
            logger.warning(f"Client {client_ip} exceeded per-minute rate limit: {requests_last_minute} requests")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded - too many requests per minute",
                    "code": "RATE_LIMITED_MINUTE",
                    "retry_after": self.rate_limit_config.block_duration_minutes * 60
                }
            )
        
        if requests_last_hour >= self.rate_limit_config.requests_per_hour:
            client.blocked_until = now + timedelta(minutes=self.rate_limit_config.block_duration_minutes)
            logger.warning(f"Client {client_ip} exceeded per-hour rate limit: {requests_last_hour} requests")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Rate limit exceeded - too many requests per hour",
                    "code": "RATE_LIMITED_HOUR",
                    "retry_after": self.rate_limit_config.block_duration_minutes * 60
                }
            )
        
        # Add current request time
        client.request_times.append(now)
        client.total_requests += 1
        client.last_request_time = now
        
        return None
    
    async def _check_ddos_protection(self, client_ip: str) -> Optional[Response]:
        """Check for DDoS attack patterns"""
        # Increment connection count
        self.connection_counts[client_ip] += 1
        
        # Check if too many concurrent connections
        if self.connection_counts[client_ip] > self.max_connections_per_ip:
            logger.warning(f"DDoS protection triggered for {client_ip}: {self.connection_counts[client_ip]} connections")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many concurrent connections",
                    "code": "DDOS_PROTECTION",
                    "retry_after": 60
                }
            )
        
        # Schedule connection cleanup
        asyncio.create_task(self._cleanup_connection(client_ip))
        
        return None
    
    async def _cleanup_connection(self, client_ip: str):
        """Clean up connection count after delay"""
        await asyncio.sleep(1)  # Wait 1 second before decrementing
        if self.connection_counts[client_ip] > 0:
            self.connection_counts[client_ip] -= 1
    
    async def _validate_request(self, request: Request) -> Optional[Response]:
        """Validate request input for security threats"""
        try:
            # Validate URL path
            path_validation = validator.validate_input(str(request.url.path), 'url')
            if path_validation.result == ValidationResult.MALICIOUS:
                logger.warning(f"Malicious path detected from {self._get_client_ip(request)}: {request.url.path}")
                await self._update_client_stats(self._get_client_ip(request), 'malicious')
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "Malicious request detected in path",
                        "code": "MALICIOUS_PATH",
                        "threats": path_validation.threats_detected
                    }
                )
            
            # Validate query parameters
            for key, value in request.query_params.items():
                param_validation = validator.validate_input(f"{key}={value}", 'url')
                if param_validation.result == ValidationResult.MALICIOUS:
                    logger.warning(f"Malicious query parameter from {self._get_client_ip(request)}: {key}={value}")
                    await self._update_client_stats(self._get_client_ip(request), 'malicious')
                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "Malicious request detected in query parameters",
                            "code": "MALICIOUS_QUERY",
                            "threats": param_validation.threats_detected
                        }
                    )
            
            # Validate headers
            for header_name, header_value in request.headers.items():
                if header_name.lower() not in ['host', 'user-agent', 'accept', 'content-type', 'content-length', 'authorization']:
                    header_validation = validator.validate_input(header_value, 'general')
                    if header_validation.result == ValidationResult.MALICIOUS:
                        logger.warning(f"Malicious header from {self._get_client_ip(request)}: {header_name}={header_value}")
                        await self._update_client_stats(self._get_client_ip(request), 'malicious')
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Malicious request detected in headers",
                                "code": "MALICIOUS_HEADER",
                                "threats": header_validation.threats_detected
                            }
                        )
            
            # Validate request body for POST/PUT requests
            if request.method in ['POST', 'PUT', 'PATCH']:
                content_type = request.headers.get('content-type', '')
                
                if 'application/json' in content_type:
                    try:
                        body = await request.body()
                        if body:
                            body_str = body.decode('utf-8')
                            json_validation = validator.validate_json(body_str)
                            
                            if json_validation.result == ValidationResult.MALICIOUS:
                                logger.warning(f"Malicious JSON from {self._get_client_ip(request)}")
                                await self._update_client_stats(self._get_client_ip(request), 'malicious')
                                return JSONResponse(
                                    status_code=400,
                                    content={
                                        "error": "Malicious request detected in JSON body",
                                        "code": "MALICIOUS_JSON",
                                        "threats": json_validation.threats_detected
                                    }
                                )
                    except Exception as e:
                        logger.warning(f"Error validating JSON body from {self._get_client_ip(request)}: {e}")
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Invalid request body",
                                "code": "INVALID_BODY"
                            }
                        )
                
                elif 'application/xml' in content_type or 'text/xml' in content_type:
                    try:
                        body = await request.body()
                        if body:
                            body_str = body.decode('utf-8')
                            xml_validation = validator.validate_xml(body_str)
                            
                            if xml_validation.result == ValidationResult.MALICIOUS:
                                logger.warning(f"Malicious XML from {self._get_client_ip(request)}")
                                await self._update_client_stats(self._get_client_ip(request), 'malicious')
                                return JSONResponse(
                                    status_code=400,
                                    content={
                                        "error": "Malicious request detected in XML body",
                                        "code": "MALICIOUS_XML",
                                        "threats": xml_validation.threats_detected
                                    }
                                )
                    except Exception as e:
                        logger.warning(f"Error validating XML body from {self._get_client_ip(request)}: {e}")
                        return JSONResponse(
                            status_code=400,
                            content={
                                "error": "Invalid XML body",
                                "code": "INVALID_XML"
                            }
                        )
            
            return None
            
        except Exception as e:
            logger.error(f"Error during request validation: {e}")
            return JSONResponse(
                status_code=500,
                content={
                    "error": "Validation error",
                    "code": "VALIDATION_ERROR"
                }
            )
    
    async def _update_client_stats(self, client_ip: str, request_type: str):
        """Update client statistics"""
        if client_ip not in self.clients:
            self.clients[client_ip] = ClientInfo(ip_address=client_ip)
        
        client = self.clients[client_ip]
        
        if request_type == 'malicious':
            client.malicious_requests += 1
        elif request_type == 'suspicious':
            client.suspicious_requests += 1
        
        # Auto-block clients with too many malicious requests
        if client.malicious_requests >= 5:
            client.blocked_until = datetime.now() + timedelta(hours=1)
            logger.warning(f"Auto-blocking client {client_ip} due to {client.malicious_requests} malicious requests")
    
    def _add_security_headers(self, response: Response):
        """Add security headers to response"""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    
    async def _cleanup_old_clients(self):
        """Clean up old client data to prevent memory leaks"""
        now = datetime.now()
        cutoff_time = now - timedelta(hours=24)
        
        clients_to_remove = []
        for ip, client in self.clients.items():
            if client.last_request_time < cutoff_time and (not client.blocked_until or client.blocked_until < now):
                clients_to_remove.append(ip)
        
        for ip in clients_to_remove:
            del self.clients[ip]
        
        self.last_cleanup = time.time()
        logger.info(f"Cleaned up {len(clients_to_remove)} old client records")
    
    def get_security_stats(self) -> Dict[str, Any]:
        """Get current security statistics"""
        total_clients = len(self.clients)
        blocked_clients = sum(1 for c in self.clients.values() if c.blocked_until and c.blocked_until > datetime.now())
        total_requests = sum(c.total_requests for c in self.clients.values())
        malicious_requests = sum(c.malicious_requests for c in self.clients.values())
        suspicious_requests = sum(c.suspicious_requests for c in self.clients.values())
        
        return {
            "total_clients": total_clients,
            "blocked_clients": blocked_clients,
            "total_requests": total_requests,
            "malicious_requests": malicious_requests,
            "suspicious_requests": suspicious_requests,
            "blocked_ips_count": len(self.blocked_ips),
            "active_connections": sum(self.connection_counts.values())
        }
    
    def block_ip(self, ip_address: str):
        """Manually block an IP address"""
        self.blocked_ips.add(ip_address)
        logger.info(f"Manually blocked IP: {ip_address}")
    
    def unblock_ip(self, ip_address: str):
        """Manually unblock an IP address"""
        self.blocked_ips.discard(ip_address)
        if ip_address in self.clients:
            self.clients[ip_address].blocked_until = None
        logger.info(f"Manually unblocked IP: {ip_address}")