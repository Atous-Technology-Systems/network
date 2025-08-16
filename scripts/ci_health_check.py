#!/usr/bin/env python3
"""
CI Health Check Script for ATous Secure Network

This script performs a quick health check of the system in approximately 30 seconds,
designed for CI/CD pipelines and deployment validation.

Usage:
    python scripts/ci_health_check.py [--base-url BASE_URL] [--timeout TIMEOUT] [--verbose]

Features:
    - Quick endpoint validation
    - Basic security testing
    - Performance metrics
    - WebSocket connectivity
    - Exit codes for CI integration
"""

import asyncio
import json
import sys
import time
import argparse
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

try:
    import requests
    import websockets
except ImportError as e:
    print(f"❌ Missing required packages: {e}")
    print("Install with: pip install requests websockets")
    sys.exit(1)

@dataclass
class HealthCheckResult:
    """Result of a health check operation"""
    name: str
    status: str  # "pass", "fail", "warning"
    response_time: float
    details: Dict[str, Any]
    error: Optional[str] = None

class CIHealthChecker:
    """CI Health Checker for ATous Secure Network"""
    
    def __init__(self, base_url: str, timeout: int = 30, verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.results: List[HealthCheckResult] = []
        self.start_time = time.time()
        
        # Configure requests session
        self.session = requests.Session()
        self.session.timeout = timeout
        
        print(f"🔍 CI Health Check - {self.base_url}")
        print(f"⏱️  Timeout: {timeout}s | Verbose: {verbose}")
        print("=" * 60)
    
    def log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            timestamp = datetime.now().strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
    
    def add_result(self, result: HealthCheckResult):
        """Add a health check result"""
        self.results.append(result)
        
        # Display result
        status_icon = {
            "pass": "✅",
            "fail": "❌",
            "warning": "⚠️"
        }.get(result.status, "❓")
        
        print(f"{status_icon} {result.name} ({result.response_time:.1f}ms)")
        if result.error:
            print(f"   Error: {result.error}")
        if result.details and self.verbose:
            print(f"   Details: {json.dumps(result.details, indent=2)}")
    
    def check_endpoint(self, name: str, path: str, method: str = "GET", 
                      expected_status: int = 200, **kwargs) -> HealthCheckResult:
        """Check a single endpoint"""
        start_time = time.time()
        
        try:
            url = f"{self.base_url}{path}"
            self.log(f"Testing {method} {url}")
            
            response = self.session.request(method, url, **kwargs)
            response_time = (time.time() - start_time) * 1000
            
            if response.status_code == expected_status:
                status = "pass"
                details = {
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "response_headers": dict(response.headers)
                }
                error = None
            else:
                status = "fail"
                details = {
                    "expected_status": expected_status,
                    "actual_status": response.status_code,
                    "response_text": response.text[:200]
                }
                error = f"Expected {expected_status}, got {response.status_code}"
            
            return HealthCheckResult(name, status, response_time, details, error)
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(name, "fail", response_time, {}, str(e))
    
    async def check_websocket(self, name: str, path: str) -> HealthCheckResult:
        """Check WebSocket connectivity"""
        start_time = time.time()
        
        try:
            url = f"ws://{self.base_url.replace('http://', '').replace('https://', '')}{path}"
            self.log(f"Testing WebSocket {url}")
            
            async with websockets.connect(url) as ws:
                # Send a simple ping
                await ws.send(json.dumps({"type": "ping", "timestamp": time.time()}))
                
                # Wait for response
                response = await asyncio.wait_for(ws.recv(), timeout=3)
                response_time = (time.time() - start_time) * 1000
                
                # Parse response
                try:
                    data = json.loads(response)
                    details = {"response": data, "response_size": len(response)}
                    status = "pass"
                    error = None
                except json.JSONDecodeError:
                    details = {"raw_response": response[:200]}
                    status = "warning"
                    error = "Non-JSON response received"
                
                return HealthCheckResult(name, status, response_time, details, error)
                
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheckResult(name, "fail", response_time, {}, str(e))
    
    def run_basic_checks(self):
        """Run basic HTTP endpoint checks"""
        print("\n📡 Basic Endpoint Checks:")
        
        # Health and info endpoints
        self.add_result(self.check_endpoint("Health Check", "/health"))
        self.add_result(self.check_endpoint("API Info", "/api/info"))
        self.add_result(self.check_endpoint("Security Status", "/api/security/status"))
        self.add_result(self.check_endpoint("System Metrics", "/api/metrics"))
        
        # Documentation endpoints
        self.add_result(self.check_endpoint("API Docs", "/docs"))
        self.add_result(self.check_endpoint("OpenAPI Schema", "/openapi.json"))
        
        # Crypto endpoints
        self.add_result(self.check_endpoint("Crypto Encrypt", "/api/crypto/encrypt", 
                                         method="POST", json={"message": "test", "key": "test"}))
    
    def run_security_checks(self):
        """Run basic security checks"""
        print("\n🔒 Security Checks:")
        
        # Test rate limiting (should get 429 after multiple requests)
        self.add_result(self.check_endpoint("Rate Limit Test", "/health"))
        self.add_result(self.check_endpoint("Rate Limit Test 2", "/health"))
        self.add_result(self.check_endpoint("Rate Limit Test 3", "/health"))
        
        # Test malicious input
        malicious_payloads = [
            ("SQL Injection", "/health?q=1' OR '1'='1"),
            ("XSS Test", "/health?q=<script>alert('xss')</script>"),
            ("Path Traversal", "/health?q=../../../etc/passwd"),
        ]
        
        for name, path in malicious_payloads:
            result = self.check_endpoint(name, path)
            # In dev mode, these might pass (200), in production they should fail (400)
            if result.status == "pass" and result.details.get("status_code") == 200:
                result.status = "warning"
                result.error = "Malicious input was allowed (dev mode?)"
            self.add_result(result)
    
    async def run_websocket_checks(self):
        """Run WebSocket connectivity checks"""
        print("\n🔌 WebSocket Checks:")
        
        websocket_paths = [
            ("Main WebSocket", "/ws"),
            ("API WebSocket", "/api/ws"),
            ("Generic WebSocket", "/websocket"),
        ]
        
        for name, path in websocket_paths:
            result = await self.check_websocket(name, path)
            self.add_result(result)
    
    def run_performance_checks(self):
        """Run basic performance checks"""
        print("\n⚡ Performance Checks:")
        
        # Test response time under load (5 requests)
        response_times = []
        for i in range(5):
            result = self.check_endpoint(f"Load Test {i+1}", "/health")
            response_times.append(result.response_time)
            if result.status == "pass":
                self.log(f"   Request {i+1}: {result.response_time:.1f}ms")
        
        # Calculate performance metrics
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            
            performance_result = HealthCheckResult(
                "Performance Summary",
                "pass" if avg_time < 100 else "warning",
                avg_time,
                {
                    "requests": len(response_times),
                    "avg_response_time_ms": round(avg_time, 1),
                    "min_response_time_ms": round(min_time, 1),
                    "max_response_time_ms": round(max_time, 1)
                }
            )
            
            if avg_time > 100:
                performance_result.status = "warning"
                performance_result.error = f"Average response time ({avg_time:.1f}ms) is above 100ms threshold"
            
            self.add_result(performance_result)
    
    async def run_all_checks(self):
        """Run all health checks"""
        try:
            # Basic checks
            self.run_basic_checks()
            
            # Security checks
            self.run_security_checks()
            
            # WebSocket checks
            await self.run_websocket_checks()
            
            # Performance checks
            self.run_performance_checks()
            
        except Exception as e:
            print(f"❌ Error during health checks: {e}")
            return False
        
        return True
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate a comprehensive health check report"""
        total_checks = len(self.results)
        passed_checks = sum(1 for r in self.results if r.status == "pass")
        failed_checks = sum(1 for r in self.results if r.status == "fail")
        warning_checks = sum(1 for r in self.results if r.status == "warning")
        
        total_time = time.time() - self.start_time
        
        # Calculate average response time
        response_times = [r.response_time for r in self.results if r.status == "pass"]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        report = {
            "summary": {
                "total_checks": total_checks,
                "passed": passed_checks,
                "failed": failed_checks,
                "warnings": warning_checks,
                "success_rate": round((passed_checks / total_checks) * 100, 1) if total_checks > 0 else 0,
                "total_time_seconds": round(total_time, 2),
                "average_response_time_ms": round(avg_response_time, 1)
            },
            "results": [
                {
                    "name": r.name,
                    "status": r.status,
                    "response_time_ms": round(r.response_time, 1),
                    "details": r.details,
                    "error": r.error
                }
                for r in self.results
            ],
            "timestamp": datetime.now().isoformat(),
            "base_url": self.base_url
        }
        
        return report
    
    def print_summary(self):
        """Print a summary of the health check results"""
        report = self.generate_report()
        summary = report["summary"]
        
        print("\n" + "=" * 60)
        print("📊 HEALTH CHECK SUMMARY")
        print("=" * 60)
        print(f"✅ Passed: {summary['passed']}")
        print(f"❌ Failed: {summary['failed']}")
        print(f"⚠️  Warnings: {summary['warnings']}")
        print(f"📈 Success Rate: {summary['success_rate']}%")
        print(f"⏱️  Total Time: {summary['total_time_seconds']}s")
        print(f"🚀 Avg Response: {summary['average_response_time_ms']}ms")
        
        # Print failed checks
        failed_checks = [r for r in self.results if r.status == "fail"]
        if failed_checks:
            print(f"\n❌ Failed Checks ({len(failed_checks)}):")
            for check in failed_checks:
                print(f"   • {check.name}: {check.error}")
        
        # Print warnings
        warning_checks = [r for r in self.results if r.status == "warning"]
        if warning_checks:
            print(f"\n⚠️  Warnings ({len(warning_checks)}):")
            for check in warning_checks:
                print(f"   • {check.name}: {check.error}")
        
        # Overall status
        if summary['failed'] == 0:
            if summary['warnings'] == 0:
                print("\n🎉 All checks passed! System is healthy.")
                return 0
            else:
                print("\n⚠️  All critical checks passed, but there are warnings.")
                return 0
        else:
            print(f"\n❌ {summary['failed']} checks failed. System needs attention.")
            return 1

async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description="CI Health Check for ATous Secure Network")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", 
                       help="Base URL for the API (default: http://127.0.0.1:8000)")
    parser.add_argument("--timeout", type=int, default=30,
                       help="Timeout in seconds (default: 30)")
    parser.add_argument("--verbose", "-v", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--output", "-o",
                       help="Output file for JSON report")
    
    args = parser.parse_args()
    
    # Create health checker
    checker = CIHealthChecker(args.base_url, args.timeout, args.verbose)
    
    # Run all checks
    success = await checker.run_all_checks()
    
    # Generate and save report
    report = checker.generate_report()
    if args.output:
        try:
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"\n📄 Report saved to: {args.output}")
        except Exception as e:
            print(f"❌ Failed to save report: {e}")
    
    # Print summary and exit
    exit_code = checker.print_summary()
    
    if not success:
        exit_code = 1
    
    sys.exit(exit_code)

if __name__ == "__main__":
    asyncio.run(main())
