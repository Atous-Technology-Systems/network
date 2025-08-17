# Security System Documentation

## Overview

The ATous Secure Network includes a comprehensive security system with configurable presets for different environments. This system provides multiple layers of protection including input validation, rate limiting, DDoS protection, and configurable security headers.

## Security Architecture

### Core Components

1. **Security Middleware** (`atous_sec_network.security.security_middleware`)
   - Request validation and sanitization
   - Rate limiting with configurable thresholds
   - DDoS protection
   - Security header management
   - Auto-blocking of malicious clients

2. **Security Presets** (`atous_sec_network.security.security_presets`)
   - Pre-configured security levels
   - Environment-specific configurations
   - Easy switching between security modes

3. **Input Validator** (`atous_sec_network.security.input_validator`)
   - Malicious pattern detection
   - SQL injection prevention
   - XSS protection
   - Path traversal detection

## Security Presets

### Available Presets

#### Development (`dev` / `development`)
- **Purpose**: Local development and testing
- **Security Level**: Permissive
- **Rate Limits**: 120 req/min, 5000 req/hour
- **Connections**: 100 per IP
- **Validation**: Basic (allows some suspicious patterns)
- **Headers**: Minimal security headers

#### Staging (`staging`)
- **Purpose**: Pre-production testing
- **Security Level**: Balanced
- **Rate Limits**: 60 req/min, 2000 req/hour
- **Connections**: 50 per IP
- **Validation**: Strict (blocks suspicious patterns)
- **Headers**: Full security headers (CSP, HSTS)

#### Production (`prod` / `production`)
- **Purpose**: Live production environment
- **Security Level**: Maximum
- **Rate Limits**: 30 req/min, 1000 req/hour
- **Connections**: 25 per IP
- **Validation**: Aggressive (immediate blocking)
- **Headers**: Maximum security headers

#### Security Testing (`security_test` / `pen_test`)
- **Purpose**: Penetration testing and security validation
- **Security Level**: Aggressive
- **Rate Limits**: 10 req/min, 100 req/hour
- **Connections**: 10 per IP
- **Validation**: Maximum (blocks everything suspicious)
- **Headers**: All security headers enabled

### Preset Configuration

Each preset configures:

- **Rate Limiting**: Requests per minute/hour, burst limits, block duration
- **DDoS Protection**: Maximum connections per IP, connection timeouts
- **Input Validation**: Strictness level, suspicious pattern blocking
- **Request Limits**: Maximum size, query parameters, headers
- **Auto-blocking**: Thresholds for malicious/suspicious requests
- **Security Headers**: CSP, HSTS, and other security headers
- **Excluded Paths**: Endpoints that bypass strict validation

## Usage

### Applying Security Presets

#### Command Line

```bash
# List available presets
python scripts/apply_security_preset.py --list

# Apply a preset
python scripts/apply_security_preset.py staging

# Test current configuration
python scripts/apply_security_preset.py --test

# Get recommendations for a preset
python scripts/apply_security_preset.py production --recommendations
```

#### Programmatic Usage

```python
from atous_sec_network.security.security_presets import get_security_preset

# Get a preset configuration
preset = get_security_preset("production")

# Apply to middleware
middleware = ComprehensiveSecurityMiddleware(
    app=app,
    security_preset="production"
)
```

### Configuration File

Security presets can be configured via YAML:

```yaml
# config/security_presets.yaml
presets:
  development:
    rate_limiting:
      requests_per_minute: 120
      requests_per_hour: 5000
    ddos_protection:
      max_connections_per_ip: 100
    # ... other settings
```

## Security Features

### Rate Limiting

- **Per-minute limits**: Configurable requests per minute
- **Per-hour limits**: Configurable requests per hour
- **Burst handling**: Temporary burst allowance
- **Auto-blocking**: Automatic IP blocking on limit exceeded
- **Configurable duration**: Block duration in minutes

### DDoS Protection

- **Connection limiting**: Maximum concurrent connections per IP
- **Automatic cleanup**: Connection count management
- **Configurable thresholds**: Environment-specific limits
- **Real-time monitoring**: Active connection tracking

### Input Validation

- **Path validation**: URL path security checking
- **Query parameter validation**: Parameter sanitization
- **Header validation**: Security header checking
- **Body validation**: JSON/XML content validation
- **Pattern detection**: Malicious pattern recognition

### Auto-blocking

- **Malicious request tracking**: Count of malicious requests
- **Suspicious request tracking**: Count of suspicious requests
- **Configurable thresholds**: Environment-specific blocking
- **Duration-based blocking**: Configurable block duration
- **Automatic unblocking**: Time-based IP unblocking

### Security Headers

- **X-Content-Type-Options**: Prevents MIME type sniffing
- **X-Frame-Options**: Prevents clickjacking
- **X-XSS-Protection**: XSS protection
- **Strict-Transport-Security**: HTTPS enforcement
- **Content-Security-Policy**: Content security policy
- **Referrer-Policy**: Referrer information control
- **Permissions-Policy**: Feature permissions

## Monitoring and Logging

### Security Events

The system logs various security events:

- Rate limit exceeded
- DDoS protection triggered
- Malicious request detected
- Suspicious pattern blocked
- IP auto-blocking
- Security header violations

### Metrics

Available security metrics:

- Total clients
- Blocked clients
- Total requests
- Malicious requests
- Suspicious requests
- Blocked IPs count
- Active connections

### Audit Log

Security events are logged with:

- Timestamp
- Client IP
- Request details
- Security action taken
- Threat type detected
- Response time

## Best Practices

### Development Environment

1. Use development preset for local testing
2. Monitor logs for security events
3. Test security features with known patterns
4. Review excluded paths regularly

### Staging Environment

1. Use staging preset for pre-production
2. Test all application features thoroughly
3. Monitor for false positives
4. Verify rate limiting impact

### Production Environment

1. Use production preset for live systems
2. Monitor system performance under load
3. Set up alerting for security events
4. Regular security audits
5. Consider penetration testing

### Security Testing

1. Use security_test preset for testing
2. Expect legitimate requests to be blocked
3. Monitor all blocked requests
4. Document false positives
5. Use only for security validation

## Troubleshooting

### Common Issues

#### Rate Limiting Too Aggressive

```bash
# Check current preset
python scripts/apply_security_preset.py --test

# Switch to more permissive preset
python scripts/apply_security_preset.py development
```

#### False Positives

1. Review security logs
2. Check preset configuration
3. Adjust thresholds if needed
4. Add legitimate patterns to exclusions

#### Performance Issues

1. Monitor response times
2. Check connection limits
3. Review rate limiting settings
4. Consider preset adjustment

### Debug Mode

Enable debug logging for security middleware:

```python
import logging
logging.getLogger('atous_sec_network.security').setLevel(logging.DEBUG)
```

## Integration

### CI/CD Pipeline

Use the health check script in your CI/CD:

```yaml
# .github/workflows/security-check.yml
- name: Security Health Check
  run: |
    python scripts/ci_health_check.py \
      --base-url ${{ secrets.API_URL }} \
      --timeout 30 \
      --output security_report.json
```

### Monitoring Systems

Integrate with monitoring systems:

- Prometheus metrics
- Grafana dashboards
- SIEM systems
- Alerting services

### External Services

Support for external integrations:

- External blocklists
- SIEM systems
- Notification services
- Security services

## Security Recommendations

### General

1. **Regular Updates**: Keep security presets updated
2. **Monitoring**: Monitor system logs regularly
3. **Testing**: Test security rules with known patterns
4. **Documentation**: Document custom configurations
5. **Audits**: Regular security audits

### Environment-Specific

1. **Development**: Use permissive settings, monitor events
2. **Staging**: Balance security and usability, test thoroughly
3. **Production**: Maximum security, monitor performance
4. **Testing**: Aggressive settings, expect blocking

### Advanced

1. **Custom Rules**: Add environment-specific patterns
2. **Integration**: Connect with external security services
3. **Automation**: Automate security responses
4. **Compliance**: Ensure compliance with security standards

## References

- [Security Middleware Implementation](../api/security_middleware.py)
- [Security Presets](../security/security_presets.py)
- [Input Validator](../security/input_validator.py)
- [Configuration Files](../../config/security_presets.yaml)
- [Management Scripts](../../scripts/apply_security_preset.py)
- [Health Check Scripts](../../scripts/ci_health_check.py)
