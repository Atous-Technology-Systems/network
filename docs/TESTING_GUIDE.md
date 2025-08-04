# ATous Secure Network - Testing Guide

## Overview

This guide provides comprehensive instructions for testing the ATous Secure Network system, including unit tests, integration tests, and API endpoint testing.

## Environment Setup

### Prerequisites

```bash
# Ensure Python 3.8+ is installed
python --version

# Install dependencies
pip install -r requirements.txt

# Install testing dependencies
pip install pytest pytest-cov pytest-asyncio
```

## Test Execution

### Running All Tests

```bash
# Run the complete test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=atous_sec_network --cov-report=html

# Run the complete functionality test
python tests/test_complete_functionality.py
```

### API Endpoint Testing

After starting the server with `python -m atous_sec_network.api.server`, test individual endpoints:

#### Core Endpoints
```bash
# Root endpoint
curl http://localhost:8000/

# Health check
curl http://localhost:8000/health

# API information
curl http://localhost:8000/api/info

# Security status
curl http://localhost:8000/api/security/status

# System metrics
curl http://localhost:8000/api/metrics
```

#### Documentation Endpoints
```bash
# OpenAPI schema
curl http://localhost:8000/openapi.json

# Interactive docs (open in browser)
# http://localhost:8000/docs
# http://localhost:8000/redoc
```

#### Encryption Endpoints
```bash
# Test encryption (example with curl)
curl -X POST http://localhost:8000/api/crypto/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "test message"}'

curl -X POST http://localhost:8000/api/security/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "test message"}'

curl -X POST http://localhost:8000/encrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "test message"}'
```

#### WebSocket Testing
```bash
# Test WebSocket connection (requires wscat or similar tool)
wscat -c ws://localhost:8000/ws
```

## Component Testing

### Security Systems Testing

#### ABISS System
```bash
# Test ABISS components
python -m pytest tests/test_abiss.py -v
```

#### NNIS System
```bash
# Test NNIS components
python -m pytest tests/test_nnis.py -v
```

### Network Systems Testing

#### P2P Recovery System
```bash
# Test P2P recovery functionality
python -m pytest tests/test_p2p_recovery.py -v
```

#### LoRa Adaptive Engine
```bash
# Test LoRa optimization
python -m pytest tests/test_lora_adaptive.py -v
```

### Central Systems Testing

#### Model Manager
```bash
# Test model management
python -m pytest tests/test_model_manager.py -v
```

#### LLM Integration
```bash
# Test LLM integration
python -m pytest tests/test_llm_integration.py -v
```

## System Execution Testing

### Starting Main Services

1. **Start the API Server**
   ```bash
   python -m atous_sec_network.api.server
   ```
   - Verify server starts on http://localhost:8000
   - Check logs for any initialization errors

2. **Test Core Functionality**
   ```bash
   # Run complete functionality test
   python tests/test_complete_functionality.py
   ```
   - Should show 100% success rate for all endpoints
   - Generates detailed report in JSON format

### Hardware Integration Testing

1. **Network Interface Testing**
   - Verify network adapters are detected
   - Test connectivity to configured networks

2. **Security Hardware Testing**
   - Test hardware security modules if available
   - Verify cryptographic acceleration

### System Monitoring

1. **Performance Metrics**
   - Monitor CPU and memory usage via `/api/metrics`
   - Check system uptime and response times

2. **Security Monitoring**
   - Verify threat detection systems are active
   - Test anomaly detection capabilities

## Test Categories

### Unit Tests
- Individual component functionality
- Isolated module testing
- Mock external dependencies

### Integration Tests
- Component interaction testing
- API endpoint integration
- Database connectivity

### End-to-End Tests
- Complete workflow testing
- User scenario simulation
- Performance benchmarking

### Security Tests
- Vulnerability scanning
- Penetration testing
- Input validation testing

## Expected Results

### Successful Test Execution
- All endpoints return appropriate HTTP status codes
- WebSocket connections establish successfully
- Encryption/decryption operations complete without errors
- System metrics are collected and reported accurately

### Performance Benchmarks
- API response times < 100ms for simple endpoints
- Encryption operations complete within acceptable timeframes
- System maintains stability under load

## Troubleshooting

### Common Issues

1. **Server Won't Start**
   - Check port 8000 availability
   - Verify all dependencies are installed
   - Review error logs for specific issues

2. **Test Failures**
   - Ensure server is running before API tests
   - Check network connectivity
   - Verify configuration files are present

3. **Performance Issues**
   - Monitor system resources
   - Check for memory leaks
   - Review log files for bottlenecks

## Continuous Integration

### Automated Testing
- Set up CI/CD pipelines for automated testing
- Include code coverage requirements
- Implement security scanning in CI process

### Test Reporting
- Generate detailed test reports
- Track test coverage metrics
- Monitor performance trends over time