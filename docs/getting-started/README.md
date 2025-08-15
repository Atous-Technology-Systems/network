# Getting Started with ATous Secure Network

## Table of Contents

1. [Quick Start](#quick-start)
2. [Installation](#installation)
   - [Prerequisites](#prerequisites)
   - [Installation Steps](#installation-steps)
3. [Application Modes](#application-modes)
   - [Understanding Different Modes](#understanding-different-modes)
   - [When to Use Each Mode](#when-to-use-each-mode)
4. [Starting the Application](#starting-the-application)
   - [Testing Mode](#testing-mode)
   - [Demo Mode](#demo-mode)
   - [Web Server Mode](#web-server-mode)
5. [Basic Operations](#basic-operations)
   - [Checking System Status](#checking-system-status)
   - [Testing Security Features](#testing-security-features)
   - [Using API Endpoints](#using-api-endpoints)
6. [Next Steps](#next-steps)

## Quick Start

### For the Impatient

1. Clone and install:
   ```bash
   git clone https://github.com/devrodts/Atous-Sec-Network.git
   cd Atous-Sec-Network
   pip install -r requirements.txt
   ```

2. Test the installation:
   ```bash
   python start_app.py --lite
   ```

3. Start the web server:
   ```bash
   python start_server.py
   ```

4. Verify the system is running:
   ```bash
   curl http://localhost:8000/health
   ```

5. Access the documentation:
   Open http://localhost:8000/docs in your browser

## Installation

### Prerequisites

- **Python**: 3.8 or higher (3.10+ recommended)
- **pip**: Python package manager
- **Git**: For cloning the repository
- **Virtual Environment**: Highly recommended
- **RAM**: 4GB minimum (8GB+ recommended for ML features)
- **Storage**: 2GB free space (additional for ML models)

### Installation Steps

#### Step 1: Clone the Repository

```bash
git clone https://github.com/devrodts/Atous-Sec-Network.git
cd Atous-Sec-Network
```

#### Step 2: Create Virtual Environment

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/macOS:**
```bash
python -m venv venv
source venv/bin/activate
```

#### Step 3: Install Dependencies

```bash
# For Windows development
pip install -r requirements-dev-windows.txt

# For Linux/Production
pip install -r requirements.txt
```

#### Step 4: Verify Installation

```bash
python start_app.py --debug
```

You should see:
```
✓ All imports successful
✓ Package structure validated
✓ Dependencies satisfied
```

## Application Modes

### Understanding Different Modes

ATous Secure Network has three distinct execution modes:

| Mode | Command | Web Server | Duration | Purpose |
|------|---------|------------|----------|---------|
| **🧪 Import Test** | `python start_app.py --lite` | ❌ No | ~10 seconds | Test imports only |
| **🎯 Demo Mode** | `python start_app.py --full` | ❌ No | ~30 seconds | System demonstration |
| **🌐 Web Server** | `python start_server.py` | ✅ Yes | Continuous | Production usage |

### When to Use Each Mode

#### Import Test Mode (`--lite`)
- **Use for**: First-time setup, CI/CD, quick validation
- **Features**: Fast import testing, no ML models, exits immediately
- **Best for**: Developers, automated testing

#### Demo Mode (`--full`)
- **Use for**: System verification, status checking, demonstrations
- **Features**: Full system initialization, shows status, exits after demo
- **Best for**: Verification, troubleshooting, presentations

#### Web Server Mode
- **Use for**: Production, development, API access, testing endpoints
- **Features**: FastAPI server, all endpoints, WebSockets, continuous operation
- **Best for**: Real usage, API testing, production deployment

## Starting the Application

### Testing Mode (Quick Validation)

```bash
# Check system status
python start_app.py --status

# Test imports (fast, exits immediately)
python start_app.py --lite

# Debug any issues
python start_app.py --debug
```

**Expected Output:**
```
ATous Secure Network - Lightweight Mode
==========================================
Testing Core Imports...
   ✓ atous_sec_network imported successfully
Testing Security Modules...
   ✓ ABISS System available
   ✓ NNIS System available
Lightweight test completed successfully!
```

### Demo Mode (System Verification)

```bash
# Full system demonstration (exits after showing status)
python start_app.py --full
# or
python -m atous_sec_network
```

**Expected Output:**
```
ATous Secure Network - Starting Application
============================================================
✓ Security systems imported successfully
✓ Network systems imported successfully
✓ All systems initialized successfully!

System Status Summary:
   ✓ ABISS Security: Active
   ✓ NNIS Immune: Active
   ✓ LoRa Network: Active (Simulation)
   ✓ P2P Recovery: Active
   ✓ Model Manager: Active
   ✓ Cognitive AI: Active

ATous Secure Network is ready for operation!
```

### Web Server Mode (Production Usage)

```bash
# Start the FastAPI web server
python start_server.py

# Or with custom options
python start_server.py --host 0.0.0.0 --port 8000 --reload

# Or using uvicorn directly
python -m uvicorn atous_sec_network.api.server:app --host 0.0.0.0 --port 8000 --reload
```

**Expected Output:**
```
🚀 Starting ATous Secure Network Server...
📡 Server will be available at: http://127.0.0.1:8000
📖 API Documentation: http://127.0.0.1:8000/docs
🔍 Health Check: http://127.0.0.1:8000/health
🔒 Security Status: http://127.0.0.1:8000/api/security/status
============================================================
INFO:     Started server process [12345]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```

## Basic Operations

### Checking System Status

```bash
# Check application status
python start_app.py --status

# Quick health check (if server is running)
curl http://localhost:8000/health

# Detailed security status
curl http://localhost:8000/api/security/status

# System metrics
curl http://localhost:8000/api/metrics
```

### Testing Security Features

```bash
# Test cryptography endpoints
curl -X POST "http://localhost:8000/api/crypto/encrypt" \
     -H "Content-Type: application/json" \
     -d '{"message": "Hello World", "algorithm": "AES-256"}'

# Test security detection (should be blocked)
curl "http://localhost:8000/api/v1/test?id=1' OR '1'='1"
```

### Using API Endpoints

#### Health and Status Endpoints

```bash
# Basic health check
curl http://localhost:8000/health

# API information
curl http://localhost:8000/api/info

# Security system status
curl http://localhost:8000/api/security/status

# System performance metrics
curl http://localhost:8000/api/metrics
```

#### Cryptography Endpoints

```bash
# Encrypt data via crypto endpoint
curl -X POST "http://localhost:8000/api/crypto/encrypt" \
     -H "Content-Type: application/json" \
     -d '{"message": "Secret data", "algorithm": "AES-256"}'

# Encrypt via security endpoint
curl -X POST "http://localhost:8000/api/security/encrypt" \
     -H "Content-Type: application/json" \
     -d '{"message": "Confidential info", "algorithm": "AES-256"}'
```

#### Interactive Documentation

Visit http://localhost:8000/docs in your browser for:
- Complete API documentation
- Interactive endpoint testing
- Request/response examples
- Authentication details

### Running Comprehensive Tests

```bash
# Run all functionality tests
python test_complete_functionality.py

# Test WebSocket connections
python test_websocket_fix.py

# Test security systems
python test_security_final.py

# Generate final system report
python test_final_summary.py
```

## Next Steps

1. Explore the [API Reference](../api-reference/README.md) for detailed API documentation
2. Learn about [Deployment Options](../deployment/README.md) for production environments
3. Check out the [Development Guide](../development/README.md) for contributing to the project
4. Join our community forum/slack for support and discussions

## Troubleshooting

### Common Issues

#### Node Fails to Start
- Check if the port is already in use
- Verify configuration file syntax
- Check log files for errors

#### Connection Issues
- Verify network connectivity between nodes
- Check firewall settings
- Ensure correct bootstrap node addresses

