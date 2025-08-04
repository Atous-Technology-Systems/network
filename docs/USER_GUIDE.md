# ATous Secure Network - User Guide

This guide provides comprehensive instructions for installing, testing, and using the ATous Secure Network application.

## Table of Contents

- [System Requirements](#system-requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Application Modes](#application-modes)
- [Testing](#testing)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

## System Requirements

### Minimum Requirements
- **Python**: 3.8 or higher
- **RAM**: 4GB (8GB recommended for ML components)
- **Storage**: 2GB free space (additional space for ML models)
- **OS**: Windows 10+, macOS 10.14+, or Linux (Ubuntu 18.04+)

### Recommended Requirements
- **Python**: 3.10 or higher
- **RAM**: 16GB
- **Storage**: 10GB free space
- **GPU**: CUDA-compatible (optional, for ML acceleration)

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/Atous-Technology-Systems/network.git
cd network
```

### Step 2: Set Up Virtual Environment

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

### Step 3: Install Dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Verify Installation

```bash
python debug_import.py
```

If successful, you should see:
```
✓ All imports successful
✓ Package structure validated
✓ Dependencies satisfied
```

## ⚡ Quick Start

### Option 1: Application Starter (Recommended)

```bash
# Check system status
python start_app.py --status

# Quick test (lightweight, fast)
python start_app.py --lite

# Full application (complete system)
python start_app.py --full
```

### Option 2: Direct Execution

```bash
# Lightweight test
python run_app_lite.py

# Full application
python -m atous_sec_network
```

## Application Modes

### Lightweight Mode (`--lite`)

**Best for:**
- First-time users
- Development and testing
- Quick functionality verification
- Systems with limited resources

**Features:**
- Fast startup (< 10 seconds)
- Basic functionality testing
- Package structure validation
- No ML model loading
- Limited security features

**Usage:**
```bash
python start_app.py --lite
```

### Full Mode (`--full`)

**Best for:**
- Production deployment
- Complete system testing
- ML-powered security features
- Full capability demonstration

**Features:**
- Complete system initialization
- All security systems active
- ML model loading
- Production-ready
- Longer startup time (2-5 minutes first time)
- Higher resource usage

**Usage:**
```bash
python start_app.py --full
# or
python -m atous_sec_network
```

## 🧪 Testing

### Quick Testing

```bash
# Run all tests
python start_app.py --test

# Check application status
python start_app.py --status

# Debug any issues
python start_app.py --debug
```

### Detailed Testing

```bash
# Unit tests
python -m pytest tests/unit/ -v

# Integration tests
python -m pytest tests/integration/ -v

# Security tests
python -m pytest tests/security/ -v

# All tests with coverage
python -m pytest tests/ --cov=atous_sec_network --cov-report=html
```

### Test Results Interpretation

**All tests passing**: System is ready for use
**Some tests skipped**: Normal (hardware-dependent tests)
**Tests failing**: Check troubleshooting section

## 📖 Usage Examples

### Example 1: First-Time User

```bash
# 1. Check if everything is installed correctly
python start_app.py --status

# 2. Run a quick test
python start_app.py --lite

# 3. If successful, try the full application
python start_app.py --full
```

### Example 2: Developer Workflow

```bash
# 1. Start development session
python start_app.py --debug

# 2. Run tests after changes
python start_app.py --test

# 3. Quick validation
python start_app.py --lite

# 4. Full system test
python start_app.py --full
```

### Example 3: Production Deployment

```bash
# 1. Verify environment
python start_app.py --status

# 2. Run comprehensive tests
python start_app.py --test

# 3. Deploy full application
python start_app.py --full
```

## Troubleshooting

### Common Issues

#### Import Errors

**Problem**: `ModuleNotFoundError` or import failures

**Solution**:
```bash
# Check dependencies
python start_app.py --debug

# Reinstall requirements
pip install -r requirements.txt --force-reinstall

# Verify Python path
python -c "import sys; print('\n'.join(sys.path))"
```

#### Slow Startup

**Problem**: Application takes too long to start

**Solution**:
```bash
# Use lightweight mode for testing
python start_app.py --lite

# Check available disk space
# Models require significant storage
```

#### Memory Issues

**Problem**: Out of memory errors

**Solution**:
```bash
# Use lightweight mode
python start_app.py --lite

# Close other applications
# Consider upgrading RAM
```

#### Test Failures

**Problem**: Tests are failing

**Solution**:
```bash
# Run specific failing test
python -m pytest tests/unit/test_specific.py -v -s

# Check test configuration
cat pytest.ini

# Verify environment
python start_app.py --debug
```

### Getting Help

1. **Check Documentation**:
   - `README.md` - Project overview
   - `PROJECT_STATUS.md` - Current status
   - `docs/development/README.md` - Development guide
   - `api-contracts.md` - API documentation

2. **Run Diagnostics**:
   ```bash
   python start_app.py --debug
   python start_app.py --status
   ```

3. **Check Logs**:
   - Application logs are displayed in console
   - Test logs available with `-v` flag

## Advanced Configuration

### Environment Variables

```bash
# Set log level
export ATOUS_LOG_LEVEL=DEBUG

# Configure model cache directory
export ATOUS_MODEL_CACHE=/path/to/cache

# Enable GPU acceleration (if available)
export ATOUS_USE_GPU=true
```

### Custom Configuration

Create a `config.json` file in the project root:

```json
{
  "security": {
    "abiss_enabled": true,
    "nnis_enabled": true
  },
  "network": {
    "lora_simulation": true,
    "p2p_enabled": true
  },
  "ml": {
    "model_cache_dir": "./models",
    "use_gpu": false
  }
}
```

### Performance Tuning

**For Development**:
```bash
# Always use lightweight mode
python start_app.py --lite

# Run specific tests only
python -m pytest tests/unit/test_specific.py
```

**For Production**:
```bash
# Ensure adequate resources
# Pre-download models
# Use SSD storage
# Enable GPU if available
```

## Monitoring and Logs

### Application Logs

Logs are displayed in real-time during execution:

```
2024-01-01 12:00:00 - INFO - System initialization started
2024-01-01 12:00:01 - INFO - ABISS Security System ready
2024-01-01 12:00:02 - INFO - NNIS Immune System ready
2024-01-01 12:00:03 - INFO - All systems operational
```

### Performance Metrics

The application provides performance metrics:

- **Startup Time**: Time to initialize all systems
- **Memory Usage**: Current RAM consumption
- **Model Loading**: Time to load ML models
- **Test Coverage**: Percentage of code tested

### Health Checks

```bash
# Quick health check
python start_app.py --status

# Comprehensive system check
python start_app.py --debug

# Test system functionality
python start_app.py --lite
```

---

## 📞 Support

For additional support:

- **Documentation**: Check the `docs/` directory
- **Issues**: Report bugs via GitHub issues
- **Development**: See `docs/development/README.md`
- **API Reference**: See `api-contracts.md`

**Happy using ATous Secure Network!**