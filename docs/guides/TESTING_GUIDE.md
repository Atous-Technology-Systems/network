# ATous Secure Network - Testing Guide

## Quick Start

### 1. Environment Setup
```bash
# Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run All Tests
```bash
# Run all unit tests with verbose output
python -m pytest tests/unit/ -v

# Run with coverage report
python -m pytest tests/unit/ --cov=atous_sec_network --cov-report=term-missing --cov-report=html --cov-report=xml
```

## Component Testing

### 1. Security Systems

#### ABISS System
```bash
# Run ABISS tests
python -m pytest tests/unit/test_abiss_system.py -v
```

#### NNIS System
```bash
# Run NNIS tests
python -m pytest tests/unit/test_nnis_system.py -v
```

### 2. Network Systems

#### LoRa Optimizer
```bash
# Run LoRa tests
python -m pytest tests/unit/test_lora_optimizer.py -v
```

#### P2P Recovery
```bash
# Run P2P Recovery tests
python -m pytest tests/unit/test_p2p_recovery.py -v
```

### 3. Core Systems

#### Model Manager
```bash
# Run Model Manager tests
python -m pytest tests/unit/test_model_manager.py -v
```

## Running the System

### 1. Start Core Services
```bash
# Start the main system service
python -m atous_sec_network.core.service

# Or run individual components:
python -m atous_sec_network.security.abiss_system
python -m atous_sec_network.security.nnis_system
python -m atous_sec_network.network.lora_optimizer
```

### 2. Test Hardware Integration (if available)
```bash
# Test LoRa hardware
python scripts/test_lora_hardware.py

# Test GPIO connections
python scripts/test_gpio.py
```

### 3. Monitor System
```bash
# Check system health
python scripts/health_check.py

# Monitor logs
tail -f logs/atous_network.log
```

## Test Categories

### 1. Unit Tests
- Individual component testing
- Mock external dependencies
- Fast execution

### 2. Integration Tests
- Component interaction testing
- Real dependencies
- Network communication

### 3. Hardware Tests
- Physical device testing
- GPIO and LoRa modules
- Real-world conditions

## Test Configuration

### 1. pytest.ini
```ini
[pytest]
testpaths = tests
python_files = test_*.py
python_functions = test_*
addopts = -v --tb=short
```

### 2. Coverage Configuration
```ini
[coverage:run]
source = atous_sec_network
omit = 
    */tests/*
    */__init__.py
```

## Common Testing Scenarios

### 1. Security Testing
```bash
# Test threat detection
python -m pytest tests/unit/test_abiss_system.py::TestABISSSystem::test_threat_detection -v

# Test immune response
python -m pytest tests/unit/test_nnis_system.py::TestNNISSystem::test_immune_response -v
```

### 2. Network Testing
```bash
# Test LoRa optimization
python -m pytest tests/unit/test_lora_optimizer.py::TestLoraOptimizer::test_parameter_adjustment -v

# Test P2P recovery
python -m pytest tests/unit/test_p2p_recovery.py::TestP2PRecovery::test_node_failure -v
```

### 3. Model Testing
```bash
# Test model updates
python -m pytest tests/unit/test_model_manager.py::TestModelManager::test_model_update -v
```

## Troubleshooting Tests

### 1. Common Issues

#### Test Timeouts
```bash
# Run with increased timeout
python -m pytest tests/unit/test_p2p_recovery.py --timeout=30
```

#### Hardware Access
```bash
# Skip hardware tests
python -m pytest -v -m "not hardware"
```

#### Memory Issues
```bash
# Run with memory profiling
mprof run python -m pytest tests/unit/test_model_manager.py
```

### 2. Debug Options
```bash
# Run with debug logging
python -m pytest -v --log-cli-level=DEBUG

# Run specific test with PDB
python -m pytest tests/unit/test_lora_optimizer.py -v --pdb
```

### 3. Clean Test Environment
```bash
# Remove cache and coverage files
python scripts/clean_tests.py
```

## Continuous Integration

### 1. Local CI Simulation
```bash
# Run full CI pipeline locally
./scripts/run_ci_pipeline.sh
```

### 2. Test Reports
```bash
# Generate HTML coverage report
python -m pytest --cov=atous_sec_network --cov-report=html

# Generate JUnit XML report
python -m pytest --junitxml=test-results.xml
```

## Performance Testing

### 1. Load Testing
```bash
# Run performance tests
python -m pytest tests/performance/ -v
```

### 2. Memory Profiling
```bash
# Profile memory usage
mprof run python -m pytest tests/performance/test_memory.py
mprof plot
```

## Best Practices

1. **Always run in virtual environment**
   ```bash
   .\venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/Mac
   ```

2. **Update dependencies when needed**
   ```bash
   pip install -r requirements.txt
   ```

3. **Clean environment before testing**
   ```bash
   python scripts/clean_env.py
   ```

4. **Check coverage regularly**
   ```bash
   python -m pytest --cov=atous_sec_network
   ```

5. **Review test logs**
   ```bash
   cat logs/test.log
   ```
