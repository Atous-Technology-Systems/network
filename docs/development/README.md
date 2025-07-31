# Development Guide

## Table of Contents

1. [Development Environment Setup](#development-environment-setup)
2. [Testing](#testing)
   - [Running Tests](#running-tests)
   - [Writing Tests](#writing-tests)
3. [Code Style](#code-style)
4. [Version Control](#version-control)
5. [Debugging](#debugging)
6. [Performance Profiling](#performance-profiling)

## Development Environment Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment (recommended)

### Setup Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/Atous-Technology-Systems/network.git
   cd atous-secure-network
   ```

2. Create and activate a virtual environment:
   ```bash
   # On Windows
   python -m venv venv
   .\venv\Scripts\activate
   
   # On Unix/macOS
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install development dependencies:
   ```bash
   pip install -r requirements-dev.txt
   ```

4. Install the package in development mode:
   ```bash
   pip install -e .
   ```

5. Verify installation with debug script:
   ```bash
   python debug_import.py
   ```

## Testing

### Quick Testing

For rapid development testing:

```bash
# Application starter with multiple options
python start_app.py --test     # Run full test suite
python start_app.py --lite     # Quick functionality test
python start_app.py --debug    # Debug import issues
python start_app.py --status   # Check application status
```

### Comprehensive Testing

Run the complete test suite:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test categories with pytest.ini configuration
python -m pytest tests/unit/ -v          # Unit tests
python -m pytest tests/integration/ -v   # Integration tests
python -m pytest tests/security/ -v      # Security tests

# Run LoRa-specific tests
python -m pytest -k "lora" -v

# Run ABISS system tests
python -m pytest -k "abiss" -v

# Generate coverage report
python -m pytest tests/ --cov=atous_sec_network --cov-report=html
```

### Test Categories

**Unit Tests** (`tests/unit/`):
- Individual component testing
- Mock-based isolation
- Fast execution
- Core functionality validation

**Integration Tests** (`tests/integration/`):
- Component interaction testing
- System-level validation
- End-to-end workflows

**Security Tests** (`tests/security/`):
- ABISS system validation
- NNIS immune system testing
- Security protocol verification

### Testing Best Practices

1. **Always run tests before committing**:
   ```bash
   python start_app.py --test
   ```

2. **Use lightweight testing during development**:
   ```bash
   python start_app.py --lite
   ```

3. **Debug import issues immediately**:
   ```bash
   python start_app.py --debug
   ```

4. **Verify specific components**:
   ```bash
   python -m pytest tests/unit/test_specific_component.py -v
   ```

### Running Tests

The project includes a standardized `pytest.ini` configuration file for consistent test execution.

Run all tests:
```bash
pytest
```

Run a specific test file:
```bash
pytest tests/unit/test_module.py
```

Run tests with coverage report:
```bash
pytest --cov=atous_sec_network tests/
```

Run specific test categories:
```bash
# Run only LoRa tests
pytest test_lora_direct_import.py test_lora_simple_import.py

# Run ABISS system tests
pytest tests/unit/test_abiss_system.py
```

### Writing Tests

1. Follow the `test_` naming convention for test files and functions
2. Place tests in the appropriate `tests/` subdirectory
3. Use descriptive test names
4. Include docstrings explaining test purpose

Example test structure:
```python
def test_feature_should_do_something():
    # Setup
    obj = SomeClass()
    
    # Exercise
    result = obj.method()
    
    # Verify
    assert result == expected_value
```

### Alternative Test Configurations

The project includes multiple pytest configuration files for different scenarios:

- `tests/unit/conftest_lora_fixed.py` - LoRa tests with GPIO mocking
- `tests/unit/conftest_backup.py` - Backup configuration with model manager fixtures
- `tests/unit/conftest.py.disabled` - External dependency stubbing (rename to `conftest.py` to activate)

## Application Usage

### Running the Application

**Application Starter Script** (Recommended):
```bash
# Check application status
python start_app.py --status

# Quick lightweight test
python start_app.py --lite

# Full application with ML components
python start_app.py --full

# Run test suite
python start_app.py --test

# Debug import issues
python start_app.py --debug
```

**Direct Execution**:
```bash
# Main application entry point
python -m atous_sec_network

# Lightweight testing
python run_app_lite.py

# Debug imports
python debug_import.py
```

### Application Modes

**Lightweight Mode** (`--lite`):
- Fast startup (< 10 seconds)
- No ML model loading
- Basic functionality testing
- Ideal for development and CI/CD
- Tests package structure and imports

**Full Mode** (`--full`):
- Complete system initialization
- ML model loading (may take 2-5 minutes first time)
- All security systems active
- Production-ready deployment
- Downloads models if not cached

### Development Workflow

1. **Start Development Session**:
   ```bash
   # Activate virtual environment
   source venv/bin/activate  # Linux/Mac
   venv\Scripts\activate     # Windows
   
   # Check system status
   python start_app.py --status
   ```

2. **Make Changes and Test**:
   ```bash
   # Quick validation
   python start_app.py --lite
   
   # Run relevant tests
   python -m pytest tests/unit/test_your_module.py -v
   ```

3. **Full Validation**:
   ```bash
   # Complete test suite
   python start_app.py --test
   
   # Full system test
   python start_app.py --full
   ```

4. **Commit Changes**:
   ```bash
   git add .
   git commit -m "feat: your feature description"
   ```

## Development Debugging

Use the debug import script to troubleshoot import issues:

```bash
python debug_import.py
# or
python start_app.py --debug
```

This script helps identify:
- Missing dependencies
- Import path issues
- Module loading problems
- Environment configuration issues
- Package structure validation

### Common Issues and Solutions

**Import Errors**:
```bash
# Check Python path and dependencies
python debug_import.py

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

**ML Model Loading Issues**:
```bash
# Use lightweight mode for development
python start_app.py --lite

# Check available disk space (models can be large)
df -h  # Linux/Mac
dir C:\ # Windows
```

**Test Failures**:
```bash
# Run specific failing test with verbose output
python -m pytest tests/unit/test_failing.py -v -s

# Check test configuration
cat pytest.ini
```

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use type hints for all function signatures
- Keep lines under 100 characters
- Use docstrings for all public modules, classes, and functions

### Linting

Run the linter:
```bash
flake8 atous_sec_network
```

### Formatting

Use `black` for code formatting:
```bash
black atous_sec_network
```

## Version Control

### Branch Naming

Use the following format for branch names:
```
<type>/<short-description>
```

Where `<type>` is one of:
- `feature/`: New features
- `fix/`: Bug fixes
- `docs/`: Documentation changes
- `refactor/`: Code refactoring
- `test/`: Test-related changes

### Commit Messages

Follow the Conventional Commits specification:
```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

Example:
```
fix(model-manager): fix rollback version check

- Add validation for version existence in metadata
- Add test cases for rollback scenarios

Fixes #123
```

## Debugging

### Debugging Tests

Use `pdb` for debugging:
```python
import pdb; pdb.set_trace()  # Add this line where you want to break
```

### Logging

Use the built-in logging module:
```python
import logging
logger = logging.getLogger(__name__)
logger.debug('Debug message')
logger.info('Info message')
logger.warning('Warning message')
logger.error('Error message')
```

## Performance Profiling

### CPU Profiling

Use `cProfile`:
```python
import cProfile
import pstats

def profile_function():
    # Code to profile here
    pass

profiler = cProfile.Profile()
profiler.runcall(profile_function)
stats = pstats.Stats(profiler)
stats.sort_stats('cumulative').print_stats(10)
```

### Memory Profiling

Use `memory_profiler`:
```python
from memory_profiler import profile

@profile
def memory_intensive_function():
    # Memory-intensive code here
    pass
```

## Documentation

### Building Documentation

1. Install documentation requirements:
   ```bash
   pip install -r docs/requirements.txt
   ```

2. Build the documentation:
   ```bash
   cd docs
   make html
   ```

3. View the documentation by opening `_build/html/index.html` in your browser.

### Writing Documentation

- Use reStructuredText for API documentation
- Include examples for all public APIs
- Document all parameters and return values
- Update documentation when changing behavior
