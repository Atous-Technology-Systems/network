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
   git clone https://github.com/yourusername/atous-secure-network.git
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

## Testing

### Running Tests

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
