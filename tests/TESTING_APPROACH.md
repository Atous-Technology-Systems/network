# Testing Approach for Atous Secure Network

This document outlines the testing strategy and best practices for the Atous Secure Network project, with a focus on the ModelManager component as a reference implementation.

## Table of Contents
1. [Testing Philosophy](#testing-philosophy)
2. [Test Organization](#test-organization)
3. [Test Fixtures](#test-fixtures)
4. [Mocking Strategy](#mocking-strategy)
5. [Running Tests](#running-tests)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

## Testing Philosophy

Our testing approach follows these core principles:

1. **Isolation**: Each test should be independent and not rely on external systems or state.
2. **Determinism**: Tests should produce the same results every time they're run.
3. **Readability**: Test code should be as clear and maintainable as production code.
4. **Coverage**: Aim for high test coverage, especially for critical paths.
5. **Speed**: Tests should run quickly to enable fast feedback during development.

## Test Organization

Tests are organized following the project's package structure:

```
tests/
├── unit/                      # Unit tests
│   ├── __init__.py
│   ├── conftest.py           # Global test configuration
│   ├── conftest_model_manager.py  # ModelManager-specific fixtures
│   ├── test_model_manager_fixed.py
│   └── ...
└── integration/              # Integration tests
    └── ...
```

## Test Fixtures

We use pytest fixtures to set up test environments and provide test data. Fixtures are defined in `conftest.py` files at the appropriate level of the test directory structure.

### Example Fixture (ModelManager)

```python
# tests/unit/conftest_model_manager.py

import pytest
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_federated_model_updater():
    """Fixture to mock the FederatedModelUpdater class."""
    with patch('atous_sec_network.core.model_manager.FederatedModelUpdater') as mock_updater:
        mock_instance = MagicMock()
        mock_updater.return_value = mock_instance
        mock_instance.download_model.return_value = True
        yield mock_instance
```

## Mocking Strategy

We use `unittest.mock` to simulate external dependencies:

1. **External Services**: Mock all network calls, file I/O, and system operations.
2. **Dependencies**: Mock dependencies that are not part of the unit under test.
3. **Verification**: Use mock assertions to verify interactions.

### Example Mocking

```python
def test_download_model(model_manager, mock_federated_model_updater):
    model_url = 'http://example.com/model.pt'
    model_path = '/tmp/test_model/model.pt'
    
    result = model_manager.download_model(model_url, model_path)
    
    assert result is True
    mock_federated_model_updater.download_model.assert_called_once_with(
        model_url, 
        model_path,
        checksum=None,
        timeout=60,
        max_retries=3
    )
```

## Running Tests

Run all tests:
```bash
pytest
```

Run a specific test file:
```bash
pytest tests/unit/test_model_manager_fixed.py
```

Run with verbose output:
```bash
pytest -v
```

## Best Practices

1. **Test Naming**: Use descriptive test names that explain the behavior being tested.
2. **Arrange-Act-Assert**: Structure tests with clear sections for setup, execution, and verification.
3. **Minimal Fixtures**: Keep fixtures focused and minimal to improve test clarity.
4. **Parameterized Tests**: Use `@pytest.mark.parametrize` for testing multiple input scenarios.
5. **Test Documentation**: Document complex test logic and the reasoning behind test cases.

## Troubleshooting

### Common Issues

1. **Import Errors**: 
   - Ensure the Python path is set correctly.
   - Check for circular imports in test files.
   - Verify all dependencies are installed.

2. **Mocking Issues**:
   - Ensure you're patching the correct import path.
   - Use `patch.object` for instance methods.
   - Reset mocks between tests if needed.

3. **Test Isolation**:
   - If tests affect each other, check for shared state in fixtures or module-level variables.
   - Use `autouse` fixtures carefully.

### Debugging Tests

To debug a failing test:

1. Run the specific test with `-s` to see print statements:
   ```bash
   pytest tests/unit/test_example.py -v -s
   ```

2. Use `pdb` for interactive debugging:
   ```python
   import pdb; pdb.set_trace()
   ```

3. Check coverage to identify untested code:
   ```bash
   pytest --cov=atous_sec_network tests/
   ```

## Extending This Approach

To add tests for a new component:

1. Create a new test file in the appropriate directory.
2. Add component-specific fixtures to the nearest `conftest.py`.
3. Follow the patterns established in the ModelManager tests.
4. Document any new testing patterns or conventions.

## Additional Resources

- [pytest Documentation](https://docs.pytest.org/)
- [unittest.mock Documentation](https://docs.python.org/3/library/unittest.mock.html)
- [Python Testing with pytest](https://pythontest.com/pytest-book/)

---

*Last Updated: July 2025*
