"""
Isolated test runner for P2P Recovery tests.

This script runs the P2P recovery tests in an isolated environment,
without relying on the global conftest.py configuration.
"""
import unittest
import sys
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def run_tests():
    """Run the P2P recovery tests."""
    # Add the project root to the Python path
    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Discover and run the tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover(
        start_dir=os.path.join(project_root, 'tests', 'unit'),
        pattern='test_p2p_recovery_isolated.py'
    )
    
    # Run the tests
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    
    # Exit with appropriate status code
    sys.exit(not result.wasSuccessful())

if __name__ == '__main__':
    run_tests()
