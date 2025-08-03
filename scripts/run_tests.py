#!/usr/bin/env python
"""
ATous Secure Network Test Runner
Runs all tests and generates coverage reports
"""
import os
import sys
import subprocess
import argparse
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def setup_environment():
    """Setup test environment"""
    logger.info("Setting up test environment...")
    
    # Ensure we're in the project root
    project_root = Path(__file__).parent.parent
    os.chdir(project_root)
    
    # Check virtual environment
    if not os.environ.get('VIRTUAL_ENV'):
        logger.warning("Not running in a virtual environment!")
        if input("Continue anyway? (y/N) ").lower() != 'y':
            sys.exit(1)
    
    # Install hardware mocks for development
    logger.info("Installing hardware mocks...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", "tests/mocks"],
            check=True
        )
    except subprocess.CalledProcessError:
        logger.error("Failed to install hardware mocks")
        sys.exit(1)
    
    # Check and install test dependencies
    try:
        import pytest
        import coverage
    except ImportError:
        logger.error("Required packages not found. Installing dependencies...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-e", ".[dev]"],
            check=True
        )

def run_tests(args):
    """Run the test suite"""
    logger.info("Running tests...")
    
    # Build pytest command
    cmd = [sys.executable, "-m", "pytest"]
    
    # Add verbosity
    if args.verbose:
        cmd.append("-v")
        
    # Add test path
    if args.component:
        cmd.append(f"tests/unit/test_{args.component}.py")
    else:
        cmd.append("tests/unit/")
    
    # Add coverage if requested
    if args.coverage:
        cmd.extend([
            "--cov=atous_sec_network",
            "--cov-report=term-missing",
            "--cov-report=html",
            "--cov-report=xml"
        ])
    
    # Add debug options
    if args.debug:
        cmd.extend(["--log-cli-level=DEBUG"])
    
    # Run tests
    try:
        result = subprocess.run(cmd, check=True)
        logger.info("Tests completed successfully")
        return result.returncode == 0
    except subprocess.CalledProcessError as e:
        logger.error(f"Tests failed with exit code {e.returncode}")
        return False

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="ATous Secure Network Test Runner")
    parser.add_argument("-c", "--component", help="Specific component to test (e.g., lora_optimizer)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--coverage", action="store_true", help="Generate coverage reports")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    # Setup
    setup_environment()
    
    # Run tests
    success = run_tests(args)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
