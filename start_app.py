#!/usr/bin/env python3
"""
ATous Secure Network - Application Starter

This script provides multiple ways to run and test the ATous Secure Network application.
"""

import sys
import subprocess
import argparse
from pathlib import Path

def run_full_app():
    """
    Run the full application with all ML components.
    """
    print("🚀 Starting ATous Secure Network (Full Version)...")
    print("⚠️  Note: This may take some time due to ML model loading.\n")
    
    try:
        result = subprocess.run([sys.executable, "-m", "atous_sec_network"], 
                              capture_output=False, text=True, timeout=300)
        return result.returncode
    except subprocess.TimeoutExpired:
        print("\n⏰ Application startup timed out (5 minutes).")
        print("   This is normal for first-time ML model downloads.")
        return 1
    except KeyboardInterrupt:
        print("\n🛑 Application stopped by user.")
        return 0

def run_lite_test():
    """
    Run the lightweight test version.
    """
    print("🧪 Running ATous Secure Network (Lightweight Test)...\n")
    
    try:
        result = subprocess.run([sys.executable, "run_app_lite.py"], 
                              capture_output=False, text=True)
        return result.returncode
    except Exception as e:
        print(f"❌ Error running lite test: {e}")
        return 1

def run_tests():
    """
    Run the test suite.
    """
    print("🧪 Running ATous Secure Network Test Suite...\n")
    
    try:
        result = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"], 
                              capture_output=False, text=True)
        return result.returncode
    except Exception as e:
        print(f"❌ Error running tests: {e}")
        return 1

def run_debug():
    """
    Run the debug import script.
    """
    print("🔍 Running ATous Secure Network Debug Check...\n")
    
    try:
        result = subprocess.run([sys.executable, "debug_import.py"], 
                              capture_output=False, text=True)
        return result.returncode
    except Exception as e:
        print(f"❌ Error running debug: {e}")
        return 1

def show_status():
    """
    Show application status and available options.
    """
    print("🛡️ ATous Secure Network - Application Status")
    print("=" * 60)
    
    # Check if key files exist
    project_root = Path.cwd()
    key_files = {
        'Main Application': 'atous_sec_network/__main__.py',
        'Lite Test': 'run_app_lite.py',
        'Debug Script': 'debug_import.py',
        'Test Suite': 'tests/',
        'Documentation': 'docs/',
        'Requirements': 'requirements.txt'
    }
    
    print("\n📁 Project Components:")
    for name, path in key_files.items():
        full_path = project_root / path
        status = "✅" if full_path.exists() else "❌"
        print(f"   {status} {name}: {path}")
    
    print("\n🚀 Available Commands:")
    print("   python start_app.py --full      # Run full application")
    print("   python start_app.py --lite      # Run lightweight test")
    print("   python start_app.py --test      # Run test suite")
    print("   python start_app.py --debug     # Run debug check")
    print("   python start_app.py --status    # Show this status")
    
    print("\n📚 Documentation:")
    print("   README.md                       # Project overview")
    print("   PROJECT_STATUS.md               # Current status")
    print("   docs/development/README.md      # Development guide")
    print("   api-contracts.md                # API documentation")
    
    return 0

def main():
    """
    Main entry point with command line argument parsing.
    """
    parser = argparse.ArgumentParser(
        description="ATous Secure Network Application Starter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python start_app.py --lite     # Quick test without ML components
  python start_app.py --full     # Full application with ML components
  python start_app.py --test     # Run all tests
  python start_app.py --debug    # Debug import issues
        """
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--full', action='store_true', 
                      help='Run the full application with ML components')
    group.add_argument('--lite', action='store_true', 
                      help='Run lightweight test version')
    group.add_argument('--test', action='store_true', 
                      help='Run the test suite')
    group.add_argument('--debug', action='store_true', 
                      help='Run debug import check')
    group.add_argument('--status', action='store_true', 
                      help='Show application status')
    
    args = parser.parse_args()
    
    if args.full:
        return run_full_app()
    elif args.lite:
        return run_lite_test()
    elif args.test:
        return run_tests()
    elif args.debug:
        return run_debug()
    elif args.status:
        return show_status()
    else:
        # Default: show status and run lite test
        show_status()
        print("\n" + "=" * 60)
        print("🧪 Running default lightweight test...\n")
        return run_lite_test()

if __name__ == "__main__":
    sys.exit(main())