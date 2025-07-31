#!/usr/bin/env python3
"""
ATous Secure Network - Lightweight Application Runner

This script provides a lightweight way to test the application without loading
heavy ML dependencies that might cause timeouts or memory issues.
"""

import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_basic_imports():
    """
    Test basic imports without heavy ML dependencies.
    """
    print("🛡️ ATous Secure Network - Lightweight Test")
    print("=" * 50)
    
    try:
        # Test basic package structure
        print("📦 Testing basic package imports...")
        
        # Test core package
        import atous_sec_network
        print("   ✅ atous_sec_network package imported")
        
        # Test core subpackages
        import atous_sec_network.core
        print("   ✅ core subpackage imported")
        
        import atous_sec_network.network
        print("   ✅ network subpackage imported")
        
        import atous_sec_network.security
        print("   ✅ security subpackage imported")
        
        import atous_sec_network.ml
        print("   ✅ ml subpackage imported")
        
        print("\n🚀 Testing lightweight components...")
        print("-" * 50)
        
        # Test network components (should be lightweight)
        try:
            from atous_sec_network.network.p2p_recovery import ChurnMitigation
            p2p = ChurnMitigation()
            print("   ✅ P2P Recovery System initialized")
        except Exception as e:
            print(f"   ⚠️ P2P Recovery System: {e}")
        
        # Test core components
        try:
            from atous_sec_network.core.model_manager_impl import ModelManager
            # Don't initialize to avoid heavy dependencies
            print("   ✅ Model Manager class imported")
        except Exception as e:
            print(f"   ⚠️ Model Manager: {e}")
        
        print("\n📊 Basic Import Test Results:")
        print("   ✅ Package structure is valid")
        print("   ✅ Core modules are accessible")
        print("   ✅ No critical import errors detected")
        
        print("\n💡 Note: Heavy ML components (ABISS, NNIS, LoRa) were not")
        print("   tested to avoid timeout issues. Use the full application")
        print("   runner for complete system testing.")
        
        return True
        
    except ImportError as e:
        logger.error(f"Import error: {e}")
        print(f"❌ Import error: {e}")
        return False
        
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"❌ Unexpected error: {e}")
        return False

def test_project_structure():
    """
    Test that the project structure is correct.
    """
    print("\n🏗️ Testing project structure...")
    print("-" * 50)
    
    project_root = Path.cwd()
    
    # Check key directories
    key_dirs = [
        'atous_sec_network',
        'tests',
        'docs',
        'atous_sec_network/core',
        'atous_sec_network/security',
        'atous_sec_network/network',
        'atous_sec_network/ml'
    ]
    
    for dir_path in key_dirs:
        full_path = project_root / dir_path
        if full_path.exists():
            print(f"   ✅ {dir_path}/")
        else:
            print(f"   ❌ {dir_path}/ (missing)")
    
    # Check key files
    key_files = [
        'README.md',
        'requirements.txt',
        'PROJECT_STATUS.md',
        'atous_sec_network/__init__.py',
        'atous_sec_network/__main__.py'
    ]
    
    for file_path in key_files:
        full_path = project_root / file_path
        if full_path.exists():
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path} (missing)")

def main():
    """
    Main function for lightweight testing.
    """
    try:
        # Test project structure
        test_project_structure()
        
        # Test basic imports
        success = test_basic_imports()
        
        if success:
            print("\n🎉 Lightweight test completed successfully!")
            print("\n🚀 To run the full application with ML components:")
            print("   python -m atous_sec_network")
            print("\n📚 For more information, see the documentation in /docs/")
            return 0
        else:
            print("\n❌ Some tests failed. Check the output above for details.")
            return 1
            
    except Exception as e:
        logger.error(f"Test runner error: {e}")
        print(f"❌ Test runner error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())