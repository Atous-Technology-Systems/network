#!/usr/bin/env python3
"""
ATous Secure Network - Debug Import Script
Diagnoses import issues and system configuration problems
"""

import sys
import os
import importlib
from pathlib import Path

def print_header(title):
    """Print a formatted header"""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def print_section(title):
    """Print a formatted section header"""
    print(f"\n📋 {title}")
    print("-" * 40)

def check_python_version():
    """Check Python version compatibility"""
    print_section("Python Version Check")
    
    version = sys.version_info
    print(f"Python Version: {version.major}.{version.minor}.{version.micro}")
    
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print("❌ ERROR: Python 3.8+ required")
        return False
    elif version.minor < 10:
        print("⚠️  WARNING: Python 3.10+ recommended")
        return True
    else:
        print("✅ Python version is compatible")
        return True

def check_virtual_environment():
    """Check if running in virtual environment"""
    print_section("Virtual Environment Check")
    
    in_venv = hasattr(sys, 'real_prefix') or (
        hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix
    )
    
    if in_venv:
        print("✅ Running in virtual environment")
        print(f"   Virtual env path: {sys.prefix}")
        return True
    else:
        print("⚠️  WARNING: Not running in virtual environment")
        print("   Recommendation: Use 'python -m venv venv' and activate it")
        return False

def check_project_structure():
    """Check if project structure is correct"""
    print_section("Project Structure Check")
    
    project_root = Path.cwd()
    required_files = [
        "atous_sec_network/__init__.py",
        "atous_sec_network/api/server.py",
        "atous_sec_network/core/__init__.py",
        "atous_sec_network/security/__init__.py",
        "atous_sec_network/network/__init__.py",
        "requirements.txt",
        "start_app.py",
        "start_server.py"
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = project_root / file_path
        if full_path.exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ {file_path} - MISSING")
            missing_files.append(file_path)
    
    if missing_files:
        print(f"\n⚠️  Missing {len(missing_files)} required files")
        return False
    else:
        print("\n✅ All required files present")
        return True

def check_dependencies():
    """Check if required dependencies are installed"""
    print_section("Dependencies Check")
    
    required_packages = [
        "fastapi",
        "uvicorn",
        "numpy",
        "torch",
        "transformers",
        "requests",
        "websockets",
        "cryptography",
        "psutil",
        "pytest"
    ]
    
    missing_packages = []
    for package in required_packages:
        try:
            importlib.import_module(package)
            print(f"✅ {package}")
        except ImportError:
            print(f"❌ {package} - NOT INSTALLED")
            missing_packages.append(package)
    
    if missing_packages:
        print(f"\n⚠️  Missing {len(missing_packages)} required packages")
        print("   Install with: pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All required packages installed")
        return True

def check_atous_imports():
    """Check if ATous Secure Network modules can be imported"""
    print_section("ATous Module Import Check")
    
    # Add project root to Python path
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    
    modules_to_test = [
        ("atous_sec_network", "Main package"),
        ("atous_sec_network.core", "Core module"),
        ("atous_sec_network.api", "API module"),
        ("atous_sec_network.security", "Security module"),
        ("atous_sec_network.network", "Network module"),
        ("atous_sec_network.ml", "ML module")
    ]
    
    failed_imports = []
    for module_name, description in modules_to_test:
        try:
            importlib.import_module(module_name)
            print(f"✅ {module_name} - {description}")
        except ImportError as e:
            print(f"❌ {module_name} - {description} - ERROR: {str(e)}")
            failed_imports.append((module_name, str(e)))
    
    if failed_imports:
        print(f"\n⚠️  Failed to import {len(failed_imports)} modules")
        return False
    else:
        print("\n✅ All ATous modules imported successfully")
        return True

def check_system_resources():
    """Check system resources"""
    print_section("System Resources Check")
    
    try:
        import psutil
        
        # Memory check
        memory = psutil.virtual_memory()
        memory_gb = memory.total / (1024**3)
        print(f"Total RAM: {memory_gb:.1f} GB")
        
        if memory_gb < 4:
            print("⚠️  WARNING: Less than 4GB RAM - ML features may be slow")
        else:
            print("✅ Sufficient RAM for ML features")
        
        # Disk space check
        disk = psutil.disk_usage('.')
        disk_free_gb = disk.free / (1024**3)
        print(f"Free disk space: {disk_free_gb:.1f} GB")
        
        if disk_free_gb < 2:
            print("⚠️  WARNING: Less than 2GB free space - may affect model downloads")
        else:
            print("✅ Sufficient disk space")
        
        return True
        
    except ImportError:
        print("⚠️  psutil not available - cannot check system resources")
        return True
    except Exception as e:
        print(f"⚠️  Error checking system resources: {e}")
        return True

def check_network_connectivity():
    """Check network connectivity for model downloads"""
    print_section("Network Connectivity Check")
    
    try:
        import requests
        
        test_urls = [
            ("https://huggingface.co", "Hugging Face (for ML models)"),
            ("https://pypi.org", "PyPI (for packages)")
        ]
        
        for url, description in test_urls:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"✅ {description} - Accessible")
                else:
                    print(f"⚠️  {description} - HTTP {response.status_code}")
            except requests.RequestException as e:
                print(f"❌ {description} - Connection failed: {str(e)}")
        
        return True
        
    except ImportError:
        print("⚠️  requests not available - cannot check network connectivity")
        return True
    except Exception as e:
        print(f"⚠️  Error checking network connectivity: {e}")
        return True

def provide_recommendations(issues_found):
    """Provide recommendations based on issues found"""
    print_section("Recommendations")
    
    if not issues_found:
        print("🎉 No issues found! Your environment is ready.")
        print("\nNext steps:")
        print("   1. Run: python start_app.py --lite")
        print("   2. Run: python start_server.py")
        print("   3. Visit: http://localhost:8000/docs")
        return
    
    print("🔧 Issues found. Here's how to fix them:")
    
    print("\n1. Install missing dependencies:")
    print("   pip install -r requirements.txt")
    
    # Windows-specific extra requirements no longer maintained
    
    print("\n3. Ensure you're in the correct directory:")
    print("   cd Atous-Sec-Network")
    
    print("\n4. Create and activate virtual environment:")
    print("   python -m venv venv")
    print("   # Windows: venv\\Scripts\\activate")
    print("   # Linux/macOS: source venv/bin/activate")
    
    print("\n5. If issues persist, try:")
    print("   pip install --upgrade pip")
    print("   pip install --force-reinstall -r requirements.txt")

def main():
    """Main debug function"""
    print_header("ATous Secure Network - Debug Diagnostic")
    print("This script will check your environment and diagnose issues.")
    
    issues_found = 0
    
    # Run all checks
    checks = [
        ("Python Version", check_python_version),
        ("Virtual Environment", check_virtual_environment),
        ("Project Structure", check_project_structure),
        ("Dependencies", check_dependencies),
        ("ATous Imports", check_atous_imports),
        ("System Resources", check_system_resources),
        ("Network Connectivity", check_network_connectivity)
    ]
    
    for check_name, check_func in checks:
        try:
            if not check_func():
                issues_found += 1
        except Exception as e:
            print(f"❌ Error during {check_name} check: {e}")
            issues_found += 1
    
    # Summary
    print_header("Debug Summary")
    if issues_found == 0:
        print("🎉 SUCCESS: All checks passed!")
        print("Your environment is ready to run ATous Secure Network.")
    else:
        print(f"⚠️  ISSUES FOUND: {issues_found} problems detected")
        print("Please review the recommendations below.")
    
    provide_recommendations(issues_found > 0)
    
    print("\n" + "=" * 60)
    print("Debug diagnostic complete.")
    
    return 0 if issues_found == 0 else 1

if __name__ == "__main__":
    sys.exit(main())