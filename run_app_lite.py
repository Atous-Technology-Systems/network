#!/usr/bin/env python3
"""
ATous Secure Network - Lightweight Test Runner
Executa uma versão simplificada da aplicação para testes rápidos
"""

import sys
import os
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def main():
    """
    Run lightweight version of ATous Secure Network
    """
    print("🚀 ATous Secure Network - Lightweight Mode")
    print("=" * 50)
    
    try:
        # Test basic imports
        print("\n📦 Testing Core Imports...")
        import atous_sec_network
        print("   ✅ atous_sec_network imported successfully")
        
        # Test network module
        print("\n🌐 Testing Network Module...")
        from atous_sec_network.network import lora_compat
        print("   ✅ LoRa compatibility module loaded")
        
        # Test security modules
        print("\n🛡️ Testing Security Modules...")
        try:
            from atous_sec_network.security.abiss_system import ABISSSystem
            print("   ✅ ABISS System available")
        except ImportError as e:
            print(f"   ⚠️ ABISS System: {e}")
            
        try:
            from atous_sec_network.security.nnis_system import NNISSystem
            print("   ✅ NNIS System available")
        except ImportError as e:
            print(f"   ⚠️ NNIS System: {e}")
        
        # Test core modules
        print("\n⚙️ Testing Core Modules...")
        try:
            from atous_sec_network.core.model_manager import ModelManager
            print("   ✅ Model Manager available")
        except ImportError as e:
            print(f"   ⚠️ Model Manager: {e}")
        
        # Test API module
        print("\n🌐 Testing API Module...")
        try:
            from atous_sec_network.api.server import app
            print("   ✅ FastAPI server available")
        except ImportError as e:
            print(f"   ⚠️ API Server: {e}")
        
        print("\n✅ Lightweight test completed successfully!")
        print("\n💡 To run the full application:")
        print("   python start_app.py --full")
        print("   python -m atous_sec_network")
        
        return 0
        
    except Exception as e:
        print(f"\n❌ Error during lightweight test: {e}")
        print("\n🔧 Troubleshooting:")
        print("   1. Check dependencies: pip install -r requirements.txt")
        print("   2. Run debug script: python scripts/debug_import.py")
        print("   3. Check virtual environment activation")
        return 1

if __name__ == "__main__":
    sys.exit(main())