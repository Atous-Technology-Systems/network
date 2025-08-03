#!/usr/bin/env python3
"""
Debug script to test imports
"""

import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

print("Python path:")
for p in sys.path:
    print(f"  {p}")

print("\nTrying to import atous_sec_network...")
try:
    import atous_sec_network
    print(f"✓ atous_sec_network imported from: {atous_sec_network.__file__}")
except ImportError as e:
    print(f"✗ Failed to import atous_sec_network: {e}")
    sys.exit(1)

print("\nTrying to import atous_sec_network.network...")
try:
    import atous_sec_network.network
    print(f"✓ atous_sec_network.network imported from: {atous_sec_network.network.__file__}")
    print(f"Available attributes: {[attr for attr in dir(atous_sec_network.network) if not attr.startswith('_')]}")
except ImportError as e:
    print(f"✗ Failed to import atous_sec_network.network: {e}")
    sys.exit(1)

print("\nTrying to access lora_compat...")
try:
    lora_compat = getattr(atous_sec_network.network, 'lora_compat', None)
    if lora_compat:
        print(f"✓ lora_compat found: {lora_compat}")
        print(f"lora_compat type: {type(lora_compat)}")
        print(f"lora_compat file: {getattr(lora_compat, '__file__', 'No __file__ attribute')}")
    else:
        print("✗ lora_compat not found")
except Exception as e:
    print(f"✗ Error accessing lora_compat: {e}")

print("\nTrying direct import of lora_compat...")
try:
    import atous_sec_network.network.lora_compat
    print(f"✓ Direct import successful: {atous_sec_network.network.lora_compat.__file__}")
except ImportError as e:
    print(f"✗ Direct import failed: {e}")

print("\nTrying from import...")
try:
    from atous_sec_network.network import lora_compat
    print(f"✓ From import successful: {lora_compat.__file__}")
except ImportError as e:
    print(f"✗ From import failed: {e}")