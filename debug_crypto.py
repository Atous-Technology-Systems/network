#!/usr/bin/env python3

from atous_sec_network.core.model_manager import FederatedModelUpdater

def test_crypto_functions():
    updater = FederatedModelUpdater(node_id="test_node")
    
    print("Testing _generate_key_pair...")
    try:
        result = updater._generate_key_pair()
        print(f"Success: Generated key pair with {len(result)} keys")
        print(f"Private key length: {len(result[0])}")
        print(f"Public key length: {len(result[1])}")
        return result
    except Exception as e:
        print(f"Error in _generate_key_pair: {e}")
        return None

if __name__ == "__main__":
    test_crypto_functions()