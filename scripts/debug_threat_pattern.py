"""
Debug script for ThreatPattern class
"""
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

from atous_sec_network.security.abiss_system import ThreatPattern

def test_pattern_matching():
    """Test pattern matching with different data types"""
    pattern = ThreatPattern(
        pattern_type="data_types_test",
        indicators=["123", "True", "3.14", "nested_value"],
        severity=0.6,
        frequency=0.1
    )
    
    # Dados com diferentes tipos: int, bool, float, dict, list, None
    test_data = { 
        "boolean": True,  
        "float_num": 3.14, 
        "nested": {
            "key": "nested_value" 
        },
        "list_data": [1, 2, 3],
        "none_value": None
    }
    
    print("\n=== Debug: Pattern Matching Test ===")
    print(f"Indicators: {pattern.indicators}")
    print(f"Test data: {test_data}")
    
    # Test each indicator individually
    for indicator in pattern.indicators:
        print(f"\n=== Testing indicator: '{indicator}' ===")
        found = False
        for key, value in test_data.items():
            print(f"\nChecking key '{key}' with value: {value} (type: {type(value)})")
            result = pattern._value_matches(value, indicator)
            print(f"  _value_matches({value}, '{indicator}') returned: {result}")
            if result:
                print(f"Found indicator '{indicator}' in key: {key} = {value}")
                found = True
                break
        if not found:
            print(f"Could not find indicator: '{indicator}'")
    
    # Test the full match
    print("\n=== Testing full match ===")
    match_score = pattern.match(test_data)
    print(f"\nMatch score: {match_score} (expected: 1.0)")
    
    if match_score == 1.0:
        print("Test passed!")
    else:
        print(f"Test failed! Expected 1.0, got {match_score}")
        
        # Additional debug: Check each indicator's match
        print("\n=== Debug: Checking each indicator's match ===")
        for i, indicator in enumerate(pattern.indicators):
            matched = False
            for value in test_data.values():
                if pattern._value_matches(value, indicator):
                    print(f"Indicator '{indicator}' matched in value: {value}")
                    matched = True
                    break
            if not matched:
                print(f"Indicator '{indicator}' did not match any value")

if __name__ == "__main__":
    test_pattern_matching()
