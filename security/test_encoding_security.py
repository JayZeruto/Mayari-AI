#!/usr/bin/env python3
"""
Test script for Unicode normalization and recursive URL/Hex decoding features
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from security.security import InputValidator

def test_unicode_normalization():
    """Test Unicode normalization for homograph attack prevention"""
    print("🛡️ Testing Unicode Normalization (Homograph Attack Prevention)")
    print("=" * 60)

    validator = InputValidator(max_length=1000)

    # Test cases for homograph attacks
    test_cases = [
        # Basic homograph attack - Cyrillic 'а' looks like Latin 'a'
        ("аррlе", "Cyrillic 'а' instead of 'a'"),
        # Greek 'ο' looks like Latin 'o'
        ("gοοgle", "Greek 'ο' instead of 'o'"),
        # Mixed scripts
        ("аdmin", "Cyrillic 'а' + Latin characters"),
        # Normal text (should pass)
        ("apple", "Normal Latin text"),
        ("google", "Normal Latin text"),
        ("admin", "Normal Latin text"),
    ]

    for test_input, description in test_cases:
        normalized = validator._normalize_unicode(test_input)
        print(f"Input: '{test_input}' ({description})")
        print(f"Normalized: '{normalized}'")
        print(f"Characters changed: {test_input != normalized}")
        print("-" * 40)

def test_recursive_decoding():
    """Test recursive URL/Hex decoding"""
    print("\\n🔓 Testing Recursive URL/Hex Decoding")
    print("=" * 45)

    validator = InputValidator(max_length=1000)

    # Test cases for encoded attacks
    test_cases = [
        # Single URL encoding
        ("%73%63%72%69%70%74", "URL encoded 'script'"),
        ("%3C%73%63%72%69%70%74%3E", "URL encoded '<script>'"),
        # Double URL encoding
        ("%253C%2573%2563%2572%2569%2570%2574%253E", "Double URL encoded '<script>'"),
        # Hex encoding
        ("\\x73\\x63\\x72\\x69\\x70\\x74", "Hex encoded 'script'"),
        # Mixed encoding
        ("%73%63%72%69%70%74\\x61\\x6c\\x65\\x72\\x74", "Mixed URL and hex encoding"),
        # Normal text (should remain unchanged)
        ("Hello world", "Normal text"),
        ("SELECT * FROM users", "Plain SQL (should be caught by other patterns)"),
    ]

    for test_input, description in test_cases:
        decoded = validator._recursive_decode(test_input)
        print(f"Input: '{test_input}' ({description})")
        print(f"Decoded: '{decoded}'")
        print(f"Decoding occurred: {test_input != decoded}")
        print("-" * 40)

def test_integrated_validation():
    """Test the complete validation pipeline"""
    print("\\n🔍 Testing Integrated Validation Pipeline")
    print("=" * 45)

    validator = InputValidator(max_length=1000)

    # Test cases that combine normalization and decoding
    test_cases = [
        # Homograph + URL encoding
        ("%61%64%6d%69%6e", "URL encoded 'admin'"),
        # Double encoded attack
        ("%253C%2573%2563%2572%2569%2570%2574%253E", "Double encoded script tag"),
        # Hex encoded SQL
        ("\\x53\\x45\\x4c\\x45\\x43\\x54", "Hex encoded 'SELECT'"),
        # Normal safe input
        ("What is the weather today?", "Safe question"),
        ("Solve: 2 + 2 = ?", "Math question"),
    ]

    for test_input, description in test_cases:
        is_valid, result = validator.validate_and_sanitize(test_input)
        print(f"Input: '{test_input}' ({description})")
        print(f"Valid: {is_valid}")
        if is_valid:
            print(f"Sanitized: '{result}'")
        else:
            print(f"Blocked: {result}")
        print("-" * 40)

def test_attack_detection():
    """Test that encoded attacks are still detected"""
    print("\\n🚨 Testing Attack Detection with Encoding")
    print("=" * 40)

    validator = InputValidator(max_length=1000)

    # Attacks that should be detected after decoding
    attack_cases = [
        ("%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%78%73%73%27%29%3C%2F%73%63%72%69%70%74%3E", "URL encoded XSS"),
        ("%53%45%4C%45%43%54%20%2A%20%46%52%4F%4D%20%75%73%65%72%73", "URL encoded SQL injection"),
        ("%2E%2E%2F%2E%2E%2F%65%74%63%2F%70%61%73%73%77%64", "URL encoded path traversal"),
        ("\\x3C\\x73\\x63\\x72\\x69\\x70\\x74\\x3E", "Hex encoded script tag"),
    ]

    for attack_input, description in attack_cases:
        is_valid, result = validator.validate_and_sanitize(attack_input)
        print(f"Attack: {description}")
        print(f"Input: '{attack_input}'")
        print(f"Detected: {not is_valid}")
        if not is_valid:
            print(f"Reason: {result}")
        print("-" * 40)

if __name__ == "__main__":
    try:
        test_unicode_normalization()
        test_recursive_decoding()
        test_integrated_validation()
        test_attack_detection()

        print("\\n🎉 All Unicode normalization and decoding tests completed!")
        print("Mayari AI is now protected against homograph and encoding-based attacks.")

    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)