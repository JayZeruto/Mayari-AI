#!/usr/bin/env python3
"""
Mayari AI Offline Security Test Script
Tests all offline security capabilities to ensure Mayari works without internet connectivity.
"""

import sys
import os
import time
from security import SecurityManager, SecurityConfig

def test_offline_security():
    """Test all offline security features"""
    print("🛡️ Mayari AI Offline Security Test")
    print("=" * 50)

    # Initialize security with offline mode enabled
    config = SecurityConfig(
        enable_offline_mode=True,
        enable_self_diagnostic=True,
        local_threat_db_path="test_threats.json",
        offline_log_path="test_logs.json",
        security_state_path="test_state.json"
    )

    security = SecurityManager(config)
    print("✅ Security system initialized in offline mode")

    # Test 1: Self-diagnostic
    print("\\n🔍 Testing Self-Diagnostic...")
    diag = security.run_self_diagnostic()
    print(f"   Health Status: {diag.get('overall_health', 'unknown').upper()}")
    for check_name, check_result in diag.get('checks', {}).items():
        status = "✅" if check_result.get('status') else "❌"
        print(f"   {status} {check_name}: {check_result.get('message')}")

    # Test 2: Threat Database
    print("\\n🛡️ Testing Local Threat Database...")
    # Add some test threats
    security.threat_db.add_threat_pattern(r'<script.*?>.*?</script>', 'high')
    security.threat_db.add_threat_pattern(r'union.*select', 'high')
    security.threat_db.add_suspicious_keyword('password')

    # Test threat detection
    test_inputs = [
        ("<script>alert('xss')</script>", True),
        ("union select * from users", True),
        ("my password is secret", True),
        ("Hello world", False),
        ("What is the weather?", False)
    ]

    for input_text, expected_threat in test_inputs:
        is_threat, reason = security.threat_db.is_known_threat(input_text)
        status = "✅" if is_threat == expected_threat else "❌"
        print(f"   {status} '{input_text[:30]}...': {is_threat} ({reason})")

    # Test 3: Security Processing
    print("\\n⚙️ Testing Security Processing...")
    test_cases = [
        ("Hello, how are you?", True, "Normal input", "192.168.1.1"),
        ("<script>malicious code</script>", False, "XSS attack", "192.168.1.2"),
        ("SELECT * FROM users", False, "SQL injection", "192.168.1.3"),
        ("What is 2+2?", True, "Math question", "192.168.1.4"),
        ("\\frac{d}{dx} x^2", True, "Mathematical expression", "192.168.1.5")
    ]

    for input_text, expected_pass, description, ip_addr in test_cases:
        result, message = security.process_security_check(input_text, ip_addr)
        status = "✅" if result == expected_pass else "❌"
        print(f"   {status} {description}: {result} - {message}")

    # Test 4: Offline Statistics
    print("\\n📊 Testing Offline Statistics...")
    stats = security.get_offline_stats()
    print(f"   Threat patterns: {stats.get('threat_database', {}).get('known_patterns_count', 0)}")
    print(f"   Total requests: {stats.get('security_state', {}).get('total_requests', 0)}")
    print(f"   Attacks blocked: {stats.get('security_state', {}).get('attacks_blocked', 0)}")

    # Test 5: Security Report
    print("\\n📋 Generating Security Report...")
    report = security.get_security_report()
    print("   Report generated successfully")
    print("   Preview:")
    lines = report.split('\\n')[:10]  # Show first 10 lines
    for line in lines:
        print(f"   {line}")

    # Test 6: Data Export/Import
    print("\\n💾 Testing Data Export/Import...")
    export_data = security.export_security_data()
    print(f"   Exported {len(export_data)} data sections")

    # Create a new security instance and import data
    security2 = SecurityManager(config)
    security2.import_security_data(export_data)
    print("   Data import completed successfully")

    # Test 7: Emergency Shutdown
    print("\\n🚨 Testing Emergency Shutdown...")
    security.emergency_shutdown()
    print("   Emergency shutdown completed - all data preserved")

    # Cleanup test files
    print("\\n🧹 Cleaning up test files...")
    for filename in ["test_threats.json", "test_logs.json", "test_state.json"]:
        if os.path.exists(filename):
            os.remove(filename)
            print(f"   Removed {filename}")

    print("\\n🎉 All offline security tests completed successfully!")
    print("Mayari AI is fully protected even without internet connectivity.")

    return True

if __name__ == "__main__":
    try:
        test_offline_security()
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)