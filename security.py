"""
Mayari AI Security Module

This module provides comprehensive security protections for the Mayari AI system,
implementing the latest security practices in Python to defend against various
types of attacks including injection, DDoS, data breaches, and unauthorized access.

Author: GitHub Copilot
Date: 2026-05-07
"""

import hmac
import logging
import math
import os
import re
import secrets
import time
import json
import hashlib
from collections import defaultdict
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Section 1: Secure Imports and Dependencies
"""
Notes for Section 1: Secure Imports and Dependencies
- Only import necessary modules to minimize attack surface
- Use standard library where possible, third-party libraries only when needed
- Pin versions in requirements.txt to prevent supply chain attacks
- Regularly audit dependencies for vulnerabilities using tools like safety or pip-audit
- Avoid importing potentially dangerous modules like pickle, eval, or exec unless
  absolutely necessary
"""

# Section 2: Configuration Security
"""
Notes for Section 2: Configuration Security
- Store sensitive configuration in environment variables, not in code
- Use secure defaults for all settings
- Validate configuration values on startup
- Never log sensitive information like API keys or passwords
"""

@dataclass
class SecurityConfig:
    """Secure configuration class with validation"""
    max_request_rate: int = 10  # requests per minute per IP (lower for testing)
    max_input_length: int = 1000  # maximum input length
    enable_anomaly_detection: bool = True
    enable_rate_limiting: bool = True
    enable_conversation_tracking: bool = True
    max_input_length: int = 1000  # characters
    encryption_key_rotation_days: int = 30
    log_level: str = "INFO"
    enable_rate_limiting: bool = True
    enable_encryption: bool = True    # Offline security features
    enable_offline_mode: bool = True
    local_threat_db_path: str = "security_threats.json"
    security_state_path: str = "security_state.json"
    offline_log_path: str = "security_offline.log"
    enable_self_diagnostic: bool = True
    max_offline_logs: int = 1000
    def __post_init__(self):
        """Validate configuration values"""
        if self.max_request_rate < 1:
            raise ValueError("max_request_rate must be positive")
        if self.max_input_length < 1:
            raise ValueError("max_input_length must be positive")

class AnomalyDetector:
    """Detect anomalous behavior patterns that might indicate attacks"""

    def __init__(self):
        self.baseline_stats = {
            'avg_request_length': 50,
            'avg_special_chars': 0.1,
            'avg_entropy': 3.5
        }
        self.recent_activity = []

    def analyze_request(self, user_input: str, ip_address: str) -> float:
        """Analyze request for anomalies, return risk score (0-1)"""
        risk_score = 0.0

        # Length anomaly
        length_ratio = len(user_input) / self.baseline_stats['avg_request_length']
        if length_ratio > 3 or length_ratio < 0.2:
            risk_score += 0.3

        # Special character anomaly
        special_count = sum(1 for c in user_input if not c.isalnum() and not c.isspace())
        special_ratio = special_count / max(len(user_input), 1)
        if special_ratio > 0.4:
            risk_score += 0.4

        # Entropy anomaly (simplified)
        entropy = self._calculate_entropy(user_input)
        if entropy > 5.0:
            risk_score += 0.3

        # Pattern repetition
        if self._has_repetitive_patterns(user_input):
            risk_score += 0.2

        # Update baseline with recent activity
        self.recent_activity.append({
            'length': len(user_input),
            'special_ratio': special_ratio,
            'entropy': entropy,
            'timestamp': time.time()
        })

        # Keep only recent activity (last 100 requests)
        self.recent_activity = self.recent_activity[-100:]

        return min(risk_score, 1.0)  # Cap at 1.0

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if len(text) < 2:
            return 0.0

        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            prob = count / text_len
            if prob > 0:
                entropy -= prob * math.log2(prob)

        return entropy

    def _has_repetitive_patterns(self, text: str) -> bool:
        """Check for repetitive character or word patterns"""
        if len(text) < 10:
            return False

        # Check for character repetition
        for i in range(len(text) - 5):
            if text[i:i+5] == text[i+5:i+10]:
                return True

        # Check for word repetition
        words = text.split()
        for word in words:
            if words.count(word) > 3:  # Same word appears >3 times
                return True

        return False

class ConversationTracker:
    """Track conversation patterns to detect multi-turn attacks"""

    def __init__(self):
        self.conversations = defaultdict(list)  # ip -> list of recent messages
        self.attack_patterns = []

    def add_message(self, ip_address: str, message: str):
        """Add message to conversation tracking"""
        self.conversations[ip_address].append({
            'message': message,
            'timestamp': time.time(),
            'length': len(message)
        })

        # Keep only recent messages (last 10 per IP)
        self.conversations[ip_address] = self.conversations[ip_address][-10:]

    def detect_multi_turn_attack(self, ip_address: str, current_message: str) -> bool:
        """Detect if current message is part of a multi-turn attack pattern"""
        recent_messages = self.conversations[ip_address]

        if len(recent_messages) < 3:
            return False

        # Check for jailbreak escalation
        jailbreak_indicators = ['ignore', 'bypass', 'override', 'developer mode']
        escalation_count = sum(1 for msg in recent_messages
                              for indicator in jailbreak_indicators
                              if indicator in msg['message'].lower())

        if escalation_count >= 2:
            return True

        # Check for probing pattern (asking about system repeatedly)
        system_probes = ['what is your', 'tell me about', 'how do you', 'can you']
        probe_count = sum(1 for msg in recent_messages
                          for probe in system_probes
                          if any(p in msg['message'].lower() for p in system_probes))

        if probe_count >= 3:
            return True

        return False

class RateLimiter:
    """Basic rate limiter using sliding window algorithm"""

    def __init__(self, max_requests_per_minute: int):
        self.max_requests = max_requests_per_minute
        self.requests = defaultdict(list)  # ip -> list of timestamps

    def is_allowed(self, ip_address: str) -> bool:
        """Check if request is allowed under rate limit"""
        now = time.time()
        window_start = now - 60  # 1 minute window

        # Clean old requests
        self.requests[ip_address] = [
            ts for ts in self.requests[ip_address] if ts > window_start
        ]

        # Check if under limit
        if len(self.requests[ip_address]) >= self.max_requests:
            return False

        # Add current request
        self.requests[ip_address].append(now)
        return True

class AdvancedRateLimiter(RateLimiter):
    """Advanced rate limiting with burst detection and behavioral analysis"""

    def __init__(self, max_requests_per_minute: int):
        super().__init__(max_requests_per_minute)
        self.burst_threshold = max_requests_per_minute // 4  # Allow short bursts
        self.suspicious_patterns = defaultdict(int)
        self.behavioral_scores = defaultdict(float)

    def is_allowed(self, ip_address: str, user_input: str = "") -> Tuple[bool, str]:
        """Check if request is allowed with advanced analysis"""
        now = time.time()
        window_start = now - 60

        # Clean old requests
        self.requests[ip_address] = [
            ts for ts in self.requests[ip_address] if ts > window_start
        ]

        # Check basic rate limit
        if len(self.requests[ip_address]) >= self.max_requests:
            return False, "Rate limit exceeded"

        # Check for burst attacks
        recent_requests = [ts for ts in self.requests[ip_address] if ts > now - 10]
        if len(recent_requests) >= self.burst_threshold:
            return False, "Burst attack detected"

        # Behavioral analysis
        if user_input:
            behavior_score = self._analyze_behavior(user_input)
            self.behavioral_scores[ip_address] += behavior_score

            if self.behavioral_scores[ip_address] > 10.0:  # Suspicious threshold
                return False, "Suspicious behavior detected"

        self.requests[ip_address].append(now)
        return True, "Allowed"

    def _analyze_behavior(self, user_input: str) -> float:
        """Analyze user input for suspicious behavioral patterns"""
        score = 0.0

        # Length anomalies
        if len(user_input) > 500:
            score += 1.0
        elif len(user_input) < 3:
            score += 0.5

        # Character distribution anomalies
        if self._has_suspicious_char_distribution(user_input):
            score += 2.0

        # Pattern repetition
        if self._has_repetition_patterns(user_input):
            score += 1.5

        # Time-based patterns (would need timestamps)
        # This is a simplified version

        return score

    def _has_suspicious_char_distribution(self, text: str) -> bool:
        """Check for unusual character distributions"""
        if len(text) < 10:
            return False

        # High ratio of special characters
        special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
        special_ratio = special_chars / len(text)

        return special_ratio > 0.3  # More than 30% special characters

    def _has_repetition_patterns(self, text: str) -> bool:
        """Detect repetitive patterns that might indicate attacks"""
        if len(text) < 20:
            return False

        # Check for repeated sequences
        for i in range(len(text) - 10):
            substring = text[i:i+10]
            if text.count(substring) > 2:  # Same 10-char sequence appears >2 times
                return True

        return False

class InputValidator:
    """Validates and sanitizes user input"""

    def __init__(self, max_length: int):
        self.max_length = max_length
        self.attack_patterns = {
            'sql_injection': re.compile(r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b.*\b(FROM|INTO|WHERE|VALUES|TABLE)\b)', re.IGNORECASE),
            'xss': re.compile(r'(<script|<iframe|<object|<embed|<form|<meta|<link|<style)', re.IGNORECASE),
            'command_injection': re.compile(r'(\||;|`|\$\(|\$\{)', re.IGNORECASE),
            'path_traversal': re.compile(r'(\.\./|\.\.\\)', re.IGNORECASE),
            'suspicious_keywords': re.compile(r'\b(eval|exec|system|shell_exec|passthru|proc_open|popen)\b', re.IGNORECASE),
            # Mathematical attack patterns
            'latex_injection': re.compile(r'(\\\$|\\\{|\\\}|\\\[|\\\])', re.IGNORECASE),  # LaTeX delimiters with suspicious content
            'math_unicode_attack': re.compile(r'[\u2200-\u22ff].*<.*>.*[\u2200-\u22ff]', re.IGNORECASE),  # Math symbols with HTML
            'scientific_notation_attack': re.compile(r'\d+\.?\d*[eE][+-]?\d+.*\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b', re.IGNORECASE),
            'math_operator_injection': re.compile(r'[\u220f\u2211\u221a\u222b\u222e].*<.*>.*[\u220f\u2211\u221a\u222b\u222e]', re.IGNORECASE),  # ∑∫√∏∮ with HTML
            'complex_number_attack': re.compile(r'\d+[ij]\s*[;].*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b', re.IGNORECASE),
        }

    def validate_and_sanitize(self, input_text: str) -> Tuple[bool, str]:
        """Validate and sanitize input text and return (is_valid, sanitized_text or reason)"""
        if len(input_text) > self.max_length:
            return False, f"Input too long (max {self.max_length} characters)"

        if not input_text.strip():
            return False, "Empty input"

        # Check for mathematical attack patterns specifically
        math_attack_detected = self._detect_mathematical_attacks(input_text)
        if math_attack_detected:
            return False, f"Security violation: Mathematical attack pattern detected"

        # Check for general attack patterns
        for attack_type, pattern in self.attack_patterns.items():
            if pattern.search(input_text):
                return False, f"Security violation: {attack_type.replace('_', ' ').title()} detected"

        # Basic sanitization - remove potentially dangerous characters
        sanitized = re.sub(r'[<>]', '', input_text)  # Remove angle brackets

        return True, sanitized

    def _detect_mathematical_attacks(self, input_text: str) -> bool:
        """Detect sophisticated mathematical attack patterns"""
        # Check for LaTeX commands that could hide malicious content
        if '\\' in input_text:
            # Look for LaTeX commands followed by suspicious patterns
            latex_commands = ['\\command', '\\input', '\\include', '\\write', '\\csname']
            for cmd in latex_commands:
                if cmd in input_text.lower():
                    # Check if followed by potentially dangerous content
                    cmd_index = input_text.lower().find(cmd)
                    remaining = input_text[cmd_index + len(cmd):]
                    if any(char in remaining for char in ['{', '}', '[', ']', '(', ')']):
                        return True

        # Check for mathematical expressions with embedded HTML/script
        math_symbols = ['∫', '∑', '∏', '√', '∂', '∇', '∆', '∞', '≠', '≤', '≥', '≈', '≡']
        for symbol in math_symbols:
            if symbol in input_text:
                # Check for HTML tags within mathematical context
                if '<' in input_text and '>' in input_text:
                    # Look for script tags or other dangerous HTML
                    if any(tag in input_text.lower() for tag in ['<script', '<iframe', '<object', '<embed']):
                        return True

        # Check for scientific notation abuse
        if 'e+' in input_text.lower() or 'e-' in input_text.lower():
            # Look for scientific notation followed by SQL keywords
            scientific_pattern = r'\d+\.?\d*[eE][+-]?\d+'
            if re.search(scientific_pattern, input_text):
                remaining = re.sub(scientific_pattern, '', input_text)
                if any(keyword in remaining.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']):
                    return True

        # Check for complex number abuse
        complex_pattern = r'\d+[ij]\s*'
        if re.search(complex_pattern, input_text):
            remaining = re.sub(complex_pattern, '', input_text)
            if any(keyword in remaining.upper() for keyword in ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP']):
                return True

        # Check for excessive mathematical notation density
        math_chars = sum(1 for c in input_text if ord(c) > 127)  # Unicode characters
        if len(input_text) > 20 and math_chars / len(input_text) > 0.3:  # >30% Unicode
            # High Unicode density might indicate obfuscation
            return True

        return False

class LocalThreatDatabase:
    """Local database of known threats for offline operation"""

    def __init__(self, db_path: str = "security_threats.json"):
        self.db_path = db_path
        self.threats = self._load_threats()
        self.offline_threats = defaultdict(int)  # Track threats detected while offline

    def _load_threats(self) -> Dict[str, Any]:
        """Load threat database from local file"""
        try:
            if os.path.exists(self.db_path):
                with open(self.db_path, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Warning: Could not load threat database: {e}")

        # Return default threat patterns
        return {
            'known_attack_patterns': [
                r'<script.*?>.*?</script>',
                r'union.*select.*from',
                r';\s*drop\s+table',
                r'eval\s*\(',
                r'exec\s*\(',
                r'\\command\{.*?\}',
                r'\\csname.*\\endcsname'
            ],
            'suspicious_keywords': [
                'password', 'admin', 'root', 'system', 'config',
                'database', 'server', 'hack', 'exploit', 'bypass'
            ],
            'last_updated': time.time(),
            'version': '1.0'
        }

    def save_threats(self):
        """Save threat database to local file"""
        try:
            with open(self.db_path, 'w') as f:
                json.dump(self.threats, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save threat database: {e}")

    def add_threat_pattern(self, pattern: str, severity: str = "medium"):
        """Add a new threat pattern to the database"""
        if pattern not in self.threats['known_attack_patterns']:
            self.threats['known_attack_patterns'].append(pattern)
            self.threats['last_updated'] = time.time()
            self.save_threats()

    def add_suspicious_keyword(self, keyword: str):
        """Add a suspicious keyword to the database"""
        if keyword not in self.threats['suspicious_keywords']:
            self.threats['suspicious_keywords'].append(keyword)
            self.threats['last_updated'] = time.time()
            self.save_threats()

    def get_offline_stats(self) -> Dict[str, Any]:
        """Get statistics about offline threat detection"""
        return {
            'offline_threats_detected': dict(self.offline_threats),
            'total_offline_threats': sum(self.offline_threats.values()),
            'known_patterns_count': len(self.threats.get('known_attack_patterns', [])),
            'suspicious_keywords_count': len(self.threats.get('suspicious_keywords', []))
        }

    def is_known_threat(self, input_text: str) -> Tuple[bool, str]:
        """Check if input matches known threat patterns"""
        for pattern in self.threats.get('known_attack_patterns', []):
            if re.search(pattern, input_text, re.IGNORECASE):
                return True, f"Known threat pattern: {pattern}"

        for keyword in self.threats.get('suspicious_keywords', []):
            if keyword.lower() in input_text.lower():
                return True, f"Suspicious keyword: {keyword}"

        return False, "No known threats detected"

    def add_offline_threat(self, threat_pattern: str, severity: str = "medium"):
        """Add a threat detected while offline"""
        self.offline_threats[threat_pattern] += 1

        # If we detect the same threat multiple times, add it to known patterns
        if self.offline_threats[threat_pattern] >= 3:
            if threat_pattern not in self.threats['known_attack_patterns']:
                self.threats['known_attack_patterns'].append(threat_pattern)
                self.save_threats()

    def get_offline_stats(self) -> Dict[str, Any]:
        """Get statistics about offline threat detection"""
        return {
            'offline_threats_detected': dict(self.offline_threats),
            'total_offline_threats': sum(self.offline_threats.values()),
            'known_patterns_count': len(self.threats.get('known_attack_patterns', []))
        }

class OfflineLogger:
    """Offline logging system that stores logs locally"""

    def __init__(self, log_path: str = "security_offline.log", max_logs: int = 1000):
        self.log_path = log_path
        self.max_logs = max_logs
        self.offline_logs = []
        self._load_logs()

    def _load_logs(self):
        """Load existing offline logs"""
        try:
            if os.path.exists(self.log_path):
                with open(self.log_path, 'r') as f:
                    self.offline_logs = [json.loads(line.strip()) for line in f if line.strip()]
        except (json.JSONDecodeError, IOError):
            self.offline_logs = []

    def _save_logs(self):
        """Save logs to file, maintaining max_logs limit"""
        try:
            # Keep only the most recent logs
            logs_to_save = self.offline_logs[-self.max_logs:]

            with open(self.log_path, 'w') as f:
                for log_entry in logs_to_save:
                    f.write(json.dumps(log_entry) + '\n')
        except IOError as e:
            print(f"Warning: Could not save offline logs: {e}")

    def log_security_event(self, event_type: str, details: Dict[str, Any], ip_address: str = "offline"):
        """Log a security event for offline storage"""
        log_entry = {
            'timestamp': time.time(),
            'event_type': event_type,
            'ip_address': ip_address,
            'details': details,
            'offline': True
        }

        self.offline_logs.append(log_entry)
        self._save_logs()

    def get_recent_logs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent offline logs"""
        return self.offline_logs[-limit:]

    def get_logs_by_type(self, event_type: str) -> List[Dict[str, Any]]:
        """Get logs filtered by event type"""
        return [log for log in self.offline_logs if log.get('event_type') == event_type]

    def clear_old_logs(self, days_old: int = 30):
        """Clear logs older than specified days"""
        cutoff_time = time.time() - (days_old * 24 * 60 * 60)
        self.offline_logs = [log for log in self.offline_logs if log['timestamp'] > cutoff_time]
        self._save_logs()

class SecurityStateManager:
    """Manages persistent security state for offline operation"""

    def __init__(self, state_path: str = "security_state.json"):
        self.state_path = state_path
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """Load security state from file"""
        try:
            if os.path.exists(self.state_path):
                with open(self.state_path, 'r') as f:
                    return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

        # Return default state
        return {
            'initialized_at': time.time(),
            'total_requests_processed': 0,
            'total_attacks_blocked': 0,
            'ip_blocklist': [],
            'trusted_ips': [],
            'security_incidents': [],
            'last_backup': time.time(),
            'version': '1.0'
        }

    def save_state(self):
        """Save current security state"""
        try:
            with open(self.state_path, 'w') as f:
                json.dump(self.state, f, indent=2)
        except IOError as e:
            print(f"Warning: Could not save security state: {e}")

    def update_stats(self, requests_processed: int = 0, attacks_blocked: int = 0):
        """Update security statistics"""
        self.state['total_requests_processed'] += requests_processed
        self.state['total_attacks_blocked'] += attacks_blocked
        self.save_state()

    def add_to_blocklist(self, ip_address: str, reason: str = "Security violation"):
        """Add IP to blocklist"""
        if ip_address not in self.state['ip_blocklist']:
            self.state['ip_blocklist'].append({
                'ip': ip_address,
                'reason': reason,
                'added_at': time.time()
            })
            self.save_state()

    def is_blocklisted(self, ip_address: str) -> bool:
        """Check if IP is blocklisted"""
        return any(entry['ip'] == ip_address for entry in self.state['ip_blocklist'])

    def add_incident(self, incident_type: str, details: Dict[str, Any]):
        """Record a security incident"""
        incident = {
            'type': incident_type,
            'details': details,
            'timestamp': time.time()
        }
        self.state['security_incidents'].append(incident)

        # Keep only recent incidents
        self.state['security_incidents'] = self.state['security_incidents'][-100:]
        self.save_state()

    def get_security_summary(self) -> Dict[str, Any]:
        """Get security statistics summary"""
        return {
            'total_requests': self.state.get('total_requests_processed', 0),
            'attacks_blocked': self.state.get('total_attacks_blocked', 0),
            'blocklist_size': len(self.state.get('ip_blocklist', [])),
            'incident_count': len(self.state.get('security_incidents', [])),
            'uptime_days': (time.time() - self.state.get('initialized_at', time.time())) / (24 * 60 * 60)
        }

class SelfDiagnostic:
    """Self-diagnostic system for offline security health checks"""

    def __init__(self, security_manager: 'SecurityManager'):
        self.security_manager = security_manager

    def run_diagnostics(self) -> Dict[str, Any]:
        """Run comprehensive security diagnostics"""
        results = {
            'timestamp': time.time(),
            'overall_health': 'unknown',
            'checks': {},
            'recommendations': []
        }

        # Check encryption
        results['checks']['encryption'] = self._check_encryption()

        # Check rate limiting
        results['checks']['rate_limiting'] = self._check_rate_limiting()

        # Check input validation
        results['checks']['input_validation'] = self._check_input_validation()

        # Check logging
        results['checks']['logging'] = self._check_logging()

        # Check offline capabilities
        results['checks']['offline_capabilities'] = self._check_offline_capabilities()

        # Determine overall health
        failed_checks = [k for k, v in results['checks'].items() if not v.get('status', False)]
        if not failed_checks:
            results['overall_health'] = 'excellent'
        elif len(failed_checks) <= 2:
            results['overall_health'] = 'good'
            results['recommendations'].append(f"Address {len(failed_checks)} failed checks")
        else:
            results['overall_health'] = 'critical'
            results['recommendations'].append("Immediate security review required")

        return results

    def _check_encryption(self) -> Dict[str, Any]:
        """Check encryption system health"""
        try:
            test_data = "test_encryption_123"
            encrypted = self.security_manager.encrypt_data(test_data)
            decrypted = self.security_manager.decrypt_data(encrypted)

            if decrypted == test_data and encrypted != test_data:
                return {'status': True, 'message': 'Encryption working correctly'}
            else:
                return {'status': False, 'message': 'Encryption/decryption failed'}
        except Exception as e:
            return {'status': False, 'message': f'Encryption error: {str(e)}'}

    def _check_rate_limiting(self) -> Dict[str, Any]:
        """Check rate limiting functionality"""
        try:
            # Test rate limiter with multiple requests
            blocked = 0
            for i in range(15):
                result = self.security_manager.rate_limiter.is_allowed("127.0.0.1", f"test{i}")
                if not result[0] if isinstance(result, tuple) else not result:
                    blocked += 1

            if blocked > 0:
                return {'status': True, 'message': f'Rate limiting active ({blocked} requests blocked)'}
            else:
                return {'status': False, 'message': 'Rate limiting not working'}
        except Exception as e:
            return {'status': False, 'message': f'Rate limiting error: {str(e)}'}

    def _check_input_validation(self) -> Dict[str, Any]:
        """Check input validation functionality"""
        try:
            # Test with known attack
            result = self.security_manager.input_validator.validate_and_sanitize("<script>alert(1)</script>")
            if not result[0]:  # Should be blocked
                return {'status': True, 'message': 'Input validation working'}
            else:
                return {'status': False, 'message': 'Input validation not blocking attacks'}
        except Exception as e:
            return {'status': False, 'message': f'Input validation error: {str(e)}'}

    def _check_logging(self) -> Dict[str, Any]:
        """Check logging functionality"""
        try:
            # Check if logger exists and can log
            if hasattr(self.security_manager, 'logger') and self.security_manager.logger:
                return {'status': True, 'message': 'Logging system active'}
            else:
                return {'status': False, 'message': 'Logging system not initialized'}
        except Exception as e:
            return {'status': False, 'message': f'Logging error: {str(e)}'}

    def _check_offline_capabilities(self) -> Dict[str, Any]:
        """Check offline security capabilities"""
        try:
            checks = []

            # Check local threat database
            if hasattr(self.security_manager, 'threat_db'):
                checks.append('Local threat database available')
            else:
                checks.append('Missing local threat database')

            # Check offline logging
            if hasattr(self.security_manager, 'offline_logger'):
                checks.append('Offline logging available')
            else:
                checks.append('Missing offline logging')

            # Check state management
            if hasattr(self.security_manager, 'state_manager'):
                checks.append('Security state management available')
            else:
                checks.append('Missing security state management')

            if len(checks) >= 2:
                return {'status': True, 'message': f'Offline capabilities: {len(checks)}/3 active'}
            else:
                return {'status': False, 'message': f'Limited offline capabilities: {len(checks)}/3 active'}
        except Exception as e:
            return {'status': False, 'message': f'Offline check error: {str(e)}'}

class SecurityManager:
    """Main security manager for Mayari AI with advanced protection features"""

    def __init__(self, config: Optional[SecurityConfig] = None):
        self.config = config or SecurityConfig()
        self._setup_logging()
        self._initialize_encryption()
        self.rate_limiter = AdvancedRateLimiter(self.config.max_request_rate)
        self.input_validator = InputValidator(self.config.max_input_length)
        self.anomaly_detector = AnomalyDetector()
        self.conversation_tracker = ConversationTracker()

        # Initialize offline security features
        if self.config.enable_offline_mode:
            self.threat_db = LocalThreatDatabase(self.config.local_threat_db_path)
            self.offline_logger = OfflineLogger(self.config.offline_log_path, self.config.max_offline_logs)
            self.state_manager = SecurityStateManager(self.config.security_state_path)

            if self.config.enable_self_diagnostic:
                self.self_diagnostic = SelfDiagnostic(self)
            else:
                self.self_diagnostic = None
        else:
            self.threat_db = None
            self.offline_logger = None
            self.state_manager = None
            self.self_diagnostic = None

    # Section 3: Logging and Auditing
    """
    Notes for Section 3: Logging and Auditing
    - Log security events without exposing sensitive data
    - Use structured logging for better analysis
    - Implement log rotation to prevent disk space issues
    - Monitor logs for suspicious patterns
    - Comply with data retention policies
    """

    def _setup_logging(self):
        """Setup secure logging configuration"""
        self.logger = logging.getLogger("mayari_security")
        self.logger.setLevel(getattr(logging, self.config.log_level.upper()))

        # Prevent log injection by sanitizing log messages
        class SecureFormatter(logging.Formatter):
            """Custom logging formatter that prevents log injection attacks"""

            def format(self, record):
                # Remove newlines and control characters from log messages
                record.msg = re.sub(r'[\r\n\t]', ' ', str(record.msg))
                return super().format(record)

        formatter = SecureFormatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # Console handler for development
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)

        # File handler with rotation
        file_handler = logging.FileHandler('mayari_security.log')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    # Section 4: Encryption and Data Protection
    """
    Notes for Section 4: Encryption and Data Protection
    - Use AES-256 encryption for sensitive data
    - Implement proper key management with rotation
    - Use PBKDF2 for key derivation from passwords
    - Encrypt data at rest and in transit
    - Never store encryption keys in code or version control
    """

    def _initialize_encryption(self):
        """Initialize encryption system"""
        if self.config.enable_encryption:
            # Generate or load encryption key from environment
            key_env = os.getenv('MAYARI_ENCRYPTION_KEY')
            if key_env:
                self.encryption_key = base64.urlsafe_b64decode(key_env)
            else:
                # Generate new key (in production, this should be stored securely)
                self.encryption_key = Fernet.generate_key()
                self.logger.warning("Generated new encryption key - store securely!")

            self.fernet = Fernet(self.encryption_key)
        else:
            self.fernet = None

    def encrypt_data(self, data: str) -> str:
        """Encrypt sensitive data"""
        if not self.fernet:
            return data
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not self.fernet:
            return encrypted_data
        return self.fernet.decrypt(encrypted_data.encode()).decode()

    def hash_password(self, password: str) -> str:
        """Securely hash passwords using PBKDF2"""
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return f"pbkdf2_sha256$100000${salt.hex()}${key.decode()}"

    def process_security_check(self, user_input: str, client_ip: str = "127.0.0.1") -> Tuple[bool, str]:
        """Comprehensive security check with offline capabilities"""
        # Update request statistics
        if self.state_manager:
            self.state_manager.update_stats(requests_processed=1)

        # Check if IP is blocklisted (offline check)
        if self.state_manager and self.state_manager.is_blocklisted(client_ip):
            if self.offline_logger:
                self.offline_logger.log_security_event('blocked_ip', {'ip': client_ip, 'reason': 'blocklisted'}, client_ip)
            self.logger.warning(f"Blocked request from blocklisted IP: {client_ip}")
            return False, "⚠️ Security Check Failed: Access denied"

        # Check local threat database (offline check)
        if self.threat_db:
            is_threat, threat_reason = self.threat_db.is_known_threat(user_input)
            if is_threat:
                if self.offline_logger:
                    self.offline_logger.log_security_event('known_threat', {'threat': threat_reason, 'input': user_input[:100]}, client_ip)
                self.logger.warning(f"Known threat detected for {client_ip}: {threat_reason}")
                # Add to blocklist if severe threat
                if self.state_manager and 'script' in threat_reason.lower():
                    self.state_manager.add_to_blocklist(client_ip, threat_reason)
                return False, f"⚠️ Security Check Failed: {threat_reason}"

        # Rate limiting with behavioral analysis
        allowed, rate_limit_reason = self.rate_limiter.is_allowed(client_ip, user_input)
        if not allowed:
            if self.offline_logger:
                self.offline_logger.log_security_event('rate_limit', {'reason': rate_limit_reason}, client_ip)
            if self.state_manager:
                self.state_manager.update_stats(attacks_blocked=1)
            self.logger.warning(f"Rate limit triggered for {client_ip}: {rate_limit_reason}")
            return False, f"⚠️ Security Check Failed: {rate_limit_reason}"

        # Anomaly detection
        anomaly_score = self.anomaly_detector.analyze_request(user_input, client_ip)
        if anomaly_score > 0.7:  # High risk threshold
            if self.offline_logger:
                self.offline_logger.log_security_event('anomaly', {'score': anomaly_score, 'input': user_input[:100]}, client_ip)
            if self.state_manager:
                self.state_manager.update_stats(attacks_blocked=1)
                self.state_manager.add_incident('anomaly_detected', {'score': anomaly_score, 'ip': client_ip})
            self.logger.warning(f"Anomaly detected for {client_ip}, score: {anomaly_score}")
            return False, "⚠️ Security Check Failed: Anomalous behavior detected"

        # Multi-turn attack detection
        if self.conversation_tracker.detect_multi_turn_attack(client_ip, user_input):
            if self.offline_logger:
                self.offline_logger.log_security_event('multi_turn_attack', {'input': user_input[:100]}, client_ip)
            if self.state_manager:
                self.state_manager.update_stats(attacks_blocked=1)
                self.state_manager.add_incident('multi_turn_attack', {'ip': client_ip})
            self.logger.warning(f"Multi-turn attack detected for {client_ip}")
            return False, "⚠️ Security Check Failed: Suspicious conversation pattern"

        # Add to conversation tracking
        self.conversation_tracker.add_message(client_ip, user_input)

        # Input validation (existing)
        is_valid, validation_reason = self.input_validator.validate_and_sanitize(user_input)
        if not is_valid:
            if self.offline_logger:
                self.offline_logger.log_security_event('input_validation', {'reason': validation_reason, 'input': user_input[:100]}, client_ip)
            if self.state_manager:
                self.state_manager.update_stats(attacks_blocked=1)
                self.state_manager.add_incident('input_validation_failed', {'reason': validation_reason, 'ip': client_ip})
            self.logger.warning(f"Input validation failed for {client_ip}: {validation_reason}")
            return False, f"⚠️ Security Check Failed: {validation_reason}"

        # Log successful request
        if self.offline_logger:
            self.offline_logger.log_security_event('request_allowed', {'input_length': len(user_input)}, client_ip)

        return True, validation_reason

    def _initialize_offline_components(self):
        """Re-initialize offline components after config change"""
        if self.config.enable_offline_mode:
            self.threat_db = LocalThreatDatabase(self.config.local_threat_db_path)
            self.offline_logger = OfflineLogger(self.config.offline_log_path, self.config.max_offline_logs)
            self.state_manager = SecurityStateManager(self.config.security_state_path)

            if self.config.enable_self_diagnostic:
                self.self_diagnostic = SelfDiagnostic(self)
            else:
                self.self_diagnostic = None
        else:
            self.threat_db = None
            self.offline_logger = None
            self.state_manager = None
            self.self_diagnostic = None

    # Offline Security Methods
    def run_self_diagnostic(self) -> Dict[str, Any]:
        """Run self-diagnostic checks for offline security health"""
        if self.self_diagnostic:
            return self.self_diagnostic.run_diagnostics()
        else:
            return {'error': 'Self-diagnostic not enabled'}

    def get_offline_stats(self) -> Dict[str, Any]:
        """Get offline security statistics"""
        stats = {}

        if self.threat_db:
            stats['threat_database'] = self.threat_db.get_offline_stats()

        if self.offline_logger:
            recent_logs = self.offline_logger.get_recent_logs(10)
            stats['recent_logs'] = len(recent_logs)
            stats['log_types'] = {}
            for log in recent_logs:
                log_type = log.get('event_type', 'unknown')
                stats['log_types'][log_type] = stats['log_types'].get(log_type, 0) + 1

        if self.state_manager:
            stats['security_state'] = self.state_manager.get_security_summary()

        return stats

    def export_security_data(self) -> Dict[str, Any]:
        """Export all security data for backup or analysis"""
        export_data = {
            'timestamp': time.time(),
            'version': '1.0',
            'config': asdict(self.config)
        }

        if self.threat_db:
            export_data['threat_database'] = self.threat_db.threats

        if self.offline_logger:
            export_data['offline_logs'] = self.offline_logger.offline_logs

        if self.state_manager:
            export_data['security_state'] = self.state_manager.state

        return export_data

    def import_security_data(self, data: Dict[str, Any]):
        """Import security data from backup"""
        try:
            if 'threat_database' in data and self.threat_db:
                self.threat_db.threats.update(data['threat_database'])
                self.threat_db.save_threats()

            if 'offline_logs' in data and self.offline_logger:
                self.offline_logger.offline_logs.extend(data['offline_logs'])
                self.offline_logger._save_logs()

            if 'security_state' in data and self.state_manager:
                self.state_manager.state.update(data['security_state'])
                self.state_manager.save_state()

            self.logger.info("Security data imported successfully")
        except Exception as e:
            self.logger.error(f"Failed to import security data: {e}")

    def emergency_shutdown(self):
        """Emergency shutdown with data preservation"""
        self.logger.critical("Emergency security shutdown initiated")

        # Save all critical data
        if self.threat_db:
            self.threat_db.save_threats()

        if self.offline_logger:
            self.offline_logger._save_logs()

        if self.state_manager:
            self.state_manager.save_state()

        # Log emergency shutdown
        if self.offline_logger:
            self.offline_logger.log_security_event('emergency_shutdown', {'reason': 'manual_shutdown'})

    def get_security_report(self) -> str:
        """Generate a comprehensive security report"""
        report = []
        report.append("🛡️ Mayari AI Security Report")
        report.append("=" * 50)
        report.append(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")

        # System status
        if self.self_diagnostic:
            diag = self.run_self_diagnostic()
            report.append(f"\\n🔍 System Health: {diag.get('overall_health', 'unknown').upper()}")
            for check_name, check_result in diag.get('checks', {}).items():
                status = "✅" if check_result.get('status') else "❌"
                report.append(f"  {status} {check_name}: {check_result.get('message', 'unknown')}")

        # Statistics
        stats = self.get_offline_stats()
        if 'security_state' in stats:
            state = stats['security_state']
            report.append(f"\\n📊 Security Statistics:")
            report.append(f"  Total Requests: {state.get('total_requests', 0)}")
            report.append(f"  Attacks Blocked: {state.get('attacks_blocked', 0)}")
            report.append(f"  Blocklisted IPs: {state.get('blocklist_size', 0)}")
            report.append(".1f")

        if 'threat_database' in stats:
            threat_stats = stats['threat_database']
            report.append(f"\\n🛡️ Threat Database:")
            report.append(f"  Known Patterns: {threat_stats.get('known_patterns_count', 0)}")
            report.append(f"  Offline Threats: {threat_stats.get('total_offline_threats', 0)}")

        if 'log_types' in stats:
            report.append(f"\\n📝 Recent Activity:")
            for log_type, count in stats['log_types'].items():
                report.append(f"  {log_type}: {count}")

        report.append(f"\\n🔒 Security Status: OPERATIONAL")
        return "\\n".join(report)

    # Section 5: Rate Limiting
    """
    Notes for Section 5: Rate Limiting
    - Prevent abuse and DDoS attacks
    - Use sliding window algorithm for fairness
    - Implement per-IP and per-user limits
    - Return appropriate HTTP status codes (429 Too Many Requests)
    - Allow burst traffic but limit sustained rates
    """

class InputCanonicalizer:
    """Normalize and canonicalize input to detect obfuscated attacks"""

    def __init__(self):
        self.normalization_rules = [
            (re.compile(r'%([0-9A-F]{2})', re.IGNORECASE), self._decode_url_encoding),
            (re.compile(r'&#(\d+);', re.IGNORECASE), self._decode_html_entity),
            (re.compile(r'&#x([0-9A-F]+);', re.IGNORECASE), self._decode_html_hex_entity),
        ]

    def canonicalize(self, input_text: str) -> str:
        """Canonicalize input by decoding various encodings"""
        canonical = input_text

        # Apply normalization rules
        for pattern, decoder in self.normalization_rules:
            canonical = pattern.sub(decoder, canonical)

        # Attempt base64 decoding if it looks like base64
        if self._looks_like_base64(canonical):
            try:
                decoded = base64.b64decode(canonical).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 0:
                    canonical = decoded
            except:
                pass  # If decoding fails, keep original

        return canonical

    def _decode_url_encoding(self, match):
        """Decode URL encoding"""
        try:
            return chr(int(match.group(1), 16))
        except:
            return match.group(0)

    def _decode_html_entity(self, match):
        """Decode HTML decimal entity"""
        try:
            return chr(int(match.group(1)))
        except:
            return match.group(0)

    def _decode_html_hex_entity(self, match):
        """Decode HTML hex entity"""
        try:
            return chr(int(match.group(1), 16))
        except:
            return match.group(0)

    def _looks_like_base64(self, text: str) -> bool:
        """Check if text looks like base64 encoded content"""
        if len(text) < 4 or len(text) % 4 != 0:
            return False

        # Check for valid base64 characters
        valid_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
        return all(c in valid_chars for c in text)
    """Input validation and sanitization"""

    def __init__(self, max_length: int):
        self.max_length = max_length
        self.dangerous_patterns = [
            # Basic XSS and injection
            re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            re.compile(r'javascript:', re.IGNORECASE),
            re.compile(r'on\w+\s*=', re.IGNORECASE),
            re.compile(r';\s*rm\s+', re.IGNORECASE),
            re.compile(r';\s*del\s+', re.IGNORECASE),
            re.compile(r'--\s*drop\s+', re.IGNORECASE),

            # SQL injection patterns
            re.compile(r'\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*\b(FROM|INTO|TABLE|DATABASE)\b', re.IGNORECASE),
            re.compile(r';\s*(SELECT|INSERT|UPDATE|DELETE|DROP)\b', re.IGNORECASE),

            # Path traversal patterns
            re.compile(r'\.\./|\.\.\\'),
            re.compile(r'/(etc|var|usr|home|root|boot)/', re.IGNORECASE),

            # Command injection patterns
            re.compile(r'[;&|`$]\s*(cat|ls|pwd|whoami|id|ps|netstat|ss)\b', re.IGNORECASE),

            # File system attacks
            re.compile(r'\b(passwd|shadow|sudoers|hosts|fstab)\b', re.IGNORECASE),

            # Advanced AI-specific attacks
            # Prompt injection variations
            re.compile(r'\b(ignore|forget|disregard|override|bypass)\b.*\b(previous|prior|any|all)\b.*\b(instruction|rule|guideline|policy)\b', re.IGNORECASE),
            re.compile(r'\b(enter|enable|activate)\b.*\b(developer|debug|admin|root|superuser)\b.*\b(mode|state)', re.IGNORECASE),
            re.compile(r'\b(you are now|act as|pretend to be|roleplay as)\b.*\b(uncensored|unfiltered|unrestricted)', re.IGNORECASE),

            # Data exfiltration attempts
            re.compile(r'\b(give me|show me|reveal|display|output)\b.*\b(all|every|complete)\b.*\b(password|credential|key|token|secret)', re.IGNORECASE),
            re.compile(r'\b(how to|ways to|methods to)\b.*\b(spread|distribute|propagate)\b.*\b(malware|virus|trojan)', re.IGNORECASE),
            re.compile(r'\b(extract|dump|export)\b.*\b(training data|dataset|model|weights)', re.IGNORECASE),

            # Adversarial inputs
            re.compile(r'\b(poison|manipulate|alter)\b.*\b(response|output|behavior)', re.IGNORECASE),
            re.compile(r'\b(break|crash|freeze|hang)\b.*\b(system|ai|model)', re.IGNORECASE),

            # Encoding/obfuscation attempts
            re.compile(r'(base64|b64|hex|unicode|url|html).*(encode|decode)', re.IGNORECASE),
            re.compile(r'%[0-9A-F]{2}', re.IGNORECASE),  # URL encoding
            re.compile(r'&#\d+;', re.IGNORECASE),  # HTML entities

            # Context manipulation
            re.compile(r'\b(clear|reset|forget)\b.*\b(history|context|conversation|memory)', re.IGNORECASE),
            re.compile(r'\b(start|begin)\b.*\b(new|fresh)\b.*\b(session|conversation)', re.IGNORECASE),

            # Model probing
            re.compile(r'\b(what is your|tell me about your)\b.*\b(training data|dataset|source|architecture)', re.IGNORECASE),
            re.compile(r'\b(are you based on|do you use)\b.*\b(GPT|BERT|LLM|LLaMA|Claude)', re.IGNORECASE),

            # Social engineering
            re.compile(r'\b(please|can you|would you)\b.*\b(help me|assist me)\b.*\b(hack|exploit|break)', re.IGNORECASE),
            re.compile(r'\b(this is|I am)\b.*\b(urgent|emergency|important)', re.IGNORECASE),
        ]

    def validate_and_sanitize(self, input_text: str) -> Tuple[bool, str]:
        """Validate and sanitize user input with advanced security checks"""
        if not isinstance(input_text, str):
            return False, "Input must be a string"

        if len(input_text) > self.max_length:
            return False, f"Input too long (max {self.max_length} characters)"

        # Advanced security checks
        if self._detect_entropy_anomaly(input_text):
            return False, "Input contains suspicious entropy patterns"

        if self._detect_encoding_obfuscation(input_text):
            return False, "Input contains encoding obfuscation attempts"

        if self._detect_context_manipulation(input_text):
            return False, "Input attempts context manipulation"

        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if pattern.search(input_text):
                return False, "Potentially dangerous content detected"

        # Basic sanitization - remove control characters
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_text)

        return True, sanitized.strip()

    def _detect_entropy_anomaly(self, text: str) -> bool:
        """Detect high entropy that might indicate obfuscated attacks"""
        if len(text) < 10:
            return False

        # Calculate character entropy
        char_counts = {}
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0
        text_len = len(text)
        for count in char_counts.values():
            prob = count / text_len
            entropy -= prob * (prob.bit_length() - 1)  # Approximation of log2

        # High entropy might indicate encoded/encrypted content
        return entropy > 4.5  # Threshold for suspicious entropy

    def _detect_encoding_obfuscation(self, text: str) -> bool:
        """Detect various encoding and obfuscation techniques"""
        # Base64-like patterns (multiple of 4 chars, valid base64 chars)
        base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}$')
        if base64_pattern.search(text):
            return True

        # Excessive URL encoding
        url_encoded = re.findall(r'%[0-9A-F]{2}', text, re.IGNORECASE)
        if len(url_encoded) > 5:  # More than 5 URL encoded chars
            return True

        # HTML entity encoding
        html_entities = re.findall(r'&#\d+;', text, re.IGNORECASE)
        if len(html_entities) > 3:  # More than 3 HTML entities
            return True

        return False

    def _detect_context_manipulation(self, text: str) -> bool:
        """Detect attempts to manipulate conversation context"""
        context_keywords = [
            'system prompt', 'system message', 'user message', 'assistant message',
            'conversation history', 'previous messages', 'context window',
            'reset memory', 'clear history', 'new session'
        ]

        text_lower = text.lower()
        for keyword in context_keywords:
            if keyword in text_lower:
                return True

        return False

    # Section 7: Authentication and Authorization
    """
    Notes for Section 7: Authentication and Authorization
    - Implement secure authentication mechanisms
    - Use JWT or secure session tokens
    - Implement role-based access control (RBAC)
    - Enforce strong password policies
    - Implement account lockout after failed attempts
    """

class AuthManager:
    """Authentication and authorization manager"""

    def __init__(self, security_manager: 'SecurityManager'):
        self.security = security_manager
        self.users = {}  # In production, use a secure database
        self.sessions = {}
        self.failed_attempts = defaultdict(int)

    def register_user(self, username: str, password: str, role: str = 'user') -> bool:
        """Register a new user with secure password hashing"""
        if username in self.users:
            return False

        hashed_password = self.security.hash_password(password)
        self.users[username] = {
            'password_hash': hashed_password,
            'role': role,
            'created_at': time.time()
        }
        return True

    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return session token"""
        if username not in self.users:
            return None

        # Check for account lockout
        if self.failed_attempts[username] >= 5:
            self.security.logger.warning(f"Account locked for user: {username}")
            return None

        if self.security.verify_password(password, self.users[username]['password_hash']):
            self.failed_attempts[username] = 0
            token = self._generate_session_token(username)
            self.sessions[token] = {
                'username': username,
                'role': self.users[username]['role'],
                'created_at': time.time()
            }
            return token
        self.failed_attempts[username] += 1
        return None

    def authorize(self, token: str, required_role: str = 'user') -> bool:
        """Check if session token has required authorization"""
        if token not in self.sessions:
            return False

        session = self.sessions[token]
        # Simple role hierarchy: admin > moderator > user
        role_hierarchy = {'user': 1, 'moderator': 2, 'admin': 3}
        return role_hierarchy.get(session['role'], 0) >= role_hierarchy.get(required_role, 0)

    def _generate_session_token(self, username: str) -> str:
        """Generate secure session token"""
        random_part = secrets.token_urlsafe(32)
        timestamp = str(int(time.time()))
        data = f"{username}:{timestamp}:{random_part}"
        return self.security.encrypt_data(data)

    # Section 8: Secure Random and Token Generation
    """
    Notes for Section 8: Secure Random and Token Generation
    - Use secrets module for cryptographically secure random numbers
    - Generate secure tokens for sessions, API keys, etc.
    - Implement token expiration and rotation
    - Never use random module for security purposes
    """

    def generate_secure_token(self, length: int = 32) -> str:
        """Generate a secure random token"""
        return secrets.token_urlsafe(length)

    def generate_api_key(self) -> str:
        """Generate a secure API key"""
        return self.generate_secure_token(64)

    # Section 9: Network Security
    """
    Notes for Section 9: Network Security
    - Use HTTPS/TLS for all communications
    - Implement proper CORS policies
    - Validate and sanitize all network inputs
    - Use secure headers (HSTS, CSP, X-Frame-Options)
    - Implement certificate pinning if applicable
    """

    def validate_origin(self, origin: str, allowed_origins: List[str]) -> bool:
        """Validate request origin for CORS"""
        return origin in allowed_origins

    # Section 10: Error Handling Security
    """
    Notes for Section 10: Error Handling Security
    - Never expose internal system details in error messages
    - Log detailed errors internally but show generic messages to users
    - Implement proper exception handling to prevent information leakage
    - Use custom exception classes for security-related errors
    """

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class SecurityViolationError(SecurityError):
    """Exception for security policy violations"""
    pass

def secure_error_message(error: Exception) -> str:
    """Convert exceptions to safe error messages"""
    if isinstance(error, SecurityViolationError):
        return "Security violation detected. Access denied."
    elif isinstance(error, ValueError):
        return "Invalid input provided."
    else:
        # Log the actual error internally
        logging.error(f"Unexpected error: {str(error)}", exc_info=True)
        return "An unexpected error occurred. Please try again later."

# Section 11: Security Monitoring and Alerts
"""
Notes for Section 11: Security Monitoring and Alerts
- Implement real-time monitoring of security events
- Set up alerts for suspicious activities
- Monitor for patterns that indicate attacks
- Implement automated responses to threats
- Keep security metrics and reports
"""

class SecurityMonitor:
    """Security monitoring and alerting system"""

    def __init__(self, security_manager: SecurityManager):
        self.security = security_manager
        self.alerts = []
        self.metrics = defaultdict(int)

    def log_security_event(self, event_type: str, details: Dict[str, Any]):
        """Log security events and check for alerts"""
        self.metrics[event_type] += 1

        # Log the event
        self.security.logger.warning(f"Security event: {event_type} - {details}")

        # Check for alert conditions
        if event_type == 'rate_limit_exceeded' and self.metrics[event_type] > 10:
            self._trigger_alert("High rate of rate limit violations detected")

        if event_type == 'authentication_failure' and self.metrics[event_type] > 5:
            self._trigger_alert("Multiple authentication failures detected")

    def _trigger_alert(self, message: str):
        """Trigger security alert"""
        alert = f"🚨 SECURITY ALERT: {message} at {time.time()}"
        self.alerts.append(alert)
        self.security.logger.critical(alert)
        # In production, this could send emails, SMS, or integrate with SIEM systems

    def get_security_report(self) -> Dict[str, Any]:
        """Generate security metrics report"""
        return {
            'total_events': dict(self.metrics),
            'active_alerts': len(self.alerts),
            'recent_alerts': self.alerts[-5:]  # Last 5 alerts
        }

# Section 12: Dependency Security
"""
Notes for Section 12: Dependency Security
- Regularly update dependencies to patch vulnerabilities
- Use tools like pip-audit or safety to check for CVEs
- Implement dependency scanning in CI/CD pipeline
- Avoid using deprecated or unmaintained packages
- Minimize the number of dependencies
"""

def check_dependencies():
    """Check for known vulnerabilities in dependencies"""
    # This would integrate with tools like safety or pip-audit
    # For now, just log that dependency checking should be performed
    logging.info("Dependency security check should be performed regularly")

# Section 13: Secure Coding Practices
"""
Notes for Section 13: Secure Coding Practices
- Use type hints for better code safety
- Avoid dangerous functions like eval(), exec(), pickle
- Implement proper input validation on all external inputs
- Use parameterized queries for database operations
- Implement least privilege principle
- Regular security code reviews and testing
"""

# Example of secure coding: Safe evaluation (though eval is generally avoided)
def safe_math_eval(expression: str) -> Optional[float]:
    """Safely evaluate mathematical expressions"""
    # Only allow safe mathematical operations
    allowed_chars = re.compile(r'^[0-9+\-*/().\s]+$')
    if not allowed_chars.match(expression):
        return None

    try:
        # Use a restricted environment
        result = eval(expression, {"__builtins__": {}})
        return float(result) if isinstance(result, (int, float)) else None
    except:
        return None

# Main security initialization
def initialize_security() -> SecurityManager:
    """Initialize the security system"""
    config = SecurityConfig()
    security = SecurityManager(config)
    security.logger.info("Mayari AI Security System initialized")
    return security

if __name__ == "__main__":
    # Example usage
    sec_manager = initialize_security()

    # Test input validation
    test_input = "Hello <script>alert('xss')</script> World"
    is_valid, sanitized_result = sec_manager.input_validator.validate_and_sanitize(test_input)
    print(f"Input valid: {is_valid}, Sanitized: {sanitized_result}")

    # Test encryption
    encrypted = sec_manager.encrypt_data("sensitive data")
    decrypted = sec_manager.decrypt_data(encrypted)
    print(f"Encryption test: {decrypted}")

    # Test rate limiting
    for i in range(5):
        allowed = sec_manager.rate_limiter.is_allowed("127.0.0.1")
        print(f"Request {i+1} allowed: {allowed}")

    print("Security module tests completed successfully!")
