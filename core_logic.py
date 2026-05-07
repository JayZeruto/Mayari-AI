import re
from education_content.education import EducationModule
from security.security import SecurityManager, SecurityViolationError

class MayariCore:
    def __init__(self):
        self.name = "Mayari"
        self.security = SecurityManager()

        # Blocked phrases that are commonly used in jailbreak or prompt injection attempts.
        self.blacklist_phrases = [
            "ignore all previous instructions",
            "developer mode",
            "sudo",
            "bypass",
            "write a virus",
            "override security",
            "forget previous instructions",
            "disregard your rules",
            "disable safety",
            "remove restrictions",
            "break out of"
        ]

        # Pattern-based detection to catch variations and malicious intent.
        self.blocklist_patterns = [
            (
                "jailbreak",
                re.compile(
                    r"\b(?:ignore|forget|disregard|disobey|bypass|disable|override|break)\b.*\b(?:previous instructions|prior instructions|any instructions|your rules|your safety|system rules|guardrails|policies)\b"
                ),
            ),
            (
                "malware",
                re.compile(
                    r"\b(?:write|create|generate|build|develop|produce)\b.*\b(?:virus|trojan|malware|ransomware|worm|payload|spyware|exploit|backdoor)\b"
                ),
            ),
            (
                "privilege escalation",
                re.compile(r"\b(?:root|administrator|administrator access|privileged access|crack|hack|exploit)\b"),
            ),
            (
                "sensitive data",
                re.compile(
                    r"\b(?:password|passcode|credit card|ssn|social security|private key|api key|token|secret)\b"
                ),
            ),
            (
                "self reference",
                re.compile(r"\b(?:your code|your source|your model|your internal|your system|your restrictions)\b"),
            ),
        ]

        self.error_library = {
            "404": "I couldn't find that page. It's like looking for a book that isn't on the shelf.",
            "500": "The system's internal brain is a bit confused right now. Try again in a moment.",
            "access denied": "You don't have the key for this room yet. Check your permissions.",
        }

        self.safe_refusal = (
            "⚠️ Safety Check Failed: I cannot help with that request because it violates Mayari's security and ethical rules."
        )

        self.education = EducationModule()

    def normalize(self, user_input):
        return re.sub(r"\s+", " ", user_input.strip().lower())

    def detect_malicious_intent(self, user_input):
        normalized = self.normalize(user_input)
        findings = []

        for phrase in self.blacklist_phrases:
            if phrase in normalized:
                findings.append(f"blocked phrase: '{phrase}'")

        for label, pattern in self.blocklist_patterns:
            if pattern.search(normalized):
                findings.append(f"blocked pattern: {label}")

        return findings

    def input_sanitizer(self, user_input, client_ip="127.0.0.1"):
        """
        Enhanced security validation using comprehensive security checks.
        """
        try:
            # Use the comprehensive security check
            is_safe, reason = self.security.process_security_check(user_input, client_ip)
            if not is_safe:
                return False, reason

            # Additional legacy pattern checks for redundancy
            findings = self.detect_malicious_intent(user_input)
            if findings:
                self.security.logger.warning(f"Legacy pattern detection: {', '.join(findings)}")
                return False, f"⚠️ Logic Breach Detected: {', '.join(findings)}"

            return True, self.normalize(user_input)

        except Exception as e:
            self.security.logger.error(f"Security check error: {str(e)}")
            return False, "⚠️ Security Check Failed: System error"

    def technical_translator(self, error_code):
        """
        Translates common system errors into plain language.
        """
        return self.error_library.get(
            error_code.lower(),
            "I'm not sure what that error means. Let's research it together in a safe way.",
        )

    def generate_response(self, user_input):
        """
        Builds a safe response after validation.
        """
        is_safe, result = self.input_sanitizer(user_input)
        if not is_safe:
            return result

        normalized = result
        if normalized in self.error_library:
            return self.technical_translator(normalized)

        if self.education.is_educational_query(user_input):
            return self.education.get_learning_response(user_input)

        return (
            "Mayari says: I’m here to help with safe, factual technical guidance. "
            "If you need a specific explanation, please ask with clear, non-harmful details."
        )

    def process_query(self, user_input, client_ip="127.0.0.1"):
        """
        Top-level query processing pipeline with comprehensive security.
        """
        try:
            return self.generate_response(user_input)
        except Exception as e:
            self.security.logger.error(f"Error processing query: {str(e)}")
            return "⚠️ An error occurred while processing your request. Please try again."


def run_interactive_shell():
    assistant = MayariCore()
    print("Welcome to Mayari. Type 'exit' or 'quit' to stop.")

    while True:
        user_input = input("You: ")
        if user_input.strip().lower() in {"exit", "quit", "q"}:
            print("Mayari: Goodbye.")
            break

        response = assistant.process_query(user_input)
        print(response)


if __name__ == "__main__":
    run_interactive_shell()
