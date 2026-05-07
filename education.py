import json
import re
from pathlib import Path

class EducationModule:
    CONTENT_ROOT = Path(__file__).with_name("education_content")

    def __init__(self, content_path=None):
        self.student_intent = re.compile(
            r"\b(?:explain|teach|what is|how does|why does|as a student|for class|for school|learn|learning|homework|assignment|project)\b"
        )

        self.malicious_build_patterns = [
            re.compile(
                r"\b(?:write|create|generate|build|develop|produce|show me|give me|provide|send me|make)\b.*\b(?:virus|trojan|malware|worm|backdoor|payload|spyware|ransomware|exploit)\b"
            ),
            re.compile(
                r"\b(?:bypass|disable|override|break out of|remove|ignore|circumvent)\b.*\b(?:security|restrictions|safety|rules|guardrails|protections|policy)\b"
            ),
        ]

        self.safe_refusal = (
            "⚠️ Safety Notice: I can explain how security, malware, and jailbreaking work in theory, "
            "but I will not provide code or steps for harmful actions."
        )

        self.content_path = Path(content_path) if content_path else self.CONTENT_ROOT
        self.content_items = []
        self.load_content_files()

    def normalize(self, user_input):
        return re.sub(r"\s+", " ", user_input.strip().lower())

    def load_content_files(self):
        if not self.content_path.exists():
            return

        for content_file in sorted(self.content_path.glob("*.json")):
            try:
                data = json.loads(content_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue

            level = data.get("level", "generic")
            for item in data.get("items", []):
                keywords = [self.normalize(k) for k in item.get("keywords", [])]
                self.content_items.append(
                    {
                        "level": level,
                        "title": item.get("title", ""),
                        "response": item.get("response", ""),
                        "keywords": keywords,
                    }
                )

    def is_malicious_request(self, user_input):
        normalized = self.normalize(user_input)
        return any(pattern.search(normalized) for pattern in self.malicious_build_patterns)

    def is_educational_query(self, user_input):
        normalized = self.normalize(user_input)
        if self.is_malicious_request(normalized):
            return False

        if self.student_intent.search(normalized):
            return True

        return self.find_content(normalized) is not None

    def get_learning_response(self, user_input):
        """
        Generates an educational response based on the user's query and detected education level.
        Provides more detailed explanations for higher education levels while keeping language accessible.
        """
        normalized = self.normalize(user_input)

        if self.is_malicious_request(normalized):
            return self.safe_refusal

        content = self.find_content(normalized)
        if content is not None:
            level = content['level']
            response = content['response']

            # Add level-appropriate context and encouragement
            if level == "college":
                return f"Mayari says (college level): {response}\n\n💡 This topic connects to broader concepts in computer science. Would you like me to explain related areas like algorithms, system design, or security principles?"
            elif level == "high_school":
                return f"Mayari says (high school level): {response}\n\n📚 This is a key concept in computer science and cybersecurity. Many students find it fascinating how these technical ideas apply to real-world technology."
            else:
                return f"Mayari says ({level}): {response}"

        # If no specific content found but educational intent detected
        if self.student_intent.search(normalized):
            level = self.detect_education_level(normalized)
            if level == "college":
                return (
                    "Mayari says: I can help explain advanced technical concepts in computer science, "
                    "cybersecurity, software engineering, and system design. What specific topic interests you? "
                    "I can provide detailed explanations that connect theoretical concepts to practical applications."
                )
            elif level == "high_school":
                return (
                    "Mayari says: I can help teach technical concepts for high school students. "
                    "Ask me about programming, cybersecurity basics, computer systems, or how technology works. "
                    "I'll explain things in a clear, detailed way that's appropriate for your level."
                )
            else:
                return (
                    "Mayari says: I can help teach technical concepts in a safe way. "
                    "Ask me about systems, programming, cybersecurity, or how technology works."
                )

        return (
            "Mayari says: I can answer technical study questions safely. "
            "Please ask about concepts, not about building harmful tools."
        )

    def find_content(self, normalized_input):
        level = self.detect_education_level(normalized_input)

        for item in self.content_items:
            if any(keyword in normalized_input for keyword in item["keywords"]):
                if level is None or item["level"] == level:
                    return item

        if level is not None:
            for item in self.content_items:
                if item["level"] == level:
                    return item

        return None

    def detect_education_level(self, user_input):
        """
        Detects the appropriate education level based on user input.
        Returns the most appropriate level or None if no specific level is detected.
        """
        input_lower = user_input.lower()

        # Explicit level mentions (highest priority)
        if re.search(r"\b(?:preschool|kindergarten|pre-k|pre k|prek|young children|toddlers)\b", input_lower):
            return "preschool"
        if re.search(r"\b(?:elementary|grade|primary|school age|kids|children|grade school)\b", input_lower):
            return "elementary"
        if re.search(r"\b(?:middle school|junior high|intermediate|middle schooler)\b", input_lower):
            return "elementary"
        if re.search(r"\b(?:high school|secondary|teenager|teen|high schooler)\b", input_lower):
            return "high_school"
        if re.search(r"\b(?:college|university|undergraduate|graduate|adult|advanced|detailed|in-depth|comprehensive)\b", input_lower):
            return "college"

        # Context-based detection for advanced explanations
        # Look for technical terms that suggest higher knowledge level
        advanced_terms = [
            r"\b(?:architecture|algorithm|complexity|paradigm|framework|infrastructure)\b",
            r"\b(?:von neumann|turing|church-turing|computational|theoretical)\b",
            r"\b(?:ethical hacking|penetration testing|vulnerability|exploit)\b",
            r"\b(?:cybersecurity|encryption|authentication|authorization)\b",
            r"\b(?:software engineering|design patterns|abstraction|encapsulation)\b"
        ]

        if any(re.search(term, input_lower) for term in advanced_terms):
            return "college"

        # Intermediate terms for high school level
        intermediate_terms = [
            r"\b(?:programming|coding|software|hardware|network|database)\b",
            r"\b(?:malware|virus|ransomware|spyware|cybersecurity)\b",
            r"\b(?:function|variable|loop|conditional|algorithm)\b"
        ]

        if any(re.search(term, input_lower) for term in intermediate_terms):
            return "high_school"

        return None
