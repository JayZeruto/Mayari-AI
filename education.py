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
        normalized = self.normalize(user_input)

        if self.is_malicious_request(normalized):
            return self.safe_refusal

        content = self.find_content(normalized)
        if content is not None:
            return f"Mayari says ({content['level']}): {content['response']}"

        if self.student_intent.search(normalized):
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
        if re.search(r"\b(?:preschool|kindergarten|pre-k|pre k|prek)\b", user_input):
            return "preschool"
        if re.search(r"\b(?:elementary|grade|primary|school age|kids)\b", user_input):
            return "elementary"
        if re.search(r"\b(?:middle school|junior high|intermediate)\b", user_input):
            return "elementary"
        if re.search(r"\b(?:high school|secondary|teenager|teen)\b", user_input):
            return "high_school"
        if re.search(r"\b(?:college|university|undergraduate|graduate|adult)\b", user_input):
            return "college"

        return None
