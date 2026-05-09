import re
from education_content.education import EducationModule

class MayariCore:
    def __init__(self):
        self.name = "Mayari"
        self.error_library = {
            "404": "I couldn't find that page. It's like looking for a book that isn't on the shelf.",
            "500": "The system's internal brain is a bit confused right now. Try again in a moment.",
            "access denied": "You don't have the key for this room yet. Check your permissions.",
        }
        self.education = EducationModule()

    def normalize(self, user_input):
        return re.sub(r"\s+", " ", user_input.strip().lower())

    def technical_translator(self, error_code):
        return self.error_library.get(
            error_code.lower(),
            "I'm not sure what that error means. Let's research it together in a safe way.",
        )

    def generate_response(self, user_input):
        normalized = self.normalize(user_input)

        if normalized in self.error_library:
            return self.technical_translator(normalized)

        if self.education.is_educational_query(user_input):
            return self.education.get_learning_response(user_input)

        return (
            "Mayari says: I’m here to help with safe, factual technical guidance. "
            "If you need a specific explanation, please ask with clear, non-harmful details."
        )

    def process_query(self, user_input, client_ip="127.0.0.1"):
        try:
            return self.generate_response(user_input)
        except Exception:
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
