# Import regular expressions for input normalization and pattern matching.
import re

# Import the EducationModule to handle educational queries and learning responses.
from education_content.education import EducationModule

# Main assistant class for Mayari.
# This class coordinates input normalization, error translation, and educational content delivery.
class MayariCore:
    def __init__(self):
        # Name of the assistant instance.
        self.name = "Mayari"

        # Predefined error messages for common system-like queries.
        # The assistant can translate these codes into human-friendly responses.
        self.error_library = {
            "404": "I couldn't find that page. It's like looking for a book that isn't on the shelf.",
            "500": "The system's internal brain is a bit confused right now. Try again in a moment.",
            "access denied": "You don't have the key for this room yet. Check your permissions.",
        }

        # Create the education module that supports teaching-style responses.
        self.education = EducationModule()

    def normalize(self, user_input):
        # Normalize user input by trimming whitespace, collapsing spaces, and lowercasing.
        # This helps make matching robust and case-insensitive.
        return re.sub(r"\s+", " ", user_input.strip().lower())

    def technical_translator(self, error_code):
        # Translate known system error codes into friendly messages.
        # Unknown codes get a fallback message asking to research the issue safely.
        return self.error_library.get(
            error_code.lower(),
            "I'm not sure what that error means. Let's research it together in a safe way.",
        )

    def generate_response(self, user_input):
        # Generate the final response based on the user's input.
        normalized = self.normalize(user_input)

        # If the user input exactly matches a known error code, return a translated message.
        if normalized in self.error_library:
            return self.technical_translator(normalized)

        # If the input appears educational, delegate to the EducationModule for a teaching response.
        if self.education.is_educational_query(user_input):
            return self.education.get_learning_response(user_input)

        # Default fallback when the query is not recognized as a known error or educational request.
        return (
            "Mayari says: I’m here to help with safe, factual technical guidance. "
            "If you need a specific explanation, please ask with clear, non-harmful details."
        )

    def process_query(self, user_input, client_ip="127.0.0.1"):
        # Top-level entry point for processing a user's query.
        # The client_ip parameter is reserved for future security or logging use.
        try:
            return self.generate_response(user_input)
        except Exception:
            # Catch all unexpected errors and return a safe error message.
            return "⚠️ An error occurred while processing your request. Please try again."


def run_interactive_shell():
    # Start a simple command-line interface for interacting with Mayari.
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
