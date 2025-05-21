class IntentEntityRecognizer:
    def __init__(self):
        self.intents = {
            "greet": ["hello", "hi", "hey"],
            "goodbye": ["bye", "farewell"],
            "thank": ["thank you", "thanks"],
            "affirm": ["yes", "sure"],
            "negate": ["no", "not really"]
        }

    def recognize_intent(self, user_input):
        for intent, keywords in self.intents.items():
            if any(keyword in user_input.lower() for keyword in keywords):
                return intent
        return None