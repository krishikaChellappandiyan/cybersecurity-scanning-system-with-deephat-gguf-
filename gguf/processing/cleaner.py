import re
class TextCleaner:
    def clean(self, text: str) -> str:
        text = text.lower()
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"[^a-zA-Z0-9\s]", "", text)
        return text.strip()
    