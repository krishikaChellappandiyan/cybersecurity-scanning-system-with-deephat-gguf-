import json
from config import CVE_DATA_PATH
class CVELoader:
    def load(self):
        with open(CVE_DATA_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)
        documents = []
        for item in data:
            documents.append({
                "source": "CVE",
                "title": item.get("id", ""),
                "content": item.get("summary", "")
            })
        return documents
