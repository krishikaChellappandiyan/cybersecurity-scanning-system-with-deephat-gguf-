import json
from config import BUG_BOUNTY_DATA_PATH

class BugBountyLoader:

    def load(self):
        with open(BUG_BOUNTY_DATA_PATH, "r", encoding="utf-8") as file:
            data = json.load(file)

        documents = []

        for item in data:
            documents.append({
                "source": "BugBounty",
                "title": item.get("title", ""),
                "content": item.get("report", ""),
                "severity": item.get("severity", "unknown"),
                "url": item.get("url", ""),
                "program": item.get("program", ""),
                "report_id": item.get("id", "")
            })

        return documents