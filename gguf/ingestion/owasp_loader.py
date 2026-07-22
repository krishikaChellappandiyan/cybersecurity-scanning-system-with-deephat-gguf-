import json
import requests
from bs4 import BeautifulSoup
from config import OWASP_DATA_PATH


class OWASPLoader:
    def __init__(self):
        self.sources = [
            "https://owasp.org/Top10/2025/",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://attack.mitre.org/techniques/T1059/",
            "https://attack.mitre.org/techniques/T1566/",
            "https://attack.mitre.org/techniques/T1059/",
            "https://attack.mitre.org/techniques/T1190/",
            "https://attack.mitre.org/techniques/T1078/",
            "https://www.exploit-db.com/exploits/40936",
            "https://www.exploit-db.com/exploits/40990",
            "https://www.exploit-db.com/exploits/47967",
            "https://www.exploit-db.com/exploits/47974",
            "https://www.exploit-db.com/exploits/47764"
        ]

    def fetch_page(self, url):
        try:
            response = requests.get(
                url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0"}
            )

            if response.status_code == 200:
                return response.text

            print(f"Failed: {url} ({response.status_code})")
            return None

        except Exception as e:
            print(f"Error fetching {url}: {e}")
            return None

    def parse_html(self, html):
        soup = BeautifulSoup(html, "html.parser")

        for tag in soup([
            "script",
            "style",
            "nav",
            "footer",
            "header",
            "aside"
        ]):
            tag.decompose()

        text = soup.get_text(separator="\n")

        bad_words = [
            "translation",
            "translated by",
            "contributors",
            "project sponsors",
            "twitter",
            "pdf",
            "pptx",
            "copyright",
            "cookie",
            "privacy policy",
            "email protected"
        ]

        lines = []

        for line in text.split("\n"):
            line = line.strip()

            if len(line) < 40:
                continue

            if any(word in line.lower() for word in bad_words):
                continue

            lines.append(line)

        return "\n".join(lines)

    def load(self):
        OWASP_DATA_PATH.parent.mkdir(parents=True, exist_ok=True)

        documents = []

        for url in self.sources:

            print(f"Fetching: {url}")

            html = self.fetch_page(url)

            if not html:
                continue

            text = self.parse_html(html)

            documents.append({
                "source": url,
                "title": url,
                "content": text,
                "url": url
            })

        with open(OWASP_DATA_PATH, "w", encoding="utf-8") as f:
            json.dump(documents, f, indent=2, ensure_ascii=False)

        return documents