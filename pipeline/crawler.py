from pathlib import Path
import subprocess
import sys


class HellhoundCrawler:
    """
    Runs the standalone Hellhound Spider and returns
    the path of the generated JSON report.
    """

    def __init__(self):
        # Project root (E:\gguf)
        self.project_root = Path(__file__).resolve().parent.parent

        # hellhound/spider.py
        self.spider_script = self.project_root / "hellhound" / "spider.py"

        # Directory to store spider reports
        self.report_dir = self.project_root / "reports" / "spiders"

        # Create reports/spiders if it doesn't exist
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def crawl(self, target: str) -> Path:
        """
        Run Hellhound exactly as if executed from the terminal.

        Returns:
            Path to the generated spider JSON.
        """

        # Existing spider reports before crawling
        before = set(self.report_dir.glob("spider_*.json"))

        command = [
            sys.executable,
            str(self.spider_script),
            target,
        ]

        print(f"\n[*] Running Hellhound on {target}\n")

        result = subprocess.run(
            command,
            cwd=self.report_dir,   # Save reports inside reports/spiders
        )

        if result.returncode != 0:
            raise RuntimeError("Hellhound crawl failed.")

        # Spider reports after crawling
        after = set(self.report_dir.glob("spider_*.json"))

        # Newly created report
        new_reports = after - before

        if new_reports:
            newest = max(new_reports, key=lambda f: f.stat().st_mtime)
        else:
            # Fallback: newest spider report
            reports = list(after)
            if not reports:
                raise FileNotFoundError("No spider JSON generated.")
            newest = max(reports, key=lambda f: f.stat().st_mtime)

        print(f"\n[+] Spider report: {newest}")

        return newest