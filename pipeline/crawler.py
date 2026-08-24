from pathlib import Path
from urllib.parse import urlparse
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

    @staticmethod
    def _target_slug(target: str) -> str:
        """
        Stable, filesystem-safe name for a target -- same host+port always
        produces the same slug, so repeat scans of the same target land
        on the same filename instead of accumulating a new timestamped
        file every run. hellhound/spider.py itself always writes a
        timestamped name internally (spider_<host>_<timestamp>.json) --
        that's vendor-tool behavior we don't touch; this wrapper just
        renames the result afterward.
        """
        parsed = urlparse(target)
        host = (parsed.netloc or parsed.path or "unknown_target").replace(":", "_")
        return host

    def crawl(self, target: str) -> Path:
        """
        Run Hellhound exactly as if executed from the terminal.

        Returns:
            Path to the spider JSON for this target. Always the same
            path for the same target across runs -- a new scan replaces
            the previous report for that target rather than piling up
            another timestamped file.
        """

        # Existing spider reports before crawling
        before = set(self.report_dir.glob("spider_*.json"))

        command = [
            sys.executable,
            str(self.spider_script),
            target,
            # Without this, Hellhound skips its known-sensitive-path probe
            # entirely ("[SensitiveFiles] Skipped (use --sensitive-probe/-e
            # to enable)") -- which includes /.git/HEAD and /.git/config
            # (type "Git_Exposure"). SOURCE_AUDIT_AGENT's routing depends
            # on that evidence actually showing up in
            # sensitive_file_evidence, so this needs to be on by default
            # rather than opt-in per scan.
            "--sensitive-probe",
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

        # Replace any previous report for this same target with the new
        # one, instead of keeping every timestamped run forever.
        stable_path = self.report_dir / f"spider_{self._target_slug(target)}.json"

        if stable_path.exists() and stable_path != newest:
            stable_path.unlink()

        newest.replace(stable_path)

        print(f"\n[+] Spider report: {stable_path}")

        return stable_path