import json
import subprocess
import sys
from pathlib import Path

from pipeline.agent_report_paths import get_agent_report_dir


class XSSWrapper:
    """
    Wrapper around the standalone XSSDetector19.py.

    Responsibilities:
    - Run the detector
    - Wait for completion
    - Read the JSON report
    - Return it as a Python dictionary
    """

    def __init__(self):
        self.detector = Path("agents/xss_agent/XSSDetector19.py")
        self.report_dir = get_agent_report_dir("xss_outputs")
        self.report = self.report_dir / "xssdetector_report.json"

    def run(self, spider_json_path: str):

        command = [
            sys.executable,
            # Resolved to absolute before cwd changes below, same reason
            # as sqli_wrapper.py / password_wrapper.py.
            str(self.detector.resolve()),
            # spider_json_path is already absolute in practice (built by
            # HellhoundCrawler with .resolve()), but resolving here too
            # is a cheap safety net against that ever changing.
            str(Path(spider_json_path).resolve()),
        ]

        print("\nLaunching XSS Agent...\n")

        result = subprocess.run(
            command,
            # No flag exists to redirect xssdetector_report.json/.txt or
            # the xssdetector_screenshots/ folder — all hardcoded
            # relative to the process's cwd.
            cwd=self.report_dir,
        )

        if result.returncode != 0:
            raise RuntimeError("XSS Agent execution failed.")

        if not self.report.exists():
            raise FileNotFoundError(
                "XSS report was not generated."
            )

        with open(self.report, "r", encoding="utf-8") as f:
            return json.load(f)