"""
agents/authz_wrapper.py

Wrapper around Agent 36 (MissingAuthZ Detector)

Responsibilities:
1. Take the specific findings Planner routed to AUTHZ_AGENT (i.e. the
   endpoints DeepHat actually flagged as suspicious) and write them to a
   small targets file.
2. Execute the AUTHZ agent in TARGETED mode (--targets-file), so it tests
   only those endpoints instead of re-discovering the whole site via its
   own wordlist.
3. Wait until it finishes.
4. Load full_scan_report.json.
5. Return the parsed report to the Executor.

Why targeted mode matters:
    Spider might surface thousands of endpoints; DeepHat narrows that
    down to a handful of suspicious ones. If the AUTHZ agent re-runs its
    own discovery, it throws away that narrowing, duplicates recon work
    the Spider already did, and tests things DeepHat never flagged.
    Targeted mode keeps the agent doing exactly what it's for: confirming
    or rejecting the LLM's specific findings.
"""

import json
import tempfile
from pathlib import Path
from urllib.parse import urljoin
import subprocess

from pipeline.agent_report_paths import get_agent_report_dir


class AuthzWrapper:

    def __init__(self):

        self.agent_script = Path(
            "agents/authz_agent/missing_authz_detector_v2.py"
        )

        self.report_dir = get_agent_report_dir("auth_output")

        self.output_report = self.report_dir / "full_scan_report.json"

    def run(self, target, findings=None):
        """
        Args:
            target:   Base URL of the scan (e.g. "https://demo.owasp-juice.shop").
            findings: Iterable of RoutingDecision (or anything with
                      .endpoint / .method / .finding_id attributes) that
                      Planner routed to AUTHZ_AGENT. If omitted or empty,
                      falls back to the agent's own discovery mode (legacy
                      behavior) so this wrapper doesn't break standalone use.
        """

        findings = list(findings or [])

        if findings:
            return self._run_targeted(target, findings)

        return self._run_discovery(target)

    # -----------------------------------------------------------------
    # Targeted mode — test only what DeepHat/Planner flagged
    # -----------------------------------------------------------------

    def _run_targeted(self, target, findings):

        print(f"\nLaunching AUTHZ Agent (targeted — {len(findings)} endpoint(s))...\n")

        targets = self._build_targets(target, findings)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(targets, tmp, indent=2)
            targets_path = tmp.name

        try:
            command = [
                "python",
                str(self.agent_script.resolve()),
                "--url", target,
                "--targets-file", targets_path,
            ]

            subprocess.run(command, check=True, cwd=self.report_dir)

            return self._load_report()

        finally:
            Path(targets_path).unlink(missing_ok=True)

    @staticmethod
    def _build_targets(target, findings):
        """
        Turn Planner's RoutingDecisions into the small JSON contract the
        detector expects for targeted testing:

            [
                {"finding_id": "authz-001", "url": "https://.../api/users", "method": "GET"},
                ...
            ]

        Endpoints are resolved to absolute URLs here so the detector
        doesn't need to know the base target separately per-entry.
        """
        seen = set()
        out = []

        for f in findings:
            endpoint = getattr(f, "endpoint", None) or "/"
            method = (getattr(f, "method", None) or "GET").upper()
            url = urljoin(target, endpoint)

            key = (url, method)
            if key in seen:
                continue
            seen.add(key)

            out.append({
                "finding_id": getattr(f, "finding_id", None),
                "url": url,
                "method": method,
            })

        return out

    # -----------------------------------------------------------------
    # Legacy discovery mode — kept for standalone/manual runs
    # -----------------------------------------------------------------

    def _run_discovery(self, target):

        print("\nLaunching AUTHZ Agent (no findings supplied — falling back to discovery mode)...\n")

        command = [
            "python",
            str(self.agent_script.resolve()),
            "--url", target,
        ]

        subprocess.run(command, check=True, cwd=self.report_dir)

        return self._load_report()

    # -----------------------------------------------------------------
    # Shared
    # -----------------------------------------------------------------

    def _load_report(self):

        if not self.output_report.exists():
            raise FileNotFoundError(
                f"{self.output_report} was not generated."
            )

        with open(self.output_report, "r", encoding="utf-8") as f:
            report = json.load(f)

        # The detector splits its output: full_scan_report.json holds
        # everything EXCEPT "VULNERABLE" findings, and VULNERABLE ones go
        # to a separate vulnerable_report.json. Merge them back together
        # here so nothing — especially the actual confirmed
        # vulnerabilities — is silently invisible to the rest of the
        # pipeline (Executor's summary, chat.py's printout, etc.).
        vulnerable_path = self.report_dir / "vulnerable_report.json"

        if vulnerable_path.exists():
            with open(vulnerable_path, "r", encoding="utf-8") as f:
                vulnerable_report = json.load(f)

            vulnerable_results = vulnerable_report.get("results", [])

            report["results"] = vulnerable_results + report.get("results", [])
            report["total_results"] = len(report["results"])
            report["total_vulnerabilities"] = vulnerable_report.get(
                "total_vulnerabilities", len(vulnerable_results)
            )

        return report