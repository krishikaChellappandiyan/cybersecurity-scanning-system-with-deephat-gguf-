"""
agents/password_wrapper.py

Wrapper around Agent 22 (Password Policy Checker).

Unlike XSS/AUTHZ/Headers, this agent isn't per-endpoint — it's a single
site-level check: find the registration flow, create a throwaway test
account, and infer what password rules the app actually enforces (or
doesn't). So unlike AuthzWrapper, there's no "targeted list" to build —
`findings` is accepted for interface consistency with the other wrappers,
but the agent always runs once against the whole target.

Responsibilities:
1. Launch agent22_password_policy_checker.py --url <target> (non-interactive).
2. Wait for it to finish (real Selenium browser automation, can be slow —
   long default timeout).
3. Load password_policy_report.json.
4. Return the parsed report to the Executor.

Note: this agent creates a real throwaway account on the target
(visible in created_accounts.json). Only point this at apps you're
authorized to test — the same rule as every other active agent here.
"""

import json
import subprocess
from pathlib import Path

from pipeline.agent_report_paths import get_agent_report_dir


DEFAULT_TIMEOUT_SECONDS = 600


class PasswordWrapper:

    def __init__(self):

        self.agent_script = Path(
            "agents/password_checker agent/password_checker .py"
        )

        self.report_dir = get_agent_report_dir("passpolicy_output")

        self.output_report = self.report_dir / "password_policy_report.json"

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        """
        Args:
            target:   Base URL of the scan.
            findings: Accepted for interface consistency with the other
                      wrappers (Executor always passes it). Not used to
                      scope the scan — see module docstring.
            timeout:  Selenium + real page loads can be slow; default
                      generously to 3 minutes.
        """

        print(f"\nLaunching PASSWORD POLICY Agent against {target}...\n")

        command = [
            "python",
            # Resolved to absolute before cwd changes below, same reason
            # as sqli_wrapper.py.
            str(self.agent_script.resolve()),
            "--url", target,
            "--output", str(self.output_report),
        ]

        subprocess.run(
            command,
            check=True,
            timeout=timeout,
            # created_accounts.json has no flag to redirect it — it's
            # hardcoded relative to the process's cwd, same situation as
            # sqli.py's native report/endpoint_logs. Running here instead
            # of the project root keeps it (and anything else the tool
            # writes without asking) inside this agent's own folder.
            cwd=self.report_dir,
        )

        return self._load_report()

    def _load_report(self):

        if not self.output_report.exists():
            raise FileNotFoundError(
                f"{self.output_report} was not generated."
            )

        with open(self.output_report, "r", encoding="utf-8") as f:
            report = json.load(f)

        return report