"""
agents/sast_wrapper.py

Wrapper around sast_analyzer25.py — SAST_AGENT.

Static Application Security Testing: analyzes real source code (not live
HTTP traffic) for hardcoded secrets, weak cryptography, injection-prone
code patterns, config/logging weaknesses, and vulnerable dependencies.

Given a plain website URL (not a git URL, not a local path), the tool's
own target-resolution logic checks that URL for an exposed .git
directory (appending /.git/HEAD itself) and, if found, dumps and
reconstructs the real source from it before scanning -- this wrapper
therefore always passes the base target URL as-is, never a URL that
already points at .git/something, since the tool appends that path
itself and would otherwise check .git/HEAD/.git/HEAD and find nothing.

Unlike most other wrappers, `findings` isn't used to build the command
here -- SAST_AGENT operates on the base target's exposed-git status as
a whole, not a specific query parameter or form field, so there's
nothing candidate-specific to extract the way NOSQL_AGENT or SQL_AGENT
need a parameter name. Accepted for interface consistency with every
other wrapper (Executor always passes it) but otherwise unused.

Exit code is deliberately NOT trusted to mean success/failure: the
tool's own main() calls sys.exit(1) for two completely different
reasons -- "no exposed .git directory was found at this URL" (a
legitimate, common, non-error outcome; the crawler's earlier evidence
may be stale, or this run may simply not have found it again) AND "a
finding at or above --fail-on's severity threshold exists" (the
opposite of a failure -- a successful scan that found something real).
Passing --fail-on none avoids the second case entirely, but the first
case still exits 1 on a normal "nothing to scan" outcome regardless --
so this wrapper uses check=False and determines success by checking
whether a real, parseable report was actually written, the same
principle used elsewhere in this project (SQL_AGENT, PARAM_INJECTION_
AGENT) after both were found to have previously reported false
successes/failures based on exit codes or ambiguous fallback counts
rather than the actual produced output.
"""

import json
import subprocess
from pathlib import Path

from pipeline.agent_report_paths import get_agent_report_dir


DEFAULT_TIMEOUT_SECONDS = 300


class SastWrapper:

    def __init__(self):

        self.agent_script = Path(
            "agents/sast_agent/sast.py"
        )

        self.output_report = get_agent_report_dir("sast_output") / "sast_report.json"

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        """
        Args:
            target:   Base URL of the scan. Passed as-is to the tool's own
                      target-resolution logic (local path / git URL / plain
                      website with automatic exposed-.git detection).
            findings: Accepted for interface consistency with the other
                      wrappers (Executor always passes it). Not used --
                      see module docstring.
            timeout:  Recovering and statically analyzing a real exposed
                      repository (dependency/CVE lookups included) can
                      take a while; default generously.
        """

        print(f"\nLaunching SAST Agent against {target}...\n")

        self.output_report.unlink(missing_ok=True)

        command = [
            "python",
            str(self.agent_script),
            target,
            "--output", "json",
            "--output-file", str(self.output_report),
            "--fail-on", "none",
        ]

        # check=False deliberately -- see module docstring on why exit
        # code alone can't distinguish "nothing to scan" from "found
        # something" from "actually crashed" for this specific tool.
        completed = subprocess.run(command, check=False, timeout=timeout)

        return self._load_report(completed.returncode)

    def _load_report(self, returncode):

        if not self.output_report.exists():
            # Legitimate outcome, not a crash: most commonly means no
            # exposed .git directory was found at this URL on this run.
            return {
                "status": "SKIPPED",
                "reason": (
                    f"No report was generated (exit code {returncode}) -- "
                    "most likely no exposed .git directory was found at "
                    "this target on this run."
                ),
                "findings": [],
                "_total": 0,
            }

        with open(self.output_report, "r", encoding="utf-8") as f:
            report = json.load(f)

        findings = report.get("findings", [])
        by_severity = {}
        for finding in findings:
            sev = (finding.get("severity") or "Unknown").title()
            by_severity[sev] = by_severity.get(sev, 0) + 1

        report["_total"] = len(findings)
        report["_by_severity"] = by_severity

        return report