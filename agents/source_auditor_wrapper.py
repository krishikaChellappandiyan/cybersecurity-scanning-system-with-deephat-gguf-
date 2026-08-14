"""
agents/source_auditor_wrapper.py

Wrapper around Source Auditor Pro (Source auditor pro.py) —
SOURCE_AUDIT_AGENT.

Standalone agent. Source Auditor Pro itself only understands local
folders (it does taint analysis / AST dataflow over source code
already on disk — it can't fetch anything), so this wrapper gives it
that source itself: it invokes Sast analyzer25.py in --dump-only mode
(recover an exposed .git directory if there is one, skip that script's
own analysis entirely) to obtain a local copy of the source, then runs
Source Auditor Pro against it, then cleans up after itself.

If DeepHat routes a finding to SOURCE_AUDIT_AGENT for a target with no
actually-exposed .git, --dump-only finds nothing and this returns a
clean SKIPPED result.

Requires the `git` CLI (used internally by Sast analyzer25.py for
`git clone` / `git cat-file`) and, for Source Auditor Pro's AST/taint
mode, the `esprima` Python package (pip install esprima) — it degrades
to regex-only mode automatically if that's missing, so it's optional,
not a hard requirement.
"""

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from pipeline.agent_report_paths import get_agent_report_dir


DUMP_TIMEOUT_SECONDS = 180
SCAN_TIMEOUT_SECONDS = 300


class SourceAuditorWrapper:

    def __init__(self):

        self.dump_script = Path(
            "agents/Sast analyzer25/Sast analyzer25.py"
        )

        self.audit_script = Path(
            "agents/Source auditor pro/Source auditor pro.py"
        )

        self.report_dir = get_agent_report_dir("souceaudit_output")

    def run(self, target, findings=None, dump_timeout=DUMP_TIMEOUT_SECONDS,
            scan_timeout=SCAN_TIMEOUT_SECONDS):
        """
        Args:
            target:   Base URL of the scan.
            findings: Accepted for interface consistency with the other
                      wrappers (Executor always passes it). Not used to
                      scope the scan — this is a site-level check.
        """

        print(f"\nLaunching Source Audit Agent against {target}...\n")

        resolved_targets, temp_cleanup_dirs = self._dump_source(target, dump_timeout)

        if not resolved_targets:
            print("[Source Audit] No exposed .git source recovered — nothing to scan.\n")
            return {
                "status": "SKIPPED",
                "reason": "No recovered source (target's .git is not exposed, or isn't a valid git URL).",
                "secrets": [], "endpoints": [], "configs": [],
                "logic": [], "sensitive": [], "taint": [],
                "_errors": [], "_total": 0,
            }

        try:
            print(f"[Source Audit] Recovered {len(resolved_targets)} source path(s) — scanning...\n")
            return self._run_source_auditor(resolved_targets, scan_timeout)

        finally:
            for d in temp_cleanup_dirs:
                shutil.rmtree(d, ignore_errors=True)

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------

    def _dump_source(self, target, timeout):
        """
        Run Sast analyzer25.py --dump-only to recover any exposed .git
        source. Returns ([], []) if nothing was recovered — a target
        with no exposed .git is a normal, valid outcome, not an error.
        """

        targets_file = self.report_dir / "source_audit_resolved_targets.json"
        targets_file.unlink(missing_ok=True)

        command = [
            "python",
            str(self.dump_script),
            target,
            "--output-file", str(targets_file),
            "--dump-only",
        ]

        try:
            subprocess.run(command, timeout=timeout, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            return [], []

        if not targets_file.exists():
            # --dump-only exits non-zero with no targets file when there
            # was nothing to recover (no exposed .git, not a git URL).
            return [], []

        with open(targets_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        targets_file.unlink(missing_ok=True)

        return data.get("resolved_targets", []), data.get("temp_cleanup_dirs", [])

    def _run_source_auditor(self, resolved_targets, timeout):

        merged = {"secrets": [], "endpoints": [], "configs": [], "logic": [], "sensitive": [], "taint": []}
        errors = []

        for source_path in resolved_targets:

            with tempfile.TemporaryDirectory(prefix="source_auditor_out_") as out_dir:

                command = [
                    "python",
                    str(self.audit_script),
                    source_path,
                    "--output-dir", out_dir,
                    "--json-only",
                    "--severity", "LOW",
                ]

                try:
                    subprocess.run(
                        command,
                        timeout=timeout,
                        stdin=subprocess.DEVNULL,
                    )

                    report_path = Path(out_dir) / "report.json"

                    if report_path.exists():
                        with open(report_path, "r", encoding="utf-8") as f:
                            findings = json.load(f)

                        for category, items in findings.items():
                            merged.setdefault(category, [])
                            merged[category].extend(items)
                    else:
                        errors.append(f"{source_path}: no report.json produced")

                except Exception as e:
                    errors.append(f"{source_path}: {e}")

        merged["status"] = "SUCCESS" if not errors else "PARTIAL"
        merged["_errors"] = errors
        merged["_total"] = sum(
            len(v) for k, v in merged.items()
            if isinstance(v, list) and k not in ("_errors",)
        )

        return merged