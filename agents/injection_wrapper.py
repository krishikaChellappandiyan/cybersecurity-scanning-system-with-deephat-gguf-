"""
agents/injection_wrapper.py

Wrapper around the async multi-vector parameter injection scanner
(injection_detector.py) — PARAM_INJECTION_AGENT.

This tool is genuinely broad — it natively covers SQL injection, XSS, and
NoSQL injection alongside SSRF, SSTI, Command Injection, Path Traversal,
Open Redirect, Host Header Injection, Referer Injection, and Server-Side
Parameter Pollution (SSPP). Since SQLi/XSS/NoSQLi already have dedicated,
carefully-tuned agents in this pipeline (SQL_AGENT, XSS_AGENT,
NOSQL_AGENT), config.py's trigger criteria deliberately scopes
PARAM_INJECTION_AGENT to the vectors none of those three cover — routing
SQLi/XSS/NoSQLi candidates here as well would just duplicate work three
different tools already do.

Unlike SQL_AGENT (one --target per subprocess call), this tool's target
JSON format natively supports multiple endpoints in a single run, each
with its own method/params/candidate flags — so this wrapper builds ONE
target file covering every DeepHat-routed candidate and makes a single
subprocess call, closer to AUTHZ_AGENT's targeted-batch model.

No CLI flag exists to control the output report's path or filename — it
always writes exploiter_report_<timestamp>.json to the current working
directory (confirmed by reading save_report() directly). Rather than
patch the tool, this wrapper runs the subprocess in a dedicated temp
directory and discovers the report there afterward — the same pattern
pipeline/crawler.py already uses for Hellhound's own timestamped output.

Candidate flags (ssrf_candidate / ssti_candidate / sspp_candidate) are
opt-in by design in the underlying tool — those three vectors carry a
higher false-positive/side-effect risk, so this wrapper only enables the
one matching flag for whichever vector DeepHat's candidate actually
claims, never all three blindly.

New dependencies this agent introduces to the project (not used by any
other agent so far): aiohttp, beautifulsoup4, rich. Needs
`pip install aiohttp beautifulsoup4 rich` on the host running the
pipeline. curl_cffi is optional (only used for WAF TLS-bypass evasion,
not required for the agent to function).
"""

import json
import subprocess
from pathlib import Path
from urllib.parse import urljoin

from pipeline.agent_report_paths import get_agent_report_dir


DEFAULT_TIMEOUT_SECONDS = 600

_VECTOR_FLAG_MAP = {
    "ssrf": "ssrf_candidate",
    "server_side_request_forgery": "ssrf_candidate",
    "ssti": "ssti_candidate",
    "server_side_template_injection": "ssti_candidate",
    "template_injection": "ssti_candidate",
    "sspp": "sspp_candidate",
    "server_side_parameter_pollution": "sspp_candidate",
    "mass_assignment": "sspp_candidate",
}


class InjectionWrapper:

    def __init__(self):
        self.agent_script = Path("agents/command_ Injection detector/injection_detector.py")
        self.attack_db = Path("agents/command_ Injection detector/Attack db final.json")

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        """
        Args:
            target:   Base URL of the scan (used as a fallback endpoint
                      if findings has nothing usable).
            findings: RoutingDecisions routed to PARAM_INJECTION_AGENT.
                      Each becomes one endpoint entry in a single target
                      JSON file — the tool natively handles multiple
                      endpoints per run.
            timeout:  This is a multi-phase async scanner testing many
                      payloads per parameter (WAF fingerprinting +
                      calibration + full active scan) — generous by
                      design; real-world reports show scans taking
                      several minutes even against one endpoint.
        """

        print(f"\nLaunching Parameter Injection Agent...\n")

        endpoints = self._build_endpoints(target, findings)
        work_dir = get_agent_report_dir("injection_output")

        try:
            targets_path = work_dir / "targets.json"
            with open(targets_path, "w", encoding="utf-8") as f:
                json.dump({"endpoints": endpoints}, f)

            command = [
                "python",
                str(Path.cwd() / self.agent_script),
                "-t", str(targets_path),
                "-d", str(Path.cwd() / self.attack_db),
            ]

            subprocess.run(
                command,
                cwd=work_dir,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
            )

            reports = list(work_dir.glob("exploiter_report_*.json"))

            if not reports:
                return {
                    "target": target,
                    # 0, not len(endpoints): this branch means the scan
                    # never actually ran anything (no report was ever
                    # produced) — reporting len(endpoints) here (how many
                    # were attempted, not how many were tested) silently
                    # defeated executor.py's completely_failed check
                    # (which specifically looks for endpoints_tested==0),
                    # causing a real failure — no attack database found,
                    # nothing tested — to be printed as "completed
                    # successfully" instead of FAILED.
                    "summary": {"endpoints_tested": 0, "total_tests": 0, "confirmed": 0},
                    "findings": [],
                    "_errors": ["No report file was produced by the scan."],
                }

            newest = max(reports, key=lambda f: f.stat().st_mtime)
            with open(newest, "r", encoding="utf-8") as f:
                raw = json.load(f)

            return self._normalize(target, endpoints, raw)

        except subprocess.TimeoutExpired:
            return {
                "target": target,
                # 0, not len(endpoints) -- same reasoning as the
                # no-report-produced branch above: a timeout means
                # nothing actually completed, regardless of how many
                # endpoints were queued for testing.
                "summary": {"endpoints_tested": 0, "total_tests": 0, "confirmed": 0},
                "findings": [],
                "_errors": [f"Scan timed out after {timeout}s."],
            }

    @classmethod
    def _build_endpoints(cls, target, findings):
        endpoints = []

        for f in (findings or []):
            endpoint = getattr(f, "endpoint", None)
            if not endpoint:
                continue

            finding_type = str(getattr(f, "type", "") or "").lower()
            flags = {"ssrf_candidate": False, "ssti_candidate": False, "sspp_candidate": False}
            matched_flag = _VECTOR_FLAG_MAP.get(finding_type)
            if matched_flag:
                flags[matched_flag] = True

            endpoints.append({
                "url": urljoin(target, endpoint),
                "method": getattr(f, "method", None) or "GET",
                "query_params": [],
                "body_params": [],
                "path_params": [],
                "risk_tags": [finding_type] if finding_type else [],
                "category": finding_type,
                **flags,
            })

        if not endpoints:
            endpoints = [{
                "url": target,
                "method": "GET",
                "query_params": [], "body_params": [], "path_params": [],
                "risk_tags": [], "category": "",
                "ssrf_candidate": False, "ssti_candidate": False, "sspp_candidate": False,
            }]

        return endpoints

    @staticmethod
    def _normalize(target, endpoints, raw):
        metadata = raw.get("scan_metadata", {})
        findings_by_category = raw.get("findings", {})

        flat_findings = []
        for category, items in findings_by_category.items():
            for item in items:
                item = dict(item)
                item.setdefault("category", category)
                flat_findings.append(item)

        confirmed = sum(1 for f in flat_findings if f.get("confidence") in ("High", "Critical"))

        return {
            "target": target,
            "summary": {
                "endpoints_tested": len(endpoints),
                "total_tests": metadata.get("total_findings", len(flat_findings)),
                "confirmed": confirmed,
                "waf_detected": metadata.get("waf_status", {}).get("detected", False),
            },
            "findings": flat_findings,
            "_errors": [],
        }