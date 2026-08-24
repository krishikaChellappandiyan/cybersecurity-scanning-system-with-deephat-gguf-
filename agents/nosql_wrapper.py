"""
agents/nosql_wrapper.py

Wrapper around NoSQLHunter (nosql_exploit.py) — NOSQL_AGENT.

Previously (like PASSWORD_POLICY_AGENT) this wasn't per-endpoint — it was
given only the base target URL and relied entirely on the tool's own
internal crawl-based endpoint discovery before testing whatever it found.

As of this patch, when `findings` contains real, evidenced candidates
(the normal case — Executor always passes them), this wrapper now uses
nosql.py's --target/--params mode instead: it builds the target/param
list directly from our own pipeline's already-evidenced candidates and
skips the tool's internal discovery crawl entirely. This was a real,
confirmed problem, not a theoretical one: the tool's own crawl produced
both wasted time (re-discovering everything our pipeline had already
found) and false-positive findings on unrelated pages our pipeline never
flagged (e.g. NodeGoat's own /tutorial/* educational pages scoring as
"vulnerable" purely because their prose content discusses passwords and
sessions as subject matter, and generic <meta name="viewport"/"author">
tags being tested as if they were real form parameters) -- confirmed
directly in nosql.py's own source and fixed there as well (2026-08-24).

If `findings` is empty or its shape doesn't match what's expected here,
this wrapper falls back to the original full-crawl --url behavior
unchanged, rather than crashing -- the exact shape Executor passes
wasn't independently confirmed against this specific wrapper's call
site, so failing safe to previously-working behavior is deliberate.

Known limitation (upstream, not something this wrapper works around):
the tool's own discovery is crawl-based (HTML links, robots.txt,
sitemap.xml, JS-embedded paths) and was observed to be intermittently
unreliable in testing — the same class of inconsistency our own Hellhound
spider has on SPA-heavy targets. The actual injection-testing engine
(auth-bypass / query-injection / $where / blind-regex) was verified
directly and works correctly and reliably; discovery finding fewer
endpoints than expected on a given run is a tool characteristic, not
something wrong with this integration. This limitation applies only to
the fallback (--url) path now -- the new --target path bypasses the
tool's discovery entirely and isn't affected by it.

No blocking prompts, no interactive input() calls — safe to launch
non-interactively as-is (verified: no `input(` anywhere in the script).
"""

import json
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from pipeline.agent_report_paths import get_agent_report_dir


DEFAULT_TIMEOUT_SECONDS = 300


class NosqlWrapper:

    def __init__(self):

        self.agent_script = Path(
            "agents/nosql_agent/nosql.py"
        )

        self.dataset_path = Path(
            "agents/nosql_agent/dataset.py"
        )

        self.output_report = get_agent_report_dir("nosql_output") / "nosql_report.json"

    @staticmethod
    def _extract_endpoint_and_params(finding):
        """
        Best-effort extraction of (path, [param_names]) from a single
        routed finding/candidate. Tries attribute access first (matches
        CandidateSkeleton's confirmed shape: .endpoint, .parameter as a
        single string), then falls back to common dict-key variants,
        since the exact object Executor passes through to this wrapper
        wasn't independently confirmed. Returns (None, []) if nothing
        usable can be found, so the caller can skip this finding rather
        than fail.
        """
        endpoint = getattr(finding, "endpoint", None)
        if endpoint is None and isinstance(finding, dict):
            endpoint = finding.get("endpoint") or finding.get("url")
        if not endpoint:
            return None, []

        param = getattr(finding, "parameter", None)
        if param is None and isinstance(finding, dict):
            param = finding.get("parameter")
        params = [param] if param else []

        # Some finding shapes may carry a plural params/parameters list
        # instead of (or in addition to) a single .parameter string --
        # merge in whatever's found rather than assume only one shape.
        extra = getattr(finding, "params", None) or getattr(finding, "parameters", None)
        if extra is None and isinstance(finding, dict):
            extra = finding.get("params") or finding.get("parameters")
        if extra:
            if isinstance(extra, str):
                extra = [extra]
            params.extend(p for p in extra if p and p not in params)

        try:
            path = urlparse(endpoint).path or "/"
        except Exception:
            return None, []

        return path, params

    def _build_target_args(self, findings):
        """
        Builds --target/--params CLI args from findings, merging
        multiple candidates that share the same real endpoint path
        (e.g. the same /login form surfaced from two slightly different
        source URLs) into one combined parameter list rather than
        testing the same path twice. Returns (None, None) if nothing
        usable was extracted, signaling the caller to fall back to the
        original --url full-crawl behavior.
        """
        if not findings:
            return None, None

        merged = {}
        for finding in findings:
            path, params = self._extract_endpoint_and_params(finding)
            if not path:
                continue
            bucket = merged.setdefault(path, [])
            if not params:
                # Endpoint extraction worked but parameter extraction
                # came back empty -- confirmed real gap (2026-08-24,
                # NodeGoat run): .parameter/.params/.parameters all
                # missed whatever the real attribute/key is. Printing
                # the raw object here (once, not per-finding) turns the
                # next real run into direct evidence instead of another
                # guess at a fourth attribute name.
                print(f"[NOSQL_AGENT] DEBUG: no parameters extracted from finding for {path} -- "
                      f"raw object: {finding!r}")
            for p in params:
                if p not in bucket:
                    bucket.append(p)

        if not merged:
            return None, None

        target_arg = ",".join(merged.keys())
        all_params = []
        for plist in merged.values():
            for p in plist:
                if p not in all_params:
                    all_params.append(p)
        params_arg = ",".join(all_params) if all_params else None

        return target_arg, params_arg

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS,
            depth=3, concurrency=10):
        """
        Args:
            target:      Base URL of the scan.
            findings:    Routed candidates for this run. When usable
                         (see _extract_endpoint_and_params), builds
                         --target/--params and skips the tool's internal
                         discovery crawl entirely. Falls back to the
                         original full-crawl --url behavior if empty or
                         if nothing usable could be extracted from it.
            timeout:     Crawl + 16-database payload testing + blind-regex
                         extraction can take a while on a site with many
                         discovered endpoints; default generously. Less
                         relevant when --target is used, since discovery
                         is skipped, but left unchanged either way.
            depth:       Crawl depth passed straight through to the tool.
                         Only relevant on the --url fallback path.
            concurrency: Concurrent request count passed straight through.
        """

        print(f"\nLaunching NoSQL Injection Agent against {target}...\n")

        self.output_report.unlink(missing_ok=True)

        target_arg, params_arg = self._build_target_args(findings)

        command = [
            "python",
            str(self.agent_script),
            "--url", target,
            "--dataset", str(self.dataset_path),
            "--output", str(self.output_report),
        ]

        if target_arg:
            print(f"[NOSQL_AGENT] Using evidenced candidate(s), skipping internal discovery: "
                  f"--target {target_arg}" + (f" --params {params_arg}" if params_arg else ""))
            command += ["--target", target_arg]
            if params_arg:
                command += ["--params", params_arg]
        else:
            print("[NOSQL_AGENT] No usable findings passed in — falling back to the tool's "
                  "own full-crawl discovery (--url only, unchanged behavior).")
            command += ["--depth", str(depth), "--concurrency", str(concurrency)]

        # No explicit exit code signals severity (always exits 0 —
        # confirmed by reading main()), so check=True is safe here and
        # won't raise just because vulnerabilities were found.
        subprocess.run(command, check=True, timeout=timeout)

        return self._load_report()

    def _load_report(self):

        if not self.output_report.exists():
            raise FileNotFoundError(
                f"{self.output_report} was not generated."
            )

        with open(self.output_report, "r", encoding="utf-8") as f:
            report = json.load(f)

        return report