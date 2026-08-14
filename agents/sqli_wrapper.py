"""
agents/sql_wrapper.py

Wrapper around the SQL injection scanner (sqli_final.py) — SQL_AGENT.

Unlike PASSWORD_POLICY_AGENT/NOSQL_AGENT (whole-site crawl) or AUTHZ_AGENT
(one CLI invocation, many targets via a file), this tool's CLI only
accepts a single --target per invocation and — critically — when given a
URL that already has query parameters and --crawl is NOT passed, it tests
exactly that URL's own parameters and nothing else (confirmed by reading
_collect_endpoints(): with use_crawl=False, it parses self.target's own
query string and builds one Endpoint from it; it does not crawl the rest
of the site). That makes it naturally endpoint-precise without needing a
crawl — closer in spirit to AUTHZ_AGENT's "test exactly what DeepHat
flagged" model, just invoked once per endpoint via a loop instead of a
single batched call.

Detection approach (for reference, not duplicated here — see the tool
itself): multi-signal scoring combining SQL error-pattern matching,
HTTP status anomaly vs. a benign baseline, response-size anomaly,
data-leak keyword matching, and timing-based blind detection, plus a
separate deterministic verify_true_positive() pass (baseline-diff +
TRUE/FALSE tautology-pair similarity) independent of any AI involvement.

--no-claude is always passed: the tool has an optional Claude-based
cross-check that (a) requires a separately-configured Anthropic API key
this pipeline has no reason to also depend on, and (b) has a blocking
input() prompt if that key is left as the placeholder default, which
would hang indefinitely under a non-interactive subprocess call. The
deterministic verification (baseline-diff, tautology-pair) still runs
either way, so disabling this doesn't remove the tool's core
false-positive protection — only the optional secondary LLM opinion.

Requires a patched copy of the tool with an added --output-json flag
(the stock tool only supports --report in .txt/.md format, no
machine-readable output) — see sqli_final.py's main() for the patch.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin

from pipeline.agent_report_paths import get_agent_report_dir


DEFAULT_TIMEOUT_SECONDS = 300


class SqlWrapper:

    def __init__(self):

        self.agent_script = Path(
            "agents/sql_agent/sqli.py"
        )

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        """
        Args:
            target:   Base URL of the scan (used only as a fallback if no
                      findings have a usable endpoint).
            findings: RoutingDecisions routed to SQL_AGENT. Each finding's
                      endpoint is tested independently, once per unique
                      URL (the tool's CLI takes one --target at a time).
            timeout:  Per-endpoint timeout — this tool sends ~20 payloads
                      per parameter with a rate-limit delay between each,
                      so a single endpoint can legitimately take a while.
        """

        urls, url_to_finding_ids = self._build_target_urls(target, findings)

        print(f"\nLaunching SQL Injection Agent — {len(urls)} endpoint(s)...\n")

        total_routed = sum(len(ids) for ids in url_to_finding_ids.values())
        if total_routed > len(urls):
            print(f"[Dedup] {total_routed} candidate(s) routed here, "
                  f"collapsed to {len(urls)} unique endpoint(s) — "
                  f"each real URL is only scanned once regardless of how "
                  f"many candidates pointed at it:")
            for url in urls:
                ids = url_to_finding_ids.get(url, [])
                if len(ids) > 1:
                    print(f"    {url}")
                    print(f"      <- {', '.join(str(i) for i in ids)}")
            print()

        merged_findings = []
        errors = []
        total_tests = 0
        endpoints_tested = 0

        for url in urls:

            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as tmp:
                output_path = tmp.name

            report_dir = get_agent_report_dir("sqli_output")

            command = [
                "python",
                # agent_script is a relative path — resolved to absolute
                # here, before the subprocess's cwd changes below, so it
                # still finds the script regardless of what directory the
                # subprocess actually runs in.
                str(self.agent_script.resolve()),
                "--target", url,
                "--no-claude",
                "--no-headers",
                "--no-cookies",
                "--no-auth-probe",
                "--output-json", output_path,
            ]

            try:
                subprocess.run(
                    command,
                    timeout=timeout,
                    stdin=subprocess.DEVNULL,
                    # sqli.py has no flag to redirect its own native
                    # report (.txt/.json) or its endpoint_logs/ folder —
                    # both are hardcoded relative to the process's cwd.
                    # Running it here instead of the project root is what
                    # actually keeps those out of E:\gguf\ directly; our
                    # own --output-json path above is unaffected since
                    # it's already absolute (from tempfile).
                    cwd=report_dir,
                )

                report_path = Path(output_path)

                if report_path.exists():
                    with open(report_path, "r", encoding="utf-8") as f:
                        result = json.load(f)

                    summary = result.get("summary", {})
                    total_tests += summary.get("total_tests", 0)
                    endpoints_tested += summary.get("endpoints_tested", 0)
                    merged_findings.extend(result.get("findings", []))
                else:
                    errors.append(f"{url}: no JSON report produced")

            except subprocess.TimeoutExpired:
                errors.append(f"{url}: timed out after {timeout}s")
            except Exception as e:
                errors.append(f"{url}: {e}")
            finally:
                Path(output_path).unlink(missing_ok=True)

        confirmed = sum(1 for f in merged_findings if f.get("verdict") == "sqli_confirmed")
        possible = sum(1 for f in merged_findings if f.get("verdict") == "sqli_possible")

        return {
            "target": target,
            "summary": {
                "endpoints_tested": endpoints_tested,
                "total_tests": total_tests,
                "confirmed": confirmed,
                "possible": possible,
                "candidates_routed": total_routed,
            },
            "findings": merged_findings,
            "_errors": errors,
            # Explicit endpoint -> [finding_ids] mapping, so "N candidates
            # routed, M endpoints scanned" is traceable from the result
            # itself rather than only visible in a console print that
            # scrolled past.
            "endpoint_dedup_map": {
                url: ids for url, ids in url_to_finding_ids.items()
            },
        }

    @staticmethod
    def _build_target_urls(target, findings):
        """
        Returns (urls, url_to_finding_ids). Multiple routed candidates
        can point at the same real URL (e.g. the same endpoint discovered
        twice — once via GET, once via POST, as two separate
        agent_targets entries) — each only needs to be scanned once, but
        which candidates collapsed onto which single scan was previously
        discarded entirely rather than tracked, making "6 candidates
        routed, 4 endpoints actually scanned" look like 2 candidates
        silently vanished rather than 2 pairs correctly sharing a scan.
        """
        seen = set()
        urls = []
        url_to_finding_ids = {}

        for f in (findings or []):
            endpoint = getattr(f, "endpoint", None)
            if not endpoint:
                continue
            url = urljoin(target, endpoint)
            finding_id = getattr(f, "finding_id", None)
            url_to_finding_ids.setdefault(url, []).append(finding_id)
            if url not in seen:
                seen.add(url)
                urls.append(url)

        if not urls:
            urls = [target]

        return urls, url_to_finding_ids