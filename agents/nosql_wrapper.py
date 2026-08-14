"""
agents/nosql_wrapper.py

Wrapper around NoSQLHunter (nosql_exploit.py) — NOSQL_AGENT.

Like PASSWORD_POLICY_AGENT, this isn't per-endpoint — it's given the base
target URL and does its own crawl-based endpoint discovery (its own
"Hellhound-Spider" component, unrelated to our project's spider of the same
name) before testing whatever it finds for NoSQL injection: auth bypass
($ne/$gt/$regex/$exists operators), blank/tautology query injection,
$where JavaScript injection, and blind regex-based data extraction across
16 supported NoSQL database engines (MongoDB, CouchDB, Redis,
Elasticsearch, DynamoDB, Firebase, Cassandra, and others).

Known limitation (upstream, not something this wrapper works around):
the tool's own discovery is crawl-based (HTML links, robots.txt,
sitemap.xml, JS-embedded paths) and was observed to be intermittently
unreliable in testing — the same class of inconsistency our own Hellhound
spider has on SPA-heavy targets. The actual injection-testing engine
(auth-bypass / query-injection / $where / blind-regex) was verified
directly and works correctly and reliably; discovery finding fewer
endpoints than expected on a given run is a tool characteristic, not
something wrong with this integration.

No blocking prompts, no interactive input() calls — safe to launch
non-interactively as-is (verified: no `input(` anywhere in the script).
"""

import json
import subprocess
from pathlib import Path

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

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS,
            depth=3, concurrency=10):
        """
        Args:
            target:      Base URL of the scan.
            findings:    Accepted for interface consistency with the other
                         wrappers (Executor always passes it). Not used to
                         scope the scan — see module docstring; this tool
                         has no targeted-endpoint mode to feed candidates
                         into.
            timeout:     Crawl + 16-database payload testing + blind-regex
                         extraction can take a while on a site with many
                         discovered endpoints; default generously.
            depth:       Crawl depth passed straight through to the tool.
            concurrency: Concurrent request count passed straight through.
        """

        print(f"\nLaunching NoSQL Injection Agent against {target}...\n")

        self.output_report.unlink(missing_ok=True)

        command = [
            "python",
            str(self.agent_script),
            "--url", target,
            "--dataset", str(self.dataset_path),
            "--output", str(self.output_report),
            "--depth", str(depth),
            "--concurrency", str(concurrency),
        ]

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