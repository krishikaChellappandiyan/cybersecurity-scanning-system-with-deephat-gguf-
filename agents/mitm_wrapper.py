"""
agents/mitm_wrapper.py

Wrapper around the Passive HTTP Observer (passiveObserver5.py) — the
MITM_AGENT.

Unlike AUTHZ_AGENT, this tool doesn't inject anything or send forged
credentials — it's purely passive: it fetches each URL normally and
inspects the real response for protocol/transport-level issues (mixed
content, weak/missing cookie flags, JWT weaknesses, GraphQL
introspection left on, OAuth misconfiguration, cache poisoning
indicators, HTTP request smuggling signals, TLS version/cipher issues,
etc.) — the class of issue a man-in-the-middle or passive network
observer would actually see.

The tool's own CLI takes a single file argument whose *extension*
selects the mode: .har / .xml (Burp) / .pcap all read pre-captured
traffic we don't have; anything else is treated as a JSON list of URLs
to fetch live and analyze passively. That's the mode this wrapper uses
— same "build a small JSON file of targets" shape as AuthzWrapper.

Note: the script also has an interactive "View HTML report in browser?
(y/n)" prompt at the very end. It already has an `except EOFError:
return False` fallback for non-interactive use, so redirecting stdin
to DEVNULL (rather than patching the script) is enough — no source
changes needed here, unlike Agent 22.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin

from pipeline.agent_report_paths import get_agent_report_dir


DEFAULT_TIMEOUT_SECONDS = 300


class MitmWrapper:

    def __init__(self):

        self.agent_script = Path(
            "agents/Passiveobserver5/Passive_observer5.py"
        )

        self.report_dir = get_agent_report_dir("miym_output")

        # Hardcoded by the script itself — no --output flag exists.
        # Redirected via cwd in run() below instead.
        self.output_report = self.report_dir / "passive_security_report.json"

    def run(self, target, findings=None, timeout=DEFAULT_TIMEOUT_SECONDS):
        """
        Args:
            target:   Base URL of the scan.
            findings: RoutingDecisions routed to MITM_AGENT. Each
                      finding's endpoint (resolved against target) is
                      added to the URL list passed to the observer. If
                      empty/None, falls back to just [target] so the
                      wrapper still does something reasonable when
                      called directly.
            timeout:  Passive scanning of several URLs can take a
                      while depending on rate limiting; default 5 min.
        """

        urls = self._build_target_urls(target, findings)

        print(f"\nLaunching MITM (Passive Observer) Agent — {len(urls)} URL(s)...\n")

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as tmp:
            json.dump(urls, tmp, indent=2)
            targets_path = tmp.name

        try:
            command = [
                "python",
                str(self.agent_script.resolve()),
                targets_path,
            ]

            # stdin=DEVNULL makes the script's end-of-run "View HTML
            # report in browser? (y/n)" input() raise EOFError
            # immediately, which it already catches and treats as "no"
            # — no source patch needed.
            subprocess.run(
                command,
                check=True,
                timeout=timeout,
                stdin=subprocess.DEVNULL,
                cwd=self.report_dir,
            )

            return self._load_report()

        finally:
            Path(targets_path).unlink(missing_ok=True)

    @staticmethod
    def _build_target_urls(target, findings):
        seen = set()
        urls = []

        for f in (findings or []):
            endpoint = getattr(f, "endpoint", None)
            if not endpoint:
                continue
            url = urljoin(target, endpoint)
            if url not in seen:
                seen.add(url)
                urls.append(url)

        if not urls:
            urls = [target]

        return urls

    def _load_report(self):

        if not self.output_report.exists():
            raise FileNotFoundError(
                f"{self.output_report} was not generated."
            )

        with open(self.output_report, "r", encoding="utf-8") as f:
            report = json.load(f)

        return report