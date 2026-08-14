"""
pipeline/agent_report_paths.py

Every agent's underlying tool writes its own native report files
(SQL_AGENT: sqli_report.txt/.json + an endpoint_logs/ folder,
NOSQL_AGENT: nosql_report.json, PASSWORD_POLICY_AGENT:
password_policy_report.json + created_accounts.json, XSS_AGENT:
xssdetector_report.json/.txt + a screenshots/ folder with per-run
randomly-suffixed filenames, AUTHZ_AGENT: full_scan_report.json +
vulnerable_report.json, MITM_AGENT: passive_security_report.json/.html,
PARAM_INJECTION_AGENT: exploiter_report_<timestamp>.json) — previously
all landing directly in the project root (E:\\gguf\\) with zero
organization, mixed in with actual source files.

Top-level layout: agents_output/<agent>_output/, one folder per agent,
matching the exact folder names/structure already created in the
project (agents_output/sqli_output, xss_outputs, auth_output,
injection_output, miym_output, nosql_output, passpolicy_output,
souceaudit_output). Deliberately a top-level folder, not nested under
reports/ — reports/spiders/ and reports/deephat/ are the spider's and
DeepHat's own outputs; agents_output/ is specifically each validation
agent's raw native tool output, kept separate.

Each run replaces the previous one rather than accumulating: every call
to get_agent_report_dir() wipes that agent's folder clean first. This
matters beyond just tidiness — several of these tools generate
timestamped or randomly-suffixed filenames internally (sqli.py's own
report naming, XSS_AGENT's screenshot filenames, PARAM_INJECTION_AGENT's
exploiter_report_<timestamp>.json) that would otherwise never collide
with a previous run's files and just pile up indefinitely, one folder
in size per invocation of the entire pipeline.

For an agent that scans several endpoints in one logical run (e.g.
SQL_AGENT looping over multiple DeepHat-routed candidates), the wipe
must happen exactly ONCE per overall run — before the loop starts, not
once per endpoint inside it — or each endpoint's result would delete the
one scanned just before it in the same run. Every wrapper below calls
get_agent_report_dir() exactly once per run() invocation, outside any
per-endpoint loop, for this reason.
"""

import shutil
from pathlib import Path


# Project root — same derivation pattern used by pipeline/crawler.py.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent

AGENTS_OUTPUT_ROOT = _PROJECT_ROOT / "agents_output"


def get_agent_report_dir(folder_name: str, clear: bool = True) -> Path:
    """
    Returns agents_output/<folder_name>/, creating it if needed.

    clear=True (the default, and what every wrapper should use for its
    one call per run()) wipes the folder's existing contents first, so
    this run's output fully replaces the previous run's rather than
    accumulating alongside it. Pass clear=False only for a read-only
    lookup of an already-populated folder (e.g. re-reading a result
    without re-running anything) — none of the wrappers currently need
    this, but it's here so a future caller doesn't have to work around
    an unconditional wipe to get one.
    """
    report_dir = AGENTS_OUTPUT_ROOT / folder_name

    if clear and report_dir.exists():
        for item in report_dir.iterdir():
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink(missing_ok=True)

    report_dir.mkdir(parents=True, exist_ok=True)
    return report_dir