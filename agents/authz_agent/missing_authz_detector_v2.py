import argparse
import json
import re
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlunparse
from bs4 import XMLParsedAsHTMLWarning
import warnings
warnings.filterwarnings(
    "ignore",
    category=XMLParsedAsHTMLWarning
)

try:
    import requests
    from requests.exceptions import Timeout
except ImportError:
    print("[ERROR] Run: pip install requests beautifulsoup4")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[ERROR] Run: pip install beautifulsoup4")
    sys.exit(1)

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# ─────────────────────────────────────────────────────────────
# COLORS
# ─────────────────────────────────────────────────────────────

class C:
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def cl(text, color):
    return f"{color}{text}{C.RESET}"


def ts():
    return datetime.now().strftime("%H:%M:%S")


def log(msg, level="info"):

    prefix = {
        "info": cl(f"[{ts()}] [INFO]   ", C.CYAN),
        "crawl": cl(f"[{ts()}] [CRAWL]  ", C.BLUE),
        "js": cl(f"[{ts()}] [JS]     ", C.YELLOW),
        "probe": cl(f"[{ts()}] [PROBE]  ", C.WHITE),
        "vuln": cl(f"[{ts()}] [VULN]   ", C.RED),
        "secure": cl(f"[{ts()}] [SECURE] ", C.GREEN),
        "warn": cl(f"[{ts()}] [WARN]   ", C.YELLOW),
        "error": cl(f"[{ts()}] [ERROR]  ", C.DIM),
        "fix": cl(f"[{ts()}] [FIX]    ", C.GREEN),
        "section": cl(f"[{ts()}] ──────── ", C.BOLD),
    }.get(level, f"[{ts()}] ")

    print(prefix + msg)


# ─────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────

def extract_base_url(raw_url: str) -> str:

    parsed = urlparse(raw_url)

    if not parsed.scheme or not parsed.netloc:
        print(f"[ERROR] Invalid URL: {raw_url}")
        sys.exit(1)

    path = parsed.path.rstrip("/")

    if "." in path.split("/")[-1]:
        path = "/".join(path.split("/")[:-1])

    return f"{parsed.scheme}://{parsed.netloc}{path}"


PUBLIC_ENDPOINTS = [
    "/",
    "/login",
    "/signin",
    "/signup",
    "/register",
    "/about",
    "/contact",
    "/news",
    "/help",
    "/forgotpassword",
]


SENSITIVE_CONTENT_PATTERNS = [
    "account number",
    "balance",
    "transaction",
    "transfer funds",
    "customer id",
    "logout",
    "admin panel",
    "dashboard",
    "wallet",
    "invoice",
    "payment",
    "profile",
    "email",
    "user",
]


COMMON_API_WORDLIST = [

    "/admin",
    "/admin/login",
    "/admin/dashboard",
    "/dashboard",
    "/management",
    "/console",

    "/api",
    "/api/users",
    "/api/user",
    "/api/admin",
    "/api/profile",
    "/api/account",
    "/api/accounts",
    "/api/settings",
    "/api/internal",
    "/api/private",

    "/api/v1/users",
    "/api/v1/admin",
    "/api/v1/auth",
    "/api/v1/profile",
    "/api/v1/account",
    "/api/v1/settings",

    "/api/v2/users",
    "/api/v2/admin",

    "/rest/admin",
    "/rest/user",
    "/rest/users",
    "/rest/orders",
    "/rest/products",

    "/graphql",
    "/graphiql",

    "/swagger",
    "/swagger-ui",
    "/swagger-ui.html",

    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v2/api-docs",

    "/internal",
    "/private",
    "/debug",

    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/metrics",

    "/auth",
    "/profile",
    "/settings",
    "/account",

    "/api/me",
    "/api/session",
]


JS_PATTERNS = [

    r'''fetch\s*\(\s*[\'"`]([^'"`\s]+)[\'"`]''',

    r'''axios\.(?:get|post|put|delete|patch)\s*\(\s*[\'"`]([^'"`\s]+)[\'"`]''',

    r'''url\s*:\s*[\'"`]([^'"`\s]+)[\'"`]''',

    r'''endpoint\s*:\s*[\'"`]([^'"`\s]+)[\'"`]''',

    r'''path\s*:\s*[\'"`]([^'"`\s]+)[\'"`]''',

    r'''["'`](/graphql[^"'`\s]*)["'`]''',

    r'''["'`](/api/[^"'`\s]+)["'`]''',

    r'''["'`](/v[0-9]+/[^"'`\s]+)["'`]''',

    r'''["'`](/(?:admin|internal|private|console|dashboard)[^"'`\s]*)["'`]''',

    r'''/_next/data/[^"'`\s]+''',

    r'''wss?://[^"'`\s]+''',

    r'''https?://[^"'`\s]+''',
]


AUTH_PROBES = [
    {
        "label": "No credentials",
        "headers": {},
        "cookies": {},
    },
    {
        "label": "Expired JWT token",
        "headers": {
            "Authorization": "Bearer invalid.jwt.token"
        },
        "cookies": {},
    },
    {
        "label": "Invalid API key",
        "headers": {
            "X-API-Key": "00000000-0000-0000-0000-000000000000"
        },
        "cookies": {},
    },
    {
        "label": "Fake session cookie",
        "headers": {},
        "cookies": {
            "session": "fake",
            "sessionid": "fake",
            "JSESSIONID": "fake",
            "PHPSESSID": "fake",
            "ASP.NET_SessionId": "fake",
        },
    },
]


def classify_sensitivity(path: str) -> str:

    p = path.lower()

    critical_keywords = [
        "admin", "internal", "private", "secret",
        "config", "env", "actuator", "backup",
        "debug", "password", "credential",
        "root", "superuser", "management",
        "console", "shell", "token", "key",
        "auth", "setup", "install", "phpinfo",
    ]

    high_keywords = [
        "user", "account", "profile",
        "report", "export", "dashboard",
        "setting", "panel", "graphql",
        "swagger", "api-docs", "openapi",
        "transfer", "payment", "invoice",
        "order", "transaction", "wallet",
        "upload", "download", "file",
        "document", "log",
    ]

    medium_keywords = [
        "data", "list", "all",
        "search", "query", "record",
        "service", "api", "rest",
        "v1", "v2", "v3", "info",
    ]

    for k in critical_keywords:
        if k in p:
            return "critical"

    for k in high_keywords:
        if k in p:
            return "high"

    for k in medium_keywords:
        if k in p:
            return "medium"

    return "low"


def classify_response(status_code, body, path="", headers=None):

    text = body.lower()
    path = path.lower()
    headers = headers or {}

    # ---------------------------------------------------------
    # PUBLIC ENDPOINTS
    # ---------------------------------------------------------

    for p in PUBLIC_ENDPOINTS:

        if path == p or path.startswith(p + "/"):
            return "PUBLIC"

    # ---------------------------------------------------------
    # SECURE RESPONSES
    # ---------------------------------------------------------

    if status_code in (401, 403):
        return "SECURE"

    # ---------------------------------------------------------
    # NOT FOUND
    # ---------------------------------------------------------

    if status_code == 404:
        return "NOT_FOUND"

    # ---------------------------------------------------------
    # SERVER ERRORS
    # ---------------------------------------------------------

    if status_code >= 500:
        return "SERVER_ERROR"

    # ---------------------------------------------------------
    # REDIRECTS
    # ---------------------------------------------------------

    if status_code in (301, 302, 303, 307, 308):

        location = headers.get("Location", "").lower()

        if any(x in location for x in [
            "login",
            "signin",
            "auth",
            "session"
        ]):
            return "REDIRECTED_TO_LOGIN"

        return "REDIRECT"

    # ---------------------------------------------------------
    # LOGIN PAGE DETECTION
    # ---------------------------------------------------------

    login_signals = [
        "login",
        "sign in",
        "signin",
        "password",
        "username",
        "authentication required",
        "session expired",
        "access denied",
        "unauthorized",
    ]

    login_count = sum(
        1 for x in login_signals if x in text
    )

    if login_count >= 2:
        return "REDIRECTED_TO_LOGIN"

    # ---------------------------------------------------------
    # SUCCESS RESPONSES
    # ---------------------------------------------------------

    if status_code == 200:

        sensitivity = classify_sensitivity(path)

        # -----------------------------------------------------
        # HIGH CONFIDENCE INDICATORS
        # -----------------------------------------------------

        HIGH_CONFIDENCE_PATTERNS = [

            # auth/session
            "jwt",
            "token",
            "bearer",
            "authorization",
            "sessionid",
            "access_token",
            "refresh_token",

            # pii
            "email",
            "phone",
            "mobile",
            "address",
            "customer id",

            # financial
            "balance",
            "payment",
            "invoice",
            "transaction",
            "wallet",

            # admin/config
            "admin",
            "role",
            "permission",
            "superuser",
            "apikey",
            "api_key",
            "secret",
            "client_secret",
            "private_key",
            "password",

            # user/account
            "username",
            "userid",
            "account",
            "profile",
        ]

        high_confidence_hits = 0

        for pattern in HIGH_CONFIDENCE_PATTERNS:

            if pattern in text:
                high_confidence_hits += 1

        # -----------------------------------------------------
        # CONTENT TYPE BONUS
        # -----------------------------------------------------

        json_bonus = 0

        content_type = headers.get(
            "Content-Type",
            ""
        ).lower()

        if "application/json" in content_type:
            json_bonus += 1

        # -----------------------------------------------------
        # SENSITIVITY BONUS
        # -----------------------------------------------------

        sensitivity_bonus = 0

        if sensitivity == "critical":
            sensitivity_bonus += 3

        elif sensitivity == "high":
            sensitivity_bonus += 2

        elif sensitivity == "medium":
            sensitivity_bonus += 1

        # -----------------------------------------------------
        # LARGE RESPONSE BONUS
        # -----------------------------------------------------

        size_bonus = 0

        if len(body) > 300:
            size_bonus += 1

        # -----------------------------------------------------
        # FINAL RISK SCORE
        # -----------------------------------------------------

        risk_score = (
            high_confidence_hits +
            json_bonus +
            sensitivity_bonus +
            size_bonus
        )

        # -----------------------------------------------------
        # DEFINITE VULNERABILITY
        # -----------------------------------------------------

        if risk_score >= 6:
            return "VULNERABLE"

        # -----------------------------------------------------
        # POSSIBLY SENSITIVE
        # -----------------------------------------------------

        if risk_score >= 4:

            if sensitivity in ("critical", "high"):
                return "LIKELY_VULNERABLE"

        # -----------------------------------------------------
        # LOW RISK PUBLIC API
        # -----------------------------------------------------

        if sensitivity == "low":
            return "PUBLIC"

        return "LIKELY_PUBLIC"

    # ---------------------------------------------------------
    # UNKNOWN
    # ---------------------------------------------------------

    return f"UNKNOWN({status_code})"


# ─────────────────────────────────────────────────────────────
# ENDPOINT DISCOVERER
# ─────────────────────────────────────────────────────────────

class EndpointDiscoverer:

    def __init__(self, base_url, max_depth=2, timeout=8):

        self.base_url = base_url.rstrip("/")
        self.base_host = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.timeout = timeout

        self.session = requests.Session()

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (SecurityScanner)",
            "Accept": "text/html,application/json,*/*",
        })

        self.visited_pages = set()
        self.visited_js = set()
        self.found_endpoints = {}

    def _normalize(self, url):

        p = urlparse(url)

        return urlunparse((
            p.scheme,
            p.netloc,
            p.path,
            "",
            "",
            ""
        ))

    def _same_host(self, url):

        return urlparse(url).netloc == self.base_host

    def _add_endpoint(self, path, method="GET", source="crawl"):

        if not path:
            return

        path = path.strip()

        if path.startswith("http"):

            parsed = urlparse(path)

            if parsed.netloc != self.base_host:
                return

            path = parsed.path

        if not path.startswith("/"):
            return

        if re.search(
            r'\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|map)$',
            path,
            re.I
        ):
            return

        if path in self.found_endpoints:
            return

        sensitivity = classify_sensitivity(path)

        self.found_endpoints[path] = {
            "path": path,
            "method": method,
            "sensitivity": sensitivity,
            "description": f"Discovered via {source}",
            "source": source,
        }

    # ─────────────────────────────────────────────────────────
    # JS FILE EXTRACTION
    # ─────────────────────────────────────────────────────────

    def _extract_js_files(self, soup, base_url):

        js_files = []

        for script in soup.find_all("script", src=True):

            src = script.get("src")

            if not src:
                continue

            full = urljoin(base_url, src)

            if self._same_host(full):
                js_files.append(full)

        return js_files

    # ─────────────────────────────────────────────────────────
    # RECURSIVE JS DISCOVERY
    # ─────────────────────────────────────────────────────────

    def _recursive_js_discovery(self, js_url, depth=0, max_depth=2):

        if depth > max_depth:
            return

        if js_url in self.visited_js:
            return

        self.visited_js.add(js_url)

        try:

            r = self.session.get(
                js_url,
                timeout=self.timeout,
                verify=False
            )

            body = r.text

            for pattern in JS_PATTERNS:

                matches = re.findall(
                    pattern,
                    body,
                    re.IGNORECASE
                )

                for m in matches:

                    if isinstance(m, tuple):
                        m = m[0]

                    if not m:
                        continue

                    if m.startswith("http"):

                        parsed = urlparse(m)

                        if parsed.netloc == self.base_host:
                            self._add_endpoint(
                                parsed.path,
                                "GET",
                                "recursive-js"
                            )

                    elif m.startswith("/"):
                        self._add_endpoint(
                            m,
                            "GET",
                            "recursive-js"
                        )

            js_matches = re.findall(
                r'''["']([^"']+\.js)["']''',
                body
            )

            for js in js_matches:

                full = urljoin(js_url, js)

                if self._same_host(full):

                    self._recursive_js_discovery(
                        full,
                        depth + 1,
                        max_depth
                    )

        except Exception:
            pass

    # ─────────────────────────────────────────────────────────
    # ROBOTS.TXT PARSER
    # ─────────────────────────────────────────────────────────

    def _parse_robots(self):

        try:

            r = self.session.get(
                self.base_url + "/robots.txt",
                timeout=self.timeout,
                verify=False
            )

            if r.status_code != 200:
                return

            for line in r.text.splitlines():

                line = line.strip()

                if line.lower().startswith(("allow:", "disallow:")):

                    path = line.split(":", 1)[1].strip()

                    if path.startswith("/"):
                        self._add_endpoint(
                            path,
                            "GET",
                            "robots"
                        )

        except Exception:
            pass

    # ─────────────────────────────────────────────────────────
    # SITEMAP PARSER
    # ─────────────────────────────────────────────────────────

    def _discover_sitemap(self):

        try:

            r = self.session.get(
                self.base_url + "/sitemap.xml",
                timeout=self.timeout,
                verify=False
            )

            if r.status_code != 200:
                return

            urls = re.findall(
                r"<loc>(.*?)</loc>",
                r.text,
                re.I
            )

            for u in urls:

                parsed = urlparse(u)

                if parsed.netloc == self.base_host:
                    self._add_endpoint(
                        parsed.path,
                        "GET",
                        "sitemap"
                    )

        except Exception:
            pass

    # ─────────────────────────────────────────────────────────
    # OPENAPI DISCOVERY
    # ─────────────────────────────────────────────────────────

    def _discover_openapi(self):

        paths = [
            "/swagger.json",
            "/openapi.json",
            "/api-docs",
            "/v2/api-docs",
            "/swagger/v1/swagger.json",
        ]

        for p in paths:

            url = self.base_url + p

            try:

                r = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False
                )

                if r.status_code != 200:
                    continue

                data = r.json()

                if "paths" in data:

                    for api_path in data["paths"]:

                        self._add_endpoint(
                            api_path,
                            "GET",
                            "openapi"
                        )

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # GRAPHQL DISCOVERY
    # ─────────────────────────────────────────────────────────

    def _discover_graphql(self):

        graphql_paths = [
            "/graphql",
            "/api/graphql",
            "/graphiql",
        ]

        query = {
            "query": """
            {
              __schema {
                types {
                  name
                }
              }
            }
            """
        }

        for path in graphql_paths:

            try:

                r = self.session.post(
                    self.base_url + path,
                    json=query,
                    timeout=self.timeout,
                    verify=False
                )

                if r.status_code == 200:

                    self._add_endpoint(
                        path,
                        "POST",
                        "graphql-introspection"
                    )

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # NEXT.JS DISCOVERY
    # ─────────────────────────────────────────────────────────

    def _discover_nextjs(self):

        manifests = [
            "/_next/build-manifest.json",
            "/_next/routes-manifest.json",
        ]

        for m in manifests:

            try:

                r = self.session.get(
                    self.base_url + m,
                    timeout=self.timeout,
                    verify=False
                )

                if r.status_code == 200:

                    matches = re.findall(
                        r'''["'](/[^"']+)["']''',
                        r.text
                    )

                    for path in matches:

                        self._add_endpoint(
                            path,
                            "GET",
                            "nextjs"
                        )

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # SECURITY.TXT
    # ─────────────────────────────────────────────────────────

    def _discover_security_txt(self):

        paths = [
            "/.well-known/security.txt",
            "/security.txt"
        ]

        for p in paths:

            try:

                r = self.session.get(
                    self.base_url + p,
                    timeout=self.timeout,
                    verify=False
                )

                if r.status_code == 200:

                    urls = re.findall(
                        r'https?://[^\s]+',
                        r.text
                    )

                    for u in urls:

                        parsed = urlparse(u)

                        if parsed.netloc == self.base_host:

                            self._add_endpoint(
                                parsed.path,
                                "GET",
                                "security-txt"
                            )

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # SERVICE WORKERS
    # ─────────────────────────────────────────────────────────

    def _discover_service_workers(self):

        sw_paths = [
            "/service-worker.js",
            "/sw.js",
            "/worker.js",
        ]

        for p in sw_paths:

            try:

                r = self.session.get(
                    self.base_url + p,
                    timeout=self.timeout,
                    verify=False
                )

                if r.status_code == 200:

                    for pattern in JS_PATTERNS:

                        matches = re.findall(
                            pattern,
                            r.text,
                            re.IGNORECASE
                        )

                        for m in matches:

                            if isinstance(m, tuple):
                                m = m[0]

                            if m.startswith("/"):

                                self._add_endpoint(
                                    m,
                                    "GET",
                                    "service-worker"
                                )

            except Exception:
                pass

    # ─────────────────────────────────────────────────────────
    # MAIN CRAWLER
    # ─────────────────────────────────────────────────────────

    def crawl(self):

        log(
            f"Crawling {cl(self.base_url, C.WHITE)} "
            f"max_depth={self.max_depth}",
            "section"
        )

        spinner = ["|", "/", "-", "\\"]
        spin_i = 0

        queue = deque([(self.base_url, 0)])

        while queue:

            url, depth = queue.popleft()

            norm = self._normalize(url)

            if norm in self.visited_pages:
                continue

            if depth > self.max_depth:
                continue

            self.visited_pages.add(norm)

            spin_i += 1

            print(
                f"\r  {spinner[spin_i % 4]} "
                f"Pages scanned: {len(self.visited_pages)}  "
                f"Endpoints found: {len(self.found_endpoints)}",
                end="",
                flush=True
            )

            # -------------------------------------------------
            # SAFE REQUEST
            # -------------------------------------------------

            try:

                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    verify=False
                )

            except Exception:
                continue

            # -------------------------------------------------
            # ADD CURRENT PAGE
            # -------------------------------------------------

            path = urlparse(url).path or "/"

            self._add_endpoint(
                path,
                "GET",
                "page-crawl"
            )

            # -------------------------------------------------
            # CONTENT-TYPE FILTERING
            # -------------------------------------------------

            content_type = resp.headers.get(
                "Content-Type",
                ""
            ).lower()

            skip_types = [
                "image/",
                "audio/",
                "video/",
                "application/pdf",
                "application/zip",
                "application/octet-stream",
                "application/vnd",
                "font/",
            ]

            if any(x in content_type for x in skip_types):
                continue

            # Skip huge responses
            if len(resp.text) > 3_000_000:
                continue

            # Empty response
            if not resp.text.strip():
                continue

            # -------------------------------------------------
            # SAFE HTML PARSING
            # -------------------------------------------------

            try:

                soup = BeautifulSoup(
                    resp.text,
                    "html.parser"
                )

            except Exception:
                continue

            # -------------------------------------------------
            # HTML LINKS
            # -------------------------------------------------

            for tag in soup.find_all(href=True):

                try:

                    href = tag["href"]

                    if not href:
                        continue

                    if href.startswith((
                        "javascript:",
                        "#",
                        "mailto:",
                        "tel:"
                    )):
                        continue

                    full = urljoin(url, href)

                    if self._same_host(full):

                        queue.append((full, depth + 1))

                        p = urlparse(full).path

                        if p:

                            self._add_endpoint(
                                p,
                                "GET",
                                "html-link"
                            )

                except Exception:
                    continue

            # -------------------------------------------------
            # FORMS
            # -------------------------------------------------

            for form in soup.find_all("form"):

                try:

                    action = form.get("action", "")
                    method = form.get("method", "GET").upper()

                    if action:

                        full = urljoin(url, action)

                        if self._same_host(full):

                            p = urlparse(full).path

                            if p:

                                self._add_endpoint(
                                    p,
                                    method,
                                    "html-form"
                                )

                except Exception:
                    continue

            # -------------------------------------------------
            # INLINE JS ENDPOINTS
            # -------------------------------------------------

            try:

                for pattern in JS_PATTERNS:

                    matches = re.findall(
                        pattern,
                        resp.text,
                        re.IGNORECASE
                    )

                    for m in matches:

                        try:

                            if isinstance(m, tuple):
                                m = m[0]

                            if not m:
                                continue

                            if m.startswith("http"):

                                parsed = urlparse(m)

                                if parsed.netloc == self.base_host:

                                    self._add_endpoint(
                                        parsed.path,
                                        "GET",
                                        "inline-js"
                                    )

                            elif m.startswith("/"):

                                self._add_endpoint(
                                    m,
                                    "GET",
                                    "inline-js"
                                )

                        except Exception:
                            continue

            except Exception:
                pass

            # -------------------------------------------------
            # JS FILES
            # -------------------------------------------------

            try:

                js_files = self._extract_js_files(
                    soup,
                    url
                )

                with ThreadPoolExecutor(
                    max_workers=5
                ) as executor:

                    executor.map(
                        self._recursive_js_discovery,
                        js_files
                    )

            except Exception:
                pass

        # -----------------------------------------------------
        # WORDLIST ENDPOINTS
        # -----------------------------------------------------

        for ep in COMMON_API_WORDLIST:

            self._add_endpoint(
                ep,
                "GET",
                "common-wordlist"
            )

        # -----------------------------------------------------
        # EXTRA DISCOVERY
        # -----------------------------------------------------

        self._parse_robots()

        self._discover_sitemap()

        self._discover_openapi()

        self._discover_graphql()

        self._discover_nextjs()

        self._discover_security_txt()

        self._discover_service_workers()

        print()

        log(
            cl(
                f"Discovery done — "
                f"{len(self.found_endpoints)} endpoints found",
                C.WHITE
            ),
            "info"
        )

        return self.found_endpoints


# ─────────────────────────────────────────────────────────────
# TARGETED ENDPOINT LOADER (pipeline mode — DeepHat-flagged only)
# ─────────────────────────────────────────────────────────────

def load_targeted_endpoints(targets_file, base_host):
    """
    Build the same {path: {path, method, sensitivity, description,
    source, finding_id}} shape EndpointDiscoverer.crawl() produces, but
    from a small JSON file of DeepHat/Planner-flagged endpoints instead
    of crawling/wordlisting the whole site.

    Expected --targets-file contents (written by AuthzWrapper):

        [
            {"finding_id": "authz-001", "url": "https://host/api/users", "method": "GET"},
            ...
        ]

    Entries pointing at a different host than the scan target are
    skipped (defensive — should never happen given how the wrapper
    builds this file, but we don't want a bad entry silently testing
    somewhere else).
    """

    with open(targets_file, "r", encoding="utf-8") as f:
        targets = json.load(f)

    endpoints = {}

    for entry in targets:

        url = entry.get("url")

        if not url:
            continue

        parsed = urlparse(url)

        if parsed.netloc and base_host and parsed.netloc != base_host:
            log(
                f"Skipping targeted entry for different host: {url}",
                "warn"
            )
            continue

        path = parsed.path or "/"
        if parsed.query:
            # Keep the query string attached to `path` itself: it doubles
            # as both the dedup key below (so two findings that only
            # differ by query string — e.g. /api/Challenges/ vs
            # /api/Challenges/?name=Score%20Board — don't collide and
            # silently drop one of them) and as the value _test_one()
            # concatenates onto base_url to build the actual request URL
            # (which otherwise ignored query strings entirely, meaning
            # no query params were ever sent even for the endpoint that
            # "won" the collision).
            path = f"{path}?{parsed.query}"
        method = (entry.get("method") or "GET").upper()

        endpoints[path] = {
            "path": path,
            "method": method,
            "sensitivity": classify_sensitivity(path),
            "description": "Flagged by DeepHat for AUTHZ validation",
            "source": "deephat-targeted",
            "finding_id": entry.get("finding_id"),
        }

    return endpoints


# ─────────────────────────────────────────────────────────────
# AUTH TESTER
# ─────────────────────────────────────────────────────────────

class AuthZTester:

    def __init__(
        self,
        base_url,
        probes,
        timeout=8,
        delay=0.3
    ):

        self.base_url = base_url.rstrip("/")
        self.probes = probes
        self.timeout = timeout
        self.delay = delay
        self.results = []

        self.session = requests.Session()

    def _test_one(self, endpoint, probe):

        path = endpoint["path"].lstrip("/")

        url = f"{self.base_url}/{path}"

        method = endpoint.get("method", "GET").upper()

        result = {
            "finding_id": endpoint.get("finding_id"),
            "url": url,
            "method": method,
            "path": endpoint["path"],
            "sensitivity": endpoint["sensitivity"],
            "description": endpoint["description"],
            "source": endpoint["source"],
            "probe_label": probe["label"],
            "status_code": None,
            "finding": None,
            "response_snippet": "",
            "error": None,
            "timestamp": datetime.now().isoformat(),
        }

        try:

            kwargs = dict(
                headers=probe.get("headers", {}),
                cookies=probe.get("cookies", {}),
                timeout=self.timeout,
                allow_redirects=False,
                verify=False,
            )

            resp = self.session.request(
                method,
                url,
                **kwargs
            )

            result["status_code"] = resp.status_code

            result["response_snippet"] = resp.text[:400].strip()
            
            # Skip obvious SPA fallback pages

            spa_indicators = [
            '<div id="root">',
            '<div id="app">',
            '__next',
            'webpack',
            'react',
            'vue',
            'angular'
            ]

            body_lower = resp.text.lower()

            spa_hits = sum(
            1 for x in spa_indicators
            if x.lower() in body_lower
            )

            if spa_hits >= 2 and len(resp.text) > 1000:
                result["finding"] = "SPA_FALLBACK"
                return result

            result["finding"] = classify_response(
                resp.status_code,
                result["response_snippet"],
                endpoint["path"],
                resp.headers
            )

        except Timeout:

            result["finding"] = "TIMEOUT"

        except Exception as e:

            result["finding"] = "ERROR"
            result["error"] = str(e)

        return result

    def run(self, endpoints):

        order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3
        }

        ep_list = sorted(
            endpoints.values(),
            key=lambda x: order.get(
                x["sensitivity"],
                4
            )
        )

        total = len(ep_list) * len(self.probes)

        done = 0

        log(
            f"Testing {len(ep_list)} endpoints × "
            f"{len(self.probes)} probes = {total} requests",
            "section"
        )

        print()

        for ep in ep_list:

            for probe in self.probes:

                result = self._test_one(ep, probe)

                self.results.append(result)

                done += 1

                if result["finding"] == "VULNERABLE" and \
                    result["sensitivity"] != "low":

                    print()

                    log(
                        f"{cl('VULNERABLE', C.RED + C.BOLD)} "
                        f"{result['method']} "
                        f"{cl(result['path'], C.WHITE)} "
                        f"[{result['sensitivity'].upper()}] "
                        f"probe: {result['probe_label']} "
                        f"HTTP {result['status_code']}",
                        "vuln"
                    )
                
                elif result["finding"] == "LIKELY_VULNERABLE":
                    print()
                    log(
                        f"{cl('POSSIBLE', C.YELLOW)} "
                        f"{result['method']} "
                        f"{cl(result['path'], C.WHITE)} "
                        f"[{result['sensitivity'].upper()}] "
                        f"probe: {result['probe_label']} "
                        f"HTTP {result['status_code']}",
                        "warn"
                    )

                pct = int((done / total) * 50)

                print(
                    f"\r  Testing: "
                    f"[{'█' * pct}{'░' * (50 - pct)}] "
                    f"{done}/{total}",
                    end="",
                    flush=True
                )

                time.sleep(self.delay)

        print()

        return self.results


# ─────────────────────────────────────────────────────────────
# REPORTING
# ─────────────────────────────────────────────────────────────

def print_summary(results, base_url):

    vuln = [
        r for r in results
        if r["finding"] == "VULNERABLE"
    ]

    secure = [
        r for r in results
        if r["finding"] in (
            "SECURE",
            "REDIRECTED_TO_LOGIN"
        )
    ]

    print()
    print(cl("═" * 65, C.BOLD))
    print(cl("  AGENT 36 — FINAL REPORT", C.BOLD))
    print(cl("═" * 65, C.BOLD))

    print(f"  Target           : {cl(base_url, C.WHITE)}")
    print(f"  Total probes     : {len(results)}")

    print(cl(
        f"  VULNERABLE       : {len(vuln)}",
        C.RED + C.BOLD
    ))

    print(cl(
        f"  SECURE           : {len(secure)}",
        C.GREEN
    ))

    print()

    if vuln:

        print(cl(
            "  ── CRITICAL FINDINGS ──",
            C.RED + C.BOLD
        ))

        seen = {}

        for r in vuln:

            if r["path"] not in seen:
                seen[r["path"]] = r

        for _, r in seen.items():

            print(cl(
                f"\n  [!] {r['method']} {r['url']}",
                C.RED
            ))

            print(
                f"      Sensitivity : "
                f"{r['sensitivity'].upper()}"
            )

            print(
                f"      Probe       : "
                f"{r['probe_label']}"
            )

            print(
                f"      Source      : "
                f"{r['source']}"
            )

    else:

        print(cl(
            "  ✓ No vulnerable endpoints detected.",
            C.GREEN
        ))

    print(cl("═" * 65, C.BOLD))


def save_report(results, base_url, endpoints, output_path):

    # ---------------------------------------------------------
    # FILTER RESULTS
    # ---------------------------------------------------------

    vulnerable_results = [
        r for r in results
        if r["finding"] == "VULNERABLE"
    ]

    remaining_results = [
        r for r in results
        if r["finding"] != "VULNERABLE"
    ]

    # ---------------------------------------------------------
    # VULNERABLE REPORT
    # ---------------------------------------------------------

    vulnerable_report = {
        "agent": "Agent 36",
        "report_type": "VULNERABLE_ENDPOINTS",
        "target": base_url,
        "scan_time": datetime.now().isoformat(),
        "total_vulnerabilities": len(vulnerable_results),
        "results": vulnerable_results,
    }

    # ---------------------------------------------------------
    # FULL/NON-VULNERABLE REPORT
    # ---------------------------------------------------------

    full_report = {
        "agent": "Agent 36",
        "report_type": "FULL_SCAN_REPORT",
        "target": base_url,
        "scan_time": datetime.now().isoformat(),
        "endpoint_count": len(endpoints),
        "total_results": len(results),
        "non_vulnerable_results": len(remaining_results),
        "results": remaining_results,
    }

    # ---------------------------------------------------------
    # SAVE FILES
    # ---------------------------------------------------------

    vuln_output = "vulnerable_report.json"

    full_output = "full_scan_report.json"

    with open(vuln_output, "w") as f:
        json.dump(vulnerable_report, f, indent=2)

    with open(full_output, "w") as f:
        json.dump(full_report, f, indent=2)

    # ---------------------------------------------------------
    # TERMINAL OUTPUT
    # ---------------------------------------------------------

    print()

    print(cl(
        f"[✓] Vulnerable report saved → {vuln_output}",
        C.RED
    ))

    print(cl(
        f"[✓] Full scan report saved → {full_output}",
        C.GREEN
    ))


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

def main():

    parser = argparse.ArgumentParser(
        description="Agent 36 — Universal MissingAuthZ Detector"
    )

    parser.add_argument("--url", required=True)

    parser.add_argument("--depth", type=int, default=2)

    parser.add_argument("--timeout", type=int, default=8)

    parser.add_argument("--delay", type=float, default=0.1)

    parser.add_argument(
        "--output",
        default="authz_report.json"
    )

    parser.add_argument(
        "--no-save",
        action="store_true"
    )

    parser.add_argument(
        "--targets-file",
        default=None,
        help=(
            "Optional JSON file of DeepHat/Planner-flagged endpoints "
            '([{"finding_id","url","method"}, ...]). When supplied, '
            "PHASE 1 discovery is skipped entirely and only these "
            "endpoints are tested — this is the mode the pipeline uses."
        ),
    )

    args = parser.parse_args()

    raw_url = args.url

    base_url = extract_base_url(raw_url)

    print(cl("""
╔═══════════════════════════════════════════════════════════╗
║         Agent 36 — MissingAuthZ Detector                 ║
║     Hybrid SPA/API Discovery Edition                     ║
║  ─────────────────────────────────────────────────────   ║
║  HTML + JS + GraphQL + OpenAPI + NextJS + SW            ║
║  Recursive JS bundle analysis included                  ║
╚═══════════════════════════════════════════════════════════╝
""", C.BOLD + C.RED))

    log(f"Target : {cl(base_url, C.WHITE)}", "info")

    log(
        f"Depth={args.depth} "
        f"Timeout={args.timeout}s "
        f"Delay={args.delay}s",
        "info"
    )

    # DISCOVERY (or targeted load, if --targets-file was supplied)

    if args.targets_file:

        log("PHASE 1 — Skipped (targeted mode: DeepHat-flagged endpoints only)", "section")

        endpoints = load_targeted_endpoints(
            args.targets_file,
            urlparse(base_url).netloc
        )

        if not endpoints:
            log("No targeted endpoints supplied.", "error")
            sys.exit(1)

        log(
            cl(f"{len(endpoints)} targeted endpoint(s) loaded", C.WHITE),
            "info"
        )

    else:

        log("PHASE 1 — Endpoint Discovery", "section")

        discoverer = EndpointDiscoverer(
            base_url,
            args.depth,
            args.timeout
        )

        endpoints = discoverer.crawl()

        if not endpoints:

            log("No endpoints discovered.", "error")
            sys.exit(1)

    # TESTING

    log("PHASE 2 — AuthZ Testing", "section")

    tester = AuthZTester(
        base_url,
        AUTH_PROBES,
        args.timeout,
        args.delay
    )

    results = tester.run(endpoints)

    # REPORT

    print_summary(results, base_url)

    if not args.no_save:

        save_report(
            results,
            base_url,
            endpoints,
            args.output
        )


if __name__ == "__main__":
    main()