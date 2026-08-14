#!/usr/bin/env python3

"""
Passive HTTP Observer v9.3 - Comprehensive Security Analysis Tool (PRODUCTION READY)
Detects: Information disclosure, security headers, cookies, mixed content,
         credit cards, JavaScript issues, WebSocket security, GraphQL introspection,
         JWT weaknesses, HTTP request smuggling, cache poisoning, SSRF reflections,
         OAuth misconfigurations, API security issues, and TLSv1.0/TLSv1.1 ciphers.
"""

import requests
import re
import argparse
import json
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, parse_qs, urljoin, unquote
import certifi
from http.cookies import SimpleCookie
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from collections import defaultdict
from typing import List, Dict, Set, Optional, Tuple, Any, Union
import xml.etree.ElementTree as ET
import base64
import logging
import sys
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum
import gc
from threading import Lock, Semaphore
import webbrowser
import os

# Try to import optional dependencies
try:
    from scapy.all import TCP, Raw, IP
    from scapy.utils import PcapReader
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    from jsbeautifier import beautify
    JS_BEAUTIFY_AVAILABLE = True
except ImportError:
    JS_BEAUTIFY_AVAILABLE = False

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

try:
    import h2.connection
    import h2.events
    from h2.config import H2Configuration
    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

# Try to import TLS/SSL scapy extensions for TLS analysis
try:
    from scapy.layers.tls.all import TLS, TLSClientHello, TLSServerHello, TLSVersion
    from scapy.layers.tls.crypto.suites import _tls_cipher_suites
    SCAPY_TLS_AVAILABLE = True
except ImportError:
    SCAPY_TLS_AVAILABLE = False
    TLSVersion = None


# -----------------------------------------------------------------------------
# Terminal Colors and Styling
# -----------------------------------------------------------------------------

class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'
    DIM = '\033[2m'
    WHITE = '\033[97m'


class Icons:
    """Icons for different finding types - using text labels instead of emojis"""
    CRITICAL = "[CRITICAL]"
    HIGH = "[HIGH]"
    MEDIUM = "[MEDIUM]"
    LOW = "[LOW]"
    INFO = "[INFO]"
    SUCCESS = "[SUCCESS]"
    ERROR = "[ERROR]"
    WARNING = "[WARNING]"
    TARGET = "[TARGET]"
    COOKIE = "[COOKIE]"
    SSL = "[SSL]"
    PAYMENT = "[PAYMENT]"
    CDN = "[CDN]"
    HEADER = "[HEADER]"
    CORS = "[CORS]"
    MIXED = "[MIXED]"
    TLS = "[TLS]"
    CLICKJACK = "[CLICKJACK]"
    WEBSOCKET = "[WEBSOCKET]"
    JAVASCRIPT = "[JAVASCRIPT]"
    DOM = "[DOM]"
    ERROR_LEAK = "[ERROR-LEAK]"
    GRAPHQL = "[GRAPHQL]"
    JWT = "[JWT]"
    CACHE = "[CACHE]"
    SMUGGLING = "[SMUGGLING]"
    SSRF = "[SSRF]"
    OAUTH = "[OAUTH]"


class Severity(Enum):
    """Severity levels for findings"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class Confidence(Enum):
    """Confidence levels for findings"""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


# -----------------------------------------------------------------------------
# Configuration Management
# -----------------------------------------------------------------------------

@dataclass
class ObserverConfig:
    """Configuration for the Passive HTTP Observer"""
    # Request settings
    timeout: int = 10
    max_workers: int = 5
    rate_limit: float = 0.5
    user_agent: str = "PassiveHTTPObserver/9.3"
    max_redirects: int = 5
    
    # Analysis settings
    max_response_size: int = 10 * 1024 * 1024
    max_findings_per_url: int = 100
    enable_heuristic_analysis: bool = True
    strict_mixed_content: bool = False
    min_session_token_length: int = 8
    enable_luhn_check: bool = True
    
    # False positive reduction
    enable_context_validation: bool = True
    min_credit_card_length: int = 13
    max_credit_card_length: int = 19
    
    # Error Information Leakage settings
    detect_stack_traces: bool = True
    detect_database_errors: bool = True
    detect_framework_paths: bool = True
    detect_debug_messages: bool = True
    detect_error_status_codes: List[int] = field(default_factory=lambda: [400, 401, 403, 404, 500, 502, 503, 504])
    
    # Advanced detection settings
    detect_graphql_introspection: bool = True
    detect_jwt_weaknesses: bool = True
    detect_http_smuggling: bool = True
    detect_cache_poisoning: bool = True
    detect_ssrf_reflections: bool = True
    detect_open_redirects: bool = True
    detect_oauth_misconfigurations: bool = True
    detect_api_version_disclosure: bool = True
    detect_http2_issues: bool = True
    
    # TLS detection settings
    detect_tls_vulnerabilities: bool = True
    detect_tls10: bool = True
    detect_tls11: bool = True
    detect_weak_ciphers: bool = True
    
    # Performance settings
    chunk_size: int = 8192
    cache_size: int = 100
    gc_interval: int = 500
    
    # Output settings
    verbose: bool = False
    save_raw_payloads: bool = False
    max_payload_size: int = 5000
    print_all_findings: bool = True
    max_display_findings: int = 1000
    
    # PCAP settings
    pcap_tcp_reassembly: bool = True
    pcap_stream_timeout: float = 30.0
    pcap_max_streams: int = 10000
    max_pcap_size_mb: int = 1024
    pcap_chunk_size: int = 1000
    
    # JavaScript analysis
    analyze_javascript: bool = True
    max_js_size: int = 1024 * 1024
    
    # WebSocket analysis
    analyze_websockets: bool = True
    
    # Passive scanning mode
    passive_scanning: bool = True
    passive_rate_limit: float = 1.0


# -----------------------------------------------------------------------------
# Thread-Safe Print Manager
# -----------------------------------------------------------------------------

class PrintManager:
    """Thread-safe manager for console output"""
    
    def __init__(self):
        self.lock = Lock()
        self.findings_output = []
    
    def print(self, message: str, end: str = "\n", flush: bool = True):
        """Thread-safe print"""
        with self.lock:
            print(message, end=end, flush=flush)
    
    def print_finding(self, finding: 'SecurityFinding', index: int):
        """Print a finding and store it for later reference"""
        with self.lock:
            output = self._format_finding(finding, index)
            print(output)
            self.findings_output.append(output)
    
    def _format_finding(self, finding: 'SecurityFinding', index: int) -> str:
        """Format a single finding for output"""
        if finding.severity == Severity.CRITICAL:
            sc, icon = Colors.RED, Icons.CRITICAL
        elif finding.severity == Severity.HIGH:
            sc, icon = Colors.RED, Icons.HIGH
        elif finding.severity == Severity.MEDIUM:
            sc, icon = Colors.YELLOW, Icons.MEDIUM
        elif finding.severity == Severity.LOW:
            sc, icon = Colors.BLUE, Icons.LOW
        else:
            sc, icon = Colors.DIM, Icons.INFO
        
        output = f"\n{Colors.BOLD}[{index}] {icon} {sc}{finding.severity_str}{Colors.END} – {finding.issue_type}\n"
        output += f"  {Colors.DIM}URL:{Colors.END}         {finding.url}\n"
        output += f"  {Colors.DIM}Indicator:{Colors.END}   {finding.indicator}\n"
        output += f"  {Colors.DIM}Impact:{Colors.END}      {finding.impact}\n"
        output += f"  {Colors.DIM}Confidence:{Colors.END}   {finding.confidence_str}\n"
        
        if finding.remediation:
            output += f"  {Colors.DIM}Remediation:{Colors.END} {finding.remediation}\n"
        
        if finding.extracted_data:
            output += f"  {Colors.DIM}Extracted Data:{Colors.END}\n"
            for key, value in list(finding.extracted_data.items())[:3]:
                if value:
                    val_str = str(value)[:100]
                    output += f"      * {key}: {val_str}...\n" if len(str(value)) > 100 else f"      * {key}: {value}\n"
        
        output += f"  {Colors.CYAN}{'-'*76}{Colors.END}"
        return output


print_manager = PrintManager()


# -----------------------------------------------------------------------------
# Data Structures
# -----------------------------------------------------------------------------

@dataclass
class SecurityFinding:
    """Structure to hold a security observation."""
    url: str
    issue_type: str
    indicator: str
    impact: str
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MEDIUM
    detection_method: str = "Analysis"
    param_location: Optional[str] = None
    response_obj: Optional[Any] = None
    remediation: Optional[str] = None
    extracted_data: Optional[Dict] = None
    cve_reference: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    affected_urls: Optional[List[str]] = None  # NEW: Track multiple affected URLs
    
    def __post_init__(self):
        if isinstance(self.severity, str):
            self.severity = Severity(self.severity)
        if isinstance(self.confidence, str):
            self.confidence = Confidence(self.confidence)
        if self.affected_urls is None:
            self.affected_urls = [self.url]
    
    @property
    def severity_str(self) -> str:
        return self.severity.value
    
    @property
    def confidence_str(self) -> str:
        return self.confidence.value
    
    def add_affected_url(self, url: str):
        """Add another affected URL to this finding"""
        if url not in self.affected_urls:
            self.affected_urls.append(url)
    
    def get_primary_url(self) -> str:
        """Get the primary URL (first one) for display"""
        return self.affected_urls[0] if self.affected_urls else self.url
    
    def _generate_clickjacking_poc(self) -> Optional[str]:
        """Generate a proof-of-concept HTML for clickjacking vulnerability"""
        if "Clickjacking" not in self.issue_type:
            return None
        primary_url = self.get_primary_url()
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC – {primary_url}</title>
    <style>
        body {{ font-family: monospace; margin: 0; padding: 20px; background: #1e1e1e; color: #d4d4d4; }}
        .container {{ max-width: 900px; margin: 0 auto; background: #2d2d2d; padding: 20px; border-radius: 5px; }}
        h1 {{ color: #f48771; }}
        .warning {{ background: #5a3a1a; border-left: 4px solid #f48771; padding: 10px; margin: 20px 0; }}
        .iframe-container {{ position: relative; width: 100%; height: 600px; border: 2px solid #4a4a4a; margin: 20px 0; }}
        iframe {{ width: 100%; height: 100%; border: none; opacity: 0.5; }}
        .deceptive-ui {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
                       background: rgba(0,0,0,0.9); padding: 20px; border-radius: 10px;
                       box-shadow: 0 4px 20px rgba(0,0,0,0.5); text-align: center; z-index: 20; pointer-events: none; }}
        .deceptive-ui button {{ pointer-events: auto; background: #f48771; color: white;
                              font-size: 18px; padding: 15px 30px; border: none;
                              border-radius: 4px; cursor: pointer; }}
        code {{ background: #1e1e1e; padding: 2px 5px; border-radius: 3px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Clickjacking Proof of Concept</h1>
        <div class="warning">
            <strong>Security Alert:</strong> <code>{primary_url}</code> is vulnerable to clickjacking.
        </div>
        <h2>Vulnerability Details</h2>
        <ul>
            <li><strong>Target URL:</strong> <code>{primary_url}</code></li>
            <li><strong>Missing Header:</strong> X-Frame-Options or CSP frame-ancestors</li>
            <li><strong>Risk Level:</strong> {self.severity_str}</li>
        </ul>
        <h2>Live Demonstration</h2>
        <div class="iframe-container">
            <iframe src="{primary_url}" sandbox="allow-same-origin allow-scripts allow-forms"></iframe>
            <div class="deceptive-ui">
                <h3>CLAIM YOUR REWARD!</h3>
                <p>Click the button below to claim your prize!</p>
                <button onclick="alert('Demo: You clicked on the hidden target website!')">
                    CLAIM NOW
                </button>
            </div>
        </div>
        <h2>Remediation</h2>
        <ul>
            <li>Add <code>X-Frame-Options: DENY</code> or <code>SAMEORIGIN</code></li>
            <li>Or use <code>Content-Security-Policy: frame-ancestors 'none'</code></li>
            <li>Consider <code>frame-ancestors 'self'</code> if framing is required</li>
        </ul>
    </div>
</body>
</html>'''
    
    def _categorise(self) -> str:
        """Categorize the finding type"""
        t = self.issue_type
        if "Cookie" in t:
            return "Session Management"
        if "SSL" in t or "TLS" in t or "Certificate" in t:
            return "Cryptography"
        if "Error" in t or "Info" in t or "Stack" in t or "Debug" in t or "Trace" in t:
            return "Information Disclosure"
        if "Payment" in t:
            return "Compliance"
        if "Header" in t or "HSTS" in t or "CSP" in t:
            return "Security Headers"
        if "CORS" in t:
            return "CORS Configuration"
        if "Mixed Content" in t:
            return "Mixed Content"
        if "Clickjacking" in t or "X-Frame-Options" in t:
            return "Clickjacking Protection"
        if "GraphQL" in t:
            return "GraphQL Security"
        if "JWT" in t or "Token" in t:
            return "JWT/Token Security"
        if "Smuggling" in t:
            return "HTTP Request Smuggling"
        if "Cache" in t:
            return "Cache Security"
        if "SSRF" in t:
            return "SSRF"
        if "OAuth" in t or "OIDC" in t:
            return "OAuth Security"
        if "API" in t:
            return "API Security"
        if "WebSocket" in t:
            return "WebSocket Security"
        if "JavaScript" in t or "DOM" in t:
            return "Client-Side Security"
        return "General"
    
    def to_report_dict(self) -> Dict:
        """Convert finding to dictionary for JSON export"""
        raw_req = raw_resp = resp_time = None
        if self.response_obj:
            req = self.response_obj.request
            host = req.headers.get('Host', urlparse(req.url).netloc) if hasattr(req, 'headers') else ''
            ua = req.headers.get('User-Agent', '') if hasattr(req, 'headers') else ''
            raw_req = f"{req.method} {req.url} HTTP/1.1\nHost: {host}\nUser-Agent: {ua}" if hasattr(req, 'method') else None
            raw_resp = (f"HTTP/1.1 {self.response_obj.status_code}\n"
                       f"Content-Type: {self.response_obj.headers.get('Content-Type', '')}\n\n"
                       f"{self.response_obj.text[:1000]}...") if hasattr(self.response_obj, 'status_code') else None
            resp_time = self.response_obj.elapsed.total_seconds() if hasattr(self.response_obj, 'elapsed') else None
        
        return {
            "id": str(uuid.uuid4()),
            "agent_group": "Reconnaissance",
            "sub_agent": "PassiveHttpObserver",
            "vulnerability_type": self.issue_type,
            "category": self._categorise(),
            "severity": self.severity_str,
            "confidence": self.confidence_str,
            "target_url": self.get_primary_url(),
            "affected_urls": self.affected_urls,  # NEW: List of all affected URLs
            "affected_urls_count": len(self.affected_urls),  # NEW: Count of affected URLs
            "affected_parameter": self.indicator if self.param_location else None,
            "description": self.impact,
            "observation": f"{self.issue_type} detected: {self.indicator}",
            "timestamp": self.timestamp,
            "proof_of_concept": self._generate_clickjacking_poc(),
            "remediation": self.remediation or "Review the identified security issue and apply best practices.",
            "cve_reference": self.cve_reference,
            "details": {
                "method": self.response_obj.request.method if self.response_obj and hasattr(self.response_obj, 'request') else "GET",
                "param_location": self.param_location,
                "payload": None,
                "detection_method": self.detection_method,
                "shell_context": None,
                "privilege_context": "Unauthenticated",
                "baseline_time": None,
                "response_time": resp_time,
                "extracted_data": self.extracted_data,
                "raw_request": raw_req,
                "raw_response": raw_resp,
            },
        }
    
    def get_deduplication_key(self) -> str:
        """Generate a key for deduplication based on issue_type and indicator"""
        return f"{self.issue_type}|{self.indicator}"
    
    def __hash__(self):
        return hash((self.url, self.issue_type, self.indicator))
    
    def __eq__(self, other):
        if not isinstance(other, SecurityFinding):
            return False
        return (self.url, self.issue_type, self.indicator) == (other.url, other.issue_type, other.indicator)


# -----------------------------------------------------------------------------
# Finding Deduplicator - NEW
# -----------------------------------------------------------------------------

class FindingDeduplicator:
    """Deduplicate findings by (issue_type + indicator) and aggregate affected URLs"""
    
    def __init__(self):
        self.deduplicated_findings: Dict[str, SecurityFinding] = {}
    
    def add_finding(self, finding: SecurityFinding):
        """Add a finding, merging with existing if duplicate key exists"""
        dedup_key = finding.get_deduplication_key()
        
        if dedup_key in self.deduplicated_findings:
            # Merge: add URL to existing finding
            existing = self.deduplicated_findings[dedup_key]
            existing.add_affected_url(finding.url)
            
            # Preserve the most severe/relevant response_obj if needed
            if finding.response_obj and not existing.response_obj:
                existing.response_obj = finding.response_obj
            
            # Merge extracted data if useful
            if finding.extracted_data and existing.extracted_data:
                for key, value in finding.extracted_data.items():
                    if key not in existing.extracted_data:
                        existing.extracted_data[key] = value
        else:
            # New finding - store it
            self.deduplicated_findings[dedup_key] = finding
    
    def add_findings(self, findings: List[SecurityFinding]):
        """Add multiple findings"""
        for finding in findings:
            self.add_finding(finding)
    
    def get_findings(self) -> List[SecurityFinding]:
        """Get all deduplicated findings"""
        return list(self.deduplicated_findings.values())
    
    def get_finding_count(self) -> int:
        """Get number of unique findings after deduplication"""
        return len(self.deduplicated_findings)
    
    def clear(self):
        """Clear all findings"""
        self.deduplicated_findings.clear()


# -----------------------------------------------------------------------------
# Cookie Parser
# -----------------------------------------------------------------------------

class CookieParser:
    """Robust cookie parser with RFC 6265 compliance"""
    
    @staticmethod
    def parse_set_cookie_header(header_value: str) -> Dict:
        """Parse a single raw Set-Cookie header value"""
        try:
            cookie = SimpleCookie()
            cookie.load(header_value)
            for name, morsel in cookie.items():
                return {
                    'name': name,
                    'value': morsel.value,
                    'secure': morsel.get('secure', False) is not None,
                    'httponly': morsel.get('httponly', False) is not None,
                    'path': morsel.get('path', '/') or '/',
                    'domain': morsel.get('domain', None),
                    'samesite': morsel.get('samesite', None),
                    'expires': morsel.get('expires', None),
                    'max-age': morsel.get('max-age', None),
                    'raw_value': header_value,
                }
        except Exception:
            return {
                'name': 'unknown',
                'value': header_value[:100],
                'secure': False,
                'httponly': False,
                'path': '/',
                'domain': None,
                'samesite': None,
                'expires': None,
                'max-age': None,
                'raw_value': header_value,
                'parse_error': str(sys.exc_info()[1]),
            }
    
    @staticmethod
    def parse_all_cookies(response) -> List[Dict]:
        """Extract and parse all Set-Cookie headers"""
        set_cookie_headers = []
        
        if hasattr(response, 'raw') and hasattr(response.raw, 'headers'):
            if hasattr(response.raw.headers, 'getlist'):
                set_cookie_headers = response.raw.headers.getlist('Set-Cookie')
        
        if not set_cookie_headers and hasattr(response, 'headers'):
            if 'Set-Cookie' in response.headers:
                val = response.headers.get('Set-Cookie')
                if val:
                    set_cookie_headers = [val] if isinstance(val, str) else val
        
        cookies = []
        seen_names = set()
        for header in set_cookie_headers:
            info = CookieParser.parse_set_cookie_header(header)
            if info and info['name'] not in seen_names:
                cookies.append(info)
                seen_names.add(info['name'])
        
        return cookies


# -----------------------------------------------------------------------------
# HTTP Message Parser
# -----------------------------------------------------------------------------

class HTTPMessageParser:
    """Robust HTTP message parser handling various line endings and encodings"""
    
    @staticmethod
    def parse_http_messages(data: bytes) -> List[Dict]:
        """Parse HTTP messages from raw bytes with robust handling"""
        messages = []
        offset = 0
        data_len = len(data)
        
        while offset < data_len:
            # Find message headers end (supports both CRLF and LF)
            headers_end = HTTPMessageParser._find_headers_end(data, offset)
            if headers_end == -1:
                break
            
            # Extract headers section
            headers_section = data[offset:headers_end]
            headers_text = headers_section.decode('utf-8', errors='replace')
            lines = headers_text.splitlines()
            
            if not lines:
                break
            
            # Parse status/request line
            first_line = lines[0].strip()
            is_request = first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 
                                                'HEAD', 'OPTIONS', 'CONNECT', 'TRACE'))
            
            # Parse headers
            headers = {}
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.strip()] = value.strip()
                elif ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Determine body length
            content_length = int(headers.get('Content-Length', 0))
            transfer_encoding = headers.get('Transfer-Encoding', '').lower()
            
            # Calculate body start position
            body_start = headers_end + HTTPMessageParser._get_line_end_length(data, headers_end)
            
            # Parse body
            body = b''
            if transfer_encoding == 'chunked':
                body, body_end = HTTPMessageParser._parse_chunked_body(data, body_start)
                offset = body_end
            elif content_length > 0:
                if body_start + content_length <= data_len:
                    body = data[body_start:body_start + content_length]
                    offset = body_start + content_length
                else:
                    # Incomplete data
                    break
            else:
                # No body
                offset = body_start
            
            # Parse URL if request
            url = ''
            if is_request:
                parts = first_line.split()
                if len(parts) >= 2:
                    path = parts[1]
                    host = headers.get('Host', '')
                    scheme = 'https' if ':443' in host or headers.get('X-Forwarded-Proto') == 'https' else 'http'
                    host_clean = host.split(':')[0]
                    if host_clean:
                        url = f"{scheme}://{host_clean}{path}"
                    else:
                        url = path
            
            messages.append({
                'is_request': is_request,
                'first_line': first_line,
                'headers': headers,
                'body': body,
                'url': url,
                'raw_offset': offset
            })
        
        return messages
    
    @staticmethod
    def _find_headers_end(data: bytes, start: int) -> int:
        """Find the end of HTTP headers (double CRLF or double LF)"""
        # Look for \r\n\r\n
        pos = data.find(b'\r\n\r\n', start)
        if pos != -1:
            return pos
        
        # Look for \n\n
        pos = data.find(b'\n\n', start)
        if pos != -1:
            return pos
        
        return -1
    
    @staticmethod
    def _get_line_end_length(data: bytes, pos: int) -> int:
        """Determine line ending length at position"""
        if pos + 1 < len(data) and data[pos:pos+2] == b'\r\n':
            return 2
        elif pos < len(data) and data[pos] == ord('\n'):
            return 1
        return 0
    
    @staticmethod
    def _parse_chunked_body(data: bytes, start: int) -> Tuple[bytes, int]:
        """Parse HTTP chunked transfer encoding body"""
        body_parts = []
        offset = start
        data_len = len(data)
        
        while offset < data_len:
            # Find chunk size line
            line_end = data.find(b'\r\n', offset)
            if line_end == -1:
                line_end = data.find(b'\n', offset)
            if line_end == -1:
                break
            
            # Parse chunk size (hex)
            chunk_size_line = data[offset:line_end].strip()
            offset = line_end + HTTPMessageParser._get_line_end_length(data, line_end)
            
            # Split extensions if present
            if b';' in chunk_size_line:
                chunk_size_hex = chunk_size_line.split(b';')[0]
            else:
                chunk_size_hex = chunk_size_line
            
            try:
                chunk_size = int(chunk_size_hex, 16)
            except ValueError:
                break
            
            if chunk_size == 0:
                # Final chunk - skip trailing CRLF
                offset += 2
                break
            
            # Read chunk data
            if offset + chunk_size <= data_len:
                chunk_data = data[offset:offset + chunk_size]
                body_parts.append(chunk_data)
                offset += chunk_size + 2  # Skip data + CRLF
            else:
                break
        
        return b''.join(body_parts), offset


# -----------------------------------------------------------------------------
# TLS Analyzer for Passive Detection of TLSv1.0/TLSv1.1 and Weak Ciphers
# -----------------------------------------------------------------------------

class TLSAnalyzer:
    """Passively analyzes TLS handshakes from PCAP captures for security issues"""
    
    # TLS version mappings
    TLS_VERSIONS = {
        0x0300: "SSL 3.0",
        0x0301: "TLS 1.0",
        0x0302: "TLS 1.1",
        0x0303: "TLS 1.2",
        0x0304: "TLS 1.3",
    }
    
    # Weak cipher suites (insecure, should be avoided)
    WEAK_CIPHER_SUITES = {
        # NULL ciphers (no encryption)
        0x0000: "TLS_NULL_WITH_NULL_NULL",
        0x0001: "TLS_RSA_WITH_NULL_MD5",
        0x0002: "TLS_RSA_WITH_NULL_SHA",
        0x000B: "TLS_DH_DSS_WITH_NULL_SHA",
        0x000C: "TLS_DH_RSA_WITH_NULL_SHA",
        0x0010: "TLS_DHE_DSS_WITH_NULL_SHA",
        0x0014: "TLS_DHE_RSA_WITH_NULL_SHA",
        0x0022: "TLS_DH_anon_WITH_NULL_MD5",
        0x0023: "TLS_DH_anon_WITH_NULL_SHA",
        
        # Export grade ciphers (weak)
        0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
        0x0004: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0006: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0018: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x001B: "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0026: "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0028: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x002C: "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        0x0030: "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
        
        # RC4 ciphers (broken)
        0x0005: "TLS_RSA_WITH_RC4_128_SHA",
        0x0004: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0018: "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        0x0020: "TLS_DH_anon_WITH_RC4_128_MD5",
        
        # DES ciphers (weak)
        0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
        0x0015: "TLS_DH_DSS_WITH_DES_CBC_SHA",
        0x0019: "TLS_DH_RSA_WITH_DES_CBC_SHA",
        0x001A: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        
        # Anonymous ciphers (no authentication - MITM risk)
        0x001B: "TLS_DH_anon_WITH_DES_CBC_SHA",
        0x001C: "TLS_DH_anon_WITH_DES_CBC_SHA",
        0x0031: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        0x0032: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    }
    
    def __init__(self, config: ObserverConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.tls_streams = {}  # Store TLS handshake info per connection
        self.seen_tls_sessions = set()
        
    def process_packet(self, packet) -> List[SecurityFinding]:
        """Process a single packet for TLS handshake information"""
        findings = []
        
        if not SCAPY_TLS_AVAILABLE:
            return findings
        
        try:
            # Check for TLS layer in packet
            if TLS in packet:
                tls_layer = packet[TLS]
                
                # Extract client and server information from IP/TCP layers
                src_ip = packet[IP].src if IP in packet else "Unknown"
                dst_ip = packet[IP].dst if IP in packet else "Unknown"
                src_port = packet[TCP].sport if TCP in packet else 0
                dst_port = packet[TCP].dport if TCP in packet else 0
                
                # Create connection identifier
                conn_id = f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
                
                # Initialize stream tracking if needed
                if conn_id not in self.tls_streams:
                    self.tls_streams[conn_id] = {
                        "client_hello": None,
                        "server_hello": None,
                        "client_ciphers": [],
                        "server_cipher": None,
                        "server_version": None,
                        "sni": None,
                        "timestamp": time.time()
                    }
                
                # Look for ClientHello (record type 22, handshake type 1)
                if hasattr(tls_layer, 'msg') and tls_layer.msg:
                    for msg in tls_layer.msg:
                        if hasattr(msg, 'type') and msg.type == 1:  # ClientHello
                            self.tls_streams[conn_id]["client_hello"] = msg
                            
                            # Extract TLS version
                            if hasattr(msg, 'version'):
                                version = msg.version
                                version_str = self.TLS_VERSIONS.get(version, f"Unknown (0x{version:04x})")
                                self.tls_streams[conn_id]["server_version"] = version_str
                            
                            # Extract cipher suites
                            if hasattr(msg, 'cipher_suites'):
                                self.tls_streams[conn_id]["client_ciphers"] = msg.cipher_suites
                            
                            # Extract SNI (Server Name Indication)
                            if hasattr(msg, 'ext') and msg.ext:
                                for ext in msg.ext:
                                    if hasattr(ext, 'type') and ext.type == 0:  # SNI extension
                                        if hasattr(ext, 'val') and hasattr(ext.val, 'servername'):
                                            self.tls_streams[conn_id]["sni"] = ext.val.servername.decode('utf-8', errors='ignore')
                            
                            # Analyze client's TLS version
                            if self.config.detect_tls_vulnerabilities:
                                version_findings = self._analyze_tls_version(
                                    conn_id, version, version_str, dst_ip, dst_port
                                )
                                findings.extend(version_findings)
                        
                        # Look for ServerHello (type 2)
                        elif hasattr(msg, 'type') and msg.type == 2:  # ServerHello
                            self.tls_streams[conn_id]["server_hello"] = msg
                            
                            # Extract server's chosen TLS version
                            if hasattr(msg, 'version'):
                                version = msg.version
                                version_str = self.TLS_VERSIONS.get(version, f"Unknown (0x{version:04x})")
                                self.tls_streams[conn_id]["server_version"] = version_str
                            
                            # Extract server's chosen cipher suite
                            if hasattr(msg, 'cipher_suite'):
                                cipher_suite = msg.cipher_suite
                                self.tls_streams[conn_id]["server_cipher"] = cipher_suite
                                
                                # Analyze server's TLS version and cipher
                                if self.config.detect_tls_vulnerabilities:
                                    version_findings = self._analyze_tls_version(
                                        conn_id, version, version_str, dst_ip, dst_port, is_server=True
                                    )
                                    findings.extend(version_findings)
                                    
                                    if self.config.detect_weak_ciphers:
                                        cipher_findings = self._analyze_cipher_suite(
                                            conn_id, cipher_suite, dst_ip, dst_port
                                        )
                                        findings.extend(cipher_findings)
            
            # Periodic cleanup of old TLS streams
            self._cleanup_old_streams()
            
        except Exception as e:
            self.logger.debug(f"TLS packet processing error: {e}")
        
        return findings
    
    def _analyze_tls_version(self, conn_id: str, version: int, version_str: str, 
                             host: str, port: int, is_server: bool = False) -> List[SecurityFinding]:
        """Analyze TLS version for security issues"""
        findings = []
        
        # Check for TLS 1.0 (deprecated)
        if version == 0x0301 and self.config.detect_tls10:
            session_key = f"tls10_{host}"
            if session_key not in self.seen_tls_sessions:
                self.seen_tls_sessions.add(session_key)
                
                findings.append(SecurityFinding(
                    url=f"https://{host}:{port}",
                    issue_type="Deprecated TLS 1.0 Detected",
                    indicator=f"TLS 1.0 negotiated on connection to {host}",
                    impact="TLS 1.0 is deprecated and contains known vulnerabilities including POODLE and BEAST. It should not be used in production environments.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="Passive TLS Analysis",
                    remediation="Disable TLS 1.0 and TLS 1.1 on the server. Enable TLS 1.2 or TLS 1.3 only.",
                    cve_reference="CVE-2011-3389 (BEAST), CVE-2014-3566 (POODLE)",
                    extracted_data={
                        "tls_version": version_str,
                        "negotiated_by": "server" if is_server else "client",
                        "host": host,
                        "connection_id": conn_id[:50]
                    }
                ))
        
        # Check for TLS 1.1 (deprecated)
        elif version == 0x0302 and self.config.detect_tls11:
            session_key = f"tls11_{host}"
            if session_key not in self.seen_tls_sessions:
                self.seen_tls_sessions.add(session_key)
                
                findings.append(SecurityFinding(
                    url=f"https://{host}:{port}",
                    issue_type="Deprecated TLS 1.1 Detected",
                    indicator=f"TLS 1.1 negotiated on connection to {host}",
                    impact="TLS 1.1 is deprecated and lacks modern security features. It should be replaced with TLS 1.2 or TLS 1.3.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    detection_method="Passive TLS Analysis",
                    remediation="Disable TLS 1.1 on the server. Configure TLS 1.2 or TLS 1.3 as the minimum version.",
                    cve_reference="RFC 8996 (TLS 1.0 and 1.1 deprecation)",
                    extracted_data={
                        "tls_version": version_str,
                        "negotiated_by": "server" if is_server else "client",
                        "host": host,
                        "connection_id": conn_id[:50]
                    }
                ))
        
        # Check for SSL 3.0 (critically insecure)
        elif version == 0x0300:
            session_key = f"ssl3_{host}"
            if session_key not in self.seen_tls_sessions:
                self.seen_tls_sessions.add(session_key)
                
                findings.append(SecurityFinding(
                    url=f"https://{host}:{port}",
                    issue_type="Critical: SSL 3.0 Detected",
                    indicator=f"SSL 3.0 negotiated on connection to {host}",
                    impact="SSL 3.0 is critically insecure and vulnerable to POODLE attacks. It allows protocol downgrade attacks.",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    detection_method="Passive TLS Analysis",
                    remediation="Completely disable SSL 3.0 on the server. Enable only TLS 1.2 or higher.",
                    cve_reference="CVE-2014-3566 (POODLE)",
                    extracted_data={
                        "tls_version": version_str,
                        "negotiated_by": "server" if is_server else "client",
                        "host": host
                    }
                ))
        
        return findings
    
    def _analyze_cipher_suite(self, conn_id: str, cipher_suite: int, 
                              host: str, port: int) -> List[SecurityFinding]:
        """Analyze cipher suite for security weaknesses"""
        findings = []
        
        if cipher_suite in self.WEAK_CIPHER_SUITES:
            cipher_name = self.WEAK_CIPHER_SUITES[cipher_suite]
            session_key = f"weak_cipher_{cipher_suite}_{host}"
            
            if session_key not in self.seen_tls_sessions:
                self.seen_tls_sessions.add(session_key)
                
                severity = Severity.HIGH
                if "NULL" in cipher_name:
                    impact = "NULL cipher offers no encryption - all traffic is transmitted in plaintext"
                    remediation = "Remove NULL cipher suites from server configuration"
                elif "EXPORT" in cipher_name:
                    impact = "Export-grade cipher uses weak 40-bit encryption that can be brute-forced"
                    remediation = "Disable all export-grade cipher suites"
                elif "RC4" in cipher_name:
                    impact = "RC4 cipher is broken and should not be used"
                    remediation = "Remove RC4 cipher suites from server configuration"
                elif "DES" in cipher_name:
                    impact = "DES cipher uses weak 56-bit encryption"
                    remediation = "Disable DES and 3DES cipher suites"
                elif "anon" in cipher_name.lower():
                    impact = "Anonymous cipher provides no authentication - vulnerable to MitM attacks"
                    remediation = "Disable anonymous Diffie-Hellman cipher suites"
                    severity = Severity.CRITICAL
                else:
                    impact = "Weak or insecure cipher suite detected"
                    remediation = "Review and remove weak cipher suites from server configuration"
                
                findings.append(SecurityFinding(
                    url=f"https://{host}:{port}",
                    issue_type="Weak TLS Cipher Suite Detected",
                    indicator=f"Weak cipher suite {cipher_name} (0x{cipher_suite:04x}) negotiated",
                    impact=impact,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    detection_method="Passive TLS Cipher Analysis",
                    remediation=remediation,
                    cve_reference="CWE-326 (Weak Encryption)",
                    extracted_data={
                        "cipher_suite": cipher_name,
                        "cipher_code": f"0x{cipher_suite:04x}",
                        "host": host,
                        "connection_id": conn_id[:50]
                    }
                ))
        
        return findings
    
    def _cleanup_old_streams(self, max_age_seconds: float = 300.0):
        """Clean up old TLS streams to prevent memory issues"""
        current_time = time.time()
        stale_streams = [
            conn_id for conn_id, stream in self.tls_streams.items()
            if current_time - stream.get("timestamp", 0) > max_age_seconds
        ]
        for conn_id in stale_streams:
            del self.tls_streams[conn_id]
    
    def get_tls_findings_for_streams(self) -> List[SecurityFinding]:
        """Get summary findings for all analyzed TLS streams"""
        findings = []
        
        # No need to return additional findings here as they are returned during processing
        return findings


# -----------------------------------------------------------------------------
# TCP Stream Class
# -----------------------------------------------------------------------------

class TCPStream:
    """TCP stream reassembly with proper sequencing"""
    
    def __init__(self, is_http2: bool = False):
        self.buffer = bytearray()
        self.segments = []
        self.last_seq = 0
        self.last_seen = time.time()
        self.is_syn_received = False
        self.is_fin_received = False
        self.is_http2 = is_http2
        self._buffer_valid = False
    
    def add_segment(self, seq: int, data: bytes, is_syn: bool = False, is_fin: bool = False):
        """Add a TCP segment"""
        if is_syn:
            self.is_syn_received = True
        
        if is_fin:
            self.is_fin_received = True
        
        if data:
            self.segments.append((seq, data))
            self.last_seq = max(self.last_seq, seq + len(data))
            self.last_seen = time.time()
            self._buffer_valid = False
            
            # Keep only recent segments
            if len(self.segments) > 100:
                self.segments.sort(key=lambda x: x[0])
                self.segments = self.segments[-100:]
    
    def get_data(self) -> bytes:
        """Get reassembled data"""
        if not self._buffer_valid:
            self._reassemble()
        return bytes(self.buffer)
    
    def _reassemble(self):
        """Reassemble segments in correct order"""
        if not self.segments:
            return
        
        # Sort by sequence number
        sorted_segments = sorted(self.segments, key=lambda x: x[0])
        
        # Rebuild buffer
        new_buffer = bytearray()
        expected_seq = sorted_segments[0][0]
        
        for seq, data in sorted_segments:
            if seq == expected_seq:
                new_buffer.extend(data)
                expected_seq = seq + len(data)
            elif seq < expected_seq:
                # Overlap - add only new data
                overlap = expected_seq - seq
                if overlap < len(data):
                    new_buffer.extend(data[overlap:])
                    expected_seq = seq + len(data)
            else:
                # Gap - stop
                break
        
        self.buffer = new_buffer
        self._buffer_valid = True
    
    def is_complete(self) -> bool:
        """Check if stream is complete"""
        return self.is_fin_received
    
    def is_stale(self, timeout: float) -> bool:
        """Check if stream is stale"""
        return time.time() - self.last_seen > timeout


# -----------------------------------------------------------------------------
# Enhanced PCAP Processor with Streaming and TLS Analysis
# -----------------------------------------------------------------------------

class EnhancedPCAPProcessor:
    """Enhanced PCAP processor with streaming, TCP reassembly, HTTP/2 support, and TLS analysis"""
    
    def __init__(self, config: ObserverConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.streams = {}
        self.stream_timeout = config.pcap_stream_timeout
        self.max_streams = config.pcap_max_streams
        self.processed_packets = 0
        self.streams_lock = Lock()
        
        # HTTP/2 support
        self.h2_connections = {}
        self.http2_responses = []
        
        # TLS analysis
        self.tls_analyzer = TLSAnalyzer(config) if SCAPY_TLS_AVAILABLE else None
        self.tls_findings = []
    
    def process_pcap(self, filepath: str) -> Tuple[List[Tuple[str, requests.Response]], List[SecurityFinding]]:
        """Process PCAP file with streaming to avoid memory issues.
        Returns tuple of (HTTP responses list, TLS findings list)"""
        if not SCAPY_AVAILABLE:
            self.logger.error("Scapy not available for PCAP processing")
            return [], []
        
        # Check file size
        try:
            file_size_mb = Path(filepath).stat().st_size / (1024 * 1024)
            if file_size_mb > self.config.max_pcap_size_mb:
                self.logger.warning(f"PCAP file too large ({file_size_mb:.1f}MB > {self.config.max_pcap_size_mb}MB), skipping")
                return [], []
        except Exception:
            pass
        
        responses = []
        packet_count = 0
        
        # Warn about TLS analysis availability
        if self.config.detect_tls_vulnerabilities and not SCAPY_TLS_AVAILABLE:
            self.logger.warning("TLS vulnerability detection requires scapy with TLS extensions. Install: pip install scapy[complete]")
        
        try:
            # Stream PCAP file instead of loading all at once
            with PcapReader(filepath) as pcap_reader:
                for packet in pcap_reader:
                    packet_count += 1
                    self.processed_packets += 1
                    
                    # Process TLS handshakes for security analysis
                    if self.config.detect_tls_vulnerabilities and self.tls_analyzer:
                        tls_findings = self.tls_analyzer.process_packet(packet)
                        self.tls_findings.extend(tls_findings)
                    
                    # Process TCP/HTTP packets
                    if TCP in packet and Raw in packet:
                        self._process_tcp_packet(packet)
                    
                    # Periodic cleanup and extraction
                    if packet_count % self.config.pcap_chunk_size == 0:
                        responses.extend(self._extract_http_transactions())
                        self._cleanup_stale_streams()
                        gc.collect()
                    
                    # Stop if too many packets (safety)
                    if packet_count > 1000000:
                        self.logger.warning("Reached packet limit, stopping processing")
                        break
            
            # Final extraction
            responses.extend(self._extract_http_transactions())
            
            # Extract HTTP/2 if available
            if H2_AVAILABLE and self.http2_responses:
                responses.extend(self.http2_responses)
            
        except Exception as e:
            self.logger.error(f"Failed to read PCAP file: {e}")
            return [], []
        
        self.logger.info(f"Extracted {len(responses)} HTTP/WebSocket transactions from {self.processed_packets} packets")
        self.logger.info(f"Found {len(self.tls_findings)} TLS security findings")
        
        return responses, self.tls_findings
    
    def _process_tcp_packet(self, packet):
        """Process a single TCP packet"""
        tcp = packet[TCP]
        ip = packet[IP] if IP in packet else None
        
        if not ip:
            return
        
        # Get stream ID
        stream_id = self._get_stream_id(ip, tcp)
        
        # Determine flags
        is_syn = bool(tcp.flags & 0x02)
        is_fin = bool(tcp.flags & 0x01)
        
        # Add segment
        raw_data = bytes(packet[Raw])
        
        with self.streams_lock:
            if stream_id not in self.streams:
                if len(self.streams) >= self.max_streams:
                    self._cleanup_stale_streams_locked()
                self.streams[stream_id] = TCPStream()
            
            stream = self.streams[stream_id]
            stream.add_segment(tcp.seq, raw_data, is_syn, is_fin)
            stream.last_seen = time.time()
    
    def _get_stream_id(self, ip, tcp) -> tuple:
        """Generate unique stream identifier"""
        # Normalize by sorting addresses to get consistent stream ID
        if tcp.sport > tcp.dport:
            return (ip.src, tcp.sport, ip.dst, tcp.dport)
        else:
            return (ip.dst, tcp.dport, ip.src, tcp.sport)
    
    def _cleanup_stale_streams(self):
        """Remove stale streams"""
        with self.streams_lock:
            self._cleanup_stale_streams_locked()
    
    def _cleanup_stale_streams_locked(self):
        """Remove stale streams (call with lock held)"""
        now = time.time()
        stale_streams = [
            sid for sid, stream in self.streams.items()
            if now - stream.last_seen > self.stream_timeout
        ]
        
        for sid in stale_streams:
            del self.streams[sid]
    
    def _extract_http_transactions(self) -> List[Tuple[str, requests.Response]]:
        """Extract HTTP transactions from reassembled streams"""
        responses = []
        completed_streams = []
        
        with self.streams_lock:
            for stream_id, stream in list(self.streams.items()):
                if stream.is_complete() or stream.is_stale(self.stream_timeout):
                    # Check if HTTP/2
                    data = stream.get_data()
                    if data and len(data) > 20:
                        # Look for HTTP/2 connection preface
                        if data[:24] == b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n':
                            stream.is_http2 = True
                            self._process_http2_stream(stream_id, stream)
                            completed_streams.append(stream_id)
                            continue
                        
                        # Parse HTTP/1.x messages
                        messages = HTTPMessageParser.parse_http_messages(data)
                        
                        # Group into request-response pairs
                        requests_list = [msg for msg in messages if msg.get('is_request')]
                        responses_list = [msg for msg in messages if not msg.get('is_request')]
                        
                        # Match requests to responses
                        for i, request in enumerate(requests_list):
                            if i < len(responses_list):
                                response = responses_list[i]
                                if request.get('url'):
                                    mock_response = self._create_mock_response(response, request)
                                    responses.append((request['url'], mock_response))
                    
                    completed_streams.append(stream_id)
            
            # Clean up completed streams
            for stream_id in completed_streams:
                if stream_id in self.streams:
                    del self.streams[stream_id]
        
        return responses
    
    def _process_http2_stream(self, stream_id: tuple, stream):
        """Process HTTP/2 stream using h2 library"""
        if not H2_AVAILABLE:
            return
        
        try:
            # Initialize HTTP/2 connection
            config = H2Configuration(client_side=True)
            conn = h2.connection.H2Connection(config=config)
            conn.initiate_connection()
            
            # Feed data
            data = stream.get_data()
            events = conn.receive_data(data)
            
            # Process events
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    # Build response
                    headers = dict(event.headers)
                    status = int(headers.get(b':status', [b'200'])[0])
                    
                    # Get body
                    body = b''
                    
                    mock_response = self._create_http2_mock_response(
                        url=headers.get(b':path', [b'/'])[0].decode(),
                        status=status,
                        headers=headers,
                        body=body
                    )
                    
                    self.http2_responses.append((mock_response.url, mock_response))
                    
        except Exception as e:
            self.logger.debug(f"HTTP/2 processing error: {e}")
    
    def _create_http2_mock_response(self, url: str, status: int, headers: Dict, body: bytes) -> requests.Response:
        """Create mock response for HTTP/2"""
        mock_response = requests.Response()
        mock_response.status_code = status
        mock_response._content = body[:self.config.max_response_size]
        mock_response.url = url
        
        # Convert headers
        for key, value in headers.items():
            if isinstance(key, bytes):
                key = key.decode('utf-8', errors='ignore')
            if isinstance(value, bytes):
                value = value.decode('utf-8', errors='ignore')
            if not key.startswith(':'):
                mock_response.headers[key] = value
        
        class MockRequest:
            def __init__(self):
                self.method = 'GET'
                self.url = url
                self.headers = {}
        
        mock_response.request = MockRequest()
        mock_response.elapsed = timedelta(seconds=0)
        mock_response.raw = None
        
        return mock_response
    
    def _create_mock_response(self, response_info: Dict, request_info: Dict) -> requests.Response:
        """Create a requests.Response object from parsed data"""
        mock_response = requests.Response()
        
        # Parse status code from first line
        first_line = response_info.get('first_line', '')
        status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', first_line)
        mock_response.status_code = int(status_match.group(1)) if status_match else 200
        
        mock_response.headers = response_info.get('headers', {})
        mock_response._content = response_info.get('body', b'')[:self.config.max_response_size]
        
        class MockRequest:
            def __init__(self, req_info):
                self.method = 'GET'
                if req_info.get('first_line'):
                    method_match = re.match(r'^([A-Z]+)\s+', req_info['first_line'])
                    if method_match:
                        self.method = method_match.group(1)
                self.url = req_info.get('url', '')
                self.headers = req_info.get('headers', {})
        
        mock_response.request = MockRequest(request_info)
        mock_response.elapsed = timedelta(seconds=0)
        mock_response.raw = None
        mock_response.url = request_info.get('url', '')
        
        return mock_response


# -----------------------------------------------------------------------------
# Credit Card Detector
# -----------------------------------------------------------------------------

class CreditCardDetector:
    """Advanced credit card detection with context validation and false positive reduction"""
    
    def __init__(self, enable_luhn: bool = True, config: ObserverConfig = None):
        self.enable_luhn = enable_luhn
        self.config = config or ObserverConfig()
        self.logger = logging.getLogger(__name__)
        
        # Whitelist patterns for false positives
        self.whitelist_patterns = [
            r'^\d{4}-\d{2}-\d{2}',
            r'^\d{2}:\d{2}:\d{2}',
            r'^\d{10,16}$',
            r'^(ORD|TRX|INV|REF|ID)[-\s]?[0-9]{8,16}$',
            r'^[A-Z0-9]{8,16}$',
        ]
        
        # False positive keywords
        self.false_positive_keywords = [
            'timestamp', 'datetime', 'date', 'time', 'epoch', 'unixtime',
            'phone', 'mobile', 'fax', 'tel', 'cell',
            'order_id', 'transaction_id', 'ref_id', 'reference', 'tracking',
            'id', 'user_id', 'account_id', 'session_id',
            'product_id', 'sku', 'upc', 'ean', 'isbn',
            'ip_address', 'port', 'sequence', 'version', 'build', 'revision',
            'serial', 'batch', 'lot', 'po', 'invoice', 'receipt'
        ]
        
        self.patterns = [
            (r'\b4[0-9]{12}(?:[0-9]{3})?\b', self._validate_visa),
            (r'\b(?:5[1-5][0-9]{14}|2(?:2[2-9][0-9]{2}|[3-6][0-9]{3}|7[0-1][0-9]{2}|720[0-9])[0-9]{12})\b', self._validate_mastercard),
            (r'\b3[47][0-9]{13}\b', self._validate_amex),
            (r'\b(?:6011[0-9]{12}|65[0-9]{14}|622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9]{2}|9[01][0-9]|92[0-5])[0-9]{10})\b', self._validate_discover),
            (r'\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b', self._validate_diners),
            (r'\b(?:352[8-9][0-9]{12}|35[3-8][0-9]{13})\b', self._validate_jcb),
        ]
    
    def detect(self, text: str, context_url: str = "") -> List[Dict]:
        """Detect credit card numbers in text with false positive filtering"""
        if not text or not self.enable_luhn:
            return []
        
        potential_cards = []
        
        for pattern, validator in self.patterns:
            matches = re.finditer(pattern, text)
            for match in matches:
                card_number = match.group(0)
                card_number_clean = re.sub(r'[\s-]', '', card_number)
                
                # Length validation
                if not (self.config.min_credit_card_length <= len(card_number_clean) <= self.config.max_credit_card_length):
                    continue
                
                # Check whitelist
                if self._is_whitelisted(card_number_clean, text, match.start()):
                    continue
                
                # Validate with BIN checking
                if validator(card_number_clean):
                    context = self._get_context(text, match.start(), match.end())
                    
                    # Enhanced false positive checking
                    if self._is_false_positive_by_context(context, card_number_clean):
                        continue
                    
                    potential_cards.append({
                        'number': self._mask_card_number(card_number_clean),
                        'full_number': card_number_clean,
                        'context': context,
                        'position': match.start(),
                        'type': self._get_card_type(card_number_clean)
                    })
        
        # Deduplicate
        seen = set()
        unique_cards = []
        for card in potential_cards:
            if card['number'] not in seen:
                seen.add(card['number'])
                unique_cards.append(card)
        
        return unique_cards
    
    def _is_whitelisted(self, card_number: str, text: str, position: int) -> bool:
        """Check if number matches whitelist patterns"""
        for pattern in self.whitelist_patterns:
            if re.match(pattern, card_number):
                return True
        
        # Check surrounding characters
        context_start = max(0, position - 10)
        context_end = min(len(text), position + len(card_number) + 10)
        context = text[context_start:context_end]
        
        # Common false positive patterns
        fp_patterns = [
            r'["\']\d{13,16}["\']',
            r'\b(?:id|ref|num|no)[:=]\s*\d{13,16}\b',
        ]
        
        for pattern in fp_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                return True
        
        return False
    
    def _is_false_positive_by_context(self, context: str, card_number: str) -> bool:
        """Check context for false positive indicators"""
        context_lower = context.lower()
        
        # Check false positive keywords
        for keyword in self.false_positive_keywords:
            if keyword in context_lower:
                return True
        
        # Check if it's a repeated pattern (likely test data)
        if card_number in context and context.count(card_number) > 3:
            return True
        
        # Check if it's in a JSON key (not value)
        if re.search(r'["\']\w*["\']\s*:\s*["\']?' + re.escape(card_number), context):
            return True
        
        # Check if it's part of a larger number
        numbers = re.findall(r'\b\d+\b', context)
        if len(numbers) > 1 and all(len(n) == len(card_number) for n in numbers[:3]):
            return True
        
        return False
    
    def _get_context(self, text: str, start: int, end: int, context_chars: int = 100) -> str:
        """Extract surrounding context"""
        context_start = max(0, start - context_chars)
        context_end = min(len(text), end + context_chars)
        return text[context_start:context_end]
    
    def _mask_card_number(self, number: str) -> str:
        """Mask credit card number for display"""
        if len(number) <= 4:
            return '*' * len(number)
        return number[:4] + '*' * (len(number) - 8) + number[-4:]
    
    def _get_card_type(self, number: str) -> str:
        """Identify card type from number"""
        if number.startswith('4'):
            return 'Visa'
        elif number.startswith(('51', '52', '53', '54', '55')) or (2221 <= int(number[:4]) <= 2720):
            return 'Mastercard'
        elif number.startswith(('34', '37')):
            return 'American Express'
        elif number.startswith(('6011', '65')) or (622126 <= int(number[:6]) <= 622925):
            return 'Discover'
        elif number.startswith(('36', '38', '39')) or (300 <= int(number[:3]) <= 305):
            return 'Diners Club'
        elif 3528 <= int(number[:4]) <= 3589:
            return 'JCB'
        return 'Unknown'
    
    def _validate_visa(self, number: str) -> bool:
        if len(number) not in [13, 16]:
            return False
        if not number.startswith('4'):
            return False
        return self._luhn_check(number)
    
    def _validate_mastercard(self, number: str) -> bool:
        if len(number) != 16:
            return False
        prefix = int(number[:2])
        if 51 <= prefix <= 55:
            return self._luhn_check(number)
        prefix_4 = int(number[:4])
        return 2221 <= prefix_4 <= 2720 and self._luhn_check(number)
    
    def _validate_amex(self, number: str) -> bool:
        if len(number) != 15:
            return False
        if not (number.startswith('34') or number.startswith('37')):
            return False
        return self._luhn_check(number)
    
    def _validate_discover(self, number: str) -> bool:
        if len(number) != 16:
            return False
        if number.startswith('6011') or number.startswith('65'):
            return self._luhn_check(number)
        prefix_6 = int(number[:6])
        return 622126 <= prefix_6 <= 622925 and self._luhn_check(number)
    
    def _validate_diners(self, number: str) -> bool:
        if len(number) != 14:
            return False
        prefix_3 = int(number[:3])
        if 300 <= prefix_3 <= 305:
            return self._luhn_check(number)
        prefix_2 = int(number[:2])
        return prefix_2 in [36, 38, 39] and self._luhn_check(number)
    
    def _validate_jcb(self, number: str) -> bool:
        if len(number) != 16:
            return False
        prefix_4 = int(number[:4])
        return 3528 <= prefix_4 <= 3589 and self._luhn_check(number)
    
    def _luhn_check(self, number: str) -> bool:
        """Luhn algorithm validation"""
        total = 0
        is_second = False
        
        for digit in reversed(number):
            d = int(digit)
            if is_second:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
            is_second = not is_second
        
        return total % 10 == 0


# -----------------------------------------------------------------------------
# GraphQL Introspection Detector
# -----------------------------------------------------------------------------

class GraphQLIntrospectionDetector:
    """Detects GraphQL introspection leakage and schema exposure"""
    
    def __init__(self):
        self.introspection_patterns = [
            r'"__schema"\s*:',
            r'"__typename"\s*:',
            r'"__type"\s*:',
            r'"possibleTypes"\s*:',
            r'"inputFields"\s*:',
            r'"enumValues"\s*:',
            r'"interfaces"\s*:',
            r'"fields"\s*:\s*\[',
            r'"kind"\s*:\s*"OBJECT"',
            r'"kind"\s*:\s*"SCALAR"',
        ]
        
        self.graphql_endpoint_patterns = [
            r'/graphql',
            r'/gql',
            r'/query',
            r'/v\d+/graphql',
            r'/api/graphql',
        ]
    
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect GraphQL introspection and schema leakage"""
        findings = []
        
        url_lower = url.lower()
        is_graphql_endpoint = any(
            re.search(pattern, url_lower) 
            for pattern in self.graphql_endpoint_patterns
        )
        
        if hasattr(response, 'text') and response.text:
            introspection_matches = []
            for pattern in self.introspection_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    introspection_matches.append(pattern)
            
            if introspection_matches and len(introspection_matches) >= 2:
                schema_snippet = self._extract_schema_snippet(response.text)
                
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="GraphQL Introspection Enabled",
                    indicator=f"GraphQL schema introspection detected ({len(introspection_matches)} indicators)",
                    impact="Attackers can discover the entire GraphQL schema, including queries, mutations, and types, enabling targeted attacks",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="GraphQL Introspection Detection",
                    response_obj=response,
                    remediation="Disable introspection in production: set 'introspection: false' in GraphQL configuration",
                    cve_reference="CWE-200",
                    extracted_data={
                        "introspection_indicators": len(introspection_matches),
                        "schema_preview": schema_snippet[:200] if schema_snippet else None,
                        "is_graphql_endpoint": is_graphql_endpoint
                    }
                ))
            elif is_graphql_endpoint and not introspection_matches:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="GraphQL Endpoint Detected",
                    indicator=f"GraphQL endpoint identified at {url}",
                    impact="GraphQL endpoints may expose excessive data or allow complex queries if not properly secured",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    detection_method="GraphQL Endpoint Detection",
                    response_obj=response,
                    remediation="Implement query depth limiting, rate limiting, and authentication for GraphQL endpoints"
                ))
        
        return findings
    
    def _extract_schema_snippet(self, text: str) -> Optional[str]:
        """Extract a snippet of GraphQL schema from response"""
        schema_patterns = [
            r'"__schema"\s*:\s*\{[^}]{0,500}\}',
            r'"fields"\s*:\s*\[\s*\{[^\]]{0,500}\}\]',
            r'"types"\s*:\s*\[\s*\{[^\]]{0,500}\}\]',
        ]
        
        for pattern in schema_patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)
        
        return None


# -----------------------------------------------------------------------------
# JWT Security Analyzer
# -----------------------------------------------------------------------------

class JWTSecurityAnalyzer:
    """Analyzes JWT tokens for security weaknesses"""
    
    def __init__(self):
        self.jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Extract and analyze JWT tokens from responses"""
        findings = []
        
        if not hasattr(response, 'text') or not response.text:
            return findings
        
        tokens = self.jwt_pattern.findall(response.text)
        
        if hasattr(response, 'request') and hasattr(response.request, 'headers'):
            auth_header = response.request.headers.get('Authorization', '')
            if 'Bearer ' in auth_header:
                token = auth_header.replace('Bearer ', '')
                if self.jwt_pattern.match(token):
                    tokens.append(token)
        
        cookies = CookieParser.parse_all_cookies(response)
        for cookie in cookies:
            if 'jwt' in cookie['name'].lower() or 'token' in cookie['name'].lower():
                if self.jwt_pattern.match(cookie['value']):
                    tokens.append(cookie['value'])
        
        unique_tokens = list(set(tokens))
        
        for token in unique_tokens[:10]:
            token_findings = self._analyze_jwt_token(token, url, response)
            findings.extend(token_findings)
        
        return findings
    
    def _analyze_jwt_token(self, token: str, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Analyze a single JWT token for security issues"""
        findings = []
        
        try:
            if JWT_AVAILABLE:
                header = jwt.get_unverified_header(token)
                payload = jwt.decode(token, options={"verify_signature": False})
            else:
                parts = token.split('.')
                if len(parts) == 3:
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
                else:
                    return findings
            
            if header.get('alg') == 'none':
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="JWT Algorithm Confusion: 'none' Algorithm",
                    indicator="JWT token uses 'none' signature algorithm",
                    impact="Attackers can forge tokens by removing signature, leading to authentication bypass",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    detection_method="JWT Token Analysis",
                    response_obj=response,
                    remediation="Never use 'none' algorithm. Always use strong algorithms like RS256 or HS256 with strong secrets",
                    cve_reference="CWE-345",
                    extracted_data={"algorithm": "none", "token_preview": token[:50]}
                ))
            
            exp = payload.get('exp')
            if exp:
                exp_time = datetime.fromtimestamp(exp, tz=timezone.utc)
                now = datetime.now(timezone.utc)
                if exp_time < now:
                    findings.append(SecurityFinding(
                        url=url,
                        issue_type="Expired JWT Token in Response",
                        indicator="Response contains an expired JWT token",
                        impact="Expired tokens indicate potential session management issues",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        detection_method="JWT Token Analysis",
                        response_obj=response,
                        remediation="Ensure tokens are properly expired and not reused"
                    ))
                elif (exp_time - now).total_seconds() > 86400 * 30:
                    findings.append(SecurityFinding(
                        url=url,
                        issue_type="Long-lived JWT Token",
                        indicator=f"Token expires in {(exp_time - now).days} days (>30 days)",
                        impact="Long-lived tokens increase risk if compromised",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        detection_method="JWT Token Analysis",
                        response_obj=response,
                        remediation="Use short-lived tokens (hours or days) with refresh mechanisms"
                    ))
            else:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="JWT Token Missing Expiration",
                    indicator="No 'exp' claim in JWT token",
                    impact="Tokens without expiration never expire, increasing risk of token theft",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="JWT Token Analysis",
                    response_obj=response,
                    remediation="Always include 'exp' claim with reasonable expiration time"
                ))
            
            sensitive_fields = ['password', 'secret', 'token', 'key', 'credit_card', 'ssn']
            found_sensitive = []
            for field in sensitive_fields:
                if field in payload:
                    found_sensitive.append(field)
            
            if found_sensitive:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Sensitive Data in JWT Payload",
                    indicator=f"Sensitive fields found in JWT: {', '.join(found_sensitive[:3])}",
                    impact="Sensitive data in JWT can be decoded by anyone with the token",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="JWT Token Analysis",
                    response_obj=response,
                    remediation="Store only non-sensitive identifiers in JWT; keep sensitive data server-side",
                    extracted_data={"sensitive_fields": found_sensitive}
                ))
            
        except Exception:
            pass
        
        return findings


# -----------------------------------------------------------------------------
# HTTP Request Smuggling Detector
# -----------------------------------------------------------------------------

class HTTPSmugglingDetector:
    """Detects HTTP request smuggling vulnerabilities"""
    
    def __init__(self):
        self.smuggling_patterns = {
            'te_cl': [
                r'Transfer-Encoding:\s*chunked',
                r'Content-Length:\s*\d+',
            ],
            'cl_te': [
                r'Content-Length:\s*\d+',
                r'Transfer-Encoding:\s*chunked',
            ],
        }
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect request smuggling indicators in responses"""
        findings = []
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        has_te = 'transfer-encoding' in headers
        has_cl = 'content-length' in headers
        
        if has_te and has_cl:
            te_value = headers.get('transfer-encoding', '').lower()
            cl_value = headers.get('content-length', '')
            
            findings.append(SecurityFinding(
                url=url,
                issue_type="HTTP Request Smuggling Vulnerability",
                indicator="Response contains both Transfer-Encoding and Content-Length headers",
                impact="This combination can lead to request smuggling attacks where attackers can bypass security controls and poison caches",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                detection_method="HTTP Header Analysis",
                response_obj=response,
                remediation="Never include both headers. Use only one. Configure your front-end and back-end servers consistently",
                cve_reference="CWE-444",
                extracted_data={
                    "transfer_encoding": te_value,
                    "content_length": cl_value
                }
            ))
        
        if has_te and 'chunked' in headers.get('transfer-encoding', '').lower():
            if hasattr(response, 'text') and response.text:
                if re.search(r'[0-9a-f]+\r\n', response.text):
                    findings.append(SecurityFinding(
                        url=url,
                        issue_type="Potential Chunked Encoding Artifact",
                        indicator="Chunked encoding artifacts found in response body",
                        impact="May indicate request smuggling or response splitting vulnerabilities",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        detection_method="Response Body Analysis",
                        response_obj=response,
                        remediation="Implement proper input validation and output encoding"
                    ))
        
        return findings


# -----------------------------------------------------------------------------
# Cache Poisoning Detector
# -----------------------------------------------------------------------------

class CachePoisoningDetector:
    """Detects cache poisoning vulnerabilities"""
    
    def __init__(self):
        self.cache_headers = [
            'x-cache', 'x-cache-status', 'x-varnish', 'via',
            'cf-cache-status', 'x-proxy-cache', 'x-accelerator-cache'
        ]
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect cache poisoning vulnerabilities"""
        findings = []
        
        cache_headers_found = {}
        for header in self.cache_headers:
            if header in response.headers:
                cache_headers_found[header] = response.headers[header]
        
        if cache_headers_found:
            findings.append(SecurityFinding(
                url=url,
                issue_type="Cache Headers Detected",
                indicator=f"Cache system identified: {', '.join(cache_headers_found.keys())}",
                impact="Cache misconfigurations can lead to cache poisoning or cache deception attacks",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                detection_method="Cache Header Analysis",
                response_obj=response,
                remediation="Configure cache keys to include all relevant headers, validate user input before caching",
                extracted_data={"cache_headers": cache_headers_found}
            ))
        
        if hasattr(response, 'request') and hasattr(response.request, 'headers'):
            req_headers = response.request.headers
            
            for header in ['X-Forwarded-Host', 'X-Forwarded-Path', 'X-Original-URL', 'X-Rewrite-URL']:
                if header in req_headers:
                    findings.append(SecurityFinding(
                        url=url,
                        issue_type="Cache Poisoning Risk",
                        indicator=f"{header} header present in request: {req_headers[header]}",
                        impact="Cache poisoning can occur if this header influences cache key generation",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        detection_method="Request Header Analysis",
                        response_obj=response,
                        remediation="Do not include user-controlled headers in cache keys. Validate and sanitize forwarded headers",
                        extracted_data={"header": header, "value": req_headers[header][:50]}
                    ))
        
        if '?' in url:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            if len(params) > 3:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Potential Cache Key Entropy",
                    indicator=f"URL contains {len(params)} query parameters that may not be properly keyed",
                    impact="Cache poisoning may be possible if cache doesn't key on all relevant parameters",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    detection_method="URL Parameter Analysis",
                    response_obj=response,
                    remediation="Ensure cache keys include all parameters that affect response content",
                    extracted_data={"parameter_count": len(params)}
                ))
        
        return findings


# -----------------------------------------------------------------------------
# SSRF Reflection Detector
# -----------------------------------------------------------------------------

class SSRFReflectionDetector:
    """Detects SSRF vulnerabilities through internal address reflections"""
    
    def __init__(self):
        self.internal_ip_patterns = [
            r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})',
            r'(?:192\.168\.\d{1,3}\.\d{1,3})',
            r'(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})',
            r'(?:169\.254\.\d{1,3}\.\d{1,3})',
        ]
        
        self.internal_hostname_patterns = [
            r'localhost',
            r'localhost\.localdomain',
            r'local',
            r'\.local$',
            r'\.internal$',
            r'\.intranet$',
            r'\.corp$',
            r'metadata\.google\.internal',
            r'169\.254\.169\.254',
            r'fd00:ec2::254',
        ]
        
        self.sensitive_paths = [
            r'/latest/meta-data/',
            r'/latest/user-data/',
            r'/ec2-metadata',
            r'/metadata',
        ]
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect SSRF through internal address reflections"""
        findings = []
        
        if not hasattr(response, 'text') or not response.text:
            return findings
        
        response_text = response.text
        
        internal_ips = set()
        for pattern in self.internal_ip_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            internal_ips.update(matches)
        
        if internal_ips:
            findings.append(SecurityFinding(
                url=url,
                issue_type="Internal IP Address Disclosure (SSRF Risk)",
                indicator=f"Internal IP addresses found in response: {', '.join(list(internal_ips)[:3])}",
                impact="Internal IP disclosure helps attackers target internal services and may indicate SSRF vulnerability",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                detection_method="SSRF Reflection Detection",
                response_obj=response,
                remediation="Filter internal IP addresses from responses. Validate and restrict outbound requests",
                cve_reference="CWE-918",
                extracted_data={"internal_ips": list(internal_ips)[:5]}
            ))
        
        internal_hostnames = set()
        for pattern in self.internal_hostname_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            internal_hostnames.update(matches)
        
        if internal_hostnames:
            findings.append(SecurityFinding(
                url=url,
                issue_type="Internal Hostname Disclosure (SSRF Risk)",
                indicator=f"Internal hostnames found: {', '.join(list(internal_hostnames)[:3])}",
                impact="Internal hostname disclosure reveals internal network structure and may enable SSRF attacks",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                detection_method="SSRF Reflection Detection",
                response_obj=response,
                remediation="Remove internal hostname references from public responses",
                extracted_data={"internal_hostnames": list(internal_hostnames)[:5]}
            ))
        
        for path in self.sensitive_paths:
            if re.search(path, response_text, re.IGNORECASE):
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Cloud Metadata Reference (Critical SSRF Risk)",
                    indicator=f"Cloud metadata endpoint reference found: {path}",
                    impact="Exposed metadata endpoints can lead to complete cloud environment compromise",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    detection_method="SSRF Reflection Detection",
                    response_obj=response,
                    remediation="Block access to metadata endpoints from application code, use IMDSv2 with session tokens",
                    cve_reference="CWE-918"
                ))
                break
        
        return findings


# -----------------------------------------------------------------------------
# Open Redirect Detector
# -----------------------------------------------------------------------------

class OpenRedirectDetector:
    """Detects open redirect vulnerabilities"""
    
    def __init__(self):
        self.redirect_status_codes = {301, 302, 303, 307, 308}
        
        self.suspicious_redirect_patterns = [
            r'url=',
            r'redirect=',
            r'return=',
            r'next=',
            r'forward=',
            r'goto=',
            r'callback=',
            r'continue=',
            r'redir=',
            r'dest=',
            r'destination=',
        ]
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect open redirect vulnerabilities"""
        findings = []
        
        if response.status_code in self.redirect_status_codes:
            location = response.headers.get('Location', '')
            
            if location:
                if hasattr(response, 'request') and hasattr(response.request, 'url'):
                    req_url = response.request.url
                    
                    for pattern in self.suspicious_redirect_patterns:
                        if pattern in req_url.lower():
                            param_value = self._extract_redirect_param(req_url, pattern)
                            if param_value and param_value in location:
                                findings.append(SecurityFinding(
                                    url=url,
                                    issue_type="Potential Open Redirect Vulnerability",
                                    indicator=f"Redirect URL appears to be influenced by parameter '{pattern.strip('?=')}'",
                                    impact="Attackers can craft URLs that redirect users to malicious sites for phishing or credential theft",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.MEDIUM,
                                    detection_method="Redirect Parameter Analysis",
                                    response_obj=response,
                                    remediation="Validate redirect URLs against an allowlist, or use indirect references",
                                    cve_reference="CWE-601",
                                    extracted_data={
                                        "redirect_url": location[:100],
                                        "suspicious_param": pattern
                                    }
                                ))
                                break
                
                if location.startswith('http'):
                    parsed_location = urlparse(location)
                    parsed_target = urlparse(url)
                    
                    if parsed_location.netloc and parsed_location.netloc != parsed_target.netloc:
                        findings.append(SecurityFinding(
                            url=url,
                            issue_type="External Open Redirect",
                            indicator=f"Redirecting to external domain: {parsed_location.netloc}",
                            impact="Redirects to external domains can be exploited for phishing attacks",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.LOW,
                            detection_method="Redirect Domain Analysis",
                            response_obj=response,
                            remediation="Only allow redirects to trusted domains, or use whitelist-based validation"
                        ))
        
        return findings
    
    def _extract_redirect_param(self, url: str, param_pattern: str) -> Optional[str]:
        """Extract value from redirect parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        param_name = param_pattern.strip('?=')
        if param_name in params:
            return params[param_name][0]
        
        return None


# -----------------------------------------------------------------------------
# OAuth Misconfiguration Detector
# -----------------------------------------------------------------------------

class OAuthMisconfigurationDetector:
    """Detects OAuth/OIDC misconfigurations"""
    
    def __init__(self):
        self.oauth_patterns = {
            'auth_endpoint': [
                r'/oauth/authorize',
                r'/oauth2/authorize',
                r'/auth/authorize',
                r'/authorize',
            ],
            'token_endpoint': [
                r'/oauth/token',
                r'/oauth2/token',
                r'/token',
                r'/api/token',
            ],
            'revoke_endpoint': [
                r'/oauth/revoke',
                r'/oauth2/revoke',
                r'/revoke',
            ],
            'userinfo_endpoint': [
                r'/oauth/userinfo',
                r'/oauth2/userinfo',
                r'/userinfo',
                r'/me',
            ],
        }
        
        self.response_type_warnings = [
            ('response_type=token', 'Implicit grant flow is less secure than authorization code flow'),
            ('response_type=token&client_id=', 'Token returned in URL fragment can be intercepted'),
        ]
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect OAuth misconfigurations"""
        findings = []
        
        if '?' in url:
            url_lower = url.lower()
            
            for warning in self.response_type_warnings:
                if warning[0] in url_lower:
                    findings.append(SecurityFinding(
                        url=url,
                        issue_type="OAuth Security: Weak Response Type",
                        indicator=f"Using '{warning[0]}' in OAuth flow",
                        impact=warning[1],
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        detection_method="OAuth Parameter Analysis",
                        response_obj=response,
                        remediation="Use 'response_type=code' (authorization code flow) with PKCE instead of implicit flow",
                        cve_reference="CWE-287"
                    ))
                    break
        
        if hasattr(response, 'text') and response.text:
            found_endpoints = []
            for endpoint_type, patterns in self.oauth_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        found_endpoints.append(f"{endpoint_type}: {pattern}")
            
            if found_endpoints:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="OAuth Endpoint Exposure",
                    indicator=f"OAuth endpoints detected: {len(found_endpoints)}",
                    impact="Exposed OAuth endpoints may be vulnerable to misconfigurations or lack proper validation",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    detection_method="OAuth Endpoint Detection",
                    response_obj=response,
                    remediation="Ensure OAuth endpoints validate redirect URIs, use PKCE for public clients",
                    extracted_data={"endpoints": found_endpoints[:5]}
                ))
        
        if hasattr(response, 'request') and hasattr(response.request, 'url'):
            req_url = response.request.url.lower()
            if '/authorize' in req_url and 'state=' not in req_url:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="OAuth Missing State Parameter",
                    indicator="OAuth authorization request missing 'state' parameter",
                    impact="Missing state parameter makes the flow vulnerable to CSRF attacks",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="OAuth Parameter Analysis",
                    response_obj=response,
                    remediation="Always include a cryptographically random 'state' parameter in authorization requests",
                    cve_reference="CWE-352"
                ))
        
        return findings


# -----------------------------------------------------------------------------
# API Version Disclosure Detector
# -----------------------------------------------------------------------------

class APIVersionDisclosureDetector:
    """Detects API version disclosure and deprecated endpoints"""
    
    def __init__(self):
        self.version_patterns = [
            r'/v(\d+(?:\.\d+)?)/',
            r'/api/v(\d+(?:\.\d+)?)/',
            r'/apiv(\d+)/',
            r'X-API-Version:\s*(\d+(?:\.\d+)?)',
            r'API-Version:\s*(\d+(?:\.\d+)?)',
            r'version=(\d+(?:\.\d+)?)',
        ]
        
        self.deprecated_indicators = [
            'deprecated',
            'will be removed',
            'legacy',
            'no longer supported',
            'sunset',
            'end of life',
            'eol',
        ]
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect API version information in responses"""
        findings = []
        
        versions_found = set()
        for pattern in self.version_patterns:
            matches = re.findall(pattern, url, re.IGNORECASE)
            versions_found.update(matches)
        
        headers_to_check = ['x-api-version', 'api-version', 'x-version']
        for header in headers_to_check:
            if header in response.headers:
                versions_found.add(response.headers[header])
        
        if hasattr(response, 'text') and response.text:
            for pattern in self.version_patterns:
                matches = re.findall(pattern, response.text, re.IGNORECASE)
                versions_found.update(matches)
        
        if versions_found:
            findings.append(SecurityFinding(
                url=url,
                issue_type="API Version Information Disclosure",
                indicator=f"API version(s) disclosed: {', '.join(list(versions_found)[:3])}",
                impact="Version disclosure helps attackers target known vulnerabilities in specific versions",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                detection_method="API Version Detection",
                response_obj=response,
                remediation="Consider removing version information from public responses or limiting disclosure",
                extracted_data={"versions": list(versions_found)[:5]}
            ))
        
        if hasattr(response, 'text') and response.text:
            deprecation_matches = []
            for indicator in self.deprecated_indicators:
                if indicator in response.text.lower():
                    deprecation_matches.append(indicator)
            
            if 'Warning' in response.headers:
                if any(indicator in response.headers['Warning'].lower() 
                       for indicator in self.deprecated_indicators):
                    deprecation_matches.append("Warning header")
            
            if deprecation_matches:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Deprecated API Endpoint",
                    indicator=f"API endpoint marked as deprecated: {', '.join(deprecation_matches[:3])}",
                    impact="Deprecated endpoints may have known vulnerabilities and may be removed without notice",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    detection_method="Deprecation Detection",
                    response_obj=response,
                    remediation="Update to current API version and remove deprecated endpoints",
                    extracted_data={"indicators": deprecation_matches}
                ))
        
        api_doc_patterns = [
            r'swagger\.json',
            r'openapi\.json',
            r'api-docs',
            r'/swagger-ui',
            r'/redoc',
            r'/graphql\?',
        ]
        
        for pattern in api_doc_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="API Documentation Exposure",
                    indicator=f"API documentation exposed at {url}",
                    impact="API documentation reveals endpoints, parameters, and authentication requirements to attackers",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    detection_method="API Documentation Detection",
                    response_obj=response,
                    remediation="Restrict access to API documentation or move behind authentication"
                ))
                break
        
        return findings


# -----------------------------------------------------------------------------
# HTTP/2 Security Analyzer
# -----------------------------------------------------------------------------

class HTTP2SecurityAnalyzer:
    """Analyzes HTTP/2 specific security issues"""
    
    def __init__(self):
        self.http2_indicator_headers = [
            'cf-ray',
            'x-firefox-spdy',
            'x-http2',
            'x-powered-by-http2',
        ]
        
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Analyze HTTP/2 security issues"""
        findings = []
        
        is_http2 = False
        
        for header in self.http2_indicator_headers:
            if header in response.headers:
                is_http2 = True
                break
        
        if hasattr(response, 'raw') and hasattr(response.raw, 'version'):
            if response.raw.version == 20:
                is_http2 = True
        
        if is_http2:
            findings.append(SecurityFinding(
                url=url,
                issue_type="HTTP/2 Detected",
                indicator="Application uses HTTP/2 protocol",
                impact="HTTP/2 introduces new attack surfaces including stream multiplexing and HPACK compression",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                detection_method="HTTP/2 Detection",
                response_obj=response,
                remediation="Keep HTTP/2 implementation updated, monitor for known HTTP/2 vulnerabilities",
                extracted_data={"protocol": "HTTP/2"}
            ))
            
            missing_headers = []
            security_headers = ['strict-transport-security', 'x-frame-options', 'x-content-type-options']
            headers_lower = {k.lower(): v for k, v in response.headers.items()}
            
            for header in security_headers:
                if header not in headers_lower:
                    missing_headers.append(header)
            
            if missing_headers:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Missing Security Headers (HTTP/2)",
                    indicator=f"HTTP/2 endpoint missing security headers: {', '.join(missing_headers)}",
                    impact="HTTP/2 doesn't eliminate need for traditional security headers",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    detection_method="HTTP/2 Security Header Analysis",
                    response_obj=response,
                    remediation=f"Implement missing headers: {', '.join(missing_headers)}"
                ))
        
        return findings


# -----------------------------------------------------------------------------
# Error Information Leakage Detector
# -----------------------------------------------------------------------------

class ErrorInformationLeakageDetector:
    """Detects error information leakage including stack traces, database errors, etc."""
    
    def __init__(self, config: ObserverConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.stack_trace_patterns = {
            'python': [
                r'Traceback\s*\(most recent call last\)',
                r'File\s+"[^"]+",\s+line\s+\d+',
                r'[\w\.]+Error:\s+.+',
                r'at\s+[\w\.]+\([^:]+:\d+\)',
                r'raise\s+\w+Error\(',
            ],
            'java': [
                r'java\.\w+\.\w+Exception',
                r'at\s+[\w\.]+\([\w\.]+\.java:\d+\)',
                r'Caused by:\s+[\w\.]+Exception',
                r'org\.\w+\.\w+Exception',
                r'javax\.\w+\.\w+Exception',
            ],
            'php': [
                r'Stack trace:',
                r'#\d+\s+[\w\\]+->[\w]+\([^)]*\)',
                r'Fatal error:\s+Uncaught \w+Error',
                r'PHP\s+(?:Warning|Error|Notice):\s+.+in\s+.+\.php\s+on\s+line\s+\d+',
            ],
            'net': [
                r'\[[\w\.]+Exception\]:\s+.+',
                r'at\s+[\w\.]+\.\w+\(\)',
                r'System\.\w+Exception',
                r'Microsoft\.\w+\.\w+Exception',
            ],
            'ruby': [
                r'from\s+[^:]+:\d+:in\s+`[\w]+',
                r'[\w]+Error\s*\(.+\):',
                r'\w+\.rb:\d+:in\s+`[\w]+',
            ],
            'nodejs': [
                r'at\s+[\w\.]+\s+\([^:]+:\d+:\d+\)',
                r'Error:\s+.+\n\s+at\s+\w+',
                r'\[object\s+Error\]',
                r'ReferenceError:\s+',
                r'TypeError:\s+',
            ],
            'go': [
                r'goroutine\s+\d+ \[.+\]:',
                r'panic:\s+.+',
                r'\[signal\s+SIGSEGV\]',
            ],
        }
        
        self.database_error_patterns = {
            'mysql': [
                r'SQL syntax.*MySQL',
                r'MySQLSyntaxErrorException',
                r'You have an error in your SQL syntax',
                r'Duplicate entry .* for key',
                r'MySQL server version',
                r'PDOException.*mysql',
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'pg_query\(\)',
                r'PG::\w+Error',
                r'ERROR:\s+\w+ at character \d+',
                r'relation\s+"\w+"\s+does not exist',
            ],
            'mssql': [
                r'Microsoft OLE DB Provider for ODBC Drivers',
                r'\[SQL Server\]',
                r'System\.Data\.SqlClient\.SqlException',
                r'Unclosed quotation mark',
            ],
            'oracle': [
                r'ORA-\d{5}',
                r'Oracle\.DataAccess\.Client\.OracleException',
            ],
            'sqlite': [
                r'SQLite3::\w+',
                r'sqlite3.OperationalError',
            ],
        }
        
        self.framework_path_patterns = {
            'paths': [
                r'[/\\](?:var|home|opt|usr|app|application|src|source|code)[/\\][\w\-_]+[/\\]',
                r'[A-Za-z]:[/\\](?:inetpub|wwwroot|xampp|wamp|laragon|htdocs)[/\\]',
                r'[/\\]home[/\\][\w\-_]+[/\\]public_html',
                r'[/\\]var[/\\]www[/\\]html[/\\]',
                r'[/\\]app[/\\]code[/\\]',
                r'[/\\]vendor[/\\][\w\-_]+[/\\][\w\-_]+[/\\]',
                r'[/\\]node_modules[/\\][\w\-_]+[/\\]',
            ],
            'frameworks': {
                'Django': [r'django\.', r'DJANGO_SETTINGS_MODULE', r'wsgi\.py', r'manage\.py'],
                'Flask': [r'flask/', r'werkzeug', r'app\.py'],
                'Laravel': [r'laravel', r'Laravel\s+v\d+', r'Illuminate\\', r'vendor/laravel'],
                'Symfony': [r'Symfony\\', r'AppKernel\.php', r'symfony/'],
                'Rails': [r'ruby-on-rails', r'Rails\.application', r'config/application\.rb'],
                'Spring': [r'org\.springframework', r'SpringApplication', r'application\.properties'],
                'ASP.NET': [r'ASP\.NET', r'__VIEWSTATE', r'__EVENTVALIDATION', r'Web\.config'],
                'Express': [r'express', r'node_modules/express', r'app\.use\('],
            },
        }
        
        self.debug_message_patterns = {
            'debug_mode': [
                r'debug\s*=\s*true',
                r'DEBUG\s*=\s*True',
                r'debug_mode\s*:\s*true',
                r'IS_DEBUG\s*=\s*true',
                r'APP_DEBUG\s*=\s*true',
            ],
            'verbose_errors': [
                r'display_errors\s*=\s*On',
                r'error_reporting\s*=\s*E_ALL',
                r'Detailed\s+Error\s+Information',
                r'Whoops\s+\\[\w+\\]',
            ],
            'debug_output': [
                r'\[DEBUG\]\s+[\w\s]+',
                r'<!\-\-\s*DEBUG\s*:\s*.+\s*\-\->',
                r'console\.log\(["\'][^"\']+["\']\)',
                r'System\.out\.println\("DEBUG',
            ],
        }
    
    def analyze(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Comprehensive error information leakage analysis"""
        findings = []
        
        if not hasattr(response, 'text') or not response.text:
            return findings
        
        status_code = response.status_code
        response_text = response.text
        content_type = response.headers.get('Content-Type', '').lower()
        
        if not any(ct in content_type for ct in ['html', 'xml', 'json', 'plain', 'text']):
            if status_code not in self.config.detect_error_status_codes:
                return findings
        
        if status_code in self.config.detect_error_status_codes:
            error_finding = self._analyze_error_status_code(url, response, status_code)
            if error_finding:
                findings.append(error_finding)
        
        if self.config.detect_stack_traces:
            stack_trace_findings = self._detect_stack_traces(url, response, response_text)
            findings.extend(stack_trace_findings)
        
        if self.config.detect_database_errors:
            db_error_findings = self._detect_database_errors(url, response, response_text)
            findings.extend(db_error_findings)
        
        if self.config.detect_framework_paths:
            path_findings = self._detect_framework_paths(url, response, response_text)
            findings.extend(path_findings)
        
        if self.config.detect_debug_messages:
            debug_findings = self._detect_debug_messages(url, response, response_text)
            findings.extend(debug_findings)
        
        return findings
    
    def _analyze_error_status_code(self, url: str, response: requests.Response, status_code: int) -> Optional[SecurityFinding]:
        """Analyze error status codes for information leakage"""
        response_text = response.text.lower()
        
        detailed_error_indicators = [
            'stack trace', 'exception', 'error on line', 'syntax error',
            'database error', 'sql', 'mysql', 'postgresql', 'oracle',
            'file not found', 'no such file', 'permission denied',
        ]
        
        has_detailed_error = any(indicator in response_text for indicator in detailed_error_indicators)
        
        if status_code in [500, 502, 503, 504] and has_detailed_error:
            severity = Severity.HIGH
            impact = f"HTTP {status_code} error page reveals detailed internal error information"
            remediation = "Configure custom error pages that don't reveal stack traces or internal paths"
        elif status_code in [404, 403, 401] and has_detailed_error:
            severity = Severity.MEDIUM
            impact = f"HTTP {status_code} error page reveals internal path or configuration information"
            remediation = "Customize error pages to avoid revealing internal file paths or system information"
        else:
            return None
        
        error_preview = response_text[:500] if len(response_text) > 500 else response_text
        
        return SecurityFinding(
            url=url,
            issue_type=f"Error Information Leakage: HTTP {status_code}",
            indicator=f"Detailed error information exposed in HTTP {status_code} response",
            impact=impact,
            severity=severity,
            confidence=Confidence.HIGH if has_detailed_error else Confidence.MEDIUM,
            detection_method="Error Status Code Analysis",
            response_obj=response,
            remediation=remediation,
            cve_reference="CWE-209",
            extracted_data={
                "status_code": status_code,
                "has_detailed_error": has_detailed_error,
                "error_preview": error_preview[:200]
            }
        )
    
    def _detect_stack_traces(self, url: str, response: requests.Response, text: str) -> List[SecurityFinding]:
        """Detect stack traces in response"""
        findings = []
        
        for language, patterns in self.stack_trace_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(pattern)
            
            if matches:
                stack_sample = self._extract_sample(text, patterns[0], 300)
                
                findings.append(SecurityFinding(
                    url=url,
                    issue_type=f"Stack Trace Disclosure ({language.title()})",
                    indicator=f"Stack trace from {language} application exposed in response",
                    impact="Stack traces reveal internal code paths, file names, and function calls",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="Stack Trace Detection",
                    response_obj=response,
                    remediation="Disable detailed error reporting in production",
                    cve_reference="CWE-209",
                    extracted_data={"language": language, "sample": stack_sample}
                ))
        
        return findings
    
    def _detect_database_errors(self, url: str, response: requests.Response, text: str) -> List[SecurityFinding]:
        """Detect database error messages"""
        findings = []
        
        for db_type, patterns in self.database_error_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    matches.append(pattern)
            
            if matches:
                error_sample = self._extract_sample(text, patterns[0], 300)
                
                findings.append(SecurityFinding(
                    url=url,
                    issue_type=f"Database Error Disclosure ({db_type.upper()})",
                    indicator=f"Database error message from {db_type.upper()} exposed to client",
                    impact="Database error messages disclose database type, version, and potentially schema information",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="Database Error Detection",
                    response_obj=response,
                    remediation="Implement proper database error handling",
                    cve_reference="CWE-209",
                    extracted_data={"database_type": db_type, "error_sample": error_sample}
                ))
        
        return findings
    
    def _detect_framework_paths(self, url: str, response: requests.Response, text: str) -> List[SecurityFinding]:
        """Detect framework path disclosures"""
        findings = []
        
        path_matches = []
        for pattern in self.framework_path_patterns['paths']:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                path_matches.extend(matches[:3])
        
        detected_frameworks = []
        for framework, patterns in self.framework_path_patterns['frameworks'].items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    detected_frameworks.append(framework)
                    break
        
        if path_matches or detected_frameworks:
            severity = Severity.MEDIUM if path_matches else Severity.LOW
            
            findings.append(SecurityFinding(
                url=url,
                issue_type="Framework Path Disclosure",
                indicator=f"Internal framework paths exposed: {', '.join(detected_frameworks[:3]) if detected_frameworks else 'Paths detected'}",
                impact="Path disclosures reveal server directory structure and framework versions",
                severity=severity,
                confidence=Confidence.HIGH if path_matches else Confidence.MEDIUM,
                detection_method="Path Disclosure Detection",
                response_obj=response,
                remediation="Configure web server to prevent path traversal",
                cve_reference="CWE-200",
                extracted_data={"detected_frameworks": detected_frameworks[:3], "exposed_paths": path_matches[:3]}
            ))
        
        return findings
    
    def _detect_debug_messages(self, url: str, response: requests.Response, text: str) -> List[SecurityFinding]:
        """Detect debug messages and development mode indicators"""
        findings = []
        
        detected_debug_indicators = []
        
        for category, patterns in self.debug_message_patterns.items():
            category_matches = []
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    category_matches.append(pattern)
            
            if category_matches:
                detected_debug_indicators.append({'category': category, 'matches': category_matches})
        
        if detected_debug_indicators:
            debug_preview = self._extract_sample(text, self.debug_message_patterns['debug_mode'][0], 200)
            
            findings.append(SecurityFinding(
                url=url,
                issue_type="Debug Mode Indicators Exposed",
                indicator="Debug mode enabled or development indicators present",
                impact="Debug output reveals internal logic and system state",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                detection_method="Debug Message Detection",
                response_obj=response,
                remediation="Disable debug mode in production",
                cve_reference="CWE-215",
                extracted_data={"debug_categories": [d['category'] for d in detected_debug_indicators[:5]], "debug_sample": debug_preview}
            ))
        
        return findings
    
    def _extract_sample(self, text: str, pattern: str, max_length: int = 300) -> str:
        """Extract a sample snippet matching the pattern"""
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(text), match.end() + 150)
            sample = text[start:end]
            if len(sample) > max_length:
                sample = sample[:max_length] + "..."
            return sample
        return text[:max_length] if text else ""


# -----------------------------------------------------------------------------
# Mixed Content Detector
# -----------------------------------------------------------------------------

class MixedContentDetector:
    """Detects mixed content with configurable strictness"""
    
    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode
        
        self.patterns = {
            'script': {
                'pattern': re.compile(r'<script[^>]*src=["\'](https?://[^"\']+)["\']', re.IGNORECASE),
                'type': 'JavaScript',
                'severity': Severity.HIGH,
                'remediation': 'Replace HTTP script URLs with HTTPS'
            },
            'stylesheet': {
                'pattern': re.compile(r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\'](https?://[^"\']+)["\']', re.IGNORECASE),
                'type': 'CSS',
                'severity': Severity.MEDIUM,
                'remediation': 'Update CSS links to use HTTPS'
            },
            'image': {
                'pattern': re.compile(r'<img[^>]*src=["\'](https?://[^"\']+)["\']', re.IGNORECASE),
                'type': 'Image',
                'severity': Severity.LOW,
                'remediation': 'Replace HTTP image URLs with HTTPS versions'
            },
            'iframe': {
                'pattern': re.compile(r'<iframe[^>]*src=["\'](https?://[^"\']+)["\']', re.IGNORECASE),
                'type': 'Iframe',
                'severity': Severity.HIGH,
                'remediation': 'Update iframe sources to use HTTPS'
            },
        }
    
    def detect(self, html: str, base_url: str) -> List[SecurityFinding]:
        """Detect mixed content issues in HTML"""
        if not html or not base_url.startswith('https'):
            return []
        
        findings = []
        
        for resource_type, config in self.patterns.items():
            matches = config['pattern'].findall(html)
            if not matches:
                continue
            
            http_matches = [m for m in matches if m.startswith('http://')]
            if not http_matches:
                continue
            
            unique_matches = list(dict.fromkeys(http_matches))[:10]
            
            if unique_matches:
                findings.append(SecurityFinding(
                    url=base_url,
                    issue_type=f"Mixed Content: HTTP {config['type']}",
                    indicator=f"Found {len(unique_matches)} HTTP {resource_type} resource(s)",
                    impact=f"Loading {resource_type} over HTTP on HTTPS page undermines TLS security guarantees",
                    severity=config['severity'],
                    confidence=Confidence.HIGH,
                    detection_method="HTML Content Analysis",
                    remediation=config['remediation'],
                    extracted_data={"resource_type": config['type'], "total_count": len(unique_matches), "sample_urls": unique_matches[:5]}
                ))
        
        return findings


# -----------------------------------------------------------------------------
# CSP Analyzer
# -----------------------------------------------------------------------------

class CSPAnalyzer:
    """Analyzes Content Security Policy headers"""
    
    def analyze(self, csp_header: str, url: str) -> List[SecurityFinding]:
        """Analyze CSP header for weaknesses"""
        if not csp_header:
            return []
        
        findings = []
        csp_lower = csp_header.lower()
        weaknesses = []
        
        if "'unsafe-inline'" in csp_lower:
            weaknesses.append("'unsafe-inline' allows inline scripts/styles")
        if "'unsafe-eval'" in csp_lower:
            weaknesses.append("'unsafe-eval' allows dynamic code execution")
        if 'default-src' not in csp_lower:
            weaknesses.append("Missing default-src directive")
        
        has_reporting = 'report-uri' in csp_lower or 'report-to' in csp_lower
        
        if not has_reporting and ("'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower):
            weaknesses.append("Missing reporting mechanism for violation detection")
        
        if weaknesses:
            findings.append(SecurityFinding(
                url=url,
                issue_type="Weak Content Security Policy",
                indicator=f"CSP has {len(weaknesses)} weakness(es)",
                impact="Weak CSP configurations can be bypassed and provide limited XSS protection",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                detection_method="CSP Analysis",
                remediation="Remove unsafe directives, use nonces or hashes for inline scripts, add reporting",
                extracted_data={"weaknesses": weaknesses[:3], "has_reporting": has_reporting}
            ))
        
        return findings


# -----------------------------------------------------------------------------
# JavaScript Security Analyzer
# -----------------------------------------------------------------------------

class JavaScriptAnalyzer:
    """Analyze JavaScript for security issues"""
    
    def __init__(self, config: ObserverConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        self.dangerous_patterns = [
            (r'eval\s*\(', 'eval() usage', Severity.HIGH, 'Avoid eval() as it allows arbitrary code execution'),
            (r'document\.write\s*\(', 'document.write() usage', Severity.MEDIUM, 'Can lead to DOM-based XSS if user input is used'),
            (r'innerHTML\s*=', 'innerHTML assignment', Severity.MEDIUM, 'Can lead to XSS if untrusted data is used'),
            (r'outerHTML\s*=', 'outerHTML assignment', Severity.MEDIUM, 'Can lead to XSS if untrusted data is used'),
            (r'setTimeout\s*\(\s*["\'][^"\']*["\']', 'setTimeout with string', Severity.MEDIUM, 'String argument to setTimeout acts like eval()'),
            (r'setInterval\s*\(\s*["\'][^"\']*["\']', 'setInterval with string', Severity.MEDIUM, 'String argument to setInterval acts like eval()'),
            (r'Function\s*\(', 'Function() constructor', Severity.HIGH, 'Function constructor can execute arbitrary code'),
            (r'\.src\s*=\s*["\'][^"\']*["\']', 'Dynamic script source', Severity.LOW, 'Dynamic script loading can lead to XSS'),
        ]
        
        self.sensitive_patterns = [
            (r'api[_-]?key\s*[:=]\s*["\'][^"\']{10,}["\']', 'API Key exposure', Severity.HIGH),
            (r'secret\s*[:=]\s*["\'][^"\']{10,}["\']', 'Secret exposure', Severity.HIGH),
            (r'token\s*[:=]\s*["\'][^"\']{10,}["\']', 'Token exposure', Severity.HIGH),
            (r'password\s*[:=]\s*["\'][^"\']{3,}["\']', 'Password exposure', Severity.CRITICAL),
            (r'auth[_-]?token\s*[:=]\s*["\'][^"\']{10,}["\']', 'Auth token exposure', Severity.HIGH),
        ]
        
        self.dom_xss_patterns = [
            (r'location\.hash\s*[+]\s*', 'DOM XSS via location.hash', Severity.HIGH),
            (r'location\.search\s*[+]\s*', 'DOM XSS via location.search', Severity.HIGH),
            (r'document\.URL\s*[+]\s*', 'DOM XSS via document.URL', Severity.HIGH),
            (r'document\.documentURI\s*[+]\s*', 'DOM XSS via document.documentURI', Severity.HIGH),
            (r'document\.baseURI\s*[+]\s*', 'DOM XSS via document.baseURI', Severity.HIGH),
            (r'document\.referrer\s*[+]\s*', 'DOM XSS via document.referrer', Severity.MEDIUM),
        ]
        
        self.postmessage_patterns = [
            (r'postMessage\s*\(\s*[^,]+,\s*["\']\*["\']', 'Wildcard postMessage target', Severity.HIGH),
            (r'addEventListener\s*\(\s*["\']message["\']\s*,\s*\w+\s*\)\s*{[^}]*eval', 'Message event handler with eval', Severity.HIGH),
        ]
    
    def analyze(self, js_content: str, url: str) -> List[SecurityFinding]:
        """Analyze JavaScript content for security issues"""
        if not js_content or len(js_content) > self.config.max_js_size:
            return []
        
        findings = []
        
        if JS_BEAUTIFY_AVAILABLE:
            try:
                js_content = beautify(js_content)
            except Exception:
                pass
        
        for pattern, description, severity, remediation in self.dangerous_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type=f"JavaScript Security: {description}",
                    indicator=f"Found {len(matches)} instance(s) of {description}",
                    impact="Dangerous JavaScript patterns can lead to code execution vulnerabilities",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    detection_method="JavaScript Static Analysis",
                    remediation=remediation,
                    extracted_data={"pattern": pattern, "count": len(matches)}
                ))
        
        for pattern, description, severity in self.sensitive_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type=f"Sensitive Data in JavaScript: {description}",
                    indicator=f"Found potential {description.lower()} in JavaScript",
                    impact="Sensitive credentials exposed client-side",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    detection_method="JavaScript Static Analysis",
                    remediation="Move secrets to server-side and use environment variables",
                    extracted_data={"sample": str(matches[0])[:50] if matches else None}
                ))
        
        for pattern, description, severity in self.dom_xss_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Potential DOM-based XSS",
                    indicator=description,
                    impact="User-controllable data may be used unsafely in DOM operations",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    detection_method="JavaScript Static Analysis",
                    remediation="Sanitize untrusted data before DOM manipulation",
                    extracted_data={"pattern": pattern}
                ))
        
        for pattern, description, severity in self.postmessage_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            if matches:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="PostMessage Security Issue",
                    indicator=description,
                    impact="Insecure postMessage usage can lead to cross-origin attacks",
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    detection_method="JavaScript Static Analysis",
                    remediation="Specify exact target origin, validate message origin in event handlers",
                    extracted_data={"pattern": pattern}
                ))
        
        if 'sourceMappingURL' in js_content and not url.startswith('localhost'):
            findings.append(SecurityFinding(
                url=url,
                issue_type="Source Map Exposure",
                indicator="Source map reference found in production JavaScript",
                impact="Source maps can expose original source code and internal paths",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                detection_method="JavaScript Content Analysis",
                remediation="Remove source map references in production builds"
            ))
        
        return findings


# -----------------------------------------------------------------------------
# WebSocket Security Analyzer
# -----------------------------------------------------------------------------

class WebSocketAnalyzer:
    """Analyze WebSocket traffic for security issues"""
    
    def __init__(self, config: ObserverConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    def analyze_websocket_upgrade(self, request_headers: Dict, response_headers: Dict, url: str) -> List[SecurityFinding]:
        """Analyze WebSocket upgrade handshake"""
        findings = []
        
        origin = request_headers.get('Origin', '')
        if origin:
            if origin == '*' or origin == 'null':
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Weak WebSocket Origin Validation",
                    indicator=f"Origin '{origin}' is too permissive",
                    impact="Cross-origin WebSocket connections may be allowed",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    detection_method="WebSocket Handshake Analysis",
                    remediation="Implement proper origin validation on the server"
                ))
        
        if not url.startswith('wss://') and not url.startswith('localhost'):
            findings.append(SecurityFinding(
                url=url,
                issue_type="Insecure WebSocket Connection",
                indicator="Using ws:// instead of wss://",
                impact="WebSocket traffic is transmitted unencrypted",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                detection_method="WebSocket Protocol Analysis",
                remediation="Use wss:// for encrypted WebSocket connections"
            ))
        
        return findings
    
    def analyze_websocket_messages(self, messages: List[Dict], url: str) -> List[SecurityFinding]:
        """Analyze WebSocket message content"""
        findings = []
        
        sensitive_patterns = {
            'password': r'password["\s]*[:=]["\s]*[^"\s]+',
            'token': r'token["\s]*[:=]["\s]*[^"\s]+',
            'secret': r'secret["\s]*[:=]["\s]*[^"\s]+',
            'credit_card': r'\b\d{4}[-]?\d{4}[-]?\d{4}[-]?\d{4}\b',
        }
        
        for msg in messages[:50]:
            payload = msg.get('payload', '')
            if not payload:
                continue
            
            for sensitive_type, pattern in sensitive_patterns.items():
                matches = re.findall(pattern, payload, re.IGNORECASE)
                if matches:
                    findings.append(SecurityFinding(
                        url=url,
                        issue_type="Sensitive Data in WebSocket Messages",
                        indicator=f"Found potential {sensitive_type} in WebSocket traffic",
                        impact="Sensitive data may be exposed through WebSocket messages",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        detection_method="WebSocket Message Analysis",
                        remediation="Encrypt sensitive data, use authentication tokens",
                        extracted_data={"sample": str(matches[0])[:50]}
                    ))
        
        return findings


# -----------------------------------------------------------------------------
# Passive HTTP Observer (Core)
# -----------------------------------------------------------------------------

class PassiveHttpObserver:
    """Main observation engine for HTTP analysis"""
    
    def __init__(self, config: ObserverConfig = None):
        self.config = config or ObserverConfig()
        self.session = self._create_session()
        self.cookie_parser = CookieParser()
        self.mixed_content_detector = MixedContentDetector(strict_mode=not self.config.strict_mixed_content)
        self.csp_analyzer = CSPAnalyzer()
        self.credit_card_detector = CreditCardDetector(enable_luhn=self.config.enable_luhn_check, config=self.config)
        self.js_analyzer = JavaScriptAnalyzer(config)
        self.ws_analyzer = WebSocketAnalyzer(config)
        self.error_leak_detector = ErrorInformationLeakageDetector(config)
        
        # Advanced detectors
        self.graphql_detector = GraphQLIntrospectionDetector()
        self.jwt_analyzer = JWTSecurityAnalyzer()
        self.smuggling_detector = HTTPSmugglingDetector()
        self.cache_detector = CachePoisoningDetector()
        self.ssrf_detector = SSRFReflectionDetector()
        self.open_redirect_detector = OpenRedirectDetector()
        self.oauth_detector = OAuthMisconfigurationDetector()
        self.api_version_detector = APIVersionDisclosureDetector()
        self.http2_analyzer = HTTP2SecurityAnalyzer()
        
        self.sensitive_keywords = {'password', 'passwd', 'secret', 'token', 'api_key', 
                                   'apikey', 'auth', 'bearer', 'jwt', 'ssn', 'credit_card'}
        
        self.payment_paths = {'/checkout', '/payment', '/billing', '/cart', 
                             '/api/pay', '/charge', '/subscribe', '/invoice'}
        
        self.cdn_signatures = {
            'Cloudflare': ['cf-ray', 'cf-cache-status'],
            'Akamai': ['akamai-origin-hop', 'x-akamai-request-id'],
            'Fastly': ['fastly-debug-digest', 'x-served-by'],
            'AWS CloudFront': ['x-amz-cf-id', 'x-amz-cf-pop'],
        }
        
        self.request_count = 0
        self.last_request_time = 0
        self.rate_limit_semaphore = Semaphore(1)
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            level=logging.DEBUG if self.config.verbose else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _create_session(self) -> requests.Session:
        """Create and configure requests session"""
        session = requests.Session()
        session.headers.update({'User-Agent': self.config.user_agent})
        session.verify = certifi.where()
        session.max_redirects = self.config.max_redirects
        return session
    
    def _rate_limit_passive(self):
        """Enforce rate limiting for passive scanning"""
        if self.config.passive_scanning and self.config.passive_rate_limit > 0:
            with self.rate_limit_semaphore:
                elapsed = time.time() - self.last_request_time
                if elapsed < self.config.passive_rate_limit:
                    time.sleep(self.config.passive_rate_limit - elapsed)
                self.last_request_time = time.time()
    
    def _make_passive_request(self, url: str) -> requests.Response:
        """Make rate-limited HTTP request for passive scanning"""
        self._rate_limit_passive()
        self.request_count += 1
        
        if self.request_count % self.config.gc_interval == 0:
            gc.collect()
        
        return self.session.get(url, timeout=self.config.timeout, allow_redirects=True)
    
    def _is_sensitive_page(self, url: str) -> bool:
        """Check if URL appears to be a sensitive page"""
        sensitive_patterns = [
            r'/login', r'/signin', r'/auth', r'/register', r'/signup',
            r'/account', r'/profile', r'/settings', r'/changepassword',
            r'/resetpassword', r'/forgotpassword', r'/payment', r'/checkout',
            r'/admin', r'/dashboard', r'/oauth', r'/2fa', r'/mfa'
        ]
        url_lower = url.lower()
        return any(re.search(p, url_lower) for p in sensitive_patterns)
    
    def analyze_endpoint(self, url: str, pre_fetched_response: requests.Response = None) -> List[SecurityFinding]:
        """Analyze a single endpoint"""
        findings = []
        
        try:
            if pre_fetched_response:
                response = pre_fetched_response
            else:
                response = self._make_passive_request(url)
            
            # Core security checks
            findings.extend(self._check_transport_security(url, response))
            findings.extend(self._check_cookie_security(url, response))
            findings.extend(self._check_sensitive_data_in_url(url))
            findings.extend(self._check_information_disclosure(url, response))
            findings.extend(self._check_payment_security(url, response))
            findings.extend(self._check_security_headers(url, response))
            findings.extend(self._check_clickjacking_protection(url, response))
            findings.extend(self._check_cors_misconfiguration(url, response))
            findings.extend(self._check_cdn_waf(url, response))
            
            # Advanced detectors
            findings.extend(self.error_leak_detector.analyze(url, response))
            findings.extend(self.graphql_detector.analyze(url, response))
            findings.extend(self.jwt_analyzer.analyze(url, response))
            findings.extend(self.smuggling_detector.analyze(url, response))
            findings.extend(self.cache_detector.analyze(url, response))
            findings.extend(self.ssrf_detector.analyze(url, response))
            findings.extend(self.open_redirect_detector.analyze(url, response))
            findings.extend(self.oauth_detector.analyze(url, response))
            findings.extend(self.api_version_detector.analyze(url, response))
            findings.extend(self.http2_analyzer.analyze(url, response))
            
            # Content-based checks
            content_type = response.headers.get('Content-Type', '').lower()
            if 'html' in content_type or 'xml' in content_type:
                findings.extend(self._check_mixed_content(url, response))
                findings.extend(self._check_subresource_integrity(url, response))
                
                csp_header = response.headers.get('Content-Security-Policy', '')
                if csp_header:
                    findings.extend(self.csp_analyzer.analyze(csp_header, url))
            
            # JavaScript analysis
            if self.config.analyze_javascript and ('javascript' in content_type or '.js' in url):
                if hasattr(response, 'text') and response.text:
                    findings.extend(self.js_analyzer.analyze(response.text, url))
            
            # WebSocket analysis
            if 'websocket' in response.headers.get('Upgrade', '').lower():
                findings.extend(self.ws_analyzer.analyze_websocket_upgrade(
                    response.request.headers if hasattr(response, 'request') else {},
                    response.headers,
                    url
                ))
            
            # Limit findings per URL
            if len(findings) > self.config.max_findings_per_url:
                findings = findings[:self.config.max_findings_per_url]
            
        except requests.exceptions.SSLError as e:
            findings.append(SecurityFinding(
                url=url,
                issue_type="SSL/TLS Error",
                indicator=f"SSL certificate validation failed: {str(e)[:100]}",
                impact="The server has a misconfigured or invalid SSL certificate",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                detection_method="SSL Handshake",
                remediation="Install a valid SSL certificate signed by a trusted CA"
            ))
        except Exception as e:
            self.logger.error(f"Failed to analyze {url}: {e}")
            if not pre_fetched_response:
                raise
        
        return findings
    
    # -------------------------------------------------------------------------
    # Security Check Implementations
    # -------------------------------------------------------------------------
    
    def _check_transport_security(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check transport security (HTTPS enforcement)"""
        findings = []
        parsed = urlparse(url)
        
        if parsed.scheme == 'http':
            redirected_to_https = any(
                h.status_code in (301, 302, 303, 307, 308) and 
                h.headers.get('Location', '').startswith('https')
                for h in response.history
            )
            
            if not redirected_to_https:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Unencrypted Traffic",
                    indicator="No HTTPS enforcement detected",
                    impact="Resource is served over plain HTTP without redirecting to HTTPS",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="Protocol Inspection",
                    response_obj=response,
                    remediation="Enable HSTS and redirect all HTTP traffic to HTTPS"
                ))
        
        return findings
    
    def _check_cookie_security(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Comprehensive cookie security analysis"""
        findings = []
        parsed_url = urlparse(url)
        is_https = parsed_url.scheme == 'https'
        
        cookies = self.cookie_parser.parse_all_cookies(response)
        
        for cookie_info in cookies:
            issues = []
            recommendations = []
            severity = Severity.LOW
            
            if not cookie_info.get('secure', False) and is_https:
                issues.append("Missing Secure flag on HTTPS connection")
                recommendations.append("Add Secure flag")
                severity = Severity.HIGH
            
            if not cookie_info.get('httponly', False):
                issues.append("Missing HttpOnly flag")
                recommendations.append("Add HttpOnly flag")
                if any(kw in cookie_info['name'].lower() for kw in ('session', 'auth', 'token')):
                    severity = Severity.HIGH
                else:
                    severity = Severity.MEDIUM
            
            samesite = cookie_info.get('samesite')
            if not samesite:
                issues.append("Missing SameSite attribute")
                recommendations.append("Set SameSite=Lax or SameSite=Strict")
                if severity != Severity.HIGH:
                    severity = Severity.MEDIUM
            
            if issues:
                is_session_cookie = any(kw in cookie_info['name'].lower() 
                                       for kw in ('session', 'auth', 'token', 'jwt', 'sid'))
                
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Weak Cookie Configuration" if is_session_cookie else "Insecure Cookie",
                    indicator=f"Cookie '{cookie_info['name']}': {issues[0]}",
                    impact=f"Cookie security issues: {'; '.join(issues[:2])}",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    detection_method="Cookie Analysis",
                    param_location="Cookie",
                    response_obj=response,
                    remediation='; '.join(recommendations[:2]),
                    extracted_data={"cookie_name": cookie_info['name'], "issues": issues}
                ))
        
        return findings
    
    def _check_sensitive_data_in_url(self, url: str) -> List[SecurityFinding]:
        """Check for sensitive data in URL parameters"""
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for key in params:
            if any(kw in key.lower() for kw in self.sensitive_keywords):
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Sensitive Data in URL",
                    indicator=f"Query parameter '{key}' may contain sensitive data",
                    impact="Credentials/tokens in URLs may be logged in server logs and browser history",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    detection_method="Query Parameter Analysis",
                    param_location="Query String",
                    remediation="Move sensitive parameters to POST body or request headers",
                    extracted_data={"parameter": key}
                ))
        
        return findings
    
    def _check_information_disclosure(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check for information disclosure in headers"""
        findings = []
        
        sensitive_headers = {
            'Server': 'Web server version',
            'X-Powered-By': 'Backend technology and version',
            'X-AspNet-Version': 'ASP.NET version',
            'X-Debug-Token': 'Debug token (development mode)'
        }
        
        for header, description in sensitive_headers.items():
            if header in response.headers:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Information Disclosure",
                    indicator=f"{header}: {response.headers[header]}",
                    impact=f"Technology version strings help attackers target known vulnerabilities",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    detection_method="Header Analysis",
                    response_obj=response,
                    remediation="Configure web server to suppress version headers",
                    extracted_data={"header": header, "value": response.headers[header]}
                ))
        
        return findings
    
    def _check_payment_security(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check payment-related security with enhanced credit card detection"""
        findings = []
        path = urlparse(url).path.lower()
        
        is_payment_endpoint = any(payment_path in path for payment_path in self.payment_paths)
        
        if is_payment_endpoint and not url.startswith('https'):
            findings.append(SecurityFinding(
                url=url,
                issue_type="Insecure Payment Transit",
                indicator="Payment endpoint accessible over HTTP",
                impact="Payment data must be transmitted exclusively over HTTPS",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                detection_method="Protocol Inspection",
                response_obj=response,
                remediation="Enforce TLS on all payment processing endpoints",
                cve_reference="CWE-319"
            ))
        
        if hasattr(response, 'text') and response.text:
            credit_cards = self.credit_card_detector.detect(response.text, url)
            
            if credit_cards:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type="Payment Data Exposure",
                    indicator=f"Potential credit card number(s) found in response body ({len(credit_cards)} unique numbers)",
                    impact="Application may be echoing sensitive payment data in responses",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    detection_method="Content Analysis with Luhn Validation",
                    response_obj=response,
                    remediation="Mask or omit sensitive payment data from API responses",
                    extracted_data={
                        "count": len(credit_cards),
                        "sample": credit_cards[0]['number'] if credit_cards else None,
                        "type": credit_cards[0]['type'] if credit_cards else None,
                        "context": credit_cards[0]['context'][:100] if credit_cards else None
                    }
                ))
        
        return findings
    
    def _check_security_headers(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check for security headers"""
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        security_headers = {
            'strict-transport-security': {
                'name': 'HSTS',
                'required': False,
                'severity': Severity.MEDIUM,
                'remediation': 'Implement HSTS with max-age>=31536000'
            },
            'x-frame-options': {
                'name': 'X-Frame-Options',
                'required': False,
                'severity': Severity.MEDIUM,
                'remediation': 'Set X-Frame-Options: DENY or SAMEORIGIN'
            },
            'x-content-type-options': {
                'name': 'X-Content-Type-Options',
                'required': True,
                'severity': Severity.LOW,
                'remediation': 'Set X-Content-Type-Options: nosniff'
            },
            'referrer-policy': {
                'name': 'Referrer-Policy',
                'required': False,
                'severity': Severity.MEDIUM,
                'remediation': 'Set Referrer-Policy: strict-origin-when-cross-origin'
            }
        }
        
        for header, config in security_headers.items():
            if config['required'] and header not in headers_lower:
                findings.append(SecurityFinding(
                    url=url,
                    issue_type=f"Missing Security Header: {config['name']}",
                    indicator=f"Required header '{header}' is absent",
                    impact=f"The application is missing the {config['name']} header",
                    severity=config['severity'],
                    confidence=Confidence.HIGH,
                    detection_method="Security Header Analysis",
                    response_obj=response,
                    remediation=config['remediation']
                ))
            elif not config['required'] and header not in headers_lower and self._is_sensitive_page(url):
                findings.append(SecurityFinding(
                    url=url,
                    issue_type=f"Missing Security Header on Sensitive Page",
                    indicator=f"Optional header '{header}' is absent",
                    impact=f"Sensitive pages should implement {config['name']} for defense in depth",
                    severity=config['severity'],
                    confidence=Confidence.MEDIUM,
                    detection_method="Security Header Analysis",
                    response_obj=response,
                    remediation=config['remediation']
                ))
        
        return findings
    
    def _check_clickjacking_protection(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check for clickjacking protection mechanisms"""
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        xfo = headers_lower.get('x-frame-options')
        csp = headers_lower.get('content-security-policy')
        
        has_frame_ancestors = False
        if csp:
            has_frame_ancestors = re.search(r'frame-ancestors\s+[^;]+', csp, re.IGNORECASE) is not None
        
        if not xfo and not has_frame_ancestors:
            findings.append(SecurityFinding(
                url=url,
                issue_type="Missing Anti-Clickjacking Protection",
                indicator="X-Frame-Options and CSP frame-ancestors are both absent",
                impact="Application can be embedded in malicious iframes, enabling clickjacking attacks",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                detection_method="Header Analysis",
                response_obj=response,
                remediation="Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
                cve_reference="CWE-1021"
            ))
        
        return findings
    
    def _check_cors_misconfiguration(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check for CORS misconfigurations"""
        findings = []
        
        acao = response.headers.get('Access-Control-Allow-Origin', '')
        acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        
        if acao == '*' and acac == 'true':
            findings.append(SecurityFinding(
                url=url,
                issue_type="Critical CORS Misconfiguration",
                indicator="Access-Control-Allow-Origin: * with credentials: true",
                impact="Any website can make authenticated cross-origin requests",
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                detection_method="CORS Header Analysis",
                response_obj=response,
                remediation="Remove wildcard origin when credentials are enabled",
                cve_reference="CWE-942"
            ))
        
        return findings
    
    def _check_cdn_waf(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Detect CDN/WAF providers"""
        findings = []
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        detected = []
        for provider, signatures in self.cdn_signatures.items():
            if any(sig in headers_lower for sig in signatures):
                detected.append(provider)
        
        if detected:
            findings.append(SecurityFinding(
                url=url,
                issue_type="CDN / WAF Detected",
                indicator=f"Protected by: {', '.join(set(detected))}",
                impact="CDN/WAF presence affects security testing approach",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                detection_method="Header Fingerprinting",
                response_obj=response,
                extracted_data={"providers": detected}
            ))
        
        return findings
    
    def _check_mixed_content(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check for mixed content issues"""
        if not url.startswith('https'):
            return []
        
        content_type = response.headers.get('Content-Type', '').lower()
        if 'html' not in content_type and 'xml' not in content_type:
            return []
        
        return self.mixed_content_detector.detect(response.text, url)
    
    def _check_subresource_integrity(self, url: str, response: requests.Response) -> List[SecurityFinding]:
        """Check for Subresource Integrity implementation"""
        findings = []
        
        content_type = response.headers.get('Content-Type', '').lower()
        if 'html' not in content_type:
            return []
        
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
        scripts = script_pattern.findall(response.text)
        
        external_scripts = [s for s in scripts if s.startswith(('http://', 'https://')) 
                           and urlparse(s).netloc != urlparse(url).netloc]
        
        missing_integrity = []
        for script in external_scripts[:20]:
            tag_pattern = re.compile(f'<script[^>]*src=["\']{re.escape(script)}["\'][^>]*>', re.IGNORECASE)
            tag_match = tag_pattern.search(response.text)
            if tag_match and 'integrity=' not in tag_match.group(0):
                missing_integrity.append(script)
        
        if missing_integrity:
            findings.append(SecurityFinding(
                url=url,
                issue_type="Missing Subresource Integrity",
                indicator=f"{len(missing_integrity)} external script(s) lack integrity hashes",
                impact="External resources without SRI can be compromised by CDN attacks",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                detection_method="HTML Analysis",
                response_obj=response,
                remediation="Add integrity and crossorigin attributes to all external script tags",
                extracted_data={"missing_count": len(missing_integrity), "samples": missing_integrity[:3]}
            ))
        
        return findings


# -----------------------------------------------------------------------------
# File Parsing Functions
# -----------------------------------------------------------------------------

class FileParser:
    """Parse various input file formats"""
    
    @staticmethod
    def parse_har_file(filepath: str, config: ObserverConfig) -> List[Tuple[str, requests.Response]]:
        """Parse HAR (HTTP Archive) file"""
        with open(filepath, 'r', encoding='utf-8') as f:
            har_data = json.load(f)
        
        responses = []
        entries = har_data.get('log', {}).get('entries', [])
        
        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})
            url = request.get('url', '')
            
            if not url:
                continue
            
            mock_response = requests.Response()
            mock_response.url = url
            mock_response.status_code = response.get('status', 200)
            
            for header in response.get('headers', []):
                name = header.get('name', '')
                value = header.get('value', '')
                if name:
                    mock_response.headers[name] = value
            
            content = response.get('content', {})
            text = content.get('text', '')
            encoding = content.get('encoding', '')
            
            if encoding == 'base64' and text:
                try:
                    text = base64.b64decode(text).decode('utf-8', errors='ignore')
                except Exception:
                    pass
            
            if len(text) > config.max_response_size:
                text = text[:config.max_response_size]
            
            class MockRequest:
                def __init__(self, req_data):
                    self.method = req_data.get('method', 'GET')
                    self.url = req_data.get('url', '')
                    self.headers = {}
                    for header in req_data.get('headers', []):
                        name = header.get('name', '')
                        value = header.get('value', '')
                        if name:
                            self.headers[name] = value
            
            mock_response.request = MockRequest(request)
            mock_response._content = text.encode('utf-8') if text else b''
            mock_response.elapsed = timedelta(seconds=entry.get('time', 0) / 1000.0)
            mock_response.raw = None
            
            responses.append((url, mock_response))
        
        return responses
    
    @staticmethod
    def parse_burp_xml_file(filepath: str, config: ObserverConfig) -> List[Tuple[str, requests.Response]]:
        """Parse Burp Suite XML export"""
        tree = ET.parse(filepath)
        root = tree.getroot()
        
        responses = []
        
        for item in root.findall('.//item'):
            url_elem = item.find('url')
            if url_elem is None or not url_elem.text:
                continue
            
            url = url_elem.text
            
            response_elem = item.find('response')
            if response_elem is not None and response_elem.text:
                response_data = base64.b64decode(response_elem.text).decode('utf-8', errors='ignore')
            else:
                response_data = ''
            
            request_elem = item.find('request')
            request_method = 'GET'
            if request_elem is not None and request_elem.text:
                request_data = base64.b64decode(request_elem.text).decode('utf-8', errors='ignore')
                request_lines = request_data.split('\n')
                if request_lines:
                    request_line = request_lines[0]
                    method_match = re.match(r'^([A-Z]+)\s+', request_line)
                    if method_match:
                        request_method = method_match.group(1)
            
            status_code = 200
            status_match = re.search(r'HTTP/\d\.\d\s+(\d+)', response_data)
            if status_match:
                status_code = int(status_match.group(1))
            
            mock_response = requests.Response()
            mock_response.url = url
            mock_response.status_code = status_code
            
            lines = response_data.split('\n')
            in_headers = True
            for line in lines[1:]:
                if line.strip() == '':
                    in_headers = False
                    continue
                if in_headers and ':' in line:
                    key, value = line.split(':', 1)
                    mock_response.headers[key.strip()] = value.strip()
            
            body_start = response_data.find('\r\n\r\n')
            if body_start == -1:
                body_start = response_data.find('\n\n')
            if body_start != -1:
                body = response_data[body_start + 2:]
            else:
                body = ''
            
            if len(body) > config.max_response_size:
                body = body[:config.max_response_size]
            
            mock_response._content = body.encode('utf-8')
            
            class MockRequest:
                def __init__(self, req_url, req_method):
                    self.method = req_method
                    self.url = req_url
                    self.headers = {}
            
            mock_response.request = MockRequest(url, request_method)
            mock_response.elapsed = timedelta(seconds=0)
            mock_response.raw = None
            
            responses.append((url, mock_response))
        
        return responses
    
    @staticmethod
    def parse_json_urls(filepath: str) -> List[str]:
        """Parse JSON file containing URLs"""
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        targets = []
        
        if isinstance(data, dict):
            if 'endpoints' in data and isinstance(data['endpoints'], list):
                targets = [ep.get('url') for ep in data['endpoints'] if 'url' in ep]
            elif 'urls' in data and isinstance(data['urls'], list):
                targets = data['urls']
            elif 'targets' in data and isinstance(data['targets'], list):
                targets = data['targets']
            else:
                def extract_urls(obj):
                    urls = []
                    if isinstance(obj, dict):
                        for v in obj.values():
                            urls.extend(extract_urls(v))
                    elif isinstance(obj, list):
                        for item in obj:
                            urls.extend(extract_urls(item))
                    elif isinstance(obj, str) and obj.startswith(('http://', 'https://')):
                        urls.append(obj)
                    return urls
                targets = extract_urls(data)
        elif isinstance(data, list):
            targets = [item.get('url') if isinstance(item, dict) else str(item) 
                      for item in data if item]
        
        targets = [t for t in targets if t and isinstance(t, str) and t.startswith(('http://', 'https://'))]
        targets = list(dict.fromkeys(targets))
        
        return targets


# -----------------------------------------------------------------------------
# HTML Report Generator
# -----------------------------------------------------------------------------

class HTMLReportGenerator:
    """Generate professional HTML security reports"""
    
    @staticmethod
    def generate_report(findings: List[SecurityFinding], metadata: Dict, output_file: str) -> str:
        """Generate a professional HTML report"""
        
        severity_colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#28a745',
            'Info': '#17a2b8'
        }
        
        severity_icons = {
            'Critical': '🔴',
            'High': '🟠',
            'Medium': '🟡',
            'Low': '🟢',
            'Info': '🔵'
        }
        
        # Calculate statistics
        severity_counts = {}
        category_counts = {}
        for finding in findings:
            sev = finding.severity_str
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = finding._categorise()
            category_counts[cat] = category_counts.get(cat, 0) + 1
        
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4}
        sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.severity_str, 5))
        
        # Build HTML
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passive HTTP Observer - Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: #f0f2f5;
            color: #1a1a2e;
            padding: 20px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
            color: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 30px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }}
        .header h1 {{
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 15px;
        }}
        .header .badge {{
            background: rgba(255,255,255,0.15);
            padding: 4px 14px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
        }}
        .header .meta {{
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            margin-top: 20px;
            font-size: 14px;
            opacity: 0.9;
        }}
        .header .meta span {{
            background: rgba(255,255,255,0.08);
            padding: 6px 16px;
            border-radius: 6px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            text-align: center;
        }}
        .stat-card .number {{
            font-size: 32px;
            font-weight: 700;
        }}
        .stat-card .label {{
            font-size: 13px;
            color: #666;
            margin-top: 4px;
        }}
        .stat-card.critical .number {{ color: #dc3545; }}
        .stat-card.high .number {{ color: #fd7e14; }}
        .stat-card.medium .number {{ color: #ffc107; }}
        .stat-card.low .number {{ color: #28a745; }}
        .stat-card.info .number {{ color: #17a2b8; }}
        
        .section {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
        }}
        .section h2 {{
            font-size: 20px;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            border-bottom: 2px solid #f0f2f5;
            padding-bottom: 12px;
        }}
        .section h2 .count {{
            background: #e9ecef;
            padding: 2px 12px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 500;
            color: #495057;
        }}
        
        .finding {{
            border: 1px solid #e9ecef;
            border-radius: 8px;
            margin-bottom: 16px;
            overflow: hidden;
            transition: box-shadow 0.2s;
        }}
        .finding:hover {{
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }}
        .finding-header {{
            padding: 14px 20px;
            display: flex;
            align-items: center;
            gap: 12px;
            cursor: pointer;
            background: #f8f9fa;
            border-bottom: 1px solid #e9ecef;
            user-select: none;
        }}
        .finding-header .severity-badge {{
            padding: 2px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            color: white;
            white-space: nowrap;
        }}
        .finding-header .issue-type {{
            font-weight: 600;
            flex: 1;
        }}
        .finding-header .expand-icon {{
            font-size: 18px;
            color: #868e96;
            transition: transform 0.3s;
        }}
        .finding-header .expand-icon.expanded {{
            transform: rotate(180deg);
        }}
        .finding-body {{
            padding: 20px;
            display: none;
        }}
        .finding-body.open {{
            display: block;
        }}
        .finding-body .detail-row {{
            margin-bottom: 10px;
        }}
        .finding-body .detail-row .label {{
            font-weight: 600;
            color: #495057;
            display: block;
            font-size: 13px;
            margin-bottom: 2px;
        }}
        .finding-body .detail-row .value {{
            background: #f8f9fa;
            padding: 8px 14px;
            border-radius: 6px;
            font-size: 14px;
            word-break: break-all;
        }}
        .finding-body .detail-row .value.url {{
            color: #0066cc;
            word-break: break-all;
        }}
        .finding-body .affected-urls {{
            margin-top: 6px;
        }}
        .finding-body .affected-urls .url-item {{
            background: #f1f3f5;
            padding: 4px 12px;
            border-radius: 4px;
            font-size: 13px;
            display: inline-block;
            margin: 2px 4px 2px 0;
            color: #495057;
            word-break: break-all;
        }}
        .extracted-data {{
            background: #f8f9fa;
            border-radius: 6px;
            padding: 12px 16px;
            margin-top: 8px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
        }}
        .extracted-data .data-key {{
            font-weight: 600;
            color: #495057;
        }}
        .extracted-data .data-value {{
            color: #212529;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 40px;
            color: #28a745;
            font-size: 18px;
        }}
        .no-findings .icon {{
            font-size: 48px;
            display: block;
            margin-bottom: 16px;
        }}
        
        .category-tag {{
            display: inline-block;
            padding: 2px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 500;
            background: #e9ecef;
            color: #495057;
            margin-left: 8px;
        }}
        
        @media (max-width: 768px) {{
            body {{ padding: 12px; }}
            .header {{ padding: 24px; }}
            .header h1 {{ font-size: 24px; flex-wrap: wrap; }}
            .header .meta {{ gap: 12px; }}
            .stats-grid {{ grid-template-columns: repeat(3, 1fr); gap: 10px; }}
            .finding-header {{ flex-wrap: wrap; }}
        }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .header {{ background: #1a1a2e !important; -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .finding-header .severity-badge {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
            .finding-body.open {{ display: block !important; }}
            .finding-header .expand-icon {{ display: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>
                🔒 Passive HTTP Observer
                <span class="badge">v9.3</span>
            </h1>
            <div style="font-size: 16px; opacity: 0.8; margin-top: 4px;">Comprehensive Security Analysis Report</div>
            <div class="meta">
                <span>📅 {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</span>
                <span>🎯 {metadata.get('targets_analyzed', 0)} Targets Analyzed</span>
                <span>🔍 {len(findings)} Findings</span>
                <span>⏱️ {metadata.get('duration_seconds', 0):.2f}s Duration</span>
                <span>📊 {metadata.get('source_type', 'Unknown')}</span>
            </div>
        </div>
        
        <!-- Statistics -->
        <div class="stats-grid">
            <div class="stat-card critical">
                <div class="number">{severity_counts.get('Critical', 0)}</div>
                <div class="label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="number">{severity_counts.get('High', 0)}</div>
                <div class="label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="number">{severity_counts.get('Medium', 0)}</div>
                <div class="label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="number">{severity_counts.get('Low', 0)}</div>
                <div class="label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="number">{severity_counts.get('Info', 0)}</div>
                <div class="label">Info</div>
            </div>
        </div>
        
        <!-- Findings Section -->
        <div class="section">
            <h2>
                📋 Detailed Findings
                <span class="count">{len(findings)} total</span>
            </h2>
            
            {'' if findings else '''
            <div class="no-findings">
                <span class="icon">✅</span>
                No security issues detected!
            </div>
            '''}
            
            {''.join(HTMLReportGenerator._render_finding(f, severity_colors, severity_icons) for f in sorted_findings)}
        </div>
        
        <!-- Footer -->
        <div style="text-align: center; padding: 20px; color: #868e96; font-size: 13px; border-top: 1px solid #e9ecef; margin-top: 20px;">
            Generated by Passive HTTP Observer v9.3 • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
        </div>
    </div>
    
    <script>
        // Toggle finding expansion
        document.querySelectorAll('.finding-header').forEach(header => {{
            header.addEventListener('click', function() {{
                const body = this.nextElementSibling;
                const icon = this.querySelector('.expand-icon');
                body.classList.toggle('open');
                icon.classList.toggle('expanded');
            }});
        }});
        
        // Expand first finding by default
        document.addEventListener('DOMContentLoaded', function() {{
            const firstFinding = document.querySelector('.finding');
            if (firstFinding) {{
                const header = firstFinding.querySelector('.finding-header');
                const body = firstFinding.querySelector('.finding-body');
                const icon = header.querySelector('.expand-icon');
                if (header && body && icon) {{
                    body.classList.add('open');
                    icon.classList.add('expanded');
                }}
            }}
        }});
    </script>
</body>
</html>'''
        
        # Write to file
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return output_file
    
    @staticmethod
    def _render_finding(finding: SecurityFinding, severity_colors: Dict, severity_icons: Dict) -> str:
        """Render a single finding as HTML"""
        sev = finding.severity_str
        color = severity_colors.get(sev, '#6c757d')
        icon = severity_icons.get(sev, '📌')
        
        # Affected URLs HTML
        affected_urls_html = ''
        if finding.affected_urls and len(finding.affected_urls) > 1:
            urls_html = ''.join(f'<span class="url-item">{url[:80]}{"..." if len(url) > 80 else ""}</span>' for url in finding.affected_urls[:10])
            if len(finding.affected_urls) > 10:
                urls_html += f'<span class="url-item">+{len(finding.affected_urls) - 10} more</span>'
            affected_urls_html = f'''
            <div class="detail-row">
                <span class="label">Affected URLs ({len(finding.affected_urls)})</span>
                <div class="affected-urls">{urls_html}</div>
            </div>
            '''
        
        # Extracted data HTML
        extracted_html = ''
        if finding.extracted_data:
            data_items = ''.join(
                f'<div><span class="data-key">{key}:</span> <span class="data-value">{str(value)[:200]}{"..." if len(str(value)) > 200 else ""}</span></div>'
                for key, value in list(finding.extracted_data.items())[:5]
            )
            if len(finding.extracted_data) > 5:
                data_items += f'<div style="color:#868e96;">... and {len(finding.extracted_data) - 5} more</div>'
            extracted_html = f'''
            <div class="detail-row">
                <span class="label">Extracted Data</span>
                <div class="extracted-data">{data_items}</div>
            </div>
            '''
        
        # CVE reference
        cve_html = f'<div class="detail-row"><span class="label">CVE Reference</span><div class="value">{finding.cve_reference}</div></div>' if finding.cve_reference else ''
        
        return f'''
        <div class="finding">
            <div class="finding-header">
                <span class="severity-badge" style="background:{color}">{icon} {sev}</span>
                <span class="issue-type">{finding.issue_type}</span>
                <span class="category-tag">{finding._categorise()}</span>
                <span class="expand-icon">▼</span>
            </div>
            <div class="finding-body">
                <div class="detail-row">
                    <span class="label">Indicator</span>
                    <div class="value">{finding.indicator}</div>
                </div>
                <div class="detail-row">
                    <span class="label">Impact</span>
                    <div class="value">{finding.impact}</div>
                </div>
                {cve_html}
                <div class="detail-row">
                    <span class="label">Confidence</span>
                    <div class="value">{finding.confidence_str}</div>
                </div>
                <div class="detail-row">
                    <span class="label">Primary URL</span>
                    <div class="value url">{finding.get_primary_url()}</div>
                </div>
                {affected_urls_html}
                {'' if not finding.remediation else f'''
                <div class="detail-row">
                    <span class="label">Remediation</span>
                    <div class="value" style="background:#d4edda;border-left:4px solid #28a745;">{finding.remediation}</div>
                </div>
                '''}
                {extracted_html}
                <div class="detail-row" style="margin-top:8px;font-size:12px;color:#868e96;">
                    Detected: {finding.timestamp[:19].replace('T', ' ')} • Method: {finding.detection_method}
                </div>
            </div>
        </div>
        '''


# -----------------------------------------------------------------------------
# Report Generator (JSON)
# -----------------------------------------------------------------------------

class ReportGenerator:
    """Generate professional security reports"""
    
    @staticmethod
    def generate_report(findings: List[SecurityFinding], metadata: Dict, output_file: str):
        """Generate JSON report"""
        report = {
            "scan_metadata": metadata,
            "status": metadata.get('error_count', 0) == 0,
            "findings": [f.to_report_dict() for f in findings],
            "statistics": ReportGenerator._calculate_statistics(findings)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        return output_file
    
    @staticmethod
    def _calculate_statistics(findings: List[SecurityFinding]) -> Dict:
        """Calculate statistics from findings"""
        stats = {
            "total_findings": len(findings),
            "by_severity": {},
            "by_category": {},
            "by_confidence": {}
        }
        
        for finding in findings:
            sev = finding.severity_str
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            
            cat = finding._categorise()
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1
            
            conf = finding.confidence_str
            stats["by_confidence"][conf] = stats["by_confidence"].get(conf, 0) + 1
        
        return stats


# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

def setup_logging(verbose: bool):
    """Setup logging configuration"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )


def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.CYAN}{'='*80}{Colors.END}
{Colors.BOLD}{Colors.HEADER}    PASSIVE HTTP OBSERVER v9.3 - Comprehensive Security Analysis {Colors.END}
{Colors.CYAN}{'='*80}{Colors.END}
"""
    print(banner)


def print_scan_summary(total_targets: int, findings: List[SecurityFinding], 
                       error_count: int, duration: float, scan_mode: str, tls_findings_count: int = 0):
    """Print scan summary"""
    severity_counts = defaultdict(int)
    for finding in findings:
        severity_counts[finding.severity_str] += 1
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}SCAN SUMMARY{Colors.END}")
    print(f"{Colors.CYAN}{'-'*80}{Colors.END}")
    print(f"\n{Colors.BOLD}Statistics:{Colors.END}")
    print(f"  * Mode             : {Colors.BOLD}{scan_mode}{Colors.END}")
    print(f"  * Targets Analyzed : {Colors.BOLD}{total_targets}{Colors.END}")
    print(f"  * Total Findings   : {Colors.BOLD}{len(findings)}{Colors.END}")
    if tls_findings_count > 0:
        print(f"  * TLS Findings     : {Colors.BOLD}{tls_findings_count}{Colors.END}")
    print(f"  * Connection Errors: {Colors.RED if error_count else Colors.GREEN}{error_count}{Colors.END}")
    print(f"  * Scan Duration    : {Colors.BOLD}{duration:.2f}s{Colors.END}")
    
    if severity_counts:
        print(f"\n{Colors.BOLD}Severity Distribution:{Colors.END}")
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts.get(severity.value, 0)
            if count > 0:
                color = Colors.RED if severity in [Severity.CRITICAL, Severity.HIGH] else \
                       Colors.YELLOW if severity == Severity.MEDIUM else Colors.DIM
                icon = Icons.CRITICAL if severity == Severity.CRITICAL else \
                       Icons.HIGH if severity == Severity.HIGH else \
                       Icons.MEDIUM if severity == Severity.MEDIUM else \
                       Icons.LOW if severity == Severity.LOW else Icons.INFO
                print(f"  {icon} {color}{severity.value}: {count}{Colors.END}")
    
    if not findings and tls_findings_count == 0:
        print(f"\n  {Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}No security issues detected!{Colors.END}")


def print_all_findings_detailed(findings: List[SecurityFinding]):
    """Print all findings with complete details (after deduplication)"""
    if not findings:
        return
    
    print(f"\n{Colors.BOLD}{Colors.CYAN}COMPLETE FINDINGS LIST ({len(findings)} unique findings){Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}")
    
    for idx, finding in enumerate(findings, 1):
        if finding.severity == Severity.CRITICAL:
            sc, icon = Colors.RED, Icons.CRITICAL
        elif finding.severity == Severity.HIGH:
            sc, icon = Colors.RED, Icons.HIGH
        elif finding.severity == Severity.MEDIUM:
            sc, icon = Colors.YELLOW, Icons.MEDIUM
        elif finding.severity == Severity.LOW:
            sc, icon = Colors.BLUE, Icons.LOW
        else:
            sc, icon = Colors.DIM, Icons.INFO
        
        # Show primary URL and note if there are multiple affected URLs
        affected_count = len(finding.affected_urls) if finding.affected_urls else 1
        url_display = finding.get_primary_url()
        if affected_count > 1:
            url_display = f"{url_display} (+{affected_count - 1} more)"
        
        print(f"\n{Colors.BOLD}[{idx}] {icon} {sc}{finding.severity_str}{Colors.END} - {finding.issue_type}")
        print(f"  {Colors.DIM}URL(s):{Colors.END}       {url_display}")
        print(f"  {Colors.DIM}Indicator:{Colors.END}   {finding.indicator}")
        print(f"  {Colors.DIM}Impact:{Colors.END}      {finding.impact}")
        print(f"  {Colors.DIM}Confidence:{Colors.END}   {finding.confidence_str}")
        
        if finding.param_location:
            print(f"  {Colors.DIM}Parameter:{Colors.END}   {finding.param_location}")
        
        if finding.remediation:
            print(f"  {Colors.DIM}Remediation:{Colors.END} {finding.remediation}")
        
        if finding.cve_reference:
            print(f"  {Colors.DIM}CVE Reference:{Colors.END} {finding.cve_reference}")
        
        if finding.extracted_data:
            print(f"  {Colors.DIM}Additional Data:{Colors.END}")
            for key, value in finding.extracted_data.items():
                if value:
                    val_str = str(value)
                    if len(val_str) > 100:
                        val_str = val_str[:100] + "..."
                    print(f"      * {key}: {val_str}")
        
        # Show all affected URLs if there are multiple (limit to first 5 for display)
        if finding.affected_urls and len(finding.affected_urls) > 1:
            print(f"  {Colors.DIM}All Affected URLs ({len(finding.affected_urls)}):{Colors.END}")
            for aff_url in finding.affected_urls[:5]:
                print(f"      * {aff_url[:100]}{'...' if len(aff_url) > 100 else ''}")
            if len(finding.affected_urls) > 5:
                print(f"      * ... and {len(finding.affected_urls) - 5} more")
        
        print(f"  {Colors.CYAN}{'-'*76}{Colors.END}")


def prompt_view_html_report(html_file: str) -> bool:
    """Prompt user with validation to view HTML report"""
    while True:
        try:
            response = input(f"\n{Colors.BOLD}View HTML report in browser? (y/n): {Colors.END}").strip().lower()
            if response in ('y', 'yes'):
                return True
            elif response in ('n', 'no'):
                return False
            else:
                print(f"{Colors.YELLOW}Please enter 'y' for yes or 'n' for no.{Colors.END}")
        except KeyboardInterrupt:
            print(f"\n{Icons.INFO} {Colors.DIM}Skipped{Colors.END}")
            return False
        except EOFError:
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Passive HTTP Observer v9.3 - Comprehensive Security Analysis Tool",
        epilog="Detects: GraphQL, JWT, HTTP Smuggling, Cache Poisoning, SSRF, OAuth, TLSv1.0/TLSv1.1, and more"
    )
    parser.add_argument("file", help="Path to input file (HAR, Burp XML, PCAP, or JSON)")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent workers (default: 5)")
    parser.add_argument("--rate-limit", type=float, default=0.5, help="Seconds between requests (default: 0.5)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--max-pcap-mb", type=int, default=1024, help="Max PCAP size in MB (default: 1024)")
    parser.add_argument("--passive-rate-limit", type=float, default=1.0, help="Rate limit for passive scanning (default: 1.0)")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--no-tls-detection", action="store_true", help="Disable TLS version/cipher detection")
    
    args = parser.parse_args()
    
    start_time = time.time()
    print_banner()
    setup_logging(args.verbose)
    
    config = ObserverConfig(
        max_workers=args.workers,
        rate_limit=args.rate_limit,
        timeout=args.timeout,
        user_agent="PassiveHTTPObserver/9.3",
        strict_mixed_content=False,
        verbose=args.verbose,
        print_all_findings=True,
        max_display_findings=10000,
        analyze_javascript=True,
        analyze_websockets=True,
        passive_scanning=True,
        passive_rate_limit=args.passive_rate_limit,
        max_pcap_size_mb=args.max_pcap_mb,
        detect_stack_traces=True,
        detect_database_errors=True,
        detect_framework_paths=True,
        detect_debug_messages=True,
        detect_graphql_introspection=True,
        detect_jwt_weaknesses=True,
        detect_http_smuggling=True,
        detect_cache_poisoning=True,
        detect_ssrf_reflections=True,
        detect_open_redirects=True,
        detect_oauth_misconfigurations=True,
        detect_api_version_disclosure=True,
        detect_http2_issues=True,
        enable_context_validation=True,
        min_credit_card_length=13,
        max_credit_card_length=19,
        detect_tls_vulnerabilities=not args.no_tls_detection,
        detect_tls10=not args.no_tls_detection,
        detect_tls11=not args.no_tls_detection,
        detect_weak_ciphers=not args.no_tls_detection
    )
    
    file_ext = Path(args.file).suffix.lower()
    responses_with_urls = []
    targets = []
    scan_mode = "Passive"
    tls_findings = []
    
    try:
        if file_ext in ['.har']:
            print(f"{Icons.INFO} {Colors.BOLD}Loading HAR file...{Colors.END}")
            responses_with_urls = FileParser.parse_har_file(args.file, config)
            scan_mode = "Passive (HAR Analysis)"
            print(f"{Icons.SUCCESS} {Colors.GREEN}Loaded {len(responses_with_urls)} HTTP transactions{Colors.END}")
            
        elif file_ext in ['.xml']:
            print(f"{Icons.INFO} {Colors.BOLD}Loading Burp XML file...{Colors.END}")
            responses_with_urls = FileParser.parse_burp_xml_file(args.file, config)
            scan_mode = "Passive (Burp XML Analysis)"
            print(f"{Icons.SUCCESS} {Colors.GREEN}Loaded {len(responses_with_urls)} HTTP transactions{Colors.END}")
            
        elif file_ext in ['.pcap', '.pcapng']:
            print(f"{Icons.INFO} {Colors.BOLD}Loading PCAP file with streaming reassembly...{Colors.END}")
            if not SCAPY_AVAILABLE:
                print(f"{Icons.ERROR} {Colors.RED}Scapy required for PCAP parsing. Install: pip install scapy{Colors.END}")
                return
            if H2_AVAILABLE:
                print(f"{Icons.SUCCESS} {Colors.GREEN}HTTP/2 support enabled{Colors.END}")
            if not args.no_tls_detection and SCAPY_TLS_AVAILABLE:
                print(f"{Icons.SUCCESS} {Colors.GREEN}TLS detection enabled (TLSv1.0/TLSv1.1/weak ciphers){Colors.END}")
            elif not args.no_tls_detection and not SCAPY_TLS_AVAILABLE:
                print(f"{Icons.WARNING} {Colors.YELLOW}TLS detection requires scapy[complete]. Install: pip install scapy[complete]{Colors.END}")
            
            processor = EnhancedPCAPProcessor(config)
            responses_with_urls, tls_findings = processor.process_pcap(args.file)
            scan_mode = "Passive (PCAP Analysis with Streaming + TLS Detection)"
            print(f"{Icons.SUCCESS} {Colors.GREEN}Extracted {len(responses_with_urls)} HTTP/WebSocket transactions{Colors.END}")
            print(f"{Icons.TLS} {Colors.CYAN}Detected {len(tls_findings)} TLS security issues{Colors.END}")
            
        else:
            print(f"{Icons.INFO} {Colors.BOLD}Loading JSON URL list for passive analysis...{Colors.END}")
            targets = FileParser.parse_json_urls(args.file)
            scan_mode = f"Passive (Analyzing {len(targets)} URLs from JSON)"
            print(f"{Icons.SUCCESS} {Colors.GREEN}Loaded {len(targets)} target URLs for analysis{Colors.END}")
            print(f"{Icons.WARNING} {Colors.YELLOW}Rate limiting: {args.passive_rate_limit}s between requests{Colors.END}")
            responses_with_urls = []
            
    except Exception as e:
        print(f"{Icons.ERROR} {Colors.RED}Failed to parse file: {e}{Colors.END}")
        logging.error(f"File parsing error: {e}", exc_info=True)
        return
    
    observer = PassiveHttpObserver(config)
    all_findings = []
    error_list = []
    
    if responses_with_urls:
        print(f"\n{Colors.BOLD}Started analysis...{Colors.END}\n")
        
        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            future_to_item = {
                executor.submit(observer.analyze_endpoint, url, response): (url, response)
                for url, response in responses_with_urls
            }
            
            completed = 0
            for future in as_completed(future_to_item):
                completed += 1
                url, _ = future_to_item[future]
                
                print(f"{Colors.DIM}[{completed}/{len(responses_with_urls)}] Analyzing: {url[:70]}{'...' if len(url) > 70 else ''}{Colors.END}", end="\r")
                
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    error_list.append(f"{url} – {str(e)}")
                    logging.error(f"Analysis failed for {url}: {e}")
        
        print()
            
    elif targets:
        print(f"\n{Colors.BOLD}Started passive scanning with rate limiting...{Colors.END}\n")
        
        with ThreadPoolExecutor(max_workers=config.max_workers) as executor:
            future_to_url = {executor.submit(observer.analyze_endpoint, url): url for url in targets}
            
            completed = 0
            for future in as_completed(future_to_url):
                completed += 1
                url = future_to_url[future]
                
                print(f"{Colors.DIM}[{completed}/{len(targets)}] Scanning: {url[:70]}{'...' if len(url) > 70 else ''}{Colors.END}", end="\r")
                
                try:
                    findings = future.result()
                    all_findings.extend(findings)
                except Exception as e:
                    error_list.append(f"{url} – {str(e)}")
                    logging.error(f"Scan failed for {url}: {e}")
        
        print()
    
    # Add TLS findings to all findings
    all_findings.extend(tls_findings)
    
    # Deduplicate findings by (issue_type + indicator) and aggregate affected URLs
    deduplicator = FindingDeduplicator()
    deduplicator.add_findings(all_findings)
    unique_findings = deduplicator.get_findings()
    
    # Sort by severity
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, 
                     Severity.LOW: 3, Severity.INFO: 4}
    unique_findings.sort(key=lambda x: (severity_order.get(x.severity, 5), x.get_primary_url()))
    
    duration = time.time() - start_time
    total_targets = len(responses_with_urls) if responses_with_urls else len(targets)
    print_scan_summary(total_targets, unique_findings, len(error_list), duration, scan_mode, len(tls_findings))
    
    if unique_findings:
        print_all_findings_detailed(unique_findings)
    
    if error_list:
        print(f"\n{Colors.BOLD}{Colors.RED}ERRORS ({len(error_list)}){Colors.END}")
        print(f"{Colors.RED}{'-'*80}{Colors.END}")
        for idx, error in enumerate(error_list[:20], 1):
            print(f"  {idx}. {error[:150]}{'...' if len(error) > 150 else ''}")
        if len(error_list) > 20:
            print(f"  {Colors.DIM}... and {len(error_list) - 20} more{Colors.END}")
    
    # Generate JSON report
    json_output_file = "passive_security_report.json"
    metadata = {
        "tool": "PassiveHTTPObserver",
        "version": "9.3",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": duration,
        "targets_analyzed": total_targets,
        "total_findings": len(unique_findings),
        "raw_findings_before_deduplication": len(all_findings),
        "deduplication_ratio": f"{len(unique_findings)}/{len(all_findings)}" if all_findings else "N/A",
        "tls_findings": len(tls_findings),
        "error_count": len(error_list),
        "source_type": "HAR" if file_ext == '.har' else "Burp XML" if file_ext == '.xml' else "PCAP" if file_ext in ['.pcap', '.pcapng'] else "JSON (Passive Scan)",
        "scan_mode": "Passive",
        "features": {
            "javascript_analysis": True,
            "websocket_analysis": True,
            "enhanced_credit_card_detection": True,
            "tcp_reassembly": True,
            "streaming_pcap": True,
            "http2_support": H2_AVAILABLE,
            "tls_detection": SCAPY_TLS_AVAILABLE and not args.no_tls_detection,
            "tls10_detection": config.detect_tls10,
            "tls11_detection": config.detect_tls11,
            "weak_cipher_detection": config.detect_weak_ciphers,
            "passive_scanning": config.passive_scanning,
            "passive_rate_limit": config.passive_rate_limit,
            "error_information_leakage": True,
            "graphql_introspection": True,
            "jwt_analysis": True,
            "http_smuggling": True,
            "cache_poisoning": True,
            "ssrf_detection": True,
            "open_redirect": True,
            "oauth_misconfigurations": True,
            "api_version_disclosure": True,
            "http2_analysis": True,
            "false_positive_reduction": True,
            "finding_deduplication": True
        },
        "config": {
            "workers": config.max_workers,
            "rate_limit": config.rate_limit,
            "passive_rate_limit": config.passive_rate_limit,
            "timeout": config.timeout,
            "strict_mode": config.strict_mixed_content,
            "max_pcap_mb": config.max_pcap_size_mb
        }
    }
    
    ReportGenerator.generate_report(unique_findings, metadata, json_output_file)
    
    # Generate HTML report
    html_output_file = "passive_security_report.html"
    print(f"\n{Colors.BOLD}{Colors.CYAN}Generating HTML report...{Colors.END}")
    html_file = HTMLReportGenerator.generate_report(unique_findings, metadata, html_output_file)
    print(f"{Icons.SUCCESS} {Colors.GREEN}HTML report saved to: {Colors.CYAN}{html_file}{Colors.END}")
    
    # Prompt user with validation
    if prompt_view_html_report(html_file):
        try:
            webbrowser.open(os.path.abspath(html_file))
            print(f"{Icons.INFO} {Colors.GREEN}Opening HTML report in browser...{Colors.END}")
        except Exception as e:
            print(f"{Icons.WARNING} {Colors.YELLOW}Could not open browser: {e}{Colors.END}")
    
    print(f"\n{Colors.CYAN}{'='*80}{Colors.END}")
    print(f"{Icons.SUCCESS} {Colors.GREEN}{Colors.BOLD}Analysis complete!{Colors.END}")
    print(f"{Icons.TARGET} {Colors.BOLD}JSON Report:{Colors.END} {Colors.CYAN}{json_output_file}{Colors.END}")
    print(f"{Icons.TARGET} {Colors.BOLD}HTML Report:{Colors.END} {Colors.CYAN}{html_output_file}{Colors.END}")
    print(f"{Icons.INFO} {Colors.BOLD}Total unique findings after deduplication:{Colors.END} {Colors.YELLOW}{len(unique_findings)}{Colors.END}")
    if len(all_findings) > len(unique_findings):
        print(f"{Icons.INFO} {Colors.BOLD}Deduplicated {len(all_findings) - len(unique_findings)} duplicate findings{Colors.END}")
    if tls_findings:
        print(f"{Icons.TLS} {Colors.BOLD}TLS issues found:{Colors.END} {Colors.YELLOW}{len(tls_findings)}{Colors.END}")
    print(f"{Colors.CYAN}{'='*80}{Colors.END}\n")


if __name__ == "__main__":
    main()
