"""
pipeline/candidate_builder.py

Deterministically builds candidate SKELETONS directly from SpiderExtractor's
already-trusted structured evidence — no LLM involvement at all in this
step. This is the architectural fix for DeepHat hallucination, not another
reactive guard.

Why this exists (read this before touching DeepHat's prompt again):
every hallucination class observed across this project's development
(invented endpoints, fabricated evidence-array citations, dropped query
strings, invented CVE IDs, invented agent names, misrouted candidates)
came from asking a 7B local model to do five jobs in one open-ended
generation call: find endpoints, author evidence text, choose an agent,
write valid JSON, and count correctly. Every fix that actually held
reliably (grounding checks, the capability map, the evidence-citation
validator) works by refusing to trust the model's output as fact and
checking it against real evidence instead. This module is the conclusion
of that principle taken all the way: if agent_targets/sqli_evidence/
sensitive_file_evidence/header_audit/tls_audit are already structured and
already real, there is no reason to ask DeepHat to re-derive or re-author
them from scratch. Build the real candidate list in code. Give DeepHat a
narrower, bounded job: for each pre-built real candidate, pick ONE agent
from a small pre-computed ELIGIBLE set (or null), and write a one-line
justification. It never gets the opportunity to invent an endpoint or an
evidence citation, because it's never asked to author either.

CandidateSkeleton fields are the same shape the rest of the pipeline
already expects (endpoint, method, evidence, etc.) so Planner/Executor/
OutputParser downstream of DeepHat's classification pass don't need to
change shape — only how the endpoint/evidence/method fields get their
value changes (built here in code, never typed by the model).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pipeline.agent_capabilities import find_owning_agents


@dataclass
class CandidateSkeleton:
    index: int
    endpoint: Optional[str]
    method: str
    parameter: Optional[str]
    real_evidence: List[str]
    suggested_type: str
    suggested_category: str
    severity_hint: str
    # The menu DeepHat is allowed to choose from for this specific
    # skeleton. Built from the capability map (pipeline/agent_capabilities
    # .py) plus this skeleton's own signal type, so DeepHat is never
    # offered an agent that structurally can't apply — e.g. a header-only
    # skeleton's eligible_agents is always [] (agent must be null), an
    # SQLi-shaped skeleton's is always exactly ["SQL_AGENT"].
    eligible_agents: List[str] = field(default_factory=list)

    def to_prompt_dict(self) -> Dict[str, Any]:
        """
        What DeepHat actually sees for this skeleton. Deliberately
        excludes nothing DeepHat needs to make the classification
        decision, and includes nothing DeepHat could misquote as a new
        fact — real_evidence is presented as already-verified, not as
        something to describe in its own words.
        """
        return {
            "index": self.index,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "evidence": self.real_evidence,
            "suggested_type": self.suggested_type,
            "eligible_agents": self.eligible_agents or ["null (no agent applies)"],
        }


def _param_tokens(param: str) -> set:
    """
    Split a parameter name into word-boundary tokens for exact-token
    matching, instead of raw substring matching. Confirmed real bug
    (testaspnet.vulnweb.com, 2026-08-14): raw "id" in param.lower()
    matched "__eventvalidation" (val-ID-ation), incorrectly flagging an
    ASP.NET framework plumbing field as an "ID-style parameter" and
    building a whole candidate skeleton around it. DeepHat's
    justification then accurately described that already-wrong skeleton
    — the bug was here, not in DeepHat's reasoning. Splits on
    underscores/hyphens and camelCase boundaries so "user_id" and
    "itemId" still correctly match "id" as a distinct token, while
    "eventvalidation" (no internal boundaries at the point "id" would
    need to be its own token) does not.
    """
    parts = re.split(r"[_\-]+", param)
    tokens = []
    for part in parts:
        if not part:
            continue
        split = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", part).split()
        tokens.extend(split if split else [part])
    return {t.lower() for t in tokens if t}


def build_candidate_skeletons(evidence: Dict[str, Any]) -> List[CandidateSkeleton]:
    """
    The single deterministic pass that replaces "ask DeepHat to find
    endpoints". Walks every structured evidence array SpiderExtractor
    produces and emits one real, evidence-backed skeleton per genuine
    signal. Order matters for skeletons sharing the same endpoint+type —
    later builders here dedupe against earlier ones by (endpoint, method,
    suggested_type) so the same real thing isn't offered twice.
    """
    skeletons: List[CandidateSkeleton] = []
    seen = set()

    def add(endpoint, method, parameter, real_evidence, suggested_type,
             suggested_category, severity_hint, eligible_agents):
        key = (endpoint, method, suggested_type)
        if key in seen:
            return
        seen.add(key)
        skeletons.append(CandidateSkeleton(
            index=len(skeletons),
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            real_evidence=real_evidence,
            suggested_type=suggested_type,
            suggested_category=suggested_category,
            severity_hint=severity_hint,
            eligible_agents=eligible_agents,
        ))

    # -----------------------------------------------------------------
    # 1. Dedicated pre-flagged evidence arrays — the crawler already did
    #    the work of identifying these as specific signal types. Highest
    #    confidence tier: cite this content directly, never paraphrase.
    # -----------------------------------------------------------------
    for entry in evidence.get("sqli_evidence") or []:
        add(entry.get("url"), entry.get("method", "GET"), entry.get("parameter"),
            [f"sqli_evidence: {entry}"], "sqli", "injection", "HIGH", ["SQL_AGENT"])

    for entry in evidence.get("idor_sqli_overlap") or []:
        # idor_sqli_overlap entries are bare URLs (see SpiderExtractor:
        # idor_urls & sqli_urls), not dicts.
        add(entry, "GET", None,
            [f"idor_sqli_overlap: {entry} (numeric/ID param AND SQL-error-shaped behavior both observed)"],
            "sqli", "injection", "HIGH", ["SQL_AGENT"])

    for entry in evidence.get("cmdi_evidence") or []:
        add(entry.get("url"), entry.get("method", "GET"), entry.get("parameter"),
            [f"cmdi_evidence: {entry}"], "command_injection", "injection", "HIGH",
            ["PARAM_INJECTION_AGENT"])

    for entry in evidence.get("unauthenticated_api_evidence") or []:
        add(entry.get("url"), entry.get("method", "GET"), None,
            [f"unauthenticated_api_evidence: {entry}"], "unauthenticated_api",
            "authz", "HIGH", ["AUTHZ_AGENT"])

    for entry in evidence.get("idor_evidence") or []:
        # Confirmed real gap (systemic audit, 2026-08-31): this used to
        # be hard-coded to eligible=[] with a "no IDOR_AGENT yet" comment
        # -- but AUTHZ_AGENT's own capability list (agent_capabilities.py)
        # explicitly includes "idor" as one of its keywords, and
        # config.py's own AUTHZ_AGENT prompt section explicitly lists
        # "IDOR" as within its scope alongside Broken Access Control and
        # Missing Authorization. There is no separate IDOR_AGENT and
        # never has been -- IDOR was always meant to be AUTHZ_AGENT's
        # job, same as every other missing-authorization-shaped finding.
        add(entry.get("url"), entry.get("method", "GET"), entry.get("parameter"),
            [f"idor_evidence: {entry}"], "idor", "authz", "MEDIUM", ["AUTHZ_AGENT"])

    for entry in evidence.get("sensitive_data_source_evidence") or []:
        add(entry.get("url"), entry.get("method", "GET"), None,
            [f"sensitive_data_source_evidence: {entry}"], "sensitive_data_source",
            "info_exposure", "MEDIUM", [])

    for entry in evidence.get("auth_required_evidence") or []:
        # 401/403 on these paths means access control is correctly
        # blocking them -- this is confirmation something is WORKING,
        # not a vulnerability to hand an agent. No agent tests "try to
        # get past auth on this one specific already-blocked path"; that
        # would just be re-confirming the same 401/403 the crawler
        # already observed. Surfaced purely so the finding (often
        # backup/leak-shaped filenames worth knowing about even while
        # correctly protected) is visible in the report instead of
        # silently dropped, same as sensitive_data_source_evidence above.
        add(entry.get("url"), entry.get("method", "GET"), None,
            [f"auth_required_evidence: {entry.get('url')} (access-controlled, not a vulnerability)"],
            "auth_walled_path", "info_exposure", "LOW", [])

    # -----------------------------------------------------------------
    # 2. sensitive_file_evidence / admin_panel_evidence — always surfaced
    #    (rule 9b's principle, enforced here in code instead of relying
    #    on the prompt to remember it every time).
    # -----------------------------------------------------------------
    for entry in evidence.get("sensitive_file_evidence") or []:
        sev = entry.get("severity", "MEDIUM")
        # Git_Exposure findings used to be eligible for SOURCE_AUDIT_AGENT
        # (which recovered and statically analyzed the exposed source).
        # That agent's underlying tools were removed from the project, so
        # this is now always ungrounded-for-agents -- the finding itself
        # is still surfaced as a candidate (visible in the report under
        # UNSUPPORTED) even with nothing left to route it to.
        add(entry.get("url"), "GET", None,
            [f"sensitive_file_evidence: {entry.get('type')} ({sev}) at {entry.get('url')}"],
            "sensitive_file", "exposure", sev, [])

    for url in evidence.get("admin_panel_evidence") or []:
        add(url, "GET", None,
            [f"admin_panel_evidence: {url}"], "admin_panel", "authz", "MEDIUM",
            ["AUTHZ_AGENT"])

    # -----------------------------------------------------------------
    # 3. agent_targets — the general shortlist. Each entry's own params/
    #    source tell us what it's plausibly relevant for; this is where
    #    SQL_AGENT/PARAM_INJECTION_AGENT/AUTHZ_AGENT/PASSWORD_POLICY_AGENT/
    #    NOSQL_AGENT candidates without a dedicated evidence array come
    #    from — same heuristics config.py used to describe in prose, now
    #    applied in code so they can't be misapplied or fabricated.
    # -----------------------------------------------------------------
    _ID_PARAM_HINTS = {"id", "uid", "pid", "item", "index", "num"}
    _URL_PARAM_HINTS = {"url", "host", "redirect", "next", "return", "dest", "goto", "link", "proxy", "fetch"}
    # Classic reflected-XSS-prone parameter names -- deliberately a
    # moderate, not maximal, set. XSS_AGENT scans the whole site
    # regardless of which candidate triggered it (unlike SQL_AGENT/
    # PARAM_INJECTION_AGENT, which test the specific candidate endpoint),
    # so the cost of a slightly-too-broad match here is lower -- but
    # still excludes very generic field names ("name", "title", "value")
    # that appear on almost every form regardless of whether user input
    # is ever reflected back, to keep the routing signal meaningful
    # rather than firing on nearly everything. Confirmed real test case:
    # xss-game.appspot.com's /level1/frame?query= (2026-08-14) -- this
    # exact parameter, on this exact canonical reflected-XSS target, had
    # no path to XSS_AGENT eligibility at all before this heuristic
    # existed, despite being correctly discovered by the crawler.
    _XSS_PARAM_HINTS = {"query", "search", "q", "keyword", "comment", "message", "msg", "text", "input", "content"}
    # Confirmed real gap (systemic audit, 2026-08-31): config.py's own
    # PARAM_INJECTION_AGENT prompt section explicitly lists these
    # parameter names as a Command Injection / Path Traversal trigger,
    # the same "parameter shape alone is sufficient grounds" pattern
    # used for every other heuristic in this function -- but no such
    # heuristic existed here before this fix. cmdi_evidence below is a
    # separate, rarer, crawler-confirmed signal; this is the common,
    # weaker parameter-name-shape signal, same tier as _ID_PARAM_HINTS.
    _CMDI_PARAM_HINTS = {"cmd", "command", "file", "filename", "path", "dir", "exec", "execute"}
    _LOGIN_PATH_HINTS = ("login", "signin", "logon")
    _REGISTER_PATH_HINTS = ("register", "signup", "newaccount")
    # Confirmed real gap (systemic audit, 2026-08-31): config.py's own
    # PASSWORD_POLICY_AGENT prompt section explicitly lists
    # "password-reset", "forgot-password", and "change-password" as
    # valid trigger paths alongside registration -- none of these were
    # ever checked here, only _REGISTER_PATH_HINTS above.
    _CREDENTIAL_CHANGE_PATH_HINTS = ("reset-password", "forgot-password", "change-password", "resetpassword", "forgotpassword", "changepassword")
    _ADMIN_PATH_HINTS = ("admin", "internal", "private", "settings", "manage", "debug")

    for t in evidence.get("agent_targets") or []:
        url = t.get("url")
        if not url:
            continue
        try:
            path_lower = urlparse(url).path.lower()
        except Exception:
            path_lower = url.lower()
        # ASP.NET/framework plumbing fields (__EVENTARGUMENT,
        # __VIEWSTATE, __EVENTVALIDATION, etc.) are never genuine
        # user-controlled data-lookup parameters — excluded entirely
        # from heuristic matching below rather than relying on token
        # matching alone to avoid them, since some (e.g.
        # __EVENTVALIDATION containing no internal separators) could
        # still coincidentally produce a matching token in principle.
        raw_params = [p for p in (t.get("params") or []) if not p.startswith("__")]
        params = [p.lower() for p in raw_params]
        method = t.get("method", "GET")

        is_login = any(h in path_lower for h in _LOGIN_PATH_HINTS)
        is_register = any(h in path_lower for h in _REGISTER_PATH_HINTS)
        is_credential_change = any(h in path_lower for h in _CREDENTIAL_CHANGE_PATH_HINTS)
        has_password_field = any("pass" in p or p == "pw" for p in params)

        if (is_register or is_credential_change) and has_password_field:
            reason = "registration form" if is_register else "password reset/change form"
            add(url, method, None,
                [f"agent_targets: {url} ({reason} with password field)"],
                "password_policy", "auth", "MEDIUM", ["PASSWORD_POLICY_AGENT"])
            continue

        if is_login and has_password_field:
            add(url, method, None,
                [f"agent_targets: {url} (login form with username/password fields)"],
                "nosql_auth_bypass", "injection", "MEDIUM", ["NOSQL_AGENT"])
            # Login pages are never AUTHZ_AGENT-eligible (they're supposed
            # to be reachable pre-auth) — deliberately not added below.
            continue

        id_params = [
            params[i] for i, p in enumerate(raw_params)
            if _ID_PARAM_HINTS & _param_tokens(p)
        ]
        if id_params:
            add(url, method, id_params[0],
                [f"agent_targets: {url} (ID-style parameter: {id_params[0]})"],
                "idor", "injection", "MEDIUM", ["SQL_AGENT"])

        url_params = [
            params[i] for i, p in enumerate(raw_params)
            if _URL_PARAM_HINTS & _param_tokens(p)
        ]
        if url_params:
            add(url, method, url_params[0],
                [f"agent_targets: {url} (URL/host-shaped parameter: {url_params[0]})"],
                "ssrf_or_redirect", "injection", "MEDIUM", ["PARAM_INJECTION_AGENT"])

        xss_params = [
            params[i] for i, p in enumerate(raw_params)
            if _XSS_PARAM_HINTS & _param_tokens(p)
        ]
        if xss_params:
            add(url, method, xss_params[0],
                [f"agent_targets: {url} (reflection-prone parameter: {xss_params[0]})"],
                "reflected_xss", "xss", "MEDIUM", ["XSS_AGENT"])

        cmdi_params = [
            params[i] for i, p in enumerate(raw_params)
            if _CMDI_PARAM_HINTS & _param_tokens(p)
        ]
        if cmdi_params:
            add(url, method, cmdi_params[0],
                [f"agent_targets: {url} (command/file-path-shaped parameter: {cmdi_params[0]})"],
                "command_injection", "injection", "MEDIUM", ["PARAM_INJECTION_AGENT"])

        if any(h in path_lower for h in _ADMIN_PATH_HINTS) and not is_login:
            add(url, method, None,
                [f"agent_targets: {url} (path suggests privileged functionality)"],
                "authz", "authz", "MEDIUM", ["AUTHZ_AGENT"])

    # -----------------------------------------------------------------
    # 4. header_audit / tls_audit / websocket / graphql / openapi / cors
    #    — the passive-network-observer signal family. header_audit
    #    alone is always agent=null (no HEADERS_AGENT exists yet); the
    #    rest deterministically decide MITM_AGENT eligibility here,
    #    matching the exact trigger criteria documented in config.py's
    #    own MITM_AGENT prompt section.
    # -----------------------------------------------------------------
    header_issues = evidence.get("header_audit") or []
    if header_issues:
        add(evidence.get("meta", {}).get("target"), "GET", None,
            [f"header_audit: {h.get('issue')} ({h.get('severity')}) — {h.get('detail')}" for h in header_issues],
            "missing_headers", "config", "LOW", [])

    for entry in evidence.get("tls_audit") or []:
        eligible = [] if entry.get("issue") == "No_HTTPS" else ["MITM_AGENT"]
        add(evidence.get("meta", {}).get("target"), "GET", None,
            [f"tls_audit: {entry.get('issue')} ({entry.get('severity')}) — {entry.get('detail')}"],
            "tls_issue", "tls", entry.get("severity", "MEDIUM"), eligible)

    # Confirmed real gap (demo.owasp-juice.shop, 2026-08-31): MITM_AGENT's
    # own capability list explicitly includes "websocket",
    # "graphql_introspection", and "cors", and config.py's prompt
    # explicitly documents all three as valid triggers -- but nothing in
    # this file ever read summary.websocket_detected/socketio_count, the
    # graphql/openapi arrays, or summary.cors_issues before this fix.
    # MITM_AGENT was correctly capable and correctly documented, but
    # structurally unreachable for these three signals specifically.
    summary = evidence.get("summary") or {}
    target = evidence.get("meta", {}).get("target")

    if summary.get("websocket_detected") or (summary.get("socketio_count") or 0) > 0:
        add(target, "GET", None,
            [f"summary: websocket_detected=True, socketio_count={summary.get('socketio_count', 0)}"],
            "websocket_exposure", "mitm", "LOW", ["MITM_AGENT"])

    for entry in evidence.get("graphql") or []:
        gql_url = entry.get("url") if isinstance(entry, dict) else None
        add(gql_url or target, "GET", None,
            [f"graphql: introspection endpoint discovered — {entry}"],
            "graphql_introspection", "mitm", "MEDIUM", ["MITM_AGENT"])

    for entry in evidence.get("openapi") or []:
        oas_url = entry.get("url") if isinstance(entry, dict) else None
        add(oas_url or target, "GET", None,
            [f"openapi: spec exposed — {entry}"],
            "openapi_exposure", "mitm", "LOW", ["MITM_AGENT"])

    if (summary.get("cors_issues") or 0) > 0:
        add(target, "GET", None,
            [f"summary: cors_issues={summary.get('cors_issues')}"],
            "cors_misconfiguration", "mitm", "MEDIUM", ["MITM_AGENT"])

    return skeletons


def merge_classification(skeleton: CandidateSkeleton, agent_choice: Optional[str],
                          justification: str) -> Dict[str, Any]:
    """
    Combine a skeleton (all real fields, code-built) with DeepHat's
    classification decision (agent choice + justification only) into
    the final candidate dict the rest of the pipeline already expects.
    endpoint/method/parameter/evidence always come from the skeleton —
    DeepHat's output for those fields, if it supplied any, is ignored.
    """
    agent = agent_choice if agent_choice in skeleton.eligible_agents else None

    id_source = "|".join([
        str(skeleton.endpoint or ""),
        str(skeleton.suggested_type or ""),
        str(skeleton.method or ""),
        str(skeleton.parameter or ""),
    ])
    digest = hashlib.sha256(id_source.encode("utf-8")).hexdigest()[:10]

    return {
        "finding_id": f"CAND-{digest}",
        "type": skeleton.suggested_type,
        "category": skeleton.suggested_category,
        "endpoint": skeleton.endpoint,
        "method": skeleton.method,
        "parameter": skeleton.parameter,
        "severity": skeleton.severity_hint,
        "confidence": "HIGH" if skeleton.eligible_agents else "MEDIUM",
        "status": "UNVALIDATED",
        "evidence": skeleton.real_evidence,
        "reasoning": justification or "(no justification supplied)",
        "recommended_agent": agent,
        # Tells Planner's capability-mismatch check (agent_capabilities.py)
        # to skip itself for this candidate. That check exists to catch
        # DeepHat inventing an inconsistent type/agent pairing when it
        # was free to choose both — here, type/category AND
        # eligible_agents were both assigned by this same trusted builder
        # at construction time, from the same evidence, so they're
        # already guaranteed consistent. Confirmed real case
        # (testaspnet.vulnweb.com, 2026-08-13): six genuinely correct
        # SQL_AGENT selections (all within their skeleton's own
        # eligible_agents) were wrongly blocked because this builder's
        # "idor" type label happens to also be a keyword in
        # AUTHZ_AGENT's capability set — a terminology collision between
        # two independently-correct pieces of code, not an actual
        # mismatch. The per-skeleton eligible_agents check
        # (merge_classification's own agent-clamping above) is the
        # correct, more precise version of this same protection for
        # anything built through this module.
        "_builder_verified": True,
    }