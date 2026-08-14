"""
pipeline/agent_capabilities.py

Authoritative map of what each validation agent actually tests. This
exists because agent-routing knowledge was previously scattered and
duplicated: config.py's SYSTEM_PROMPT describes each agent's scope in
prose for DeepHat, and pipeline/planner.py separately hardcoded a
reactive blocklist (_AGENT_CATEGORY_MISMATCHES) of specific mismatches
as they were observed in practice (SSRF/Open Redirect -> MITM_AGENT,
cookie findings -> AUTHZ_AGENT). That blocklist only ever caught
mismatches after someone had already seen them happen once.

This module is the single place that knowledge now lives. Planner's
capability check (see _is_capability_mismatch in planner.py) uses it
proactively: a candidate is blocked when its type/category positively
matches a DIFFERENT agent's known capability set, not merely when it
fails to match the one it was routed to (that distinction matters —
it avoids false-positive-blocking a legitimately-routed candidate whose
category phrasing is a novel synonym this map doesn't happen to list).

Keep this in sync with config.py's per-agent trigger-criteria sections
when either changes — they describe the same boundaries from two
different angles (this is the enforceable, code-level version; config.py
is the prompt-level version DeepHat actually reads).
"""

# Each agent's capability keywords, matched case-insensitively as
# substrings against a candidate's "type" + "category" fields combined.
# Keywords are deliberately specific compound terms/phrases rather than
# single generic words (e.g. NOT bare "injection", which every one of
# SQL/NoSQL/Command/SSTI legitimately involves) — the goal is each
# keyword should unambiguously identify one vector, so cross-agent
# overlap stays intentional rather than accidental.
#
# SAST_AGENT is included for completeness/documentation even when it
# isn't currently in pipeline/planner.py's SUPPORTED_AGENTS (it can be
# disabled independently of this map — that's a routing-availability
# decision, not a capability-definition one; attempting to route there
# while disabled is already blocked by the earlier SUPPORTED_AGENTS
# check regardless of what this map says).
AGENT_CAPABILITIES = {
    "XSS_AGENT": {
        "xss", "reflected_xss", "stored_xss", "dom_xss", "dom_based_xss",
        "cross_site_scripting", "script_injection", "html_injection",
    },
    "AUTHZ_AGENT": {
        "authz", "broken_access_control", "missing_authorization",
        "missing_authz", "idor", "privilege_escalation", "missing_auth",
        "access_control", "unauthorized_access", "broken_authorization",
    },
    "PASSWORD_POLICY_AGENT": {
        "password_policy", "weak_password_policy", "default_credentials",
        "password_complexity", "credential_policy", "weak_password",
    },
    "SAST_AGENT": {
        "git_exposure", "exposed_source", "source_code_exposure",
        "hardcoded_secret", "dependency_vulnerability", "cve",
    },
    "SOURCE_AUDIT_AGENT": {
        "git_exposure", "exposed_source", "source_code_exposure",
        "taint", "hardcoded_secret", "dataflow",
    },
    "MITM_AGENT": {
        "mitm", "cookie", "websocket", "graphql_introspection",
        "cors", "jwt", "oauth_misconfiguration", "mixed_content",
        "csp_weakness", "http_smuggling", "cache_poisoning",
        "api_version_disclosure", "error_information_leakage",
        "weak_tls_version", "self_signed_cert", "cert_expired",
        "cert_hostname_mismatch", "tls_handshake_error",
    },
    "NOSQL_AGENT": {
        "nosql", "nosql_injection", "mongo_injection", "mongodb_injection",
        "nosql_auth_bypass",
    },
    "SQL_AGENT": {
        "sql_injection", "sqli", "sql_injection_error", "sql_injection_blind",
        "sql_injection_boolean",
    },
    "PARAM_INJECTION_AGENT": {
        "ssrf", "server_side_request_forgery",
        "ssti", "server_side_template_injection", "template_injection",
        "sspp", "server_side_parameter_pollution", "mass_assignment",
        "command_injection", "path_traversal",
        "open_redirect", "openredirect",
        "host_header_injection", "referer_injection",
    },
}


def _normalize(finding_type, finding_category):
    return " ".join([
        str(finding_type or ""),
        str(finding_category or ""),
    ]).lower().replace("-", "_").replace(" ", "_")


def find_owning_agents(finding_type, finding_category):
    """
    Which agent(s) this capability map says a candidate's type/category
    actually belongs to, based on positive keyword match. Usually 0 or 1
    agents; can be >1 for legitimately shared categories (e.g. a plain
    "injection" phrasing that isn't specific enough to disambiguate —
    though the keyword set is designed to keep this rare).
    """
    haystack = _normalize(finding_type, finding_category)

    return [
        agent
        for agent, keywords in AGENT_CAPABILITIES.items()
        if any(keyword in haystack for keyword in keywords)
    ]


def is_capability_mismatch(finding_type, finding_category, routed_agent):
    """
    True when the candidate's type/category positively matches a
    capability set belonging to some OTHER agent, and does NOT match
    routed_agent's own capability set. This is the proactive check:
    it catches any mismatch this map knows about, not just ones that
    have already been observed and hardcoded reactively.

    Returns False (does not block) when:
    - The candidate matches no known agent's capabilities at all (a
      genuinely novel category this map doesn't cover yet — falls
      through to other checks rather than being blocked here).
    - The candidate matches routed_agent's own capabilities, even if it
      also happens to match another agent's (ambiguous/shared category
      — not a confident enough signal to block on).
    """
    owning_agents = find_owning_agents(finding_type, finding_category)

    if not owning_agents:
        return False

    if routed_agent in owning_agents:
        return False

    return True