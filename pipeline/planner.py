"""
planner/planner.py

Single responsibility: given the validated dict produced by OutputParser,
decide WHICH agent each finding should be routed to, and group the results
by agent so the future executor doesn't have to re-scan the list.

Pipeline position:

    OutputParser (validated dict)
          |
          v
    Planner.route()
          |
          v
    Dict[str, List[RoutingDecision]]   ← grouped by agent
          |
          v
    (future) Executor / Agents

This module does NOT:
    - instantiate or call any agent
    - validate findings (OutputParser already did that)
    - modify findings
    - generate reports

It only decides where each finding *should* go, and logs that decision.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs

try:
    from pipeline.agent_capabilities import is_capability_mismatch
except ImportError:
    # Running planner.py directly as a script (python pipeline/planner.py,
    # used by the self-test below) puts pipeline/ itself on sys.path
    # rather than the project root, so the package-qualified import above
    # fails even though agent_capabilities.py is right next to this file.
    from agent_capabilities import is_capability_mismatch

logger = logging.getLogger(__name__)

# Findings in these statuses are not actionable right now:
#   FALSE_POSITIVE -> already resolved, nothing to validate.
_SKIP_STATUSES = {"FALSE_POSITIVE"}

# The only agents currently wrapped in the pipeline. Keep this in sync with
# processing/output_parser.py's VALID_AGENTS — that list defines what
# DeepHat is *allowed to recommend*; this one defines what the Planner is
# *actually able to route to today*. They can legitimately diverge (e.g. a
# new agent gets added to VALID_AGENTS before it's wired into the Planner).
#
# HEADERS_AGENT is intentionally left out — not wired into Executor yet.
# Findings DeepHat routes to it (or leaves unrouted) land in UNSUPPORTED
# rather than erroring. Add it here once implemented.
SUPPORTED_AGENTS = {
    "XSS_AGENT",
    "AUTHZ_AGENT",
    "PASSWORD_POLICY_AGENT",
    "MITM_AGENT",
    "NOSQL_AGENT",
    "SQL_AGENT",
    "PARAM_INJECTION_AGENT",
    "SAST_AGENT",
}

# Bucket keys used in the grouped output for findings that were NOT routed
# to a real agent. Kept distinct so callers can tell "nothing to do" apart
# from "something is wrong here".
BUCKET_UNSUPPORTED = "UNSUPPORTED"
BUCKET_SKIPPED = "SKIPPED"


@dataclass
class RoutingDecision:
    """One routing outcome for one finding. Nothing is executed yet."""
    finding_id: Any
    type: Any
    endpoint: Any
    agent: Optional[str]
    routed: bool
    reason: Optional[str] = None
    evidence: List[Any] = None
    method: Optional[str] = None

    def __str__(self) -> str:
        if self.routed:
            return f"Route → {self.agent}   (finding_id={self.finding_id}, type={self.type})"
        return f"Skip  → {self.finding_id}   (reason={self.reason})"


class Planner:
    """Decides which agent each finding should be routed to. Does not execute agents."""

    def route(
        self,
        report: Dict[str, Any],
        spider_evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, List[RoutingDecision]]:
        """
        Args:
            report: The validated dict returned by OutputParser.parse().
            spider_evidence: The extracted spider context (same dict handed
                to DeepHat as evidence). When supplied, every finding
                DeepHat routed to a real agent is cross-checked against
                it — the finding's endpoint must actually appear
                somewhere in the crawler evidence (agent_targets,
                robots_allowed/disallowed, secrets sources,
                sensitive_file_evidence, or the target itself). This is
                a code-level backstop: the system prompt already tells
                DeepHat never to invent an endpoint that isn't in the
                evidence, but a small local model doesn't always follow
                that reliably (observed: DeepHat routing to AUTHZ_AGENT/
                PASSWORD_POLICY_AGENT with real-looking endpoints like
                "/admin" or "/register" while agent_targets was
                completely empty). An ungrounded finding is demoted to
                SKIPPED (the finding itself is treated as invalid, same
                as a FALSE_POSITIVE status) instead of an agent actually
                firing requests at a URL nobody ever observed on the
                target. If spider_evidence isn't supplied, this check is
                skipped entirely (backward compatible).

        Returns:
            Decisions grouped by agent, e.g.:

                {
                    "XSS_AGENT": [RoutingDecision(...), ...],
                    "AUTHZ_AGENT": [RoutingDecision(...)],
                    "UNSUPPORTED": [RoutingDecision(...)],   # agent not wired in yet
                    "SKIPPED": [RoutingDecision(...)],       # e.g. false positives
                }

            Only groups that actually have entries are included, except the
            agent groups aren't pre-populated — a caller checking
            `groups.get("SQL_AGENT", [])` is expected either way.
        """
        groups: Dict[str, List[RoutingDecision]] = {}

        known_paths = (
            self._known_evidence_paths(spider_evidence)
            if spider_evidence is not None
            else None
        )
        known_target = (
            spider_evidence.get("meta", {}).get("target")
            if spider_evidence is not None
            else None
        )
        tls_audit = (
            spider_evidence.get("tls_audit")
            if spider_evidence is not None
            else None
        )

        for finding in report.get("candidates", []):
            self._normalize_endpoint_scheme(finding, known_target)
            self._restore_known_query_string(finding, spider_evidence)
            decision = self._route_one(finding, known_paths, tls_audit, spider_evidence)
            bucket = self._bucket_for(decision)
            groups.setdefault(bucket, []).append(decision)
            logger.info(decision)

        return groups

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------

    @staticmethod
    def _known_evidence_paths(spider_evidence: Dict[str, Any]) -> set:
        """
        Collect every URL/path path-component the crawler actually
        observed, normalized for comparison. Used to catch DeepHat
        routing findings to endpoints that were never in the evidence.
        """
        paths = set()

        def add(url_or_path):
            if not url_or_path or not isinstance(url_or_path, str):
                return
            try:
                p = urlparse(url_or_path).path or url_or_path
            except Exception:
                p = url_or_path
            p = p.rstrip("/") or "/"
            paths.add(p)
            # Also index the raw value as given (covers cases where
            # "endpoint" isn't a URL/path at all, e.g. a bare hostname).
            paths.add(url_or_path.rstrip("/") or "/")

        add(spider_evidence.get("meta", {}).get("target"))

        for t in spider_evidence.get("agent_targets", []) or []:
            add(t.get("url"))
            # A condensed agent_target (see SpiderExtractor._condense_
            # agent_targets) folds several near-identical URLs into one
            # representative plus a "sample_urls" list - those sample URLs
            # were literally shown to DeepHat in the prompt, so citing one
            # of them is grounded even though it isn't the representative
            # "url" itself.
            for sample_url in t.get("sample_urls", []) or []:
                add(sample_url)

        for p in spider_evidence.get("robots_allowed", []) or []:
            add(p)
        for p in spider_evidence.get("robots_disallowed", []) or []:
            add(p)

        for s in spider_evidence.get("secrets", []) or []:
            add(s.get("source"))

        for s in spider_evidence.get("sensitive_file_evidence", []) or []:
            add(s.get("url"))

        # These evidence arrays are dedicated pre-flagged signals (see
        # config.py rule 9c) that were previously never checked here —
        # meaning a candidate correctly citing one of them would have
        # been wrongly blocked as "not grounded" the moment DeepHat
        # actually started using them. None of these arrays have
        # appeared populated in any real scan yet, so their exact
        # per-entry shape isn't confirmed — handled defensively across
        # a few plausible field names (and raw strings) rather than
        # assuming one.
        for key in (
            "admin_panel_evidence", "idor_evidence", "sqli_evidence",
            "cmdi_evidence", "sensitive_data_source_evidence",
            "unauthenticated_api_evidence", "auth_required_evidence",
            "idor_sqli_overlap",
        ):
            for entry in spider_evidence.get(key, []) or []:
                if isinstance(entry, dict):
                    add(entry.get("url"))
                    add(entry.get("endpoint"))
                    add(entry.get("path"))
                elif isinstance(entry, str):
                    add(entry)

        return paths

    @staticmethod
    def _normalize_endpoint_scheme(finding: Dict[str, Any], known_target: Optional[str]) -> None:
        """
        Correct a fabricated http(s) scheme on a finding's endpoint before
        it can reach an agent that fires real network requests.

        The path-only comparison in _is_grounded() intentionally ignores
        scheme, so a candidate citing "https://host/" is treated as
        "grounded" even when the crawler only ever observed "http://host/"
        (or vice versa) — a small local model has been observed doing
        exactly this (e.g. citing HSTS-related evidence and silently
        upgrading the endpoint to https:// even when the crawler evidence
        explicitly recorded the target as http-only, no TLS available).
        That's not a routing problem, it's a fabricated-evidence problem:
        the endpoint string itself no longer matches what was observed.

        This only rewrites the scheme when the finding's host:port matches
        the known target's host:port exactly — it never touches an
        endpoint that legitimately points at a different host, since that
        is a routing/grounding question, not a scheme-fidelity one.
        """
        endpoint = finding.get("endpoint")
        if not endpoint or not isinstance(endpoint, str) or not known_target:
            return

        try:
            ep = urlparse(endpoint)
            known = urlparse(known_target)
        except Exception:
            return

        if not ep.scheme or not known.scheme:
            return
        if ep.scheme == known.scheme:
            return
        if ep.netloc != known.netloc:
            # Different host — leave it for the grounding check to judge,
            # don't assume it should match the primary target's scheme.
            return

        corrected = ep._replace(scheme=known.scheme).geturl()
        logger.warning(
            "Candidate '%s': endpoint scheme %r doesn't match the crawler-"
            "confirmed target scheme %r for the same host — correcting "
            "%r -> %r instead of dispatching an agent at an unverified URL.",
            finding.get("finding_id", "?"), ep.scheme, known.scheme, endpoint, corrected,
        )
        finding["endpoint"] = corrected

    @staticmethod
    def _restore_known_query_string(finding: Dict[str, Any], spider_evidence) -> None:
        """
        Confirmed real case (testaspnet.vulnweb.com, 2026-08-13): the only
        real evidence for this endpoint was "/Comments.aspx?id=0" — the
        crawler never observed a bare "/Comments.aspx" with no query
        string at all. DeepHat cited the endpoint as
        "/Comments.aspx" (query string dropped), which passed the
        grounding check fine (_is_grounded() intentionally compares paths
        only, ignoring query strings, by design), but this then routed
        AUTHZ_AGENT at a URL that was never actually evidenced and likely
        behaves completely differently (no "id" value could easily mean a
        different page entirely, a redirect, a 404 — not the endpoint
        anyone actually meant to test). This restores the query string
        from the matching evidence entry when the candidate's own
        endpoint has none, the same "correct rather than block" approach
        _normalize_endpoint_scheme takes for a wrong scheme.

        Only acts when there's exactly one distinct query string on
        record for that path — if the same path was observed with
        several different query strings (e.g. several different id
        values), which one DeepHat "meant" is genuinely ambiguous, so
        this leaves the endpoint alone rather than guessing.
        """
        if spider_evidence is None:
            return

        endpoint = finding.get("endpoint")
        if not endpoint or not isinstance(endpoint, str):
            return

        try:
            parsed = urlparse(endpoint)
        except Exception:
            return

        if parsed.query:
            return  # already has a query string, nothing to restore

        candidates = set()

        for t in spider_evidence.get("agent_targets", []) or []:
            url = t.get("url")
            if not url or not isinstance(url, str):
                continue
            try:
                t_parsed = urlparse(url)
            except Exception:
                continue
            if t_parsed.path == parsed.path and t_parsed.query:
                candidates.add(t_parsed.query)

        if len(candidates) == 1:
            restored_query = next(iter(candidates))
            corrected = parsed._replace(query=restored_query).geturl()
            logger.warning(
                "Candidate '%s': endpoint %r has no query string, but the "
                "only evidence for this path was observed WITH one "
                "(%r) — restoring it rather than dispatching an agent at "
                "an unevidenced bare-path variant.",
                finding.get("finding_id", "?"), endpoint, restored_query,
            )
            finding["endpoint"] = corrected

    @staticmethod
    def _is_grounded(endpoint: Any, known_paths: set) -> bool:
        if not endpoint or not isinstance(endpoint, str):
            # No endpoint claimed (e.g. a site-wide header finding) —
            # nothing to fabricate, so nothing to check.
            return True

        try:
            path = urlparse(endpoint).path or endpoint
        except Exception:
            path = endpoint

        path = path.rstrip("/") or "/"

        return path in known_paths or endpoint.rstrip("/") in known_paths

    # Path segments that identify an authentication *entry point* itself
    # (as opposed to a privileged endpoint that should require auth).
    # These pages are SUPPOSED to be reachable without prior authentication
    # — that's not a missing-authz signal, it's how they're designed to
    # work. config.py's SYSTEM_PROMPT already tells DeepHat not to route
    # these to AUTHZ_AGENT, but this has been observed not to hold
    # reliably in practice (e.g. routing "/login?return_to=..." to
    # AUTHZ_AGENT with reasoning "no auth requirement observed" — the
    # exact pattern the prompt says not to do). This is a deterministic
    # backstop for that specific prompt instruction, the same pattern as
    # _is_grounded() above: don't rely on the model to reliably follow a
    # rule that has a clear, checkable, always-correct answer in code.
    _AUTH_ENTRY_PATH_SEGMENTS = (
        "login", "log-in", "logon", "signin", "sign-in",
        "signup", "sign-up", "register", "registration",
    )

    @classmethod
    def _is_auth_entry_point(cls, endpoint: Any) -> bool:
        if not endpoint or not isinstance(endpoint, str):
            return False

        try:
            parsed = urlparse(endpoint)
            # SPA hash-routing (e.g. "/#/register", "/#/login") puts the
            # meaningful path in .fragment, not .path — check both so
            # client-side-routed auth pages aren't missed.
            combined = f"{parsed.path}/{parsed.fragment}".lower()
        except Exception:
            combined = endpoint.lower()

        segments = [s for s in combined.split("/") if s]

        return any(
            seg == marker or seg.startswith(marker + ".")
            for seg in segments
            for marker in cls._AUTH_ENTRY_PATH_SEGMENTS
        )

    # sqli.py's CLI (agents/sql_agent/sqli.py) has no flag at all for
    # specifying a POST body or method -- its "POST+JSON" testing is
    # only reachable through its own --crawl auto-discovery mode, which
    # this pipeline deliberately never uses (single-target --target mode
    # only, to avoid exactly the kind of scope explosion this guard now
    # prevents a different way). Confirmed real (steerwings.com
    # enq_back.php, 2026-08-14): SQL_AGENT routed a POST candidate whose
    # real evidenced parameter ("pid") lives in the request body, not the
    # URL's query string. The wrapper has no way to pass that parameter
    # to the tool, so it called sqli.py with a bare URL and no query
    # string -- triggering the tool's "nothing specified, guess 10
    # common params" fallback (the same fallback the word-boundary
    # candidate-builder fix addressed for a different root cause) and a
    # guaranteed 300s timeout, testing nothing. This isn't a one-off --
    # every future POST-body candidate will hit this identically until
    # the wrapper gains real POST-body support. Blocking it here is
    # strictly better than the current behavior: UNSUPPORTED is an
    # honest, immediate "can't test this yet," rather than a wasted
    # 5-minute timeout that reports a misleading FAILED status.
    @staticmethod
    def _is_untestable_post_body_candidate(finding: Dict[str, Any], method: Any) -> bool:
        if not isinstance(method, str) or method.upper() != "POST":
            return False

        parameter = finding.get("parameter")
        if not parameter:
            return False

        endpoint = finding.get("endpoint")
        if not isinstance(endpoint, str):
            return True

        try:
            query_params = parse_qs(urlparse(endpoint).query)
        except Exception:
            return True

        # If the evidenced parameter is ALSO present in the endpoint's
        # own query string, sqli.py's normal query-string testing path
        # still applies -- only block when the parameter is genuinely
        # body-only.
        return parameter not in query_params

    # config.py's SYSTEM_PROMPT explicitly tells DeepHat that a bare
    # "No_HTTPS" tls_audit entry is NOT a valid MITM_AGENT trigger on its
    # own — there's no TLS handshake for that agent's TLS-specific
    # detectors to inspect on a plain-HTTP target, so routing there
    # wastes a real agent run for no benefit (confirmed in practice: it
    # just produces a WinError 10061/connection-refused-shaped no-op,
    # or on a reachable target, zero TLS-relevant findings). Same as
    # _is_auth_entry_point above, this has been observed not to hold
    # reliably via prompt instruction alone — DeepHat routed a
    # No_HTTPS-only candidate to MITM_AGENT anyway, quoting the exact
    # "Target is HTTP only — no TLS" detail text the prompt says isn't
    # sufficient. This checks the REAL tls_audit array (ground truth)
    # rather than trying to parse DeepHat's evidence text, which may be
    # paraphrased.
    _TLS_CANDIDATE_TYPES = ("tls", "tls_audit", "tls_issues")

    @classmethod
    def _is_no_https_only_tls_candidate(cls, finding: Dict[str, Any], tls_audit) -> bool:
        is_tls_candidate = (
            str(finding.get("type", "")).lower() in cls._TLS_CANDIDATE_TYPES
            or str(finding.get("category", "")).lower() in cls._TLS_CANDIDATE_TYPES
        )
        if not is_tls_candidate:
            return False

        if not tls_audit:
            # No real tls_audit evidence at all to justify a TLS-category
            # candidate in the first place — treat the same as
            # No_HTTPS-only rather than silently allowing it through.
            return True

        real_issues = {
            str(entry.get("issue", "")) for entry in tls_audit if isinstance(entry, dict)
        }

        return real_issues.issubset({"No_HTTPS"})

    # See agents/agent_capabilities.py for why this replaced a
    # hardcoded reactive blocklist: that approach only ever caught a
    # mismatch after someone had already observed it happen once
    # (confirmed cases: SSRF/Open Redirect routed to MITM_AGENT, cookie
    # findings routed to AUTHZ_AGENT). The capability map is proactive —
    # it catches any candidate whose type/category positively belongs to
    # a different agent, including ones not yet specifically observed.
    @staticmethod
    def _is_known_category_mismatch(finding: Dict[str, Any], agent: str) -> bool:
        return is_capability_mismatch(
            finding.get("type"), finding.get("category"), agent
        )

    # config.py's rule 9c tells DeepHat about several dedicated
    # pre-flagged evidence arrays (idor_evidence, sqli_evidence,
    # cmdi_evidence, unauthenticated_api_evidence,
    # sensitive_data_source_evidence, auth_required_evidence,
    # admin_panel_evidence, idor_sqli_overlap) and when to cite them.
    # Confirmed real case (testaspnet.vulnweb.com, 2026-08-13): DeepHat
    # cited "auth_required_evidence: Comments.aspx" as evidence for an
    # AUTHZ_AGENT candidate — but the real auth_required_evidence array
    # was completely empty. This is the same fabrication pattern already
    # caught for tls_audit (inventing "TLS version 1.0 detected" language
    # when no TLS existed at all), just against a different evidence
    # field. The endpoint-grounding check alone can't catch this: the
    # endpoint itself was real, only the CITED EVIDENCE CONTENT about it
    # was invented.
    _EVIDENCE_ARRAY_FIELDS = (
        "idor_evidence", "sqli_evidence", "cmdi_evidence",
        "unauthenticated_api_evidence", "sensitive_data_source_evidence",
        "auth_required_evidence", "admin_panel_evidence",
        "idor_sqli_overlap",
    )

    @classmethod
    def _cites_empty_evidence_array(cls, finding: Dict[str, Any], spider_evidence) -> Optional[str]:
        if spider_evidence is None:
            return None

        evidence_text = " ".join(
            str(e) for e in (finding.get("evidence") or []) if e
        ).lower()

        if not evidence_text:
            return None

        for field in cls._EVIDENCE_ARRAY_FIELDS:
            if field not in evidence_text:
                continue
            real_array = spider_evidence.get(field)
            if not real_array:
                return field

        return None

    def _route_one(
        self,
        finding: Dict[str, Any],
        known_paths: Optional[set] = None,
        tls_audit: Optional[list] = None,
        spider_evidence: Optional[Dict[str, Any]] = None,
    ) -> RoutingDecision:
        finding_id = finding.get("finding_id")
        finding_type = finding.get("type")
        endpoint = finding.get("endpoint")
        status = finding.get("status")
        agent = finding.get("recommended_agent")
        evidence = finding.get("evidence") or []
        method = finding.get("method") or "GET"

        if status in _SKIP_STATUSES:
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=f"status={status}",
                evidence=evidence,
                method=method,
            )

        # Deliberately runs before the "no agent recommended" check below:
        # a candidate with recommended_agent=null still ends up in the
        # final report (as an UNSUPPORTED entry) even though no agent is
        # dispatched against it — so a fabricated evidence citation is
        # still a real problem worth catching here, not just for
        # candidates that would actually trigger an agent run. Confirmed
        # real case (testaspnet.vulnweb.com, 2026-08-13): a
        # recommended_agent=null candidate cited "idor_evidence:
        # Comments.aspx?id=0" — real idor_evidence was empty — and this
        # check previously never even ran for it, since it came after
        # the null-agent short-circuit.
        fabricated_field = self._cites_empty_evidence_array(finding, spider_evidence)
        if fabricated_field is not None:
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=(
                    f"Candidate's evidence cites {fabricated_field!r}, but "
                    f"the real {fabricated_field} array from this scan is "
                    f"empty — this evidence was fabricated, not observed. "
                    f"Blocked regardless of whether the endpoint itself is "
                    f"real, since the specific claim about it is not."
                ),
                evidence=evidence,
                method=method,
            )

        if not agent:
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=None,
                routed=False,
                reason="missing recommended_agent",
                evidence=evidence,
                method=method,
            )

        if agent not in SUPPORTED_AGENTS:
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=f"unsupported agent: {agent}",
                evidence=evidence,
                method=method,
            )

        if agent == "AUTHZ_AGENT" and self._is_auth_entry_point(endpoint):
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=(
                    f"AUTHZ_AGENT is not applicable to an authentication "
                    f"entry point itself (login/signup/register page) — "
                    f"being reachable without prior auth is expected, "
                    f"correct behavior for this endpoint: {endpoint!r}"
                ),
                evidence=evidence,
                method=method,
            )

        if agent == "SQL_AGENT" and self._is_untestable_post_body_candidate(finding, method):
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=(
                    f"SQL_AGENT cannot test this candidate: the evidenced "
                    f"parameter {finding.get('parameter')!r} lives in the "
                    f"POST request body, not the endpoint's URL query "
                    f"string, and the underlying tool's single-target CLI "
                    f"mode has no way to specify POST body data. Testing "
                    f"this correctly requires the tool's own crawl/form-"
                    f"discovery mode, which this pipeline deliberately "
                    f"does not use."
                ),
                evidence=evidence,
                method=method,
            )

        if agent == "MITM_AGENT" and self._is_no_https_only_tls_candidate(finding, tls_audit):
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=(
                    "MITM_AGENT is not applicable to a bare 'no HTTPS in "
                    "use' signal — there is no TLS handshake for this "
                    "agent's TLS-specific detectors to inspect on a "
                    "plain-HTTP target. This is a real, valid finding "
                    "(missing HTTPS), it's just not something an active "
                    "TLS/cert agent can meaningfully test."
                ),
                evidence=evidence,
                method=method,
            )

        if not finding.get("_builder_verified") and self._is_known_category_mismatch(finding, agent):
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=(
                    f"{agent} does not test this category of finding "
                    f"(type={finding_type!r}, category={finding.get('category')!r}) "
                    f"— its type/category belongs to a different agent's "
                    f"known capabilities (see pipeline/agent_capabilities.py). "
                    f"Blocked regardless of endpoint grounding since the "
                    f"agent choice itself is wrong, not the endpoint."
                ),
                evidence=evidence,
                method=method,
            )

        if known_paths is not None and not self._is_grounded(endpoint, known_paths):
            return RoutingDecision(
                finding_id=finding_id,
                type=finding_type,
                endpoint=endpoint,
                agent=agent,
                routed=False,
                reason=(
                    f"endpoint not grounded in crawler evidence "
                    f"(likely hallucinated): {endpoint!r}"
                ),
                evidence=evidence,
                method=method,
            )

        return RoutingDecision(
            finding_id=finding_id,
            type=finding_type,
            endpoint=endpoint,
            agent=agent,
            routed=True,
            evidence=evidence,
            method=method,
        )

    @staticmethod
    def _bucket_for(decision: RoutingDecision) -> str:
        """Which group a decision lands in within the returned dict."""
        if decision.routed:
            return decision.agent
        if decision.reason and decision.reason.startswith("unsupported agent"):
            return BUCKET_UNSUPPORTED
        if decision.reason and decision.reason == "missing recommended_agent":
            return BUCKET_UNSUPPORTED
        return BUCKET_SKIPPED


# ---------------------------------------------------------------------------
# Manual smoke test: python planner/planner.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    sample_report = {
        "scan_id": "SEC-2026-001",
        "target": "https://pentest-ground.com:9000",
        "summary": {
            "total_candidates": 4,
            "critical": 0,
            "high": 2,
            "medium": 1,
            "low": 1,
            "informational": 0,
        },
        "candidates": [
            {
                "finding_id": "SEC-001",
                "type": "SQL Injection",
                "endpoint": "/details.php?id=3",
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "UNVALIDATED",
                "recommended_agent": "SQL_AGENT",
            },
            {
                "finding_id": "SEC-002",
                "type": "Missing Security Headers",
                "endpoint": "/help",
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "status": "UNVALIDATED",
                "recommended_agent": "HEADERS_AGENT",
            },
            {
                "finding_id": "SEC-003",
                "type": "Reflected XSS",
                "endpoint": "/search?q=test",
                "severity": "LOW",
                "confidence": "LOW",
                "status": "FALSE_POSITIVE",
                "recommended_agent": "XSS_AGENT",
            },
            {
                "finding_id": "SEC-004",
                "type": "Insecure JWT Handling",
                "endpoint": "/api/token",
                "severity": "HIGH",
                "confidence": "MEDIUM",
                "status": "UNVALIDATED",
                "recommended_agent": "JWT_AGENT",  # not wired into the pipeline yet
            },
        ],
    }

    planner = Planner()
    groups = planner.route(sample_report)

    print()
    for bucket, decisions in groups.items():
        print(f"{bucket}: {len(decisions)} finding(s)")