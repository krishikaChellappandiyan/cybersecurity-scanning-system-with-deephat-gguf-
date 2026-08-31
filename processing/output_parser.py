"""
processing/output_parser.py

Single responsibility: convert the raw string returned by DeepHat into a
validated, normalized Python dictionary.

Pipeline position:

    DeepHat (raw string)
          |
          v
    OutputParser.parse()
          |
          v
    Python dict (validated + normalized)
          |
          v
    Planner

Stages:

    extract_json_block()
          |
          v
    load_json()
          |
          v
    validate_top_level()
          |
          v
    validate_candidates()
          |
          v
    normalize()

This module does NOT call DeepHat, run agents, generate reports, or route
candidates. It only parses and validates.
"""

from __future__ import annotations

import json
import re
import logging
import hashlib
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OutputParserError(ValueError):
    """Base exception for all output parsing/validation failures."""


class InvalidJSONError(OutputParserError):
    """Raised when the raw LLM output could not be parsed as JSON at all."""


class SchemaValidationError(OutputParserError):
    """Raised when parsed JSON is missing required fields or uses invalid values."""


# ---------------------------------------------------------------------------
# Schema definition (kept in one place so it's easy to freeze/extend)
# ---------------------------------------------------------------------------

REQUIRED_TOP_LEVEL_FIELDS = ("scan_id", "target", "summary", "candidates")

# Matches DeepHat's actual candidate schema (a proposal to test, not a
# confirmed vulnerability — see config.py's SYSTEM_PROMPT):
# {
#   "finding_id": "...", "type": "...", "category": "...", "endpoint": "...",
#   "method": "...", "parameter": "...", "severity": "...", "confidence": "...",
#   "status": "...", "evidence": [], "reasoning": "...", "recommended_agent": "..."
# }
REQUIRED_FINDING_FIELDS = (
    "finding_id",
    "type",
    "endpoint",
    "severity",
    "confidence",
    "status",
    "recommended_agent",
)

# Canonical value sets. These are DISTINCT concepts and must not be merged:
#   - severity   -> how bad the issue is if real
#   - confidence -> how sure the model is that this candidate is worth routing
#   - status     -> where the candidate is in the validation lifecycle
VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
VALID_CONFIDENCE = ("HIGH", "MEDIUM", "LOW")
VALID_STATUS = ("UNVALIDATED", "VALIDATING", "CONFIRMED", "FALSE_POSITIVE")

# Only harmless spelling/formatting variants are aliased here — never
# aliases that change meaning across concepts (e.g. confidence "CONFIRMED"
# is NOT mapped to HIGH; that would silently conflate confidence and status).
_SEVERITY_ALIASES = {
    "CRIT": "CRITICAL",
    "SEVERE": "CRITICAL",
    "MED": "MEDIUM",
    "MODERATE": "MEDIUM",
    "MINOR": "LOW",
    "INFO": "INFORMATIONAL",
    "NONE": "INFORMATIONAL",
}

_CONFIDENCE_ALIASES = {
    # formatting-only variants, same meaning
    "HIGH CONFIDENCE": "HIGH",
    "MEDIUM CONFIDENCE": "MEDIUM",
    "LOW CONFIDENCE": "LOW",
}

_STATUS_ALIASES = {
    "PENDING": "UNVALIDATED",
    "UNCONFIRMED": "UNVALIDATED",
    "IN_PROGRESS": "VALIDATING",
    "VALIDATED": "CONFIRMED",
    "FALSE POSITIVE": "FALSE_POSITIVE",
    "FALSEPOSITIVE": "FALSE_POSITIVE",
}

# Canonical agent identifiers the Planner is allowed to route to. Extend
# this list as new agents are wrapped (Step 6+ of the roadmap).
VALID_AGENTS = (
    "SQL_AGENT",
    "XSS_AGENT",
    "HEADERS_AGENT",
    "AUTHZ_AGENT",
    "PASSWORD_POLICY_AGENT",
    "SAST_AGENT",
    "MITM_AGENT",
    "NOSQL_AGENT",
    "PARAM_INJECTION_AGENT",
)

# Free-text variants DeepHat might emit, mapped onto the canonical set above.
# Keys are upper-cased before lookup, so casing/spacing is the only thing
# that needs covering here.
_AGENT_ALIASES = {
    "SQL AGENT": "SQL_AGENT",
    "SQLAGENT": "SQL_AGENT",
    "SQL INJECTION AGENT": "SQL_AGENT",
    "XSS AGENT": "XSS_AGENT",
    "XSSAGENT": "XSS_AGENT",
    "HEADERS AGENT": "HEADERS_AGENT",
    "HEADERSAGENT": "HEADERS_AGENT",
    "HEADER AGENT": "HEADERS_AGENT",
    "SECURITY HEADERS AGENT": "HEADERS_AGENT",
    "AUTHZ AGENT": "AUTHZ_AGENT",
    "AUTHZAGENT": "AUTHZ_AGENT",
    "MISSING AUTHZ AGENT": "AUTHZ_AGENT",
    "AUTHORIZATION AGENT": "AUTHZ_AGENT",
    "PASSWORD POLICY AGENT": "PASSWORD_POLICY_AGENT",
    "PASSWORDPOLICYAGENT": "PASSWORD_POLICY_AGENT",
    "PASSWORD AGENT": "PASSWORD_POLICY_AGENT",
    "SAST AGENT": "SAST_AGENT",
    "SASTAGENT": "SAST_AGENT",
    "STATIC ANALYSIS AGENT": "SAST_AGENT",
    "MITM AGENT": "MITM_AGENT",
    "MITMAGENT": "MITM_AGENT",
    "MAN IN THE MIDDLE AGENT": "MITM_AGENT",
    "PASSIVE OBSERVER AGENT": "MITM_AGENT",
    "NOSQL AGENT": "NOSQL_AGENT",
    "NOSQLAGENT": "NOSQL_AGENT",
    "NOSQL INJECTION AGENT": "NOSQL_AGENT",
    "NO SQL AGENT": "NOSQL_AGENT",
    "MONGODB AGENT": "NOSQL_AGENT",
    "MONGO AGENT": "NOSQL_AGENT",
    "PARAM INJECTION AGENT": "PARAM_INJECTION_AGENT",
    "PARAMETER INJECTION AGENT": "PARAM_INJECTION_AGENT",
    "PARAMINJECTIONAGENT": "PARAM_INJECTION_AGENT",
    "SSRF AGENT": "PARAM_INJECTION_AGENT",
    "SSTI AGENT": "PARAM_INJECTION_AGENT",
    "INJECTION AGENT": "PARAM_INJECTION_AGENT",
}


class OutputParser:
    """Parses and validates DeepHat's raw output into a normalized dict."""

    def parse(self, llm_output: str, strict: bool = True) -> Dict[str, Any]:
        """
        Convert DeepHat's raw string output into a validated Python dict.

        Args:
            llm_output: Raw string returned by the model (may contain
                        markdown code fences or stray text around the JSON).
            strict:     If True, raise on any missing/invalid required field.
                        If False, log a warning and fill in safe defaults
                        instead of raising (useful during early integration
                        while DeepHat's output format is still settling).

        Returns:
            A validated, normalized dict with keys:
                scan_id, target, summary, candidates (list of dicts)

        Raises:
            InvalidJSONError: if no valid JSON object could be extracted.
            SchemaValidationError: if strict=True and required fields/values
                are missing or invalid.
        """
        raw = self._extract_json_block(llm_output)
        report = self._load_json(raw)

        if not isinstance(report, dict):
            raise InvalidJSONError(
                f"Expected a JSON object at top level, got {type(report).__name__}"
            )

        self._validate_top_level(report, strict=strict)
        report["candidates"] = self._validate_and_normalize_findings(
            report.get("candidates", []), strict=strict
        )
        self._validate_summary_consistency(report, strict=strict)

        return report

    # -----------------------------------------------------------------
    # Step 1: extract JSON from potentially messy LLM output
    # -----------------------------------------------------------------

    @staticmethod
    def _extract_json_block(llm_output: str) -> str:
        """
        LLMs frequently wrap JSON in ```json ... ``` fences, or prepend
        commentary before/after the object. This pulls out the most likely
        JSON substring so json.loads() has a clean shot at it.
        """
        if not llm_output or not llm_output.strip():
            raise InvalidJSONError("DeepHat returned empty output.")

        text = llm_output.strip()

        # 1. Prefer a fenced code block if one exists.
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if fence_match:
            return fence_match.group(1)

        # 2. Otherwise, fall back to the first top-level {...} block by
        #    matching from the first '{' to the last '}'. This tolerates
        #    stray text like "Sure, here's the report:" before the JSON.
        first_brace = text.find("{")
        last_brace = text.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            return text[first_brace:last_brace + 1]

        # 3. Nothing that looks like JSON at all.
        return text

    # -----------------------------------------------------------------
    # Step 2: parse JSON
    # -----------------------------------------------------------------

    @staticmethod
    def _load_json(raw: str) -> Any:
        try:
            return json.loads(raw)
        except json.JSONDecodeError as e:
            raise InvalidJSONError(f"Invalid JSON returned by DeepHat: {e}") from e

    # -----------------------------------------------------------------
    # Step 3: validate top-level required fields
    # -----------------------------------------------------------------

    def _validate_top_level(self, report: Dict[str, Any], strict: bool) -> None:
        missing = [f for f in REQUIRED_TOP_LEVEL_FIELDS if f not in report]

        if missing:
            msg = f"Missing required top-level field(s): {missing}"
            if strict:
                raise SchemaValidationError(msg)
            logger.warning("%s — filling defaults (non-strict mode).", msg)
            for field in missing:
                report[field] = [] if field == "candidates" else ""

        if not isinstance(report.get("candidates"), list):
            msg = f"'candidates' must be a list, got {type(report.get('candidates')).__name__}"
            if strict:
                raise SchemaValidationError(msg)
            logger.warning("%s — resetting to empty list (non-strict mode).", msg)
            report["candidates"] = []

    # -----------------------------------------------------------------
    # Step 4: validate + normalize each finding
    # -----------------------------------------------------------------

    def _validate_and_normalize_findings(
        self, findings: List[Any], strict: bool
    ) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []

        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                msg = f"Candidate at index {i} is not an object: {finding!r}"
                if strict:
                    raise SchemaValidationError(msg)
                logger.warning("%s — skipping.", msg)
                continue

            missing = [f for f in REQUIRED_FINDING_FIELDS if f not in finding]
            if missing:
                msg = (
                    f"Finding at index {i} (finding_id={finding.get('finding_id', '?')}) "
                    f"missing required field(s): {missing}"
                )
                if strict:
                    raise SchemaValidationError(msg)
                logger.warning("%s — filling defaults (non-strict mode).", msg)
                for field in missing:
                    finding[field] = None

            finding["severity"] = self._normalize_bucket(
                finding.get("severity"),
                VALID_SEVERITIES,
                _SEVERITY_ALIASES,
                field_name="severity",
                finding_id=finding.get("finding_id", f"index {i}"),
                strict=strict,
            )
            finding["confidence"] = self._normalize_bucket(
                finding.get("confidence"),
                VALID_CONFIDENCE,
                _CONFIDENCE_ALIASES,
                field_name="confidence",
                finding_id=finding.get("finding_id", f"index {i}"),
                strict=strict,
            )
            finding["status"] = self._normalize_bucket(
                finding.get("status"),
                VALID_STATUS,
                _STATUS_ALIASES,
                field_name="status",
                finding_id=finding.get("finding_id", f"index {i}"),
                strict=strict,
            )
            finding["recommended_agent"] = self._normalize_agent(
                finding.get("recommended_agent"),
                finding_id=finding.get("finding_id", f"index {i}"),
                strict=strict,
            )

            # DeepHat's own finding_id is untrustworthy in two ways:
            # it's often a plain incrementing "1"/"2" (collision-prone
            # across separate runs — meaningless as a stable identifier),
            # and it has been observed inventing CVE-shaped IDs
            # ("CVE-2023-12345") for candidates that were never matched
            # against any real CVE database — which falsely implies a
            # cataloged, verified vulnerability. Rather than rely on a
            # prompt instruction not to do this (the same category of
            # fix that's repeatedly failed to hold reliably elsewhere in
            # this pipeline), the ID actually used everywhere downstream
            # is now always deterministically derived here, regardless
            # of what DeepHat supplied. Same endpoint+type+method always
            # produces the same ID, so retries/re-scans of the same real
            # finding are stable and comparable. DeepHat's original value
            # is kept under _deephat_finding_id for debugging only — it
            # is never used for routing, deduplication, or display.
            original_id = finding.get("finding_id")
            finding["_deephat_finding_id"] = original_id

            id_source = "|".join([
                str(finding.get("endpoint") or ""),
                str(finding.get("type") or ""),
                str(finding.get("method") or ""),
                str(finding.get("parameter") or ""),
            ])
            digest = hashlib.sha256(id_source.encode("utf-8")).hexdigest()[:10]
            finding["finding_id"] = f"CAND-{digest}"

            normalized.append(finding)

        # Deduplication is a natural side effect of deterministic IDs:
        # two candidates for the same real endpoint+type+method+parameter
        # now always produce the same finding_id, so a collision here is
        # a genuine duplicate (DeepHat proposing the same thing twice),
        # not two different candidates that happened to share an ID.
        # Keep the first occurrence — findings are processed in the order
        # DeepHat returned them, so this preserves whichever one it
        # listed first rather than an arbitrary pick.
        seen_ids = set()
        deduplicated = []
        for finding in normalized:
            fid = finding["finding_id"]
            if fid in seen_ids:
                continue
            seen_ids.add(fid)
            deduplicated.append(finding)

        return deduplicated

    # -----------------------------------------------------------------
    # Step 5: cross-check summary against actual candidates
    # -----------------------------------------------------------------

    def _validate_summary_consistency(self, report: Dict[str, Any], strict: bool) -> None:
        summary = report.get("summary")
        findings = report.get("candidates", [])

        # summary must always be an object per the frozen schema:
        # { total_candidates, critical, high, medium, low, informational }
        if not isinstance(summary, dict):
            msg = f"'summary' must be an object, got {type(summary).__name__}."
            if strict:
                raise SchemaValidationError(msg)
            logger.warning("%s — resetting to empty object (non-strict mode).", msg)
            report["summary"] = {}
            return

        actual = len(findings)
        claimed_total = summary.get("total_candidates")

        if claimed_total is not None and claimed_total != actual:
            msg = (
                f"Summary/candidates mismatch: summary.total_candidates={claimed_total} "
                f"but candidates array has {actual} item(s)."
            )
            # Not raised even in strict mode: this is now expected to
            # happen legitimately whenever deduplication removes a
            # candidate (see _validate_and_normalize_findings) — DeepHat's
            # claimed count described the pre-dedup list, which is stale
            # by design, not malformed. The recompute logic a few lines
            # below (for the severity breakdown) already corrects
            # total_candidates from the real post-dedup list; raising
            # here would burn a full local-model retry to "fix" something
            # that's already handled.
            logger.warning("%s — will be recomputed from the actual candidates list.", msg)

        # Cross-check that the per-severity breakdown adds up. Missing keys
        # are treated as 0 rather than triggering their own error, since the
        # important signal here is the arithmetic, not key presence.
        severity_keys = ("critical", "high", "medium", "low", "informational")
        if any(k in summary for k in severity_keys) and claimed_total is not None:
            expected = sum(summary.get(k, 0) or 0 for k in severity_keys)
            if expected != claimed_total:
                msg = (
                    f"Summary severity breakdown does not add up: "
                    f"critical+high+medium+low+informational={expected} "
                    f"but total_candidates={claimed_total}."
                )
                if strict:
                    raise SchemaValidationError(msg)
                logger.warning("%s — DeepHat's summary may be unreliable; check the prompt.", msg)

        # The arithmetic check above only proves the summary's own numbers
        # are internally consistent with each other — it does NOT prove
        # those numbers describe the actual candidates returned. A small
        # local model can (and does, in practice) emit a summary bucket
        # that doesn't match any single candidate's own "severity" field —
        # e.g. one HIGH-severity candidate but summary.high=0 and
        # summary.informational=1. That's a real, silent misreport: anyone
        # reading only the summary (a dashboard, a report header) would
        # undercount HIGH findings. So recompute the per-severity counts
        # directly from the (already-normalized) candidates and compare.
        severity_to_summary_key = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFORMATIONAL": "informational",
        }
        actual_counts = {key: 0 for key in severity_to_summary_key.values()}
        for f in findings:
            key = severity_to_summary_key.get(f.get("severity"))
            if key is not None:
                actual_counts[key] += 1

        mismatched = {
            key: (summary.get(key, 0) or 0, actual_counts[key])
            for key in actual_counts
            if key in summary and (summary.get(key, 0) or 0) != actual_counts[key]
        }
        if mismatched:
            details = ", ".join(
                f"{key}: summary says {claimed}, candidates actually contain {real}"
                for key, (claimed, real) in mismatched.items()
            )
            # Unlike the total_candidates check above, this one is always
            # auto-corrected rather than raised even in strict mode: the
            # ground truth (each candidate's own "severity" field) already
            # went through _normalize_bucket and is trustworthy, so there's
            # nothing ambiguous to fail a retry over. Making this fatal in
            # strict mode would just burn a full local-model regeneration
            # (see chat.py's MAX_DEEPHAT_ATTEMPTS retry loop) to fix
            # something five lines of arithmetic already knows how to fix.
            logger.warning(
                "Summary severity counts don't match the candidates' own "
                "'severity' fields (%s) — overwriting summary with the "
                "counts recomputed from the candidates themselves.", details
            )
            for key, count in actual_counts.items():
                if key in summary:
                    summary[key] = count
            if "total_candidates" in summary:
                summary["total_candidates"] = len(findings)

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _normalize_bucket(
        value: Any,
        valid_values: tuple,
        aliases: Dict[str, str],
        field_name: str,
        finding_id: Any,
        strict: bool,
    ):
        """
        Uppercase + map formatting-only variants onto the canonical set for
        this field. Unlike a generic normalizer, this NEVER maps a value
        across concepts (e.g. a confidence value onto a status value).
        An unrecognized value is a signal the prompt/schema drifted, not
        something to silently paper over.
        """
        if not value or not isinstance(value, str):
            msg = f"Candidate '{finding_id}': missing or non-string '{field_name}'."
            if strict:
                raise SchemaValidationError(msg)
            logger.warning("%s — defaulting to None.", msg)
            return None

        cleaned = value.strip().upper()

        if cleaned in valid_values:
            return cleaned
        if cleaned in aliases:
            return aliases[cleaned]

        msg = (
            f"Candidate '{finding_id}': invalid '{field_name}' value '{value}'. "
            f"Expected one of {valid_values}."
        )
        if strict:
            raise SchemaValidationError(msg)
        logger.warning("%s — leaving as-is; check DeepHat's prompt/schema.", msg)
        return cleaned

    @staticmethod
    def _normalize_agent(value: Any, finding_id: Any, strict: bool):
        """
        Normalize 'recommended_agent'. Unlike severity/confidence/status,
        this field is legitimately nullable: DeepHat returns null when a
        finding doesn't warrant routing to any follow-up agent (e.g. a
        LOW-severity informational disclosure). Only a *present but
        non-string, non-null* value (e.g. a number or object) or an
        unrecognized agent name is treated as a schema problem.
        """
        if value is None:
            return None

        if not isinstance(value, str):
            msg = f"Candidate '{finding_id}': 'recommended_agent' must be a string or null, got {type(value).__name__}."
            if strict:
                raise SchemaValidationError(msg)
            logger.warning("%s — defaulting to None.", msg)
            return None

        cleaned = value.strip().upper()
        if not cleaned or cleaned in ("NONE", "N/A", "NULL"):
            return None

        if cleaned in VALID_AGENTS:
            return cleaned
        if cleaned in _AGENT_ALIASES:
            return _AGENT_ALIASES[cleaned]

        msg = (
            f"Candidate '{finding_id}': invalid 'recommended_agent' value '{value}'. "
            f"Expected one of {VALID_AGENTS} or null."
        )
        if strict:
            raise SchemaValidationError(msg)
        logger.warning("%s — leaving as-is; check DeepHat's prompt/schema.", msg)
        return cleaned


# ---------------------------------------------------------------------------
# Manual smoke test: python processing/output_parser.py
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sample_output = """
    Sure, here is the structured report:

    ```json
    {
      "scan_id": "SEC-2026-001",
      "target": "https://pentest-ground.com:9000",
      "summary": {
        "total_candidates": 2,
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "informational": 0
      },
      "candidates": [
        {
          "finding_id": "SEC-001",
          "type": "SQL Injection",
          "category": "Injection",
          "endpoint": "/details.php?id=3",
          "method": "GET",
          "parameter": "id",
          "severity": "high",
          "confidence": "high",
          "status": "unvalidated",
          "evidence": [],
          "reasoning": "Numeric parameter reflected without apparent sanitization.",
          "recommended_agent": "SQL Agent"
        },
        {
          "finding_id": "SEC-002",
          "type": "Missing Security Headers",
          "category": "Security Misconfiguration",
          "endpoint": "/help",
          "method": "GET",
          "parameter": null,
          "severity": "med",
          "confidence": "medium",
          "status": "unvalidated",
          "evidence": [],
          "reasoning": "CSP and X-Frame-Options headers absent.",
          "recommended_agent": "HeadersAgent"
        }
      ]
    }
    ```
    """

    parser = OutputParser()
    report = parser.parse(sample_output)

    print(type(report))
    print(json.dumps(report, indent=2))