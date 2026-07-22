"""
processing/spider_extractor.py

Converts a Hellhound Spider scan into a compact dict safe to json.dumps()
into a DeepHat prompt.

Unlike the earlier version, this one doesn't rely on fixed "N items" caps
tuned against one sample site. Different sites produce wildly different
data density (a marketing site vs. an intentionally-vulnerable test app
like testaspnet.vulnweb.com can have very different agent_targets/secrets
verbosity even with the same item count). So instead:

    1. Build the extracted context with generous starting caps.
    2. Measure its ACTUAL token count (via llama-server's /tokenize
       endpoint if reachable, else a conservative char-based estimate).
    3. If it's over budget, trim the least security-critical fields first,
       then trim agent_targets one at a time starting from the LOWEST
       priority_score (since the list is already sorted descending).
    4. Repeat until it fits, and log exactly what was dropped.

This makes the extractor's output size self-correcting for any site,
instead of requiring a new hand-tuned cap every time you scan somewhere
new.

Class name and extract() method match what chat.py already expects:
    extractor = SpiderExtractor()
    extracted_json = extractor.extract(spider_json)
    prompt = f"...{json.dumps(extracted_json, separators=(',', ':'))}..."
"""

import json
import requests


class SpiderExtractor:

    # Where llama-server's tokenizer endpoint lives. If unreachable
    # (server down, endpoint not exposed, etc.) we fall back to a
    # char-based estimate automatically - this never raises.
    TOKENIZE_URL = "http://127.0.0.1:8080/tokenize"

    # Target ceiling for THIS extracted context specifically - leaves
    # headroom in an 8192-token ctx-size for the system prompt (~200),
    # RAG-retrieved chunks (can be ~2000-2500), the task question, and
    # the reply (MAX_TOKENS). Adjust if you change --ctx-size.
    TOKEN_BUDGET = 4000

    # Conservative fallback when /tokenize isn't reachable. JSON is
    # punctuation-heavy (braces, quotes, colons), so tokens run a bit
    # denser than English prose - 3.3 chars/token is a safe overestimate
    # of token count (better to over-trim slightly than overflow).
    CHARS_PER_TOKEN_FALLBACK = 3.3

    # Generous starting caps - just enough to stop something absurd
    # (e.g. thousands of secrets) from even entering the trim loop.
    # The token-budget trimming below does the real work.
    MAX_AGENT_TARGETS = 30
    MAX_SECRETS = 15
    MAX_SUBDOMAINS = 20
    MAX_HEADER_AUDIT = 15
    MAX_WAF_FINDINGS = 8
    MAX_JS_ORPHAN_PARAMS = 10

    # NEW: filtered (not raw) endpoint evidence - these only ever include
    # endpoints that matched a specific candidate flag (idor/sqli/admin),
    # never the full 136-item endpoints list, so they stay small even on
    # a site with hundreds of endpoints.
    MAX_IDOR_EVIDENCE = 8
    MAX_SQLI_EVIDENCE = 8
    MAX_CMDI_EVIDENCE = 8
    MAX_ADMIN_PANEL_EVIDENCE = 10
    MAX_SENSITIVE_FILE_EVIDENCE = 8

    # Fields trimmed away entirely (down to a small floor) before we
    # ever touch agent_targets, since agent_targets is the highest-value
    # field for DeepHat's analysis and should be cut last.
    # Format: (field_name, minimum_floor_to_keep)
    DROP_ORDER = [
        ("js_orphan_params", 0),
        ("crt_subdomains", 0),
        ("waf_findings", 1),
        ("header_audit", 2),
        ("secrets", 2),
        ("admin_panel_evidence", 3),
        ("sensitive_file_evidence", 3),
    ]

    def __init__(self, token_budget=None):
        self.token_budget = token_budget or self.TOKEN_BUDGET

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, spider: dict) -> dict:

        extracted = self._build(spider)
        extracted, trimmed_log, final_tokens = self._fit_to_budget(extracted)

        if trimmed_log:
            print(
                f"[SpiderExtractor] Trimmed to fit ~{self.token_budget}-token budget "
                f"(final: ~{final_tokens} tokens): {', '.join(trimmed_log)}"
            )
        else:
            print(f"[SpiderExtractor] Context fits budget as-is (~{final_tokens} tokens).")

        return extracted

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _endpoint_evidence(self, endpoints, flag_key, limit):
        """Real url/method/params for endpoints flagged True on flag_key.
        Only ever returns matching items (never the full endpoints list),
        so this stays small regardless of total endpoint count."""
        matches = [e for e in endpoints if e.get(flag_key)]
        return [
            {
                "url": e.get("url"),
                "method": e.get("method", "GET"),
                "params": e.get("params", []),
            }
            for e in matches[:limit]
        ]

    def _admin_panel_evidence(self, endpoints, limit):
        matches = [e.get("url") for e in endpoints if e.get("admin_panel")]
        return matches[:limit]

    def _sensitive_file_evidence(self, sensitive_files, limit):
        return [
            {
                "url": f.get("url"),
                "type": f.get("type"),
                "severity": f.get("severity"),
                "preview": (f.get("preview") or "")[:150],
            }
            for f in sensitive_files[:limit]
        ]

    def _build(self, spider: dict) -> dict:

        extracted = {}

        extracted["meta"] = spider.get("meta", {})
        extracted["summary"] = spider.get("summary", {})
        extracted["tech_stack"] = spider.get("tech_stack", [])
        extracted["waf_findings"] = spider.get("waf_findings", [])[: self.MAX_WAF_FINDINGS]
        extracted["header_audit"] = spider.get("header_audit", [])[: self.MAX_HEADER_AUDIT]
        extracted["secrets"] = spider.get("secrets", [])[: self.MAX_SECRETS]
        extracted["graphql"] = spider.get("graphql", [])
        extracted["openapi"] = spider.get("openapi", [])
        extracted["robots_allowed"] = spider.get("robots_allowed", [])
        extracted["robots_disallowed"] = spider.get("robots_disallowed", [])
        extracted["crt_subdomains"] = spider.get("crt_subdomains", [])[: self.MAX_SUBDOMAINS]
        extracted["js_orphan_params"] = spider.get("js_orphan_params", [])[: self.MAX_JS_ORPHAN_PARAMS]

        # agent_targets is the crawler's own pre-filtered, highest-value
        # shortlist - sort by priority_score so trimming (if needed)
        # always drops the least interesting ones first.
        agent_targets = spider.get("agent_targets", [])
        agent_targets = sorted(
            agent_targets,
            key=lambda t: t.get("priority_score", 0),
            reverse=True,
        )
        extracted["agent_targets"] = agent_targets[: self.MAX_AGENT_TARGETS]

        # Never include the raw endpoints list - only its count. This is
        # what caused the original memory allocation crash.
        endpoints = spider.get("endpoints", [])
        extracted["raw_endpoint_count"] = len(endpoints)

        # NEW: real evidence for the candidate flags, filtered down from
        # the raw endpoints/sensitive_files lists so DeepHat sees actual
        # URLs+params instead of only bare counts like "idor_candidates: 3".
        extracted["idor_evidence"] = self._endpoint_evidence(
            endpoints, "idor_candidate", self.MAX_IDOR_EVIDENCE
        )
        extracted["sqli_evidence"] = self._endpoint_evidence(
            endpoints, "sqli_candidate", self.MAX_SQLI_EVIDENCE
        )
        extracted["cmdi_evidence"] = self._endpoint_evidence(
            endpoints, "cmdi_candidate", self.MAX_CMDI_EVIDENCE
        )
        extracted["admin_panel_evidence"] = self._admin_panel_evidence(
            endpoints, self.MAX_ADMIN_PANEL_EVIDENCE
        )
        extracted["sensitive_file_evidence"] = self._sensitive_file_evidence(
            spider.get("sensitive_files", []), self.MAX_SENSITIVE_FILE_EVIDENCE
        )

        # Flag overlap so DeepHat doesn't report the same parameter as two
        # unrelated findings (e.g. one "id" param flagged as both IDOR and
        # SQLi candidate is one weak spot, not two).
        idor_urls = {e["url"] for e in extracted["idor_evidence"]}
        sqli_urls = {e["url"] for e in extracted["sqli_evidence"]}
        extracted["idor_sqli_overlap"] = sorted(idor_urls & sqli_urls)

        return extracted

    def _count_tokens(self, obj) -> int:
        """Real token count via llama-server's /tokenize if reachable,
        else a conservative char-based estimate. Never raises."""

        text = json.dumps(obj, separators=(",", ":"))

        try:
            resp = requests.post(
                self.TOKENIZE_URL,
                json={"content": text},
                timeout=5,
            )
            if resp.status_code == 200:
                tokens = resp.json().get("tokens", [])
                if tokens:
                    return len(tokens)
        except Exception:
            pass

        return int(len(text) / self.CHARS_PER_TOKEN_FALLBACK)

    def _fit_to_budget(self, extracted: dict):

        trimmed_log = []
        token_count = self._count_tokens(extracted)

        if token_count <= self.token_budget:
            return extracted, trimmed_log, token_count

        # Phase 1: drop whole low-value fields down to their floor first.
        # agent_targets is deliberately NOT in this list - it's the most
        # security-relevant field and gets trimmed last, one item at a time.
        for field, floor in self.DROP_ORDER:
            if token_count <= self.token_budget:
                break
            current = extracted.get(field, [])
            if len(current) > floor:
                removed = len(current) - floor
                extracted[field] = current[:floor]
                trimmed_log.append(f"{field} (-{removed})")
                token_count = self._count_tokens(extracted)

        # Phase 2: trim agent_targets one at a time from the bottom
        # (lowest priority_score first, since sorted descending).
        removed_targets = 0
        while token_count > self.token_budget and len(extracted.get("agent_targets", [])) > 3:
            extracted["agent_targets"].pop()
            removed_targets += 1
            token_count = self._count_tokens(extracted)

        if removed_targets:
            trimmed_log.append(f"agent_targets (-{removed_targets})")

        return extracted, trimmed_log, token_count


if __name__ == "__main__":
    # Quick self-test: python spider_extractor.py <spider_output.json> [token_budget]
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else None
    budget = int(sys.argv[2]) if len(sys.argv) > 2 else None

    if not path:
        print("Usage: python spider_extractor.py <spider_output.json> [token_budget]")
        sys.exit(1)

    with open(path, "r", encoding="utf-8") as f:
        spider_json = json.load(f)

    extractor = SpiderExtractor(token_budget=budget)
    result = extractor.extract(spider_json)

    dumped = json.dumps(result, separators=(",", ":"))
    print(f"\nFinal JSON size: {len(dumped)} characters")