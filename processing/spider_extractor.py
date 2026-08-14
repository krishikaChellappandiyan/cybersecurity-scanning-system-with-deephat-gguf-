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

CHANGE (2026-08-02): "graphql" and "openapi" used to be copied straight
from the spider report with no cap at all - the only two fields in this
file that bypassed the budget system entirely. On a Shopify/GraphQL-heavy
target this alone produced a 16k+ token prompt against an 8k ctx-size and
crashed the request. They're now SUMMARIZED (endpoint counts + a filtered
shortlist of auth/payment/PII-sounding query & mutation names) instead of
dumped raw, and both now sit in DROP_ORDER as a safety net so the trim
loop can still shrink them further on an unusually large schema.

Class name and extract() method match what chat.py already expects:
    extractor = SpiderExtractor()
    extracted_json = extractor.extract(spider_json)
    prompt = f"...{json.dumps(extracted_json, separators=(',', ':'))}..."
"""

import json
import requests
from typing import Dict
from urllib.parse import urlparse, parse_qs

# Pull the real numbers this budget depends on, instead of a hand-typed
# guess that goes stale every time SYSTEM_PROMPT/ANALYSIS_PROMPT grows
# (which happened: this crashed a real scan once the accumulated agent
# trigger-criteria text pushed system+task overhead to ~4300+ tokens,
# far past the ~1500 this budget used to assume). If config.py isn't
# importable (e.g. running this file standalone from outside the
# project root), fall back to the old conservative numbers rather than
# failing outright — CLI callers can still override via `--token-budget`.
try:
    from config import CTX_SIZE, MAX_TOKENS, SYSTEM_PROMPT, ANALYSIS_PROMPT
    _CONFIG_AVAILABLE = True
except ImportError:
    CTX_SIZE, MAX_TOKENS, SYSTEM_PROMPT, ANALYSIS_PROMPT = 8192, 2500, "", ""
    _CONFIG_AVAILABLE = False


class SpiderExtractor:

    # Where llama-server's tokenizer endpoint lives. If unreachable
    # (server down, endpoint not exposed, etc.) we fall back to a
    # char-based estimate automatically - this never raises.
    TOKENIZE_URL = "http://127.0.0.1:8080/tokenize"

    # Conservative fallback when /tokenize isn't reachable. JSON is
    # punctuation-heavy (braces, quotes, colons), so tokens run a bit
    # denser than English prose - 3.3 chars/token is a safe overestimate
    # of token count (better to over-trim slightly than overflow).
    CHARS_PER_TOKEN_FALLBACK = 3.3

    # Fixed per-request overhead beyond system+task+evidence text itself:
    # chat-template special tokens (role markers etc.) that /v1/chat/
    # completions adds per message, plus a safety margin since the
    # char-based estimate below is approximate. Better to under-fill the
    # context slightly than overflow it again.
    _REQUEST_OVERHEAD_TOKENS = 400

    @classmethod
    def _default_token_budget(cls) -> int:
        """
        TOKEN_BUDGET = how many tokens are left for spider evidence once
        the context window (CTX_SIZE) has system prompt + analysis task
        text + the reserved completion budget (MAX_TOKENS) + per-request
        overhead all subtracted out. Recomputes from the real current
        prompt text every time instead of a hardcoded guess, so it can't
        silently drift out of date the way the old fixed 4500 did.
        """
        system_task_chars = len(SYSTEM_PROMPT) + len(ANALYSIS_PROMPT)
        system_task_tokens = round(system_task_chars / cls.CHARS_PER_TOKEN_FALLBACK)

        budget = CTX_SIZE - MAX_TOKENS - system_task_tokens - cls._REQUEST_OVERHEAD_TOKENS

        # Never go negative or absurdly small even in a misconfigured
        # setup — clamp to a minimum that still lets *some* evidence
        # through rather than producing an empty, useless prompt.
        return max(budget, 300)

    # Populated right after the class definition below, via
    # _default_token_budget(). Computed from current config.py values at
    # import time — if you change --ctx-size, MAX_TOKENS, or grow
    # SYSTEM_PROMPT/ANALYSIS_PROMPT, this recalculates automatically the
    # next time the process starts. No manual arithmetic, no stale
    # comments to remember to update.
    TOKEN_BUDGET = 300  # placeholder; overwritten right after the class body

    # Generous starting caps - just enough to stop something absurd
    # (e.g. thousands of secrets) from even entering the trim loop.
    # The token-budget trimming below does the real work.
    MAX_AGENT_TARGETS = 30
    MAX_SECRETS = 15
    MAX_SUBDOMAINS = 20
    MAX_HEADER_AUDIT = 15
    MAX_WAF_FINDINGS = 8
    MAX_JS_ORPHAN_PARAMS = 10

    # Filtered (not raw) endpoint evidence - these only ever include
    # endpoints that matched a specific candidate flag (idor/sqli/admin),
    # never the full endpoints list, so they stay small even on
    # a site with hundreds of endpoints.
    MAX_IDOR_EVIDENCE = 8
    MAX_SQLI_EVIDENCE = 8
    MAX_CMDI_EVIDENCE = 8
    MAX_ADMIN_PANEL_EVIDENCE = 10
    MAX_SENSITIVE_FILE_EVIDENCE = 8
    MAX_SENSITIVE_DATA_SOURCE_EVIDENCE = 8
    MAX_UNAUTHENTICATED_API_EVIDENCE = 8
    MAX_AUTH_REQUIRED_EVIDENCE = 8

    # GraphQL/OpenAPI schemas can be arbitrarily large (a Storefront API
    # schema alone can be 300+ fields). Never include the raw schema -
    # summarize it: how many queries/mutations/paths exist, plus a
    # filtered shortlist of ones that sound auth/payment/PII-relevant.
    MAX_GRAPHQL_ENDPOINTS = 5
    MAX_GRAPHQL_SENSITIVE_ITEMS = 20
    MAX_OPENAPI_SPECS = 5
    MAX_OPENAPI_SENSITIVE_PATHS = 20

    # Keyword list used to shortlist "interesting" GraphQL query/mutation
    # names and OpenAPI paths out of a potentially huge schema. This is a
    # relevance filter for what DeepHat sees, not a vulnerability claim -
    # DeepHat still has to reason about whether any of these are actually
    # exploitable from the evidence given.
    SENSITIVE_NAME_KEYWORDS = (
        "password", "token", "auth", "login", "logout", "session",
        "customer", "account", "address", "payment", "card", "billing",
        "secret", "credential", "admin", "delete", "reset", "email",
        "personal", "ssn", "credit", "otp", "mfa", "2fa", "apikey",
        "api_key", "private", "internal", "impersonate", "sudo",
    )

    # Fields trimmed away entirely (down to a small floor) before we
    # ever touch agent_targets, since agent_targets is the highest-value
    # field for DeepHat's analysis and should be cut last.
    # Format: (field_name, minimum_floor_to_keep)
    DROP_ORDER = [
        ("js_orphan_params", 0),
        ("crt_subdomains", 0),
        ("waf_findings", 1),
        ("header_audit", 2),
        ("tls_audit", 2),
        ("secrets", 2),
        ("graphql", 1),
        ("openapi", 1),
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
    # Internal helpers - agent_targets condensing (NEW)
    # ------------------------------------------------------------------

    # Fields kept per agent_target after condensing. Deliberately drops
    # params_detail/form_fields_detail/observed_values: those are just a
    # more verbose re-statement of the same info already in "params", and
    # on a real WordPress-style site every post page repeats the exact
    # same generic comment-form/search-box param breakdown verbatim, so
    # keeping the nested detail multiplies token cost for zero new signal.
    _AGENT_TARGET_KEEP_KEYS = (
        "url", "method", "confidence", "params", "priority_score", "source",
    )
    # Boolean/near-boolean flags only included when truthy, since a page
    # like the one above is auth_required=False, file_upload_candidate=
    # False, etc. on every single one of 300 pages - printing "False" 300
    # times is pure waste. legacy_reason is only meaningful when
    # legacy_endpoint is True, so it rides along with it.
    _AGENT_TARGET_FLAG_KEYS = (
        "auth_required", "file_upload_candidate", "unauthenticated_api",
        "sensitive_data_source", "legacy_endpoint",
    )

    def _slim_agent_target(self, t: dict) -> dict:
        slim = {k: t.get(k) for k in self._AGENT_TARGET_KEEP_KEYS if t.get(k) not in (None, [], "")}
        for k in self._AGENT_TARGET_FLAG_KEYS:
            if t.get(k):
                slim[k] = True
                if k == "legacy_endpoint" and t.get("legacy_reason"):
                    slim["legacy_reason"] = t["legacy_reason"]
        if t.get("sensitive_signals"):
            slim["sensitive_signals"] = t["sensitive_signals"]
        return slim

    def _target_signature(self, slim: dict):
        """
        Identity for "is this effectively the same kind of page as another
        one" - same method, same confidence, same param set, same source
        detection, same flags. Two different URLs with this signature are
        redundant evidence of the same page pattern (e.g. every WordPress
        post inheriting the theme's identical comment form), not two
        distinct attack surfaces. url is intentionally excluded.
        """
        return (
            slim.get("method"),
            slim.get("confidence"),
            tuple(sorted(slim.get("params", []))),
            tuple(sorted(slim.get("source", []))),
            tuple(sorted(k for k in self._AGENT_TARGET_FLAG_KEYS if slim.get(k))),
        )

    @staticmethod
    def _derive_fallback_targets(endpoints: list, exclude: list) -> list:
        """
        Build agent_targets-shaped entries directly from the raw
        endpoints array, for use only when hellhound's own agent_targets
        came back empty/sparse despite real candidates existing. Mirrors
        the same dict shape real agent_targets entries have (url, method,
        confidence, params, priority_score, source) so nothing downstream
        (grounding checks, DeepHat's prompt, Planner) needs to know the
        difference.

        Selection is deliberately conservative — only endpoints with
        actual non-empty params (a real injection-relevant surface) or an
        explicit ctf_highlights flag qualify. A site's full endpoints
        list is often mostly static pages with nothing to test; promoting
        all of them would just reintroduce the token-budget blowup
        agent_targets exists to prevent in the first place.
        """
        excluded_urls = {t.get("url") for t in exclude if isinstance(t, dict)}
        derived = []

        for ep in endpoints:
            if not isinstance(ep, dict):
                continue

            url = ep.get("url")
            if not url or url in excluded_urls:
                continue

            params = ep.get("params") or []
            ctf_highlights = ep.get("ctf_highlights") or []

            if not params and not ctf_highlights:
                continue

            # CTF-flagged entries (explicit "High-Value Params" signal)
            # always outrank plain parameterized ones in the derived
            # priority score, since that flag is itself a strong signal
            # this endpoint is worth testing.
            priority_score = ep.get("confidence_score", 0) + (10 if ctf_highlights else 0)

            derived.append({
                "url": url,
                "method": ep.get("method", "GET"),
                "confidence": ep.get("confidence", "MEDIUM"),
                "params": params,
                "priority_score": priority_score,
                "source": ep.get("source", []) + ["SpiderExtractor_fallback"],
            })
            excluded_urls.add(url)

        return derived

    def _condense_agent_targets(self, agent_targets: list) -> list:
        """
        Collapse agent_targets that share a signature (see
        _target_signature) into one representative entry plus a
        duplicate_count and a few sample URLs, instead of repeating the
        same param/flag breakdown once per URL.

        This is what actually fixes a real production failure: a 353-
        endpoint WordPress site where dozens of agent_targets were just
        the same generic comment-form params on a different post URL. The
        pre-existing MAX_AGENT_TARGETS=30 cap didn't help because each of
        those 30 entries carried a large, near-identical nested payload
        (params_detail/form_fields_detail/observed_values) - the JSON
        stayed inside CTX_SIZE's token budget but was large and repetitive
        enough that local llama.cpp prompt processing exceeded the 1200s
        TIMEOUT before DeepHat ever produced a token. Condensing collapses
        that redundancy so real distinct signal (different param sets,
        different auth/upload/sensitive flags) drives the token count
        instead of duplicate boilerplate.
        """
        groups: Dict[tuple, list] = {}
        for t in agent_targets:
            if not isinstance(t, dict):
                continue
            slim = self._slim_agent_target(t)
            sig = self._target_signature(slim)
            groups.setdefault(sig, []).append(slim)

        condensed = []
        for members in groups.values():
            members.sort(key=lambda m: m.get("priority_score", 0), reverse=True)
            rep = dict(members[0])
            if len(members) > 1:
                rep["duplicate_count"] = len(members)
                rep["sample_urls"] = [m["url"] for m in members[:3] if m.get("url")]
            condensed.append(rep)

        return condensed

    # ------------------------------------------------------------------
    # Internal helpers - endpoint evidence (unchanged)
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

    # ------------------------------------------------------------------
    # Internal helpers - GraphQL / OpenAPI summarization (NEW)
    # ------------------------------------------------------------------

    def _filter_sensitive_names(self, names):
        """Shortlist names that sound auth/payment/PII-relevant out of a
        potentially huge list of field/path names. Case-insensitive
        substring match against SENSITIVE_NAME_KEYWORDS."""
        matches = [
            n for n in names
            if any(kw in str(n).lower() for kw in self.SENSITIVE_NAME_KEYWORDS)
        ]
        return sorted(matches)

    def _summarize_graphql_entry(self, entry: dict) -> dict:
        """
        Summarize one GraphQL endpoint's schema instead of including it
        raw. Handles the schema living either directly on the entry
        (entry["queries"], entry["mutations"], ...) or nested under an
        entry["schema"] dict - defensive since the exact upstream shape
        can vary between Hellhound Spider versions.
        """
        schema = entry
        if "queries" not in entry and isinstance(entry.get("schema"), dict):
            schema = entry["schema"]

        queries = schema.get("queries") or {}
        mutations = schema.get("mutations") or {}
        subscriptions = schema.get("subscriptions") or {}

        summary = {
            "url": entry.get("url") or entry.get("endpoint"),
            "query_count": len(queries),
            "mutation_count": len(mutations),
            "subscription_count": len(subscriptions),
            "sensitive_queries": self._filter_sensitive_names(queries.keys())[
                : self.MAX_GRAPHQL_SENSITIVE_ITEMS
            ],
            "sensitive_mutations": self._filter_sensitive_names(mutations.keys())[
                : self.MAX_GRAPHQL_SENSITIVE_ITEMS
            ],
        }

        # Preserve any other top-level scan flags already present on the
        # entry (e.g. introspection_enabled, auth_required) without
        # pulling in the raw schema itself.
        for key, value in entry.items():
            if key not in ("queries", "mutations", "subscriptions", "schema", "url", "endpoint"):
                summary.setdefault(key, value)

        return summary

    def _summarize_graphql(self, graphql_list) -> list:
        if not graphql_list:
            return []
        return [
            self._summarize_graphql_entry(entry)
            for entry in graphql_list[: self.MAX_GRAPHQL_ENDPOINTS]
            if isinstance(entry, dict)
        ]

    def _summarize_openapi_entry(self, entry: dict):
        """
        Summarize one OpenAPI/Swagger spec. Standard specs expose paths
        under entry["paths"] (a dict of path -> methods). If that shape
        isn't present, we don't know the structure well enough to
        summarize meaningfully - keep the entry as-is (it will still be
        bounded by MAX_OPENAPI_SPECS and, if needed, further reduced by
        the DROP_ORDER trim loop).
        """
        if isinstance(entry.get("paths"), dict):
            paths = entry["paths"]
            return {
                "url": entry.get("url") or entry.get("endpoint"),
                "path_count": len(paths),
                "sensitive_paths": self._filter_sensitive_names(paths.keys())[
                    : self.MAX_OPENAPI_SENSITIVE_PATHS
                ],
            }
        return entry

    def _summarize_openapi(self, openapi_list) -> list:
        if not openapi_list:
            return []
        return [
            self._summarize_openapi_entry(entry)
            for entry in openapi_list[: self.MAX_OPENAPI_SPECS]
            if isinstance(entry, dict)
        ]

    # ------------------------------------------------------------------
    # Build + budget fitting
    # ------------------------------------------------------------------

    def _build(self, spider: dict) -> dict:

        extracted = {}

        extracted["meta"] = spider.get("meta", {})
        extracted["summary"] = spider.get("summary", {})
        extracted["tech_stack"] = spider.get("tech_stack", [])
        extracted["waf_findings"] = spider.get("waf_findings", [])[: self.MAX_WAF_FINDINGS]
        extracted["header_audit"] = spider.get("header_audit", [])[: self.MAX_HEADER_AUDIT]
        # Mirrors header_audit exactly (same {issue, severity, detail}
        # shape from the spider's own TLSChecker). Without this, only the
        # *count* of TLS issues reaches DeepHat via summary.tls_issues,
        # with no actual detail to ground a candidate in — confirmed in
        # practice to produce a fully fabricated candidate (invented TLS
        # version/cipher names) on an HTTP-only target with no TLS at
        # all. This was previously fixed, then found missing again from
        # this file — re-added; if it goes missing a third time, that's
        # a sign this needs an automated regression test, not just a
        # manual re-check.
        extracted["tls_audit"] = spider.get("tls_findings", [])[: self.MAX_HEADER_AUDIT]
        extracted["secrets"] = spider.get("secrets", [])[: self.MAX_SECRETS]

        # Summarized, NOT raw - see class docstring "CHANGE" note.
        extracted["graphql"] = self._summarize_graphql(spider.get("graphql", []))
        extracted["openapi"] = self._summarize_openapi(spider.get("openapi", []))

        extracted["robots_allowed"] = spider.get("robots_allowed", [])
        extracted["robots_disallowed"] = spider.get("robots_disallowed", [])
        extracted["crt_subdomains"] = spider.get("crt_subdomains", [])[: self.MAX_SUBDOMAINS]
        extracted["js_orphan_params"] = spider.get("js_orphan_params", [])[: self.MAX_JS_ORPHAN_PARAMS]

        # agent_targets is the crawler's own pre-filtered, highest-value
        # shortlist. Condense duplicates first (see _condense_agent_targets
        # docstring - this is what prevents near-identical boilerplate
        # entries from blowing up prompt size/inference time on sites with
        # many structurally-identical pages), then sort by priority_score
        # so any further trimming always drops the least interesting ones
        # first.
        agent_targets = spider.get("agent_targets", [])

        # Confirmed real case (insecure-website.com, 2026-08-13): the raw
        # spider JSON's OWN agent_targets came back completely empty even
        # though the full endpoints array had 30 real endpoints, several
        # with non-empty params AND explicit ctf_highlights like
        # "High-Value Params: host" — hellhound's internal agent_targets
        # selection heuristic simply didn't pick them up for this site.
        # Patching that heuristic means editing an 8,900+-line vendor
        # script we treat as a black box everywhere else in this project —
        # not worth the risk for what is fundamentally a fallback case.
        # Instead: if agent_targets is empty (or unusably sparse) but the
        # full endpoints array clearly has real parameterized/CTF-flagged
        # candidates, derive a shortlist from there directly, so DeepHat
        # still gets real evidence instead of nothing (which is what led
        # it to hallucinate /admin, /settings, /register on that scan —
        # none of which existed anywhere in evidence).
        if len(agent_targets) < 3:
            agent_targets = agent_targets + self._derive_fallback_targets(
                spider.get("endpoints", []), exclude=agent_targets
            )

        # Confirmed real case (nodegoat.herokuapp.com, 2026-08-14): the
        # crawler produced raw_endpoint_count=0 AND agent_targets=[] —
        # meaning even the fallback above had nothing to derive from,
        # since it also reads from spider["endpoints"]. But the SEED URL
        # itself (http://nodegoat.herokuapp.com/allocations/2?threshold=5)
        # already had a real query parameter — the user typed it
        # explicitly, it isn't something that needed "discovering". This
        # is the same known-open "crawl returns 0 endpoints" issue
        # documented elsewhere in this project (previously only seen on
        # SPA-heavy sites where navigation discovery fails after the seed
        # page loads fine) — confirming it isn't SPA-specific, since this
        # target has no further navigation to fail at all. Rather than
        # let a real, user-supplied parameter go completely unused
        # because the crawler found nothing else, this last-resort tier
        # synthesizes exactly one candidate directly from the target
        # URL's own query string when nothing else produced anything —
        # honest because it's built from a fact we're already certain of
        # (the exact URL that was scanned), not a guess.
        if not agent_targets:
            seed_target = (spider.get("meta") or {}).get("target")
            if seed_target:
                try:
                    parsed_seed = urlparse(seed_target)
                    seed_params = list(parse_qs(parsed_seed.query).keys())
                except Exception:
                    seed_params = []
                if seed_params:
                    agent_targets = [{
                        "url": seed_target,
                        "method": "GET",
                        "confidence": "MEDIUM",
                        "params": seed_params,
                        "priority_score": 6,
                        "source": ["SpiderExtractor_seed_url_fallback"],
                    }]

        agent_targets = self._condense_agent_targets(agent_targets)
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

        # Real evidence for the candidate flags, filtered down from
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

        # These three were previously summary-only: summary.
        # sensitive_data_sources / unauthenticated_apis / auth_required
        # carried a count, but nothing in the evidence handed to DeepHat
        # said WHICH endpoint(s) tripped it - so DeepHat had no way to act
        # on a count it could see but not locate. Real-world case: a scan
        # reported summary.sensitive_data_sources=1 (Hellhound itself
        # flagged /profile.php as a sensitive data source), but that URL
        # appeared nowhere in agent_targets (its priority_score was too
        # low to make the cap) or any other evidence array, so DeepHat's
        # candidates never mentioned it at all - it only reported the
        # generic missing-headers finding. Same _endpoint_evidence helper
        # already used for idor/sqli/cmdi_candidate, just wired up to the
        # flags that were falling through.
        extracted["sensitive_data_source_evidence"] = self._endpoint_evidence(
            endpoints, "sensitive_data_source", self.MAX_SENSITIVE_DATA_SOURCE_EVIDENCE
        )
        extracted["unauthenticated_api_evidence"] = self._endpoint_evidence(
            endpoints, "unauthenticated_api", self.MAX_UNAUTHENTICATED_API_EVIDENCE
        )
        extracted["auth_required_evidence"] = self._endpoint_evidence(
            endpoints, "auth_required", self.MAX_AUTH_REQUIRED_EVIDENCE
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


# Overwrite the placeholder now that the class is fully defined. Runs once
# at import time; see _default_token_budget() docstring above for the math.
SpiderExtractor.TOKEN_BUDGET = SpiderExtractor._default_token_budget()


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