class SpiderContextBuilder:
    """
    Converts the compact SpiderExtractor output into a concise,
    LLM-friendly security summary.

    Input:
        dict returned by SpiderExtractor.extract()

    Output:
        Plain text summary for DeepHat.
    """

    def build(self, spider):

        lines = []

        # ======================================================
        # Target
        # ======================================================

        meta = spider.get("meta", {})

        if meta:
            lines.append("========== TARGET ==========")

            if meta.get("target"):
                lines.append(f"Target: {meta['target']}")

            if meta.get("tool"):
                lines.append(f"Crawler: {meta['tool']}")

            lines.append("")

        # ======================================================
        # Summary
        # ======================================================

        summary = spider.get("summary", {})

        if summary:

            lines.append("========== SCAN SUMMARY ==========")

            for key, value in summary.items():
                lines.append(f"{key}: {value}")

            lines.append("")

        # ======================================================
        # Technology
        # ======================================================

        tech = spider.get("tech_stack", [])

        if tech:

            lines.append("========== TECHNOLOGY ==========")

            for t in tech:
                lines.append(f"- {t}")

            lines.append("")

        # ======================================================
        # WAF
        # ======================================================

        waf = spider.get("waf_findings", [])

        if waf:

            lines.append("========== WAF ==========")

            for item in waf:

                waf_name = item.get("waf", "Unknown")
                confidence = item.get("confidence", "Unknown")

                lines.append(
                    f"- {waf_name} (Confidence: {confidence})"
                )

            lines.append("")

        # ======================================================
        # Header Issues
        # ======================================================

        headers = spider.get("header_audit", [])

        if headers:

            lines.append("========== SECURITY HEADER FINDINGS ==========")

            for h in headers:

                header = h.get("header", "")
                issue = h.get("issue", "")
                severity = h.get("severity", "")

                lines.append(
                    f"- {header} | {severity} | {issue}"
                )

            lines.append("")

        # ======================================================
        # Secrets
        # ======================================================

        secrets = spider.get("secrets", [])

        if secrets:

            lines.append("========== DISCOVERED SECRETS ==========")

            for s in secrets:

                lines.append(
                    f"- {s.get('type','Unknown')} "
                    f"(Source: {s.get('source','Unknown')})"
                )

            lines.append("")

        # ======================================================
        # JS Parameters
        # ======================================================

        js_params = spider.get("js_orphan_params", [])

        if js_params:

            lines.append("========== JAVASCRIPT PARAMETERS ==========")

            for item in js_params:

                js = item.get("js_file", "")

                params = item.get("params", [])

                if params:
                    lines.append(
                        f"- {js} -> {', '.join(params)}"
                    )

            lines.append("")

        # ======================================================
        # IDOR / SQLi / CMDi Evidence (CANDIDATES - unconfirmed)
        # ======================================================

        idor_ev = spider.get("idor_evidence", [])
        sqli_ev = spider.get("sqli_evidence", [])
        cmdi_ev = spider.get("cmdi_evidence", [])
        overlap = set(spider.get("idor_sqli_overlap", []))

        if idor_ev or sqli_ev or cmdi_ev:

            lines.append(
                "========== INJECTION/IDOR CANDIDATES "
                "(UNCONFIRMED - requires manual validation) =========="
            )

            for e in idor_ev:
                tag = " [ALSO FLAGGED SQLI - SAME PARAM]" if e["url"] in overlap else ""
                lines.append(
                    f"- IDOR candidate: {e['method']} {e['url']} "
                    f"(params: {', '.join(e['params'])}){tag}"
                )

            for e in sqli_ev:
                if e["url"] not in overlap:
                    lines.append(
                        f"- SQLi candidate: {e['method']} {e['url']} "
                        f"(params: {', '.join(e['params'])})"
                    )

            for e in cmdi_ev:
                lines.append(
                    f"- Command injection candidate: {e['method']} {e['url']} "
                    f"(params: {', '.join(e['params'])})"
                )

            lines.append("")

        # ======================================================
        # Admin Panels (CONFIRMED endpoints exist - access control unverified)
        # ======================================================

        admin_ev = spider.get("admin_panel_evidence", [])

        if admin_ev:

            lines.append(
                "========== ADMIN PANELS DISCOVERED "
                "(endpoints exist - access control not yet tested) =========="
            )

            for url in admin_ev:
                lines.append(f"- {url}")

            lines.append("")

        # ======================================================
        # Sensitive Files (CONFIRMED exposed - content previewed by crawler)
        # ======================================================

        sens_ev = spider.get("sensitive_file_evidence", [])

        if sens_ev:

            lines.append(
                "========== SENSITIVE FILES EXPOSED "
                "(CONFIRMED - crawler retrieved live content) =========="
            )

            for f in sens_ev:
                preview = f.get("preview", "").replace("\n", " ").strip()
                lines.append(
                    f"- [{f.get('severity','')}] {f.get('type','')}: {f.get('url','')}"
                )
                if preview:
                    lines.append(f"    preview: {preview[:100]}...")

            lines.append("")

        # ======================================================
        # High Priority Targets
        # ======================================================

        targets = spider.get("agent_targets", [])

        if targets:

            lines.append("========== HIGH PRIORITY TARGETS ==========")

            for t in targets:

                method = t.get("method", "GET")
                url = t.get("url", "")
                score = t.get("priority_score", "")

                lines.append(
                    f"- {method} {url} (Priority: {score})"
                )

            lines.append("")

        # ======================================================
        # Subdomains
        # ======================================================

        subs = spider.get("crt_subdomains", [])

        if subs:

            lines.append("========== SUBDOMAINS ==========")

            for s in subs:

                hostname = s.get("hostname", "")

                if hostname:
                    lines.append(f"- {hostname}")

            lines.append("")

        # ======================================================
        # Statistics
        # ======================================================

        endpoint_count = spider.get("raw_endpoint_count", 0)

        lines.append("========== STATISTICS ==========")
        lines.append(f"Raw Endpoints Discovered: {endpoint_count}")

        return "\n".join(lines)