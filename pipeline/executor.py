from agents.xss_wrapper import XSSWrapper
from agents.authz_wrapper import AuthzWrapper
from agents.password_wrapper import PasswordWrapper
from agents.mitm_wrapper import MitmWrapper
from agents.nosql_wrapper import NosqlWrapper
from agents.sqli_wrapper import SqlWrapper
from agents.injection_wrapper import InjectionWrapper
from agents.sast_wrapper import SastWrapper


class Executor:

    def __init__(self):

        self.xss = XSSWrapper()
        self.authz = AuthzWrapper()
        self.password = PasswordWrapper()
        self.mitm = MitmWrapper()
        self.nosql = NosqlWrapper()
        self.sql = SqlWrapper()
        self.injection = InjectionWrapper()
        self.sast = SastWrapper()

    def execute(self, groups, spider_json_path, target_url):

        print("\n========== EXECUTOR ==========\n")

        agent_results = []

        for agent, findings in groups.items():

            print(f"{agent}")

            for finding in findings:
                print(f"  • {finding.finding_id} -> {finding.endpoint}")

            # =====================================================
            # XSS AGENT
            # =====================================================

            if agent == "XSS_AGENT":

                print("\nLaunching XSS Validation Agent...\n")

                try:

                    result = self.xss.run(spider_json_path)

                    print("✓ XSS Agent completed successfully.")

                    summary = result.get("summary", {})

                    print("\n========== XSS SUMMARY ==========")
                    print(f"Total Findings     : {summary.get('total', 0)}")
                    print(f"Confirmed Findings : {summary.get('confirmed', 0)}")
                    print("=================================\n")

                    agent_results.append({
                        "agent": "XSS_AGENT",
                        "status": "SUCCESS",
                        "result": result
                    })

                except Exception as e:

                    print(f"XSS Agent failed: {e}")

                    agent_results.append({
                        "agent": "XSS_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # SQL AGENT
            # =====================================================

            elif agent == "SQL_AGENT":

                print("\nLaunching SQL Injection Validation Agent...\n")

                try:

                    result = self.sql.run(target_url, findings)

                    sql_findings = result.get("findings", [])
                    summary = result.get("summary", {})
                    errors = result.get("_errors", [])

                    # Previously this printed "completed successfully" and
                    # recorded status=SUCCESS unconditionally, even on a
                    # run where every endpoint failed outright (e.g. the
                    # underlying scanner erroring on an unrecognized CLI
                    # flag before it could test anything) — the only
                    # signal anything went wrong was buried in the Errors
                    # line a few rows down, easy to miss, and agent_results
                    # itself claimed success regardless. Now: a run where
                    # nothing was actually tested AND errors exist is
                    # reported as FAILED, matching what actually happened.
                    endpoints_tested = summary.get("endpoints_tested", 0)
                    total_tests = summary.get("total_tests", 0)
                    completely_failed = bool(errors) and endpoints_tested == 0 and total_tests == 0

                    if completely_failed:
                        print("✗ SQL Agent failed — no endpoint was successfully tested.")
                    else:
                        print("✓ SQL Agent completed successfully.")

                    print("\n========== SQL SUMMARY ==========")
                    print(f"Endpoints Tested : {endpoints_tested}")
                    print(f"Total Tests      : {total_tests}")
                    print(f"Confirmed        : {summary.get('confirmed', 0)}")
                    print(f"Possible         : {summary.get('possible', 0)}")

                    candidates_routed = summary.get("candidates_routed")
                    if candidates_routed and candidates_routed > endpoints_tested:
                        print(
                            f"\n({candidates_routed} candidate(s) routed here, "
                            f"{endpoints_tested} unique endpoint(s) actually scanned — "
                            f"some candidates pointed at the same real URL, not dropped):"
                        )
                        for url, ids in result.get("endpoint_dedup_map", {}).items():
                            if len(ids) > 1:
                                print(f"  {url}")
                                print(f"    <- {', '.join(str(i) for i in ids)}")

                    if errors:
                        print(f"Errors           : {errors}")
                    print("==================================\n")

                    agent_results.append({
                        "agent": "SQL_AGENT",
                        "status": "FAILED" if completely_failed else "SUCCESS",
                        "result": result,
                        **({"error": "; ".join(errors)} if completely_failed else {}),
                    })

                except Exception as e:

                    print(f"SQL Agent failed: {e}")

                    agent_results.append({
                        "agent": "SQL_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # PARAM INJECTION AGENT (SSRF/SSTI/SSPP/CMDi/PathTraversal/
            # OpenRedirect/HostHeader — vectors SQL_AGENT/XSS_AGENT/
            # NOSQL_AGENT don't cover)
            # =====================================================

            elif agent == "PARAM_INJECTION_AGENT":

                print("\nLaunching Parameter Injection Validation Agent...\n")

                try:

                    result = self.injection.run(target_url, findings)

                    inj_findings = result.get("findings", [])
                    summary = result.get("summary", {})
                    errors = result.get("_errors", [])

                    endpoints_tested = summary.get("endpoints_tested", 0)
                    completely_failed = bool(errors) and endpoints_tested == 0 and not inj_findings

                    if completely_failed:
                        print("✗ Parameter Injection Agent failed — no endpoint was successfully tested.")
                    else:
                        print("✓ Parameter Injection Agent completed successfully.")

                    print("\n========== PARAM INJECTION SUMMARY ==========")
                    print(f"Endpoints Tested : {endpoints_tested}")
                    print(f"Total Findings   : {len(inj_findings)}")
                    print(f"Confirmed        : {summary.get('confirmed', 0)}")
                    print(f"WAF Detected     : {summary.get('waf_detected', False)}")
                    if errors:
                        print(f"Errors           : {errors}")
                    print("===============================================\n")

                    agent_results.append({
                        "agent": "PARAM_INJECTION_AGENT",
                        "status": "FAILED" if completely_failed else "SUCCESS",
                        "result": result,
                        **({"error": "; ".join(errors)} if completely_failed else {}),
                    })

                except Exception as e:

                    print(f"Parameter Injection Agent failed: {e}")

                    agent_results.append({
                        "agent": "PARAM_INJECTION_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # AUTHORIZATION AGENT
            # =====================================================

            elif agent == "AUTHZ_AGENT":

                print("\nLaunching AUTHORIZATION Validation Agent...\n")

                try:

                    result = self.authz.run(target_url, findings)

                    print("✓ AUTHORIZATION Agent completed successfully.")

                    print("\n========== AUTHZ SUMMARY ==========")

                    print(f"Target            : {result.get('target')}")
                    print(f"Endpoints         : {result.get('endpoint_count', 0)}")
                    print(f"Results           : {result.get('total_results', 0)}")

                    vulnerable = sum(
                        1
                        for r in result.get("results", [])
                        if r.get("finding") in (
                            "VULNERABLE",
                            "LIKELY_VULNERABLE",
                        )
                    )

                    # Store this back into result itself — AuthzWrapper's
                    # real return shape is flat (results/total_results/
                    # total_vulnerabilities, no nested "summary" key at
                    # all), but chat.py's _extract_finding_counts and
                    # report_manager.py's formatters were both written
                    # expecting agent_result["summary"]["confirmed"].
                    # That mismatch meant AUTHZ_AGENT's real finding count
                    # was silently reported as 0 everywhere downstream of
                    # this print statement, on every run, regardless of
                    # what was actually found — this local "vulnerable"
                    # value was the only place the correct number ever
                    # existed. Computing it once here and storing it back
                    # is the fix, rather than re-deriving the same
                    # VULNERABLE/LIKELY_VULNERABLE classification logic
                    # separately in every downstream reader.
                    result["confirmed_count"] = vulnerable

                    print(f"Potential Issues  : {vulnerable}")

                    print("===================================\n")

                    agent_results.append({
                        "agent": "AUTHZ_AGENT",
                        "status": "SUCCESS",
                        "result": result
                    })

                except Exception as e:

                    print(f"AUTHORIZATION Agent failed: {e}")

                    agent_results.append({
                        "agent": "AUTHZ_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # PASSWORD POLICY AGENT
            # =====================================================

            elif agent == "PASSWORD_POLICY_AGENT":

                print("\nLaunching PASSWORD POLICY Validation Agent...\n")

                try:

                    result = self.password.run(target_url, findings)

                    print("✓ PASSWORD POLICY Agent completed successfully.")

                    severity = result.get("severity", {})
                    policy = result.get("policy", result.get("password_policy", {}))

                    print("\n========== PASSWORD POLICY SUMMARY ==========")
                    print(f"Target             : {result.get('target')}")
                    print(f"Severity           : {severity.get('label', 'UNKNOWN')} "
                          f"(score {severity.get('score', '?')}/100)")
                    print(f"Minimum length     : {policy.get('minimum_length')}")
                    print(f"Requires uppercase : {policy.get('requires_uppercase')}")
                    print(f"Requires lowercase : {policy.get('requires_lowercase')}")
                    print(f"Requires number    : {policy.get('requires_number')}")
                    print(f"Requires symbol    : {policy.get('requires_symbol')}")
                    print("==============================================\n")

                    agent_results.append({
                        "agent": "PASSWORD_POLICY_AGENT",
                        "status": "SUCCESS",
                        "result": result
                    })

                except Exception as e:

                    print(f"PASSWORD POLICY Agent failed: {e}")

                    agent_results.append({
                        "agent": "PASSWORD_POLICY_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # MITM AGENT (Passive Observer)
            # =====================================================

            elif agent == "MITM_AGENT":

                print("\nLaunching MITM Validation Agent...\n")

                try:

                    result = self.mitm.run(target_url, findings)

                    print("✓ MITM Agent completed successfully.")

                    mitm_findings = result.get("findings", [])
                    stats = result.get("statistics", {})
                    by_severity = stats.get("by_severity", {})

                    print("\n========== MITM (PASSIVE) SUMMARY ==========")
                    print(f"Target         : {target_url}")
                    print(f"Total Findings : {len(mitm_findings)}")
                    for sev in ("Critical", "High", "Medium", "Low", "Info"):
                        print(f"  {sev:8}: {by_severity.get(sev, 0)}")
                    print("=============================================\n")

                    agent_results.append({
                        "agent": "MITM_AGENT",
                        "status": "SUCCESS",
                        "result": result
                    })

                except Exception as e:

                    print(f"MITM Agent failed: {e}")

                    agent_results.append({
                        "agent": "MITM_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # NOSQL AGENT (NoSQLHunter)
            # =====================================================

            elif agent == "NOSQL_AGENT":

                print("\nLaunching NoSQL Injection Validation Agent...\n")

                try:

                    result = self.nosql.run(target_url, findings)

                    print("✓ NoSQL Agent completed successfully.")

                    nosql_findings = result.get("findings", [])
                    summary = result.get("summary", {})

                    print("\n========== NOSQL SUMMARY ==========")
                    print(f"Endpoints Discovered : {summary.get('endpoints_discovered', 0)}")
                    print(f"Total Findings       : {len(nosql_findings)}")
                    print(f"  Critical: {summary.get('critical', 0)}")
                    print(f"  High    : {summary.get('high', 0)}")
                    print("====================================\n")

                    agent_results.append({
                        "agent": "NOSQL_AGENT",
                        "status": "SUCCESS",
                        "result": result
                    })

                except Exception as e:

                    print(f"NoSQL Agent failed: {e}")

                    agent_results.append({
                        "agent": "NOSQL_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # SAST AGENT (Static Application Security Testing)
            # =====================================================

            elif agent == "SAST_AGENT":

                print("\nLaunching SAST Validation Agent...\n")

                try:

                    result = self.sast.run(target_url, findings)

                    if result.get("status") == "SKIPPED":

                        print(f"SAST Agent skipped: {result.get('reason')}\n")

                        agent_results.append({
                            "agent": "SAST_AGENT",
                            "status": "SKIPPED",
                            "result": result
                        })

                    else:

                        print("✓ SAST Agent completed successfully.")

                        sast_findings = result.get("findings", [])
                        by_severity = result.get("_by_severity", {})

                        print("\n========== SAST SUMMARY ==========")
                        print(f"Target         : {target_url}")
                        print(f"Total Findings : {result.get('_total', 0)}")
                        for sev in ("Critical", "High", "Medium", "Low", "Info"):
                            print(f"  {sev:8}: {by_severity.get(sev, 0)}")
                        print("===================================\n")

                        agent_results.append({
                            "agent": "SAST_AGENT",
                            "status": "SUCCESS",
                            "result": result
                        })

                except Exception as e:

                    print(f"SAST Agent failed: {e}")

                    agent_results.append({
                        "agent": "SAST_AGENT",
                        "status": "FAILED",
                        "error": str(e)
                    })

            # =====================================================
            # UNSUPPORTED
            # =====================================================

            elif agent == "UNSUPPORTED":

                print("\nUnsupported findings (no validation agent).\n")

                agent_results.append({
                    "agent": "UNSUPPORTED",
                    "status": "SKIPPED",
                    "result": {
                        "candidates": [
                            {
                                "finding_id": f.finding_id,
                                "endpoint": f.endpoint,
                                "reason": f.reason,
                            }
                            for f in findings
                        ]
                    }
                })

            # =====================================================
            # SKIPPED
            # =====================================================

            elif agent == "SKIPPED":

                print("\nSkipped findings.\n")

                agent_results.append({
                    "agent": "SKIPPED",
                    "status": "SKIPPED",
                    "result": {
                        "candidates": [
                            {
                                "finding_id": f.finding_id,
                                "endpoint": f.endpoint,
                                "reason": f.reason,
                            }
                            for f in findings
                        ]
                    }
                })

        print("\n========== EXECUTOR COMPLETE ==========\n")

        return agent_results