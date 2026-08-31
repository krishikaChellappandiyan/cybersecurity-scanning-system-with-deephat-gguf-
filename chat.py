import json
from urllib.parse import urlparse

from config import ANALYSIS_PROMPT, CLASSIFICATION_PROMPT

from deephat import DeepHat
from processing.spider_extractor import SpiderExtractor
from processing.output_parser import OutputParser, OutputParserError

from pipeline.candidate_builder import build_candidate_skeletons
from processing.classification_parser import (
    parse_classifications,
    build_final_candidates,
    ClassificationParserError,
)

from pipeline.crawler import HellhoundCrawler
from pipeline.planner import Planner
from pipeline.executor import Executor

from storage.report_manager import ReportManager


def _extract_finding_counts(agent_name, agent_result):
    """
    Each agent wrapper returns a completely different result shape (the
    underlying tools were never designed to share a schema), so there's
    no single pair of keys that means "total/confirmed" across all of
    them. This was previously hardcoded to AUTHZ_AGENT's
    summary.total/summary.confirmed shape alone, which silently printed
    0/0 for every other agent regardless of what it actually found —
    each agent already has its own correctly-detailed summary block
    earlier in Executor's output, but this final rollup was wrong.

    Returns (total, confirmed) as ints. Falls back to (0, 0) only when
    the shape is genuinely unrecognized, not as a silent default for
    every agent that isn't AUTHZ_AGENT.
    """
    if not isinstance(agent_result, dict):
        return 0, 0

    if agent_name == "AUTHZ_AGENT":
        # AuthzWrapper's real return shape is flat (results/total_results/
        # total_vulnerabilities) — there is no nested "summary" key.
        # confirmed_count is written by Executor's AUTHZ_AGENT branch
        # (the same VULNERABLE/LIKELY_VULNERABLE count it prints as
        # "Potential Issues"); fall back to recomputing from results
        # directly in case this is ever called on an older/raw result
        # that predates that fix.
        total = agent_result.get("total_results", len(agent_result.get("results", [])))
        confirmed = agent_result.get("confirmed_count")
        if confirmed is None:
            confirmed = sum(
                1 for r in agent_result.get("results", [])
                if r.get("finding") in ("VULNERABLE", "LIKELY_VULNERABLE")
            )
        return total, confirmed

    if agent_name == "NOSQL_AGENT":
        summary = agent_result.get("summary", {})
        total = summary.get("vulnerabilities_found", len(agent_result.get("findings", [])))
        confirmed = summary.get("critical", 0) + summary.get("high", 0)
        return total, confirmed

    if agent_name in ("SQL_AGENT", "PARAM_INJECTION_AGENT"):
        # Both wrappers normalize to summary.total_tests/summary.confirmed
        # (see sql_wrapper.py / injection_wrapper.py) — using this instead
        # of the generic findings-list fallback below matters here
        # specifically because not every finding in the list is
        # "confirmed" (SQL_AGENT can report "sqli_possible", not just
        # "sqli_confirmed" — treating every list entry as confirmed would
        # overcount).
        summary = agent_result.get("summary", {})
        total = summary.get("total_tests", len(agent_result.get("findings", [])))
        confirmed = summary.get("confirmed", 0)
        return total, confirmed

    if agent_name == "PASSWORD_POLICY_AGENT":
        # Single overall policy assessment, not a list of discrete
        # findings — "confirmed" means "a real weakness was identified",
        # which is anything worse than a clean policy. report["severity"]
        # is a NESTED dict ({"score", "label", "findings"}, per
        # generate_report()'s actual output), not a plain string — using
        # it as a flat string here previously always fell through to
        # (0, 0) even on a real CRITICAL result, since
        # str({...}).upper() never equals "CRITICAL".
        severity_obj = agent_result.get("severity")
        label = ""
        if isinstance(severity_obj, dict):
            label = str(severity_obj.get("label", "")).upper()
        elif isinstance(severity_obj, str):
            # Tolerate a flat-string shape too, in case this ever changes.
            label = severity_obj.upper()
        is_weak = label in ("CRITICAL", "WEAK", "MODERATE")
        return (1, 1) if is_weak else (0, 0)

    # XSS_AGENT, SAST_AGENT, MITM_AGENT, and anything else with a plain
    # "findings" list — the most common shape across the remaining agents.
    findings = agent_result.get("findings", [])
    total = len(findings) if isinstance(findings, list) else 0
    return total, total


# Common accidental prefixes people paste along with the URL itself —
# most often from copying a whole line like "Target URL : https://..."
# out of a chat message or a previous transcript rather than just the
# URL. Matched case-insensitively, with or without a trailing colon.
_STRAY_TARGET_PREFIXES = (
    "target url", "target", "url",
)


def _clean_target_input(raw: str) -> str:
    cleaned = raw.strip()

    for prefix in _STRAY_TARGET_PREFIXES:
        lowered = cleaned.lower()
        if lowered.startswith(prefix):
            rest = cleaned[len(prefix):].lstrip()
            if rest.startswith(":"):
                rest = rest[1:].lstrip()
                cleaned = rest
                break

    return cleaned


def _prompt_for_target() -> str:
    """
    Keeps prompting until the input actually looks like a URL, instead
    of handing something like a stray "Target URL: " label straight to
    the crawler — that previously produced a confusing cascade (a
    "Port could not be cast to integer" config error, then a crawler
    crash, then a wrong output file path) instead of a clear message
    about what was actually wrong.
    """
    while True:
        raw = input("\nTarget URL : ")
        target = _clean_target_input(raw)

        if not target:
            print("[!] Please enter a target URL.")
            continue

        parsed = urlparse(target)

        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            print(
                f"[!] {target!r} doesn't look like a valid URL — it needs "
                f"to start with http:// or https:// and include a host "
                f"(e.g. http://example.com/). Just the URL, nothing else."
            )
            continue

        return target


bot = DeepHat()
crawler = HellhoundCrawler()
extractor = SpiderExtractor()
parser = OutputParser()
planner = Planner()
executor = Executor()
report_manager = ReportManager()

print("=" * 60)
print(" DeepHat Cybersecurity Assistant")
print("=" * 60)

while True:

    print("\nChoose Mode")
    print("1. Normal Chat")
    print("2. Website Security Analysis")
    print("3. Exit")

    choice = input("\nChoice : ").strip()

    if choice == "3":
        break

    # ==========================================================
    # NORMAL CHAT
    # ==========================================================

    if choice == "1":

        prompt = input("\nYou : ")

        if prompt.lower() in ["quit", "exit"]:
            break

    # ==========================================================
    # WEBSITE SECURITY ANALYSIS
    # ==========================================================

    elif choice == "2":

        target = _prompt_for_target()

        # Each scan is a fresh, self-contained analysis — don't carry
        # forward context (and inference time) from unrelated prior scans.
        bot.reset()

        try:

            print("\nRunning Hellhound Spider...\n")

            json_path = crawler.crawl(target)

            print(f"\nSpider report generated:\n{json_path}")

            with open(json_path, "r", encoding="utf-8") as f:
                spider_json = json.load(f)

            # The spider normalizes the target internally (e.g. adds
            # https:// if the user typed a bare hostname) but that
            # normalization never made it back to this variable before —
            # sync it from the spider's own report so report filenames,
            # the AUTHZ/Headers/Password agents, and anything else keyed
            # off `target` all use the same, correctly-schemed URL.
            normalized_target = spider_json.get("meta", {}).get("target")
            if normalized_target:
                target = normalized_target

        except Exception as e:

            print(f"\nCrawler failed: {e}")
            continue

        # ------------------------------------------------------
        # Extract security context
        # ------------------------------------------------------

        extracted_context_dict = extractor.extract(spider_json)

        if isinstance(extracted_context_dict, dict):
            extracted_context = json.dumps(
                extracted_context_dict,
                indent=2,
                ensure_ascii=False
            )
        else:
            # Extractor didn't return a dict (unexpected) — no evidence
            # dict available for the grounding check in Planner.route().
            extracted_context = extracted_context_dict
            extracted_context_dict = None

        print("\nSpider scan completed successfully.")
        print("Using extracted security context for analysis.")

        print("\n================ SPIDER CONTEXT ================\n")
        print(extracted_context)
        print("\n================================================\n")

        # ------------------------------------------------------
        # Build real candidate skeletons deterministically, in code,
        # directly from the trusted structured evidence — before DeepHat
        # is ever involved. See pipeline/candidate_builder.py's module
        # docstring for why: every hallucination class this pipeline has
        # fought (invented endpoints, fabricated evidence citations,
        # dropped query strings, invented CVE IDs/agent names, wrong
        # summary counts) came from asking DeepHat to author these facts
        # itself in one open-ended generation call. It no longer does —
        # it only picks an agent from a pre-computed eligible menu per
        # already-real candidate.
        # ------------------------------------------------------

        skeletons = build_candidate_skeletons(extracted_context_dict or {})

        print(f"\n[CandidateBuilder] {len(skeletons)} real candidate(s) built "
              f"deterministically from crawler evidence (zero LLM calls).")

        if not skeletons:
            # Nothing to classify — skip DeepHat entirely rather than
            # spend a generation call on an empty list. A quiet scan
            # with genuinely no evidenced candidates is a correct,
            # valid outcome, not a failure.
            print("[CandidateBuilder] No candidates to classify — skipping DeepHat call.")
            prompt = None
        else:
            skeleton_menu = json.dumps(
                [s.to_prompt_dict() for s in skeletons],
                indent=2, ensure_ascii=False,
            )
            prompt = f"""
==========================
Candidates (already real — built from crawler evidence in code)
==========================

{skeleton_menu}

==========================
Task
==========================

{CLASSIFICATION_PROMPT}
"""

    else:
        print("Invalid Choice")
        continue

    # ==========================================================
    # DEEPHAT
    # ==========================================================

    print("\nDeepHat is thinking...\n")

    try:

        if choice == "2" and prompt is None:
            # No candidates were built — nothing for DeepHat to classify.
            # Build an empty, valid report directly rather than calling
            # the model at all.
            report = {
                "scan_id": target,
                "target": target,
                "generated_at": "",
                "summary": {
                    "total_candidates": 0, "critical": 0, "high": 0,
                    "medium": 0, "low": 0, "informational": 0,
                },
                "candidates": [],
            }
            answer = json.dumps(report)

        else:

            # A local model occasionally goes off-script entirely — returning
            # markdown commentary instead of JSON, or otherwise unparseable
            # output — rather than a subtly-wrong JSON object. Retrying with a
            # fresh conversation (bot.reset()) usually gets a clean response
            # on the next attempt, so don't kill the whole scan over one bad
            # generation. Only retries JSON-parse failures (choice == "2");
            # Normal Chat mode has no structured-output requirement to retry.
            MAX_DEEPHAT_ATTEMPTS = 3
            report = None

            for attempt in range(1, MAX_DEEPHAT_ATTEMPTS + 1):

                answer = bot.chat(prompt=prompt)

                print("\n================ DEEPHAT =================\n")
                print(answer)
                print("\n==========================================\n")

                if choice != "2":
                    break

                print("\nParsing DeepHat classifications...\n")

                try:
                    classifications = parse_classifications(answer, len(skeletons))
                    final_candidates = build_final_candidates(skeletons, classifications)

                    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
                    for c in final_candidates:
                        sev = str(c.get("severity", "")).lower()
                        if sev in severity_counts:
                            severity_counts[sev] += 1

                    report = {
                        "scan_id": target,
                        "target": target,
                        "generated_at": "",
                        "summary": {
                            "total_candidates": len(final_candidates),
                            **severity_counts,
                        },
                        "candidates": final_candidates,
                    }
                    answer = json.dumps(report)

                    classified = sum(1 for i in range(len(skeletons)) if i in classifications)
                    routed = sum(1 for c in final_candidates if c.get("recommended_agent"))
                    print(
                        f"✓ Classified {classified}/{len(skeletons)} candidates "
                        f"({routed} routed to a real agent)."
                    )
                    break

                except ClassificationParserError as e:

                    if attempt < MAX_DEEPHAT_ATTEMPTS:
                        print(f"[!] DeepHat returned unparseable classifications (attempt {attempt}/{MAX_DEEPHAT_ATTEMPTS}): {e}")
                        print(f"[!] Retrying with a fresh request ({MAX_DEEPHAT_ATTEMPTS - attempt} attempt(s) left)...\n")
                        bot.reset()
                    else:
                        raise

        # ======================================================
        # WEBSITE SECURITY PIPELINE
        # ======================================================

        if choice == "2":

            print("\nPlanning validation workflow...\n")

            groups = planner.route(report, spider_evidence=extracted_context_dict)

            print("\n================ ROUTING SUMMARY ================\n")

            for agent, decisions in groups.items():
                print(f"{agent}: {len(decisions)} finding(s)")

            print("\n=================================================\n")

            # --------------------------------------------------
            # Execute Validation Agents
            # --------------------------------------------------

            agent_results = executor.execute(
                groups,
                spider_json_path=json_path,
                target_url=target
            )

            print("\n================ AGENT RESULTS ================\n")

            if agent_results:

                for result in agent_results:

                    print(f"Agent : {result.get('agent')}")
                    print(f"Status: {result.get('status')}")

                    if result.get("status") == "SUCCESS":

                        agent_name = result.get("agent")
                        agent_result = result.get("result") or {}
                        total, confirmed = _extract_finding_counts(agent_name, agent_result)

                        if agent_name == "AUTHZ_AGENT":
                            # "total" here is a probe count (endpoints x 4
                            # auth-bypass attempts each), not a count of
                            # distinct findings — labeling it "Total
                            # Findings" implied 4 separate vulnerabilities
                            # when it actually meant "4 probes were run,
                            # 0 came back vulnerable."
                            print(f"Probes Tested      : {total}")
                            print(f"Vulnerable         : {confirmed}")
                        else:
                            print(f"Total Findings     : {total}")
                            print(f"Confirmed Findings : {confirmed}")

                    elif result.get("status") == "FAILED":

                        print(f"Error: {result.get('error')}")

                    elif result.get("status") == "SKIPPED" and result.get("agent") in ("UNSUPPORTED", "SKIPPED"):

                        # "Agent" here is a bucket name (UNSUPPORTED or
                        # SKIPPED), not a real agent — this previously
                        # printed nothing else, collapsing every candidate
                        # that landed in one of these buckets into one
                        # uninformative "Status: SKIPPED" line with no way
                        # to tell which candidates were involved or why.
                        candidates = (result.get("result") or {}).get("candidates", [])
                        print(f"Candidates ({len(candidates)}):")
                        for c in candidates:
                            print(f"  - {c.get('finding_id')} -> {c.get('endpoint')}")
                            print(f"    reason: {c.get('reason')}")

                    print()

            else:

                print("No validation agents were executed.")

            print("================================================\n")

            # --------------------------------------------------
            # Pipeline Execution Summary
            # --------------------------------------------------
            # Purely additive: every value here is aggregated from counts
            # already computed earlier in this same function (skeletons,
            # classified, groups, agent_results) -- no new computation,
            # no change to any existing behavior or printed section above.
            # Exists so it's immediately obvious, at a glance, whether an
            # unexpected result traces back to discovery, classification,
            # routing, or agent execution, without re-reading the full
            # transcript.

            candidates_routed = sum(
                len(decisions) for agent, decisions in groups.items()
                if agent not in ("UNSUPPORTED", "SKIPPED")
            )
            candidates_unsupported = sum(
                len(decisions) for agent, decisions in groups.items()
                if agent in ("UNSUPPORTED", "SKIPPED")
            )

            real_agent_results = [
                r for r in agent_results
                if r.get("agent") not in ("UNSUPPORTED", "SKIPPED")
            ]
            agents_succeeded = sum(1 for r in real_agent_results if r.get("status") == "SUCCESS")
            agents_failed = sum(1 for r in real_agent_results if r.get("status") == "FAILED")

            total_confirmed = 0
            for r in real_agent_results:
                if r.get("status") != "SUCCESS":
                    continue
                _, c = _extract_finding_counts(r.get("agent"), r.get("result") or {})
                total_confirmed += c or 0

            print("================ PIPELINE SUMMARY ================\n")
            print(f"Target                 : {target}")
            print(f"Candidates discovered  : {len(skeletons)}")
            print(f"Candidates classified  : {classified}")
            print(f"Candidates routed      : {candidates_routed}")
            print(f"Unsupported            : {candidates_unsupported}")
            print()
            print(f"Agents executed        : {len(real_agent_results)}")
            print(f"Successful             : {agents_succeeded}")
            print(f"Failed                 : {agents_failed}")
            print()
            print(f"Confirmed findings     : {total_confirmed}")
            # No "potential findings" line here: the "total" half of
            # _extract_finding_counts() means probe/request count for
            # some agents (AUTHZ_AGENT: probes run; PARAM_INJECTION_AGENT:
            # HTTP requests made), not a count of distinct findings --
            # total-minus-confirmed produced numbers like "628 potential
            # findings" from 4 probes and 624 requests, neither of which
            # were actually findings. Confirmed findings is the one
            # number this data reliably supports across every agent
            # shape; each agent's own detailed summary above already
            # shows its real per-agent breakdown (Possible/Confirmed for
            # SQL_AGENT, etc.) for anyone who needs that detail.
            print("\n====================================================\n")

            # --------------------------------------------------
            # Save DeepHat Report
            # --------------------------------------------------

            report_path = report_manager.generate_combined_report(
                target=target,
                deephat_response=answer,
                agent_results=agent_results
            )

            print(f"\nDeepHat report saved to:\n{report_path}")

    except Exception as e:

        print(f"\nDeepHat Error: {e}")