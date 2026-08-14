"""
processing/classification_parser.py

Parses DeepHat's response to CLASSIFICATION_PROMPT (see config.py) — the
new, narrower task where DeepHat only picks an agent per pre-built
candidate skeleton instead of authoring full candidates from scratch.

Deliberately much smaller than processing/output_parser.py: there's far
less to validate when DeepHat is only returning
{"index": int, "agent": str|null, "justification": str} per candidate,
because entire categories of the old validation surface (schema for
endpoint/method/parameter/evidence fields, summary-count consistency,
finding_id handling) don't exist anymore — DeepHat never writes those
fields, so there's nothing there to validate or repair.
"""

from __future__ import annotations

import json
import re
import logging
from typing import Any, Dict, List, Optional

from pipeline.candidate_builder import CandidateSkeleton, merge_classification

logger = logging.getLogger(__name__)


class ClassificationParserError(Exception):
    pass


def _extract_json_block(llm_output: str) -> str:
    """Same tolerant extraction approach as OutputParser — see that
    module's docstring for why (fenced blocks, stray prose, etc.)."""
    if not llm_output or not llm_output.strip():
        raise ClassificationParserError("DeepHat returned empty output.")

    text = llm_output.strip()

    fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fence_match:
        return fence_match.group(1)

    first_brace = text.find("{")
    last_brace = text.rfind("}")
    if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
        return text[first_brace:last_brace + 1]

    raise ClassificationParserError(
        f"Expecting value: line 1 column 1 (char 0)" if first_brace == -1
        else "No valid JSON object found in DeepHat's output."
    )


def parse_classifications(llm_output: str, skeleton_count: int) -> Dict[int, Dict[str, str]]:
    """
    Returns {index: {"agent": str|None, "justification": str}} for every
    index DeepHat actually returned a classification for. Missing indices
    (DeepHat skipped one) simply aren't in the returned dict — the caller
    treats a missing classification the same as an explicit null (no
    agent recommended), which is always a safe default.

    Deliberately tolerant rather than strict: a malformed individual
    entry is skipped with a warning rather than failing the whole batch,
    since the classification task is low-stakes enough (it can only ever
    pick from a pre-vetted menu or null) that discarding one bad entry
    and keeping the rest is safer than burning a full retry over it.
    """
    json_text = _extract_json_block(llm_output)

    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as e:
        raise ClassificationParserError(f"Invalid JSON from DeepHat: {e}")

    if not isinstance(data, dict) or "classifications" not in data:
        raise ClassificationParserError(
            "Expected a top-level 'classifications' array in DeepHat's response."
        )

    classifications = data["classifications"]
    if not isinstance(classifications, list):
        raise ClassificationParserError("'classifications' must be an array.")

    result: Dict[int, Dict[str, str]] = {}

    for entry in classifications:
        if not isinstance(entry, dict):
            logger.warning("Skipping non-object classification entry: %r", entry)
            continue

        index = entry.get("index")
        if not isinstance(index, int) or not (0 <= index < skeleton_count):
            logger.warning(
                "Skipping classification with invalid/out-of-range index: %r "
                "(valid range: 0-%d)", index, skeleton_count - 1,
            )
            continue

        agent = entry.get("agent")
        if agent in ("null", "None", ""):
            agent = None

        justification = str(entry.get("justification") or "")

        result[index] = {"agent": agent, "justification": justification}

    return result


def build_final_candidates(
    skeletons: List[CandidateSkeleton],
    classifications: Dict[int, Dict[str, str]],
) -> List[Dict[str, Any]]:
    """
    The actual merge step: every skeleton becomes exactly one final
    candidate dict, in the same shape the rest of the pipeline
    (Planner/Executor/report_manager) already expects. A skeleton with no
    matching classification (DeepHat skipped it, or its entry was
    dropped as malformed) still becomes a candidate — with
    recommended_agent=None — rather than silently disappearing; the same
    "never drop a real signal silently" principle config.py's rule 9b/9c
    already establishes for the old flow applies here too.
    """
    final = []

    for skeleton in skeletons:
        c = classifications.get(skeleton.index, {})
        agent_choice = c.get("agent")
        justification = c.get("justification") or (
            "(DeepHat did not return a classification for this candidate; "
            "defaulted to no agent recommended rather than dropping it.)"
        )
        final.append(merge_classification(skeleton, agent_choice, justification))

    return final