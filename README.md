![Python](https://img.shields.io/badge/Python-3.11-blue)
![Model](https://img.shields.io/badge/LLM-DeepHat-green)
![Inference](https://img.shields.io/badge/Inference-llama.cpp-orange)

# DeepHat — AI-Guided Web Vulnerability Validation Pipeline

An automated web security testing framework that combines **Hellhound
Spider** (reconnaissance), a local **DeepHat** LLM (triage), and eight
independent, purpose-built **validation agents** (active testing) into one
pipeline — with a deterministic guardrail layer sitting between the AI's
suggestions and anything actually being tested.

**Core design principle:** the AI never decides "this site is vulnerable"
on its own. It only ever picks *which existing validation agent* should
look at *which specific, already-confirmed-real* endpoint. Every finding
that reaches the final report was produced by a real tool sending real
requests to a real target — not by the AI guessing. A routing guardrail
(the Planner) checks every AI decision against the actual crawl evidence
before anything is allowed to execute, specifically to catch cases where
the model's suggestion doesn't hold up: an endpoint that was never really
discovered, a tool that doesn't actually handle that category of problem,
or evidence cited that doesn't actually exist.

---

# Architecture

```text
                    Target URL
                         │
                         ▼
                Hellhound Spider          (discovery — passive only)
                         │
                         ▼
                Spider JSON Report
                         │
                         ▼
                 SpiderExtractor          (raw crawl → token-budgeted context)
                         │
                         ▼
                CandidateBuilder          (deterministic - testable candidates)
                         │                            
                         ▼
                     DeepHat LLM          (picks an agent -per candidate,
                         │                  or declines — never invents endpoints)
                         │                 
                         ▼
              Planner / Router            (guardrail: grounding check,
                         │                 capability-mismatch check,
                         │                 fabricated-evidence check)
                         ▼
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
   SQL_AGENT         XSS_AGENT       AUTHZ_AGENT      ... (8 total, see below)
        │                │                │
        └────────────────┼────────────────┘
                         ▼
              Findings Aggregator
                         │
                         ▼
                  Final Report          (reports/deephat/deephat_<target>.md)
```

---

# The Eight Validation Agents

Each agent is a real, independent security tool — not an AI — that tests
for exactly one category of vulnerability once the Planner has approved a
candidate for it.

| Agent | Tests for | Wrapper |
|---|---|---|
| `SQL_AGENT` | SQL Injection | `agents/sqli_wrapper.py` |
| `XSS_AGENT` | Cross-Site Scripting (browser-validated, confirm-only) | `agents/xss_wrapper.py` |
| `AUTHZ_AGENT` | Broken access control / missing authorization | `agents/authz_wrapper.py` |
| `NOSQL_AGENT` | NoSQL injection (MongoDB-style operator abuse) | `agents/nosql_wrapper.py` |
| `PARAM_INJECTION_AGENT` | SSRF, SSTI, command injection, path traversal, open redirect | `agents/injection_wrapper.py` |
| `PASSWORD_POLICY_AGENT` | Weak/missing password policy enforcement | `agents/password_wrapper.py` |
| `SOURCE_AUDIT_AGENT` | Exposed `.git` source + static secret/taint analysis | `agents/source_auditor_wrapper.py` |
| `MITM_AGENT` | Passive TLS/cookie/CORS/header-level issues | `agents/mitm_wrapper.py` |

There is no separate `COMMAND_INJECTION_AGENT` (handled by
`PARAM_INJECTION_AGENT`) or standalone `IDOR_AGENT` (handled by
`AUTHZ_AGENT`/`SQL_AGENT` depending on the evidence)..

---

# Workflow

## 1. Reconnaissance

A target URL is provided by the user. `pipeline/crawler.py` launches
**Hellhound Spider**, which performs passive discovery — endpoints,
parameters, forms, headers, technology stack, exposed sensitive files,
robots.txt, secrets — and saves the raw report under `reports/spiders/`.

## 2. Extraction

`processing/spider_extractor.py` filters the (often very large) raw crawl
down to security-relevant evidence and fits it within the LLM's token
budget, trimming least-critical fields first.

## 3. Candidate Building

`pipeline/candidate_builder.py` deterministically converts extracted
evidence into a list of real, testable candidates

## 4. Classification

DeepHat (running locally via `llama.cpp`) reviews the candidate list and,
for each one, either picks an agent  or declines with a reason. 
It cannot select an agent outside the menu — any
attempt to do so is clamped to "no agent" before it ever reaches routing.

## 5. Routing & Validation

`pipeline/planner.py` re-checks every one of DeepHat's choices against the
real evidence before allowing it through: was the endpoint actually
discovered, does the chosen agent's capability actually match the
candidate's category, does any cited evidence actually exist. Candidates
that fail these checks, or that no agent covers, land in an explicit
`UNSUPPORTED` bucket — visible in the final report, not silently dropped.

## 6. Active Testing

Approved candidates are dispatched to their real agent
(`pipeline/executor.py`), which sends genuine requests/payloads against
the actual target and returns an honest result — including "tested,
nothing found," which is a valid, distinct outcome from "the agent
failed to run at all."

## 7. Reporting

`storage/report_manager.py` collects every agent's results into one
combined, human-readable report, saved to `reports/deephat/`. Each
agent's own raw output is also kept separately under `agents_output/`.

---

# Setup

## 1. Start the DeepHat Model Server

**Windows**

```powershell
cd <project-root>\llama.cpp

.\llama-server.exe `
  --hf-repo VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF `
  --hf-file deephat-v1-7b-q4_k_m.gguf `
  --threads 8 `
  --ctx-size 8192 `
  --cache-type-k q8_0 `
  --cache-type-v q8_0 `
  --flash-attn on `
  --parallel 1
```

**Linux/macOS**

Use your own `llama-server` build with the same flags and update
`SERVER_URL` and `HEALTH_URL` in `config.py` if the server runs on a
different host or port.

Wait until the model finishes loading before continuing.

## 2. Launch the Application

Open a second terminal and run:

```bash
python chat.py
```

You will see:

```text
============================================================
 DeepHat Cybersecurity Assistant
============================================================

Choose Mode

1. Normal Chat
2. Website Security Analysis
3. Exit
```

### Available Modes

**Normal Chat** — interact directly with DeepHat without a scan.

**Website Security Analysis** — runs the full pipeline described above:
crawl → extract → build candidates → classify → route → validate →
report. Findings are saved to `reports/deephat/`; each agent's own raw
output is saved separately under `agents_output/`.

---
# Acknowledgements

This project builds upon several open-source projects and technologies.

## Hellhound Spider

Hellhound provides website crawling and passive reconnaissance
capabilities, including endpoint discovery, technology fingerprinting,
parameter extraction, JavaScript analysis, and security header collection.

## DeepHat

AI classification is powered by the **DeepHat** Large Language Model
running locally in GGUF format.

**Model:** https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF

## llama.cpp

Efficient local inference is provided by **llama.cpp**.

**Repository:** https://github.com/ggml-org/llama.cpp

## Validation Agents

Each of the eight validation agents wraps an independently-built,
purpose-specific security testing tool, integrated with real-target
testing, evidence-grounded routing, and normalized result reporting.
