# DeepHat — AI-Guided Web Vulnerability Validation Pipeline

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Model](https://img.shields.io/badge/LLM-DeepHat-green)
![Inference](https://img.shields.io/badge/Inference-llama.cpp-orange)
![Security](https://img.shields.io/badge/Security-Automated%20Validation-red)

DeepHat is an AI-guided web security testing framework that combines:

- **Hellhound Spider** for automated reconnaissance and evidence gathering
- **DeepHat V1 7B** for local AI-based vulnerability triage
- **Deterministic candidate generation**
- **Evidence-grounded AI classification**
- **Planner-based routing and validation**
- **Eight independent security validation agents**
- **Centralized result aggregation and reporting**

The system is designed so that the AI does **not** decide that a target is vulnerable by itself.

Instead, the AI only determines:

> Which existing security validation agent should test which already-discovered candidate?

The actual vulnerability validation is performed by dedicated security tools that interact with the target.

---

# License Notice

This project incorporates a  copy of **Hellhound Spider**
(`hellhound/spider.py`), which is licensed under the **GNU General
Public License v3.0 (GPL-3.0)**.

Repository: https://github.com/project-hellhound-org/Hellhound-Spider
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
                CandidateBuilder          (deterministic, zero LLM calls —
                         │                 evidence → real testable candidates)
                         ▼
                     DeepHat LLM          (classification only: picks an agent
                         │                 from a pre-built menu per candidate,
                         │                 or declines — never invents endpoints)
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
# Core Design Principle

DeepHat is an **AI-guided validation system**, not an AI-only vulnerability detector.

The pipeline separates:

```text
Discovery
    ↓
Evidence
    ↓
Candidate Generation
    ↓
AI Classification
    ↓
Deterministic Validation
    ↓
Real Security Testing
    ↓
Reporting
```

The AI does not create arbitrary URLs, parameters, or vulnerabilities.

The Planner verifies the AI's proposed action against the evidence produced by the crawler.

This provides an additional guardrail against:

* Fabricated endpoints
* Unsupported vulnerability categories
* Invalid agent selection
* Evidence that does not actually exist
* Testing candidates that were never discovered

---

# Validation Agents

The project currently integrates eight security validation agents.

| Agent                   | Purpose                                                                     | Underlying Tool                                    | Wrapper                       | Candidate Type      |
| ----------------------- | --------------------------------------------------------------------------- | --------------------------------------------------- | ------------------------------ | -------------------- |
| `SQL_AGENT`             | SQL Injection validation                                                    | `agents/sql_agent/sqli.py`                          | `agents/sqli_wrapper.py`      | Confirm-or-Reject     |
| `XSS_AGENT`             | Cross-Site Scripting validation                                             | `agents/xss_agent/XSSDetector19.py`                 | `agents/xss_wrapper.py`       | Confirm-Only          |
| `AUTHZ_AGENT`           | Authorization / access-control validation                                   | `agents/authz_agent/missing_authz_detector_v2.py`   | `agents/authz_wrapper.py`     | Confirm-or-Reject     |
| `NOSQL_AGENT`           | NoSQL injection validation                                                  | `agents/nosql_agent/nosql.py`                       | `agents/nosql_wrapper.py`     | Confirm-or-Reject     |
| `PARAM_INJECTION_AGENT` | SSRF, SSTI, command injection, path traversal and related injection testing | `agents/command_ Injection detector/injection_detector.py` | `agents/injection_wrapper.py` | Confirm-or-Reject     |
| `PASSWORD_POLICY_AGENT` | Password policy enforcement testing                                         | `agents/password_checker agent/password_checker .py`| `agents/password_wrapper.py`  | Confirm-or-Reject     |
| `SAST_AGENT`            | Static source-code security analysis and exposed Git/source analysis        | `agents/sast_agent/sast.py`                         | `agents/sast_wrapper.py`      | Confirm-or-Reject     |
| `MITM_AGENT`            | TLS, cookie, CORS and security-header related checks                        | `agents/Passiveobserver5/Passive_observer5.py`      | `agents/mitm_wrapper.py`      | Confirm-or-Reject     |

Each agent is an independent security testing component, dispatched
directly from the Planner's routing decision — no agent depends on
another agent's output or execution order.

**Confirm-Only** (`XSS_AGENT`): the crawler evidence already suggests a
concrete issue; the agent re-checks and confirms it with real browser
execution.

**Confirm-or-Reject** (the other seven): the crawler evidence only
establishes that something is *worth testing* — the agent actively
probes the target to determine whether a real issue exists. A "nothing
found" result from one of these agents is a legitimate, expected
outcome, not a failure.

The wrappers provide a common interface so that the pipeline can
execute different tools consistently.
---

# 1. Hellhound Spider

Hellhound Spider performs automated reconnaissance against the target.

Its role is discovery and evidence gathering. This includes active
probing of known sensitive paths (e.g. checking for an exposed `.git`
directory), active CORS auditing, GraphQL introspection probing, and,
where enabled, form interaction — not purely passive observation.

The crawler can collect information such as:

* URLs
* Endpoints
* Query parameters
* Forms
* HTTP methods
* Headers
* Technology information
* JavaScript references
* Security-related observations
* `robots.txt`
* Potentially sensitive files
* Other reconnaissance evidence

The crawler output becomes the evidence source for the rest of the pipeline.

```text
Target
  ↓
Hellhound Spider
  ↓
Spider JSON
```

The pipeline does not directly allow the AI to invent targets outside this evidence.

---

# 2. Spider Extraction

`processing/spider_extractor.py`

The raw crawler output can contain a large amount of information.

The SpiderExtractor converts the raw crawl into a more useful security-oriented context.

Its responsibilities include:

* Extracting relevant evidence
* Filtering unnecessary information
* Normalizing crawler data
* Preparing information for the LLM
* Managing the context/token budget

```text
Raw Spider Report
        ↓
SpiderExtractor
        ↓
Security-Relevant Evidence
```

---

# 3. Candidate Builder

`pipeline/candidate_builder.py`

The CandidateBuilder converts crawler evidence into deterministic, testable candidates.

For example:

```text
Endpoint:
    /search

Method:
    GET

Parameter:
    q

Evidence:
    Parameter observed during crawl
```

This can become a candidate such as:

```text
Candidate:
    URL = /search
    Parameter = q
    Category = injection-related
```

The important property is that the candidate originates from actual crawler evidence.

---

# 4. DeepHat Classification

DeepHat runs locally through `llama.cpp`.

The model receives the candidate information and determines which validation agent is appropriate.

Conceptually:

```text
Candidate
    ↓
DeepHat
    ↓
Agent Selection
```

For example:

```text
Candidate → SQL_AGENT
```

or:

```text
Candidate → XSS_AGENT
```

or:

```text
Candidate → NO_AGENT
```

The model does not directly execute security tools.

---

# 5. Planner / Router

`pipeline/planner.py`

The Planner is the deterministic guardrail layer between the AI and the security agents.

It checks whether the proposed AI action is actually valid.

Important checks include:

### Endpoint grounding

Was the endpoint actually discovered by the crawler?

### Capability validation

Does the selected agent actually support the vulnerability category?

### Evidence validation

Does the evidence referenced by the model actually exist?

### Candidate validation

Is the candidate a legitimate testable candidate?

Conceptually:

```text
DeepHat Decision
       ↓
     Planner
       ↓
 ┌─────┴─────┐
 │           │
Valid      Invalid
 │           │
 ▼           ▼
Execute   Reject / Unsupported
```

This prevents the LLM from directly controlling arbitrary security testing.

---

# 6. Executor

`pipeline/executor.py`

The Executor dispatches approved candidates to the appropriate validation agent.

```text
Planner
   ↓
Executor
   ↓
Wrapper
   ↓
Security Agent
   ↓
Target
```

The Executor also normalizes the returned result so that different agents can participate in the same pipeline.

A useful distinction is maintained between:

```text
Agent executed + vulnerability found
```

```text
Agent executed + nothing found
```

and:

```text
Agent failed / could not execute
```

These are different outcomes and should not be treated as the same result.

---

# 7. SQL Injection Agent

`agents/sql_agent/sqli.py`

The SQL agent performs active SQL injection validation.

It can test discovered parameters using SQL injection techniques and analyze responses for evidence of injection.

The wrapper is:

```text
agents/sqli_wrapper.py
```

Pipeline:

```text
Crawler Evidence
      ↓
CandidateBuilder
      ↓
DeepHat
      ↓
Planner
      ↓
SQL_AGENT
      ↓
SQLi Result
```

---

# 8. XSS Agent

`agents/xss_agent/XSSDetector19.py`

The XSS agent is responsible for Cross-Site Scripting validation.

The wrapper is:

```text
agents/xss_wrapper.py
```

The agent can perform active testing and use browser-oriented validation where applicable.

---

# 9. Authorization Agent

`agents/authz_agent/missing_authz_detector_v2.py`

The authorization agent checks for access-control problems and missing authorization controls.

The wrapper is:

```text
agents/authz_wrapper.py
```

This category covers situations where an endpoint or resource may be accessible without the required authorization.

---

# 10. NoSQL Injection Agent

`agents/nosql_agent/nosql.py`

The NoSQL agent tests for NoSQL injection conditions, particularly MongoDB-style operator abuse.

Supporting dataset:

```text
agents/nosql_agent/dataset.py
```

Wrapper:

```text
agents/nosql_wrapper.py
```

Pipeline:

```text
Candidate
    ↓
DeepHat
    ↓
Planner
    ↓
NOSQL_AGENT
    ↓
Validation
```

---

# 11. Parameter Injection Agent

`agents/command_ Injection detector/injection_detector.py`

This functionality is exposed through:

```text
agents/injection_wrapper.py
```

The injection validation layer covers multiple injection-oriented categories, including:

* SSRF
* SSTI
* Command injection
* Path traversal
* Open redirect

The pipeline uses the appropriate candidate category and dispatches it through the injection wrapper.

---

# 12. Password Policy Agent

The password policy validation functionality is implemented through:

```text
agents/password_checker agent/password_checker .py
```

and exposed through:

```text
agents/password_wrapper.py
```

It focuses on password-policy enforcement and related account-creation behavior.

---

# 13. SAST Agent

`agents/sast_agent/sast.py`

The SAST agent performs **Static Application Security Testing**.

Unlike the active web agents, SAST is primarily concerned with source code rather than sending vulnerability payloads to individual HTTP parameters.

It can analyze source code for security-relevant patterns such as:

* Hardcoded secrets
* Weak cryptography
* Injection-prone code
* Configuration weaknesses
* Logging weaknesses
* Dependency-related issues
* Static source-level security patterns

The SAST wrapper is:

```text
agents/sast_wrapper.py
```

The agent can also resolve a target website's exposed `.git` repository when such exposure exists, reconstruct source material, and then analyze the recovered source.

Therefore:

```text
Website
   ↓
Exposed .git check
   ↓
Git recovery
   ↓
Source extraction
   ↓
Static analysis
   ↓
SAST findings
```

A normal website without an exposed `.git` repository can legitimately produce a skipped/no-source outcome rather than a SAST finding.

---

# 14. MITM Agent

`agents/Passiveobserver5/Passive_observer5.py`

The MITM-related validation layer focuses on passive web-security properties such as:

* TLS configuration
* Cookie security
* CORS behavior
* Security headers
* WebSocket, GraphQL, and OpenAPI exposure
* Other transport/browser security observations

The wrapper is:

```text
agents/mitm_wrapper.py
```

It complements the active vulnerability-testing agents by checking security properties that do not necessarily require injection payloads.

---

# Reporting

The pipeline combines validation results into a unified report.

The reporting layer is handled by:

```text
storage/report_manager.py
```

The final pipeline result can distinguish between:

```text
Confirmed Finding
Possible Finding
Tested — Nothing Found
Unsupported
Skipped
Agent Failure
```

This distinction is important because:

> No vulnerability found is not the same as the agent failing to run.

---

# Local Runtime Files

Large and generated files are intentionally kept outside the Git repository.

The project `.gitignore` excludes:

```text
models/
reports/
agents_output/
__pycache__/
*.pyc
```

Therefore the following are local/runtime assets:

```text
models/
    deephat-v1-7b-q4_k_m.gguf

reports/
    ...

agents_output/
    ...
```

These files are **not required to be committed to the Git repository**.

The DeepHat GGUF model is intentionally kept locally because of its large size.

---

# DeepHat Model

The project uses the DeepHat V1 7B model in GGUF format.

Model:

[https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF](https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF)

The model is loaded locally using `llama.cpp`.

The model file itself is not included in this repository.

---

# llama.cpp

Local inference is provided by `llama.cpp`.

Repository:

[https://github.com/ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp)

The project communicates with the local DeepHat model server through the configured server endpoint.

---

# Setup

## 1. Install Python Dependencies

Create and activate a virtual environment if desired.

Then install the project requirements:

```bash
pip install -r requirements.txt
```

---

## 2. Obtain the DeepHat Model

Download the DeepHat GGUF model separately.

The model should be placed locally under:

```text
models/
```

For example:

```text
models/
└── deephat-v1-7b-q4_k_m.gguf
```

The model directory is ignored by Git.

---

# 3. Start llama.cpp

Navigate to the llama.cpp directory.

### Windows

Example:

```powershell
cd llama.cpp

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

Wait for the model server to finish loading.

If the model server runs on another host or port, update the appropriate configuration in:

```text
config.py
```

---

# 4. Launch DeepHat

Open a second terminal:

```bash
python chat.py
```

The application provides the main interaction interface.

Example:

```text
============================================================
 DeepHat Cybersecurity Assistant
============================================================

Choose Mode

1. Normal Chat
2. Website Security Analysis
3. Exit
```

---

# Website Security Analysis

Selecting Website Security Analysis starts the complete pipeline:

```text
Target URL
    ↓
Hellhound Spider
    ↓
Spider JSON
    ↓
SpiderExtractor
    ↓
CandidateBuilder
    ↓
DeepHat Classification
    ↓
Planner Validation
    ↓
Executor
    ↓
Security Agent
    ↓
Result Aggregation
    ↓
Final Report
```

---

# Security Testing Notice

This project is intended for authorized security testing.

Only test:

* Systems you own
* Applications you are explicitly authorized to assess
* Deliberately vulnerable security-training applications
* Environments where you have written permission to perform testing

Do not use the active validation agents against systems without authorization.

---

# Project Structure

```text
gguf/
│
├── agents/
│   ├── authz_agent/
│   ├── command_ Injection detector/
│   ├── nosql_agent/
│   ├── Passiveobserver5/
│   ├── password_checker agent/
│   ├── sast_agent/
│   ├── sql_agent/
│   ├── xss_agent/
│   │
│   ├── authz_wrapper.py
│   ├── injection_wrapper.py
│   ├── mitm_wrapper.py
│   ├── nosql_wrapper.py
│   ├── password_wrapper.py
│   ├── sast_wrapper.py
│   ├── sqli_wrapper.py
│   └── xss_wrapper.py
│
├── context/
│
├── hellhound/
│   └── spider.py
│
├── pipeline/
│   ├── agent_capabilities.py
│   ├── agent_report_paths.py
│   ├── candidate_builder.py
│   ├── crawler.py
│   ├── executor.py
│   └── planner.py
│
├── processing/
│   ├── classification_parser.py
│   ├── output_parser.py
│   └── spider_extractor.py
│
├── storage/
│   └── report_manager.py
│
├── chat.py
├── config.py
├── deephat.py
├── requirements.txt
│
├── models/              # Local — not committed
├── reports/             # Generated — not committed
└── agents_output/       # Generated — not committed
```

---

# Design Summary

DeepHat separates AI reasoning from security validation.

The AI performs:

```text
Classification
```

The deterministic pipeline performs:

```text
Grounding
Routing
Capability Validation
Candidate Validation
```

The security agents perform:

```text
Actual Security Testing
```

The reporting layer performs:

```text
Result Aggregation
```

Therefore the overall architecture is:

```text
        AI
        │
        │ classification only
        ▼
   Deterministic
      Planner
        │
        │ validated decision
        ▼
 Real Security Agents
        │
        │ actual testing
        ▼
    Findings
        │
        ▼
     Reports
```

This architecture is intended to reduce hallucinated vulnerability claims while allowing a local LLM to intelligently coordinate multiple specialized security-testing agents.

---

# Acknowledgements

## Hellhound Spider

Hellhound Spider provides this project's automated reconnaissance and
evidence-gathering capabilities — a fully autonomous crawler that
performs active discovery (including probing known sensitive paths,
CORS auditing, and GraphQL introspection), not purely passive traffic
observation.

Repository: https://github.com/project-hellhound-org/Hellhound-Spider

License: GNU General Public License v3.0 (GPL-3.0)

This project includes and has modified a copy of Hellhound Spider
(`hellhound/spider.py`). See the License Notice at the top of this
document.

## DeepHat

AI classification is powered by the DeepHat Large Language Model running locally in GGUF format.

Model:

[https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF](https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF)

## llama.cpp

Local inference is provided by llama.cpp:

[https://github.com/ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp)

## Validation Agents

The project integrates multiple purpose-built security validation tools through a common wrapper and execution architecture.
