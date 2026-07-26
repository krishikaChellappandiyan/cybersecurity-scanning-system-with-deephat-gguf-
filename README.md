![Python](https://img.shields.io/badge/Python-3.11-blue)
![Model](https://img.shields.io/badge/LLM-DeepHat-green)
![Inference](https://img.shields.io/badge/Inference-llama.cpp-orange)

An AI-powered passive website security analysis framework that combines **Hellhound Spider** with the **DeepHat** Large Language Model (LLM) to generate intelligent security assessments.

Instead of sending raw crawler output directly to an LLM, the framework extracts security-relevant evidence, fits it to a token budget, builds an optimized context, and performs local AI inference using **DeepHat GGUF** running on **llama.cpp** 

---

## Architecture

```
                Target URL
                     │
                     ▼
            Hellhound Spider
                     │
                     ▼
            Spider JSON Report
                     │
                     ▼
             SpiderExtractor
                     │
                     ▼
        SpiderContextBuilder
                     │
                     ▼
                 DeepHat LLM
                     │
                     ▼
         AI Security Assessment

## Workflow

### 1. Website Crawling

A target URL is provided by the user.

Example:

```
https://example.com
```

The framework launches Hellhound Spider (via `pipeline/crawler.py`) to perform passive reconnaissance, and stores the raw scan under:

```
reports/spiders/
```

### 2. Reconnaissance

Hellhound collects security-related information including:

- Endpoints
- Parameters
- Forms
- Technologies
- Security Headers
- Cookies
- Authentication paths
- JavaScript resources
- Robots.txt / Sitemap
- Response metadata
- Secrets (if detected)

### 3. Spider Extraction

Raw crawler output is usually too large for direct LLM inference. `SpiderExtractor` (`processing/spider_extractor.py`) filters it down to the security-relevant evidence, then measures the **real token count** against llama-server's `/tokenize` endpoint (falling back to a character estimate if the server isn't reachable) and trims the least-critical fields first — `agent_targets`, the crawler's own highest-value shortlist, is only ever trimmed last, one item at a time from the lowest-priority end.

### 4. Context Generation

`SpiderContextBuilder` (`context/spider_context_builder.py`) turns the trimmed evidence into a structured, readable summary — target info, tech stack, WAF findings, header issues, secrets, JS parameters, IDOR/SQLi/CMDi candidates, admin panels, exposed sensitive files, high-priority targets, subdomains, and endpoint statistics.

### 5. AI Analysis

DeepHat receives:

- The structured spider summary
- Your analysis prompt

and generates an AI-assisted passive security assessment.

### 6. Report Storage

`ReportManager` (`storage/report_manager.py`) automatically saves every DeepHat website-analysis response as a Markdown file:

```
reports/deephat/deephat_<target-host>_<timestamp>.md

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- A DeepHat GGUF model (downloaded separately from Hugging Face)
- `llama.cpp` (prebuilt Windows binaries are bundled under `llama.cpp/`; build your own on Linux/macOS)

### Install dependencies

```bash
pip install -r requirements.txt
```

---

## Running the Project

### 1. Start the DeepHat model server

```powershell
cd <project-root>/llama.cpp

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

Linux/macOS: use your own `llama-server` build with the same flags, and update `SERVER_URL` / `HEALTH_URL` in `config.py` if the host/port differs.

Wait until the model finishes loading before continuing.

### 2. Launch the application

In a second terminal, from the project root:

```bash
python chat.py
```

```
============================================================
 DeepHat Cybersecurity Assistant
============================================================

Choose Mode

1. Normal Chat
2. Website Security Analysis
3. Exit
```

- **Normal Chat** — talk to DeepHat directly, no scan context.
- **Website Security Analysis** — runs the full passive analysis pipeline described above, and saves DeepHat's write-up to `reports/deephat/`.

- ## Acknowledgements

This project builds upon several open-source projects and technologies.

### Hellhound Spider


Hellhound provides the website crawling and passive reconnaissance capabilities, including endpoint discovery, technology fingerprinting, parameter extraction, JavaScript analysis, and security header collection.

This project extends Hellhound by transforming crawler output into optimized LLM context and generating AI-assisted security assessments.


### DeepHat

AI analysis is powered by the DeepHat Large Language Model running locally in GGUF format.

Model: [VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF](https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF)

### llama.cpp

Efficient local inference is provided by llama.cpp.

Repository: [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp)
