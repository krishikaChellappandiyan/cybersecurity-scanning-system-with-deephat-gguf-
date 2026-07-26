![Python](https://img.shields.io/badge/Python-3.11-blue)
![Model](https://img.shields.io/badge/LLM-DeepHat-green)
![Inference](https://img.shields.io/badge/Inference-llama.cpp-orange)

# AI-Powered Website Security Analysis using DeepHat GGUF

An AI-powered passive website security analysis framework that combines **Hellhound Spider** with the **DeepHat** Large Language Model (LLM) to generate intelligent security assessments.

Instead of sending raw crawler output directly to an LLM, the framework extracts security-relevant evidence, fits it within a token budget, builds an optimized context, and performs local AI inference using **DeepHat GGUF** running on **llama.cpp**.

---

# Architecture

```text
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
```

---

# Workflow

## 1. Website Crawling

A target URL is provided by the user.

Example:

```text
https://example.com
```

The framework launches **Hellhound Spider** (via `pipeline/crawler.py`) to perform passive reconnaissance and stores the raw scan under:

```text
reports/spiders/
```

---

## 2. Reconnaissance

Hellhound collects security-related information including:

- Endpoints
- Parameters
- Forms
- Technologies
- Security Headers
- Cookies
- Authentication Paths
- JavaScript Resources
- Robots.txt / Sitemap
- Response Metadata
- Secrets (if detected)

---

## 3. Spider Extraction

Raw crawler output is usually too large for direct LLM inference.

`SpiderExtractor` (`processing/spider_extractor.py`) filters the crawler output down to security-relevant evidence, measures the **real token count** against llama-server's `/tokenize` endpoint (falling back to a character estimate if the server is unavailable), and trims the least critical fields first.

`agent_targets`, the crawler's highest-priority security targets, are trimmed only as a last resort, one item at a time from the lowest-priority end.

---

## 4. Context Generation

`SpiderContextBuilder` (`context/spider_context_builder.py`) converts the extracted data into a structured summary containing:

- Target information
- Technology stack
- WAF detection
- Security headers
- Secrets
- JavaScript parameters
- IDOR candidates
- SQL Injection candidates
- Command Injection candidates
- Admin panels
- Sensitive files
- High-priority targets
- Subdomains
- Endpoint statistics

---

## 5. AI Analysis

DeepHat receives:

- Structured spider summary
- User analysis prompt

and generates an AI-assisted passive security assessment.

---

## 6. Report Storage

`ReportManager` (`storage/report_manager.py`) automatically saves every website analysis as a Markdown report:

```text
reports/deephat/deephat_<target-host>_<timestamp>.md
```

---

# Getting Started

## Prerequisites

- Python 3.11+
- Git
- DeepHat GGUF model (downloaded separately from Hugging Face)
- `llama.cpp`
  - Windows: prebuilt binaries included under `llama.cpp/`
  - Linux/macOS: build `llama.cpp` manually

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Running the Project

## 1. Start the DeepHat Model Server

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

Use your own `llama-server` build with the same flags and update `SERVER_URL` and `HEALTH_URL` in `config.py` if the server runs on a different host or port.

Wait until the model finishes loading before continuing.

---

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

### Normal Chat

Interact directly with DeepHat without website scan context.

### Website Security Analysis

Runs the complete passive analysis pipeline:

- Crawl the target website
- Extract security-relevant evidence
- Build optimized LLM context
- Generate an AI-assisted security assessment
- Save the generated report to:

```text
reports/deephat/
```

---

# Acknowledgements

This project builds upon several open-source projects and technologies.

## Hellhound Spider

Hellhound provides website crawling and passive reconnaissance capabilities, including:

- Endpoint discovery
- Technology fingerprinting
- Parameter extraction
- JavaScript analysis
- Security header collection

This project extends Hellhound by transforming crawler output into optimized LLM context and generating AI-assisted security assessments.

---

## DeepHat

AI analysis is powered by the **DeepHat** Large Language Model running locally in GGUF format.

**Model**

https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF

---

## llama.cpp

Efficient local inference is provided by **llama.cpp**.

**Repository**

https://github.com/ggml-org/llama.cpp
