

<div align="center">
🛡️ DeepHat Cybersecurity Assistant

Passive website security analysis, powered by a local LLM.

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Model](https://img.shields.io/badge/LLM-DeepHat-green)
![Inference](https://img.shields.io/badge/Inference-llama.cpp-orange)

</div>

An AI-powered passive website security analysis framework that combines Hellhound Spider with the DeepHat Large Language Model (LLM) to generate intelligent security assessments.

Instead of sending raw crawler output directly to an LLM, the framework extracts security-relevant evidence, fits it to a token budget, builds an optimized context, and performs local AI inference using DeepHat GGUF running on llama.cpp — no external APIs, nothing leaves your machine.

📑 Contents
Architecture
Workflow
Project Structure
Getting Started
Running the Project
Example Usage
Acknowledgements
License
🕸️ Architecture
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
                     │
                     ▼
           Saved Markdown Report
🔄 Workflow
1️⃣ Website Crawling

A target URL is provided by the user.

https://example.com

The framework launches Hellhound Spider (via pipeline/crawler.py) to perform passive reconnaissance, and stores the raw scan under:

reports/spiders/
2️⃣ Reconnaissance

Hellhound collects security-related information including:

Category	Examples
Surface	Endpoints, parameters, forms
Stack	Technologies, security headers, cookies
Access	Authentication paths, robots.txt / sitemap
Client-side	JavaScript resources
Sensitive	Secrets (if detected), response metadata
3️⃣ Spider Extraction

Raw crawler output is usually too large for direct LLM inference. SpiderExtractor (processing/spider_extractor.py) filters it down to the security-relevant evidence, then measures the real token count against llama-server's /tokenize endpoint (falling back to a character estimate if the server isn't reachable) and trims the least-critical fields first — agent_targets, the crawler's own highest-value shortlist, is only ever trimmed last, one item at a time from the lowest-priority end.

4️⃣ Context Generation

SpiderContextBuilder (context/spider_context_builder.py) turns the trimmed evidence into a structured, readable summary — target info, tech stack, WAF findings, header issues, secrets, JS parameters, IDOR/SQLi/CMDi candidates, admin panels, exposed sensitive files, high-priority targets, subdomains, and endpoint statistics.

5️⃣ AI Analysis

DeepHat receives the structured spider summary plus your analysis prompt, and generates an AI-assisted passive security assessment.

6️⃣ Report Storage

ReportManager (storage/report_manager.py) automatically saves every DeepHat website-analysis response as a Markdown file:

reports/deephat/deephat_<target-host>_<timestamp>.md
📁 Project Structure
.
├── chat.py                       # Entry point: menu-driven CLI (Normal Chat / Website Security Analysis)
├── test.py                       # Minimal smoke test for the DeepHat client
├── deephat.py                    # Chat client for the llama-server GGUF endpoint
├── config.py                     # Server URL, system prompt, token/history limits
├── requirements.txt
│
├── pipeline/
│   └── crawler.py                # Runs hellhound/spider.py as a subprocess, returns the report path
├── processing/
│   └── spider_extractor.py       # Token-budget-aware trimming of raw spider scans
├── context/
│   └── spider_context_builder.py # Builds the LLM-friendly security summary
├── storage/
│   └── report_manager.py         # Saves DeepHat's assessment as a Markdown report
│
├── reports/
│   ├── spiders/                  # Raw Hellhound scan JSON (created automatically)
│   └── deephat/                  # DeepHat's Markdown security assessments (created automatically)
│
├── hellhound/                    # Vendored Hellhound Spider (own README/LICENSE, GPL-3.0)
└── llama.cpp/                    # Prebuilt llama.cpp binaries (Windows: llama-server.exe, etc.)

⚠️ Scope note: this build is intentionally scoped to the passive scan → DeepHat pipeline above. An earlier RAG-based knowledge-base chat mode (OWASP/CVE retrieval, FAISS/BM25, file upload) has been removed for now while it's reworked. requirements.txt still lists its dependencies (sentence-transformers, faiss-cpu, rank_bm25, fastapi, uvicorn, pydantic, sqlite-utils, pandas) even though no current module imports them — trim it down if you only need the scanning pipeline. config.py also still has unused DATA_DIR / VECTOR_DB_PATH paths left over from that mode.

🚀 Getting Started
Prerequisites
Python 3.11+
Git
A DeepHat GGUF model (downloaded separately from Hugging Face)
llama.cpp (prebuilt Windows binaries are bundled under llama.cpp/; build your own on Linux/macOS)
Install dependencies
bash
pip install -r requirements.txt
▶️ Running the Project
1. Start the DeepHat model server
powershell
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

Linux/macOS: use your own llama-server build with the same flags, and update SERVER_URL / HEALTH_URL in config.py if the host/port differs. Wait until the model finishes loading before continuing.

2. Launch the application

In a second terminal, from the project root:

bash
python chat.py
============================================================
 DeepHat Cybersecurity Assistant
============================================================

Choose Mode

1. Normal Chat
2. Website Security Analysis
3. Exit
Mode	What it does
1. Normal Chat	Talk to DeepHat directly, no scan context
2. Website Security Analysis	Runs the full passive analysis pipeline and saves DeepHat's write-up to reports/deephat/
💡 Example Usage
Choice : 2
Target URL : https://example.com
Analysis Prompt : Analyze the website for potential security vulnerabilities.
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
    DeepHat
      │
      ▼
AI Security Assessment
      │
      ▼
reports/deephat/deephat_example.com_20260726_161000.md
🙏 Acknowledgements

This project builds upon several open-source projects and technologies.

🕷️ Hellhound Spider — provides the website crawling and passive reconnaissance capabilities: endpoint discovery, technology fingerprinting, parameter extraction, JavaScript analysis, and security header collection. This project extends Hellhound by transforming crawler output into optimized LLM context and generating AI-assisted security assessments.
Repository: project-hellhound-org/Hellhound-Spider

🐐 DeepHat — the language model powering the analysis, running locally in GGUF format.
Model: VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF

⚙️ llama.cpp — provides efficient local GGUF inference.
Repository: ggml-org/llama.cpp
