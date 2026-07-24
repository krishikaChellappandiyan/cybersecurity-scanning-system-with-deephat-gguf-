# DeepHat Cybersecurity Assistant

![Python](https://img.shields.io/badge/Python-3.11-blue)
![Model](https://img.shields.io/badge/LLM-DeepHat-green)
![Inference](https://img.shields.io/badge/Inference-llama.cpp-orange)

An AI-powered passive website security analysis framework that combines **Hellhound Spider** with the **DeepHat** Large Language Model (LLM) to generate intelligent security assessments.

Instead of sending raw crawler output directly to an LLM, the framework extracts security-relevant evidence, builds an optimized context, and performs local AI inference using **DeepHat GGUF** running on **llama.cpp**.

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
```

---

## Workflow

### 1. Website Crawling

A target URL is provided by the user.

Example:

```
https://example.com
```

The framework launches Hellhound Spider to perform passive reconnaissance.

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
- Robots.txt
- Sitemap
- Response metadata
- Secrets (if detected)

Crawler reports are automatically stored in:

```
reports/spiders/
```

### 3. Spider Extraction

Raw crawler output is usually too large for direct LLM inference. `SpiderExtractor` filters and extracts only the security-relevant evidence required for analysis.

### 4. Context Generation

The extracted information is transformed into an optimized, structured context suitable for DeepHat.

### 5. AI Analysis

DeepHat receives:

- Optimized crawler context
- User analysis prompt

and generates an AI-assisted passive security assessment.

---

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- A DeepHat GGUF model (downloaded separately from Hugging Face)
- `llama.cpp` (prebuilt Windows binaries are bundled under `llama.cpp/`; build your own on Linux/macOS)

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

- **Normal Chat** — talk to DeepHat directly, no retrieval or scan context.
- **Website Security Analysis** — runs the full passive analysis pipeline described above.

Alternatively, run `python main.py` for the RAG-grounded chat CLI, which answers from the local knowledge base in `data/` and supports temporarily uploading your own JSON file for the session (`upload <path>` / `unload` / `quit`).

---

## Example Usage

```
Choice : 2
Target URL : https://example.com
Analysis Prompt : Analyze the website for potential security vulnerabilities.
```

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
    DeepHat
      │
      ▼
AI Security Assessment
```

---

## Acknowledgements

This project builds upon several open-source projects and technologies.

### Hellhound Spider

Hellhound provides the website crawling and passive reconnaissance capabilities, including endpoint discovery, technology fingerprinting, parameter extraction, JavaScript analysis, and security header collection.

This project extends Hellhound by transforming crawler output into optimized LLM context and generating AI-assisted security assessments.

Repository: [project-hellhound-org/Hellhound-Spider](https://github.com/project-hellhound-org/Hellhound-Spider)

Author
L4ZZ3RJ0D

### DeepHat

AI analysis is powered by the DeepHat Large Language Model running locally in GGUF format.

Model: [VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF](https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF)

### llama.cpp

Efficient local inference is provided by llama.cpp.

Repository: [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp)
