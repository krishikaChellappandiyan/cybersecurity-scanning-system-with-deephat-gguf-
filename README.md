# DeepHat Cybersecurity Assistant

DeepHat Cybersecurity Assistant is an AI-powered website security analysis framework that integrates the **Hellhound Spider** crawler with the **DeepHat Large Language Model (LLM)** to perform intelligent passive security assessments.

The framework automatically crawls a target website, extracts security-relevant information, optimizes the crawler output for LLM consumption, and generates an AI-assisted security assessment. All analysis is performed locally using **DeepHat GGUF** running on **llama.cpp**.

---

# Features

- Automated website crawling using Hellhound Spider
- Passive security assessment using DeepHat
- Intelligent extraction of security-relevant crawler data
- Optimized context generation for LLM inference
- Local inference using DeepHat GGUF with `llama.cpp`
- Automatic storage of crawler reports
- Automatic storage of DeepHat analysis reports
- Modular pipeline for future agent integration

---

# Project Architecture

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

# Project Structure

```
GGUF/
│
├── api/
├── context/
├── data/
├── embedding/
├── gguf/
├── hellhound/
├── ingestion/
├── llama.cpp/
├── models/
│
├── pipeline/
│   └── crawler.py
│
├── processing/
│   └── spider_extractor.py
│
├── retrieval/
│
├── retrieval_storage/
│   ├── vector_db.py
│   └── metadata_db.py
│
├── reports/
│   ├── spiders/
│   └── deephat/
│
├── storage/
│   └── report_manager.py
│
├── chat.py
├── deephat.py
├── config.py
├── main.py
└── requirements.txt
```

---

# Workflow

## 1. Crawl Target

The user provides a target URL.

Example:

```
https://example.com
```

---

## 2. Hellhound Spider

The crawler performs passive reconnaissance and generates a JSON report containing:

- Endpoints
- Parameters
- Forms
- Technologies
- Security Headers
- Cookies
- Authentication paths
- JavaScript analysis
- Robots.txt
- Sitemap
- Response metadata
- Secrets (if detected)

The generated crawler report is automatically stored in:

```
reports/spiders/
```

---

## 3. Spider Extraction

Instead of sending the complete crawler output to the LLM, the framework extracts only the security-relevant information.

This significantly reduces the prompt size while preserving important security evidence.

---

## 4. Context Builder

The extracted information is converted into a structured summary optimized for LLM inference.

---

## 5. DeepHat Analysis

DeepHat receives:

- Optimized crawler context
- User analysis prompt

and generates an AI-assisted passive security assessment.

---

## 6. Report Storage

DeepHat responses are automatically stored in JSON format.

Location:

```
reports/deephat/
```

Example:

```json
{
    "target": "https://example.com",
    "timestamp": "20260724_143428",
    "model": "DeepHat",
    "response": "..."
}
```

---

# Getting Started

## Prerequisites

- Python 3.11+
- Git
- Hellhound Spider
- DeepHat GGUF model
- llama.cpp

---

## 1. Clone the Repository

```bash
git clone <repository-url>
cd <repository-directory>
```

---

## 2. Create a Python Environment

Using Conda (recommended):

```bash
conda create -n deephat python=3.11
conda activate deephat
```

Or using venv:

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate
```

---

## 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Download the DeepHat Model

Download the DeepHat GGUF model from Hugging Face.

Repository:

```
VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF
```

Place the model where `llama.cpp` can access it.

---

# Running the Project

## Step 1 – Start the DeepHat Server

Open a terminal and navigate to the `llama.cpp` directory.

```powershell
cd <project-root>/llama.cpp
```

Start the DeepHat server:

```powershell
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

Wait until the model has finished loading.

Keep this terminal running.

---

## Step 2 – Launch the Application

Open another terminal.

Navigate to the project root.

```powershell
cd <project-root>
```

Run:

```powershell
python chat.py
```

The application will display:

```
============================================================
 DeepHat Cybersecurity Assistant
============================================================

Choose Mode

1. Normal Chat
2. Website Security Analysis
3. Exit
```

---

## Step 3 – Website Security Analysis

Select:

```
2
```

Enter the target URL:

```
https://example.com
```

Then provide an analysis prompt.

Example:

```
Analyze the website for potential security vulnerabilities.
```

The framework executes the following pipeline:

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

# Application Modes

## Normal Chat

Interact directly with DeepHat for general cybersecurity discussions.

---

## Website Security Analysis

Performs a complete passive security assessment using the crawler and DeepHat pipeline.

---

# Generated Reports

Crawler Reports

```
reports/spiders/
```

DeepHat Reports

```
reports/deephat/
```

Example:

```
reports/
├── spiders/
│   └── spider_<target>_<timestamp>.json
│
└── deephat/
    └── deephat_<target>_<timestamp>.json
```

---

# Current Capabilities

- Passive website reconnaissance
- Intelligent crawler output extraction
- Context optimization for LLM inference
- AI-assisted passive security analysis
- Local inference using DeepHat GGUF
- JSON report generation
- Automatic report management

---

# Planned Enhancements

- Retrieval-Augmented Generation (RAG)
- Planner module
- SQL Injection validation agent
- XSS validation agent
- Authentication testing agent
- IDOR validation agent
- CSRF validation agent
- Consolidated security report generation
- Agent orchestration pipeline

---

# Technologies Used

- Python
- Hellhound Spider
- DeepHat LLM
- GGUF
- llama.cpp
- JSON
- Hugging Face
