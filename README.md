## Running the Project

### 1. Start the DeepHat Server

Open a terminal and navigate to the `llama.cpp` directory:

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

Use your own `llama-server` build with the same flags, and update the `SERVER_URL` and `HEALTH_URL` values in `config.py` if your server is running on a different host or port.

Wait until the model has fully loaded before continuing.

---

### 2. Launch the Application

Open a **second terminal**, navigate to the project root, and run:

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

#### 1. Normal Chat

Interact directly with the DeepHat model without any website scan context.

#### 2. Website Security Analysis

Runs the complete passive analysis pipeline:

- Crawls the target website using Hellhound Spider
- Extracts security-relevant context
- Performs RAG-based retrieval
- Generates an AI-assisted security assessment using DeepHat
- Saves the generated report to:

```text
reports/deephat/
```

---

# Acknowledgements

This project builds upon several open-source projects and technologies.

## Hellhound Spider

Hellhound provides the website crawling and passive reconnaissance capabilities, including:

- Endpoint discovery
- Technology fingerprinting
- Parameter extraction
- JavaScript analysis
- Security header collection

This project extends Hellhound by transforming crawler output into optimized LLM context and generating AI-assisted security assessments.

---

## DeepHat

AI-powered security analysis is performed using the **DeepHat** Large Language Model running locally in GGUF format.

**Model**

https://huggingface.co/VISHNUDHAT/DeepHat-V1-7B-Q4_K_M-GGUF

---

## llama.cpp

Efficient local inference is powered by **llama.cpp**.

**Repository**

https://github.com/ggml-org/llama.cpp
