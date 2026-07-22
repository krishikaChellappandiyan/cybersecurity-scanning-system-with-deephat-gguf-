from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# llama.cpp GGUF server (DeepHat model, served via llama-server)
# ---------------------------------------------------------------------------
SERVER_URL = "http://127.0.0.1:8080/v1/chat/completions"
HEALTH_URL = "http://127.0.0.1:8080/health"

TEMPERATURE = 0.2
MAX_TOKENS = 1536
MAX_HISTORY = 10       # number of user/assistant turn-pairs kept in context
TIMEOUT = 1200      # 20 minutes - CPU-only 7B inference on large prompts is slow

SYSTEM_PROMPT = """
You are DeepHat, an expert cybersecurity assistant.

You may be given retrieved context from a cybersecurity knowledge base
(OWASP, MITRE ATT&CK, CVE data, bug bounty write-ups, etc).

Rules:
1. When context is provided, use ONLY that context to answer - do not rely on outside knowledge.
2. Do not guess, and do not invent tool names, payloads, CVEs, or code that isn't in the context.
3. If the provided context does not support an answer, say so clearly rather than making something up.
4. If no context is provided, answer normally as an expert cybersecurity assistant.
5. Always give defensive, evidence-based guidance. Prefer prevention and mitigation details when available.
6. Keep answers clear, concise, and in English.
"""

# ---------------------------------------------------------------------------
# RAG data paths
# ---------------------------------------------------------------------------
DATA_DIR = BASE_DIR / "data"
VECTOR_DB_PATH = DATA_DIR / "vectors"
METADATA_DB_PATH = DATA_DIR / "metadata"
OWASP_DATA_PATH = DATA_DIR / "owasp.json"
BUG_BOUNTY_DATA_PATH = DATA_DIR / "bugbounty.json"
CVE_DATA_PATH = DATA_DIR / "cve.json"