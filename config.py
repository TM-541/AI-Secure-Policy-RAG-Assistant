import os
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


def _env_int(name, default, minimum=1, maximum=None):
    """Read a bounded integer from the environment, falling back on bad input."""
    try:
        value = int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
    if value < minimum or (maximum is not None and value > maximum):
        return default
    return value


def _env_float(name, default, minimum=0.0, maximum=None):
    """Read a bounded float from the environment, falling back on bad input."""
    try:
        value = float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default
    if value < minimum or (maximum is not None and value > maximum):
        return default
    return value


# Application metadata
APP_NAME = "Policy RAG Chatbot"
APP_VERSION = "1.1.0"
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")  # development | production

# Directories and storage
DATA_DIR = BASE_DIR / "data"
IMPORT_DIR = BASE_DIR / "policy_docs" / "to_import"
CHROMA_DIR = DATA_DIR / "chroma_db"
SQLITE_PATH = DATA_DIR / "policy_store.sqlite3"
AUDIT_PATH = DATA_DIR / "audit.log"

# Ollama configuration
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
OLLAMA_TIMEOUT = _env_int("OLLAMA_TIMEOUT", 180, maximum=1800)

# Backward-compatible aliases for rag_engine.py
OLLAMA_BASE_URL = OLLAMA_HOST

CHAT_MODEL = os.getenv("CHAT_MODEL", "llama3.2:3b")
OLLAMA_MODEL = CHAT_MODEL

EMBED_MODEL = os.getenv("EMBED_MODEL", "nomic-embed-text")
EMBEDDING_MODEL = EMBED_MODEL

# A non-local Ollama host means questions and policy text leave this machine.
OLLAMA_IS_LOCAL = urlparse(OLLAMA_HOST).hostname in {"127.0.0.1", "localhost", "::1"}
if not OLLAMA_IS_LOCAL:
    print(f"WARNING: OLLAMA_HOST points to a remote server ({OLLAMA_HOST}). "
          "Policy text and questions will be sent over the network.")

# Admin access for the security audit panel.
# Set ADMIN_PASSWORD in .env; if unset, the audit panel stays locked.
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
ADMIN_MAX_ATTEMPTS = _env_int("ADMIN_MAX_ATTEMPTS", 5, maximum=100)

# Retrieval settings (changing chunk settings triggers a re-index automatically)
TOP_K = _env_int("TOP_K", 4, maximum=20)
CHUNK_SIZE = _env_int("CHUNK_SIZE", 1000, minimum=200, maximum=8000)
CHUNK_OVERLAP = _env_int("CHUNK_OVERLAP", 150, minimum=0, maximum=2000)
# Questions whose closest policy chunk is further than this (cosine distance)
# are treated as off-topic and never reach the LLM. Calibrated for
# nomic-embed-text: real policy questions ~0.20-0.42, off-topic/jailbreaks >0.50.
RELEVANCE_MAX_DISTANCE = _env_float("RELEVANCE_MAX_DISTANCE", 0.50, maximum=2.0)
# Blocked inputs per browser session before the chat is paused.
MAX_BLOCKED_PER_SESSION = _env_int("MAX_BLOCKED_PER_SESSION", 3, maximum=100)
BLOCK_COOLDOWN_SECONDS = _env_int("BLOCK_COOLDOWN_SECONDS", 300, maximum=86400)

# Question and response limits
MAX_QUESTION_CHARS = 1200
MAX_CONTEXT_CHARS = 8000
MAX_ANSWER_TOKENS = _env_int("MAX_ANSWER_TOKENS", 300, maximum=4096)
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
ANSWER_CACHE_SIZE = _env_int("ANSWER_CACHE_SIZE", 128, minimum=0, maximum=10000)

# Model performance
MODEL_KEEP_ALIVE = os.getenv("MODEL_KEEP_ALIVE", "30m")

# === Cybersecurity Guardrail Constants ===
# These are used by rag_engine.py to prevent Prompt Injection and Data Leakage.

# 1. Prompt Injection Detection
# Catches common jailbreaks, system prompt extractions, and instruction overrides.
INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|above|prior)\s+instructions",
    r"you\s+are\s+now\s+(DAN|developer\s+mode|unrestricted)",
    r"system\s+prompt\s*(:|is|reveal)",
    r"repeat\s+(the\s+)?(text|words)\s+above",
    r"</?(system|instruction|prompt|admin)>",
    r"forget\s+(everything|all)\s+(you\s+know|above)",
    r"bypass\s+(security|rules|guidelines)",
]

# 2. Sensitive Information (PII) Redaction
# Catches SSNs, credit cards, private keys, and API tokens.
SENSITIVE_PATTERNS = [
    r"\b\d{3}-\d{2}-\d{4}\b",  # US SSN
    r"\b(?:\d[ -]*?){13,16}\b",  # Credit Card approximation
    r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",  # Private Keys
    r"\b(?:api[_-]?key|secret|token|password)\s*[:=]\s*\S{8,}",  # Generic secrets
]

# Create required directories
for folder in (DATA_DIR, IMPORT_DIR, CHROMA_DIR):
    folder.mkdir(parents=True, exist_ok=True)
