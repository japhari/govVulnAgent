"""
GovVulnAgent Configuration
"""
from pathlib import Path
import os

BASE_DIR = Path(__file__).parent

# ── Ollama / LLM ─────────────────────────────────────────────────────────────
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
PRIMARY_MODEL = os.getenv("PRIMARY_MODEL", "qwen2.5-coder:32b")
FALLBACK_MODEL = os.getenv("FALLBACK_MODEL", "codellama:34b")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "120"))
LLM_TEMPERATURE = 0.0         # deterministic for security analysis
LLM_MAX_TOKENS = 2048

# ── Code Parsing ─────────────────────────────────────────────────────────────
SUPPORTED_LANGUAGES = {
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}
CHUNK_MAX_TOKENS = 256
CHUNK_OVERLAP_TOKENS = 32
MAX_FILE_SIZE_KB = 500         # skip files larger than this

# ── Semgrep ───────────────────────────────────────────────────────────────────
SEMGREP_TIMEOUT = 60           # seconds per file
SEMGREP_RULESETS = {
    # Keep to registry packs that are broadly available without login.
    # `p/spring-security` is not a valid public pack and causes exit code 7.
    "java": ["p/java", "p/owasp-top-ten"],
    "javascript": ["p/javascript", "p/owasp-top-ten", "p/react"],
    "typescript": ["p/typescript", "p/owasp-top-ten", "p/react"],
}

# ── RAG / FAISS ───────────────────────────────────────────────────────────────
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
FAISS_INDEX_PATH = BASE_DIR / "data" / "cwe" / "nvd_cwe.faiss"
FAISS_META_PATH = BASE_DIR / "data" / "cwe" / "nvd_cwe_meta.json"
RAG_TOP_K = 3
RAG_MIN_SIMILARITY = 0.45

# ── CVSS Defaults ─────────────────────────────────────────────────────────────
SEVERITY_MAP = {
    "CRITICAL": 9.0,
    "HIGH": 7.0,
    "MEDIUM": 5.0,
    "LOW": 2.0,
    "INFO": 0.0,
}

# ── API ───────────────────────────────────────────────────────────────────────
API_HOST = os.getenv("API_HOST", "0.0.0.0")
API_PORT = int(os.getenv("API_PORT", "8080"))
API_WORKERS = int(os.getenv("API_WORKERS", "1"))

# ── Output ────────────────────────────────────────────────────────────────────
REPORT_OUTPUT_DIR = BASE_DIR / "reports"
REPORT_OUTPUT_DIR.mkdir(exist_ok=True)
