"""Central configuration, read from environment variables (or a .env file)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader so we don't need python-dotenv."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


PROJECT_ROOT = Path(__file__).resolve().parent.parent
_load_dotenv(PROJECT_ROOT / ".env")


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("GDPR_RAG_DATA_DIR", PROJECT_ROOT / "storage")))
    # Secret used to encrypt the PII vault and to compute HMAC lookup keys.
    # Generate one with:  python cli.py gen-key
    master_key: str = field(default_factory=lambda: os.getenv("GDPR_RAG_MASTER_KEY", ""))
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "offline"))
    anthropic_api_key: str = field(default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", ""))
    anthropic_model: str = field(default_factory=lambda: os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"))
    openai_api_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    ollama_url: str = field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: os.getenv("OLLAMA_MODEL", "llama3.1"))
    chunk_size: int = field(default_factory=lambda: int(os.getenv("CHUNK_SIZE", "900")))
    chunk_overlap: int = field(default_factory=lambda: int(os.getenv("CHUNK_OVERLAP", "120")))
    top_k: int = field(default_factory=lambda: int(os.getenv("TOP_K", "4")))
    retention_days: int = field(default_factory=lambda: int(os.getenv("RETENTION_DAYS", "90")))

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    @property
    def vault_path(self) -> Path:
        return self.data_dir / "vault.sqlite"

    @property
    def store_path(self) -> Path:
        return self.data_dir / "documents.sqlite"

    @property
    def audit_path(self) -> Path:
        return self.data_dir / "audit_log.jsonl"

    @property
    def key_file(self) -> Path:
        return self.data_dir / ".master_key"
