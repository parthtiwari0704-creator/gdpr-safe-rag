import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gdpr_rag.config import Settings  # noqa: E402
from gdpr_rag.loaders import load_path  # noqa: E402
from gdpr_rag.pipeline import GDPRAssistant  # noqa: E402


@pytest.fixture
def assistant(tmp_path):
    settings = Settings(data_dir=tmp_path, master_key="test-key-not-for-production", llm_provider="offline")
    app = GDPRAssistant(settings)
    for path in sorted((ROOT / "data" / "sample_docs").glob("*.txt")):
        app.ingest(path.name, load_path(path))
    return app
