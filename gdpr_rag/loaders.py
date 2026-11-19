"""Turn uploaded files into plain text (all processing happens locally)."""
from __future__ import annotations

import io
from pathlib import Path

SUPPORTED = (".txt", ".md", ".csv", ".json", ".eml", ".pdf", ".docx")


def load_bytes(filename: str, data: bytes) -> str:
    ext = Path(filename).suffix.lower()
    if ext == ".pdf":
        from pypdf import PdfReader

        reader = PdfReader(io.BytesIO(data))
        return "\n\n".join((page.extract_text() or "") for page in reader.pages)
    if ext == ".docx":
        try:
            import docx  # python-docx
        except ImportError as exc:
            raise RuntimeError("Install python-docx to read .docx files") from exc
        document = docx.Document(io.BytesIO(data))
        return "\n\n".join(p.text for p in document.paragraphs)
    if ext in SUPPORTED:
        return data.decode("utf-8", errors="replace")
    raise ValueError(f"Unsupported file type '{ext}'. Supported: {', '.join(SUPPORTED)}")


def load_path(path: str | Path) -> str:
    path = Path(path)
    return load_bytes(path.name, path.read_bytes())
