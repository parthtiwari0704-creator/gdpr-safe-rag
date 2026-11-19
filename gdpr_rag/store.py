"""Document store and retriever.

Only REDACTED text is ever written here. Retrieval uses TF-IDF with word
uni/bi-grams (runs fully offline, no embedding API that could leak data).
Placeholders like [PERSON_3] are kept as single tokens, so a question about a
person retrieves the chunks about that same person.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class Chunk:
    doc_id: str
    filename: str
    index: int
    text: str
    score: float = 0.0


def chunk_text(text: str, size: int = 600, overlap: int = 100) -> list[str]:
    """Paragraph-aware chunking with character overlap."""
    paragraphs = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, current = [], ""
    for p in paragraphs:
        if len(current) + len(p) + 2 <= size:
            current = f"{current}\n\n{p}" if current else p
            continue
        if current:
            chunks.append(current)
        while len(p) > size:  # very long paragraph: hard split on a space
            cut = p.rfind(" ", 0, size)
            cut = cut if cut > size // 2 else size
            chunks.append(p[:cut])
            p = p[max(cut - overlap, 0):].lstrip()
        tail = chunks[-1][-overlap:] if chunks and overlap else ""
        tail = tail[tail.find(" ") + 1:] if " " in tail else tail
        current = f"{tail} {p}".strip() if tail else p
    if current:
        chunks.append(current)
    return chunks


class DocumentStore:
    def __init__(self, path: Path):
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS documents (
                doc_id TEXT PRIMARY KEY, filename TEXT, created_at TEXT,
                pii_counts TEXT, tokens TEXT
            );
            CREATE TABLE IF NOT EXISTS chunks (
                doc_id TEXT, idx INTEGER, text TEXT,
                PRIMARY KEY (doc_id, idx)
            );
            """
        )
        self._db.commit()
        self._vectorizer: TfidfVectorizer | None = None
        self._matrix = None
        self._rows: list[tuple[str, str, int, str]] = []
        self._dirty = True

    # ------------------------------------------------------------------ #
    def add_document(self, filename: str, redacted_text: str, pii_counts: dict[str, int],
                     tokens: list[str], chunk_size: int, overlap: int) -> tuple[str, int]:
        doc_id = uuid.uuid4().hex[:12]
        pieces = chunk_text(redacted_text, chunk_size, overlap)
        # Give every chunk the document title so later chunks keep their context.
        title = next((line.strip() for line in redacted_text.splitlines() if line.strip()), filename)[:120]
        pieces = [p if i == 0 else f"({title})\n{p}" for i, p in enumerate(pieces)]
        with self._lock:
            self._db.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?, ?)",
                (doc_id, filename, datetime.now(timezone.utc).isoformat(),
                 json.dumps(pii_counts), json.dumps(sorted(set(tokens)))),
            )
            self._db.executemany("INSERT INTO chunks VALUES (?, ?, ?)",
                                 [(doc_id, i, c) for i, c in enumerate(pieces)])
            self._db.commit()
            self._dirty = True
        return doc_id, len(pieces)

    def list_documents(self) -> list[dict]:
        rows = self._db.execute(
            "SELECT d.doc_id, d.filename, d.created_at, d.pii_counts, d.tokens, COUNT(c.idx) "
            "FROM documents d LEFT JOIN chunks c ON c.doc_id = d.doc_id "
            "GROUP BY d.doc_id ORDER BY d.created_at"
        ).fetchall()
        return [
            {"doc_id": r[0], "filename": r[1], "created_at": r[2],
             "pii_counts": json.loads(r[3]), "tokens": json.loads(r[4]), "chunks": r[5]}
            for r in rows
        ]

    def get_document_text(self, doc_id: str) -> str:
        rows = self._db.execute("SELECT text FROM chunks WHERE doc_id=? ORDER BY idx", (doc_id,)).fetchall()
        return "\n\n".join(r[0] for r in rows)

    def documents_with_token(self, token: str) -> list[str]:
        like = f'%"{token}"%'
        return [r[0] for r in self._db.execute("SELECT doc_id FROM documents WHERE tokens LIKE ?", (like,))]

    def delete_document(self, doc_id: str) -> bool:
        with self._lock:
            cur = self._db.execute("DELETE FROM documents WHERE doc_id=?", (doc_id,))
            self._db.execute("DELETE FROM chunks WHERE doc_id=?", (doc_id,))
            self._db.commit()
            self._dirty = True
            return cur.rowcount > 0

    def expired_documents(self, retention_days: int) -> list[str]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=retention_days)).isoformat()
        return [r[0] for r in self._db.execute("SELECT doc_id FROM documents WHERE created_at < ?", (cutoff,))]

    # ------------------------------------------------------------------ #
    def _rebuild(self) -> None:
        self._rows = self._db.execute(
            "SELECT c.doc_id, d.filename, c.idx, c.text FROM chunks c JOIN documents d ON d.doc_id = c.doc_id"
        ).fetchall()
        if self._rows:
            self._vectorizer = TfidfVectorizer(
                lowercase=True, ngram_range=(1, 2), sublinear_tf=True, stop_words="english",
                token_pattern=r"(?u)\[?[A-Za-z_]+_Q?\d+\]?|\b\w\w+\b",
            )
            self._matrix = self._vectorizer.fit_transform([r[3] for r in self._rows])
        else:
            self._vectorizer, self._matrix = None, None
        self._dirty = False

    def search(self, query: str, k: int = 4, min_score: float = 0.02) -> list[Chunk]:
        with self._lock:
            if self._dirty:
                self._rebuild()
            if self._vectorizer is None:
                return []
            scores = cosine_similarity(self._vectorizer.transform([query]), self._matrix)[0]
        ranked = scores.argsort()[::-1][:k]
        return [
            Chunk(self._rows[i][0], self._rows[i][1], self._rows[i][2], self._rows[i][3], float(scores[i]))
            for i in ranked if scores[i] >= min_score
        ]
