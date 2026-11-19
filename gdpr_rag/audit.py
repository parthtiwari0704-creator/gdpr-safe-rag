"""Tamper-evident audit log.

Every action (ingest, query, LLM call, re-identification, erasure ...) is
appended to a JSON-lines file. Each entry contains the SHA-256 hash of the
previous entry, forming a hash chain: if anyone edits or deletes a line,
``verify()`` reports exactly where the chain breaks.

The log itself never contains personal data — only counts, document IDs,
placeholder tokens and hashes of prompts.
"""
from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _hash(entry: dict[str, Any]) -> str:
    payload = json.dumps(entry, sort_keys=True, ensure_ascii=False).encode()
    return hashlib.sha256(payload).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.touch(exist_ok=True)
        self._lock = threading.Lock()

    def _last_hash(self) -> str:
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = json.loads(line)["hash"]
        return last

    def log(self, action: str, actor: str = "system", **details: Any) -> dict[str, Any]:
        with self._lock:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "actor": actor,
                "details": details,
                "prev_hash": self._last_hash(),
            }
            entry["hash"] = _hash(entry)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            return entry

    def entries(self) -> list[dict[str, Any]]:
        with self.path.open("r", encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def verify(self) -> tuple[bool, str]:
        prev = GENESIS
        for i, entry in enumerate(self.entries(), start=1):
            stored = entry.get("hash")
            body = {k: v for k, v in entry.items() if k != "hash"}
            if body.get("prev_hash") != prev:
                return False, f"Chain broken at entry {i}: prev_hash does not match entry {i - 1}"
            if _hash(body) != stored:
                return False, f"Entry {i} was modified (hash mismatch)"
            prev = stored
        return True, f"OK — {len(self.entries())} entries, hash chain intact"
