"""Encrypted PII vault.

The vault is the ONLY place where original personal data is kept. Each value
is stored encrypted (Fernet / AES-128-CBC + HMAC-SHA256) and indexed by a keyed
HMAC, so we can look up "do we already have a token for this IBAN?" without
storing the IBAN in plain text.

Erasure (GDPR Art. 17) deletes the ciphertext. The placeholder stays in the
redacted documents, but it can never be turned back into the real value —
the data subject is effectively forgotten ("crypto-shredding").
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .pii import normalise


def generate_master_key() -> str:
    return secrets.token_urlsafe(32)


def resolve_master_key(configured: str, key_file: Path) -> str:
    """Use the configured key, else a locally generated one (dev only)."""
    if configured:
        return configured
    if key_file.exists():
        return key_file.read_text().strip()
    key = generate_master_key()
    key_file.write_text(key)
    try:
        key_file.chmod(0o600)
    except OSError:
        pass
    return key


class PIIVault:
    def __init__(self, path: Path, master_key: str):
        if not master_key:
            raise ValueError("A master key is required for the PII vault")
        enc_key = base64.urlsafe_b64encode(hashlib.sha256(("enc:" + master_key).encode()).digest())
        self._fernet = Fernet(enc_key)
        self._mac_key = hashlib.sha256(("mac:" + master_key).encode()).digest()
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS vault (
                   token TEXT PRIMARY KEY,
                   etype TEXT NOT NULL,
                   lookup TEXT UNIQUE NOT NULL,
                   ciphertext BLOB,
                   created_at TEXT NOT NULL,
                   erased_at TEXT
               )"""
        )
        self._db.execute("CREATE TABLE IF NOT EXISTS counters (etype TEXT PRIMARY KEY, n INTEGER NOT NULL)")
        self._db.commit()

    # ------------------------------------------------------------------ #
    def _lookup_key(self, etype: str, value: str) -> str:
        msg = f"{etype}:{normalise(etype, value)}".encode()
        return hmac.new(self._mac_key, msg, hashlib.sha256).hexdigest()

    def tokenize(self, etype: str, value: str) -> str:
        """Return the stable token for a value, creating one if needed."""
        lookup = self._lookup_key(etype, value)
        with self._lock:
            row = self._db.execute("SELECT token, erased_at FROM vault WHERE lookup=?", (lookup,)).fetchone()
            if row:
                token, erased = row
                return token
            cur = self._db.execute("SELECT n FROM counters WHERE etype=?", (etype,)).fetchone()
            n = (cur[0] if cur else 0) + 1
            self._db.execute("INSERT OR REPLACE INTO counters VALUES (?, ?)", (etype, n))
            token = f"[{etype}_{n}]"
            self._db.execute(
                "INSERT INTO vault VALUES (?, ?, ?, ?, ?, NULL)",
                (token, etype, lookup, self._fernet.encrypt(value.encode()),
                 datetime.now(timezone.utc).isoformat()),
            )
            self._db.commit()
            return token

    __call__ = tokenize  # so the vault can be passed as a tokenizer

    def find_token(self, etype: str, value: str) -> str | None:
        row = self._db.execute("SELECT token FROM vault WHERE lookup=?", (self._lookup_key(etype, value),)).fetchone()
        return row[0] if row else None

    def reveal(self, token: str) -> str | None:
        row = self._db.execute("SELECT ciphertext FROM vault WHERE token=?", (token,)).fetchone()
        if not row or row[0] is None:
            return None
        try:
            return self._fernet.decrypt(row[0]).decode()
        except InvalidToken:
            return None

    def erase(self, token: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                # Drop the ciphertext AND the lookup hash, so the token can no
                # longer be linked to the person in any way.
                "UPDATE vault SET ciphertext=NULL, lookup='erased:' || token, erased_at=? "
                "WHERE token=? AND erased_at IS NULL",
                (datetime.now(timezone.utc).isoformat(), token),
            )
            self._db.commit()
            return cur.rowcount > 0

    def known_values(self, etype: str) -> list[str]:
        """Decrypt all live values of a type (used locally to spot known names)."""
        rows = self._db.execute(
            "SELECT token FROM vault WHERE etype=? AND erased_at IS NULL", (etype,)
        ).fetchall()
        return [v for v in (self.reveal(r[0]) for r in rows) if v]

    def stats(self) -> dict[str, int]:
        rows = self._db.execute(
            "SELECT etype, COUNT(*) FROM vault WHERE erased_at IS NULL GROUP BY etype"
        ).fetchall()
        return dict(rows)

    def close(self) -> None:
        self._db.close()
