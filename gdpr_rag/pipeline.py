"""The GDPR-safe RAG pipeline that ties everything together.

    upload ─► extract text ─► detect PII ─► pseudonymise (vault) ─► chunk + index
    question ─► pseudonymise ─► retrieve ─► leak guard ─► LLM ─► (optional) re-identify
                                  every step ─► hash-chained audit log
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from .audit import AuditLog, sha256_text
from .config import Settings
from .llm import LLMClient, LLMError, build_prompt
from .pii import ENTITY_TYPES, PIIDetector, PLACEHOLDER_RE, normalise, redact, reidentify
from .store import Chunk, DocumentStore
from .vault import PIIVault, resolve_master_key

# Who may see real values again. Analysts work with pseudonymised data only.
ROLES_ALLOWED_TO_REVEAL = {"dpo", "compliance_officer"}


@dataclass
class Answer:
    question_redacted: str
    answer_redacted: str
    answer_display: str
    sources: list[Chunk] = field(default_factory=list)
    revealed: bool = False
    leak_guard_hits: int = 0
    provider: str = ""
    latency_ms: int = 0


class GDPRAssistant:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or Settings()
        key = resolve_master_key(self.settings.master_key, self.settings.key_file)
        self.vault = PIIVault(self.settings.vault_path, key)
        self.store = DocumentStore(self.settings.store_path)
        self.audit = AuditLog(self.settings.audit_path)
        self.llm = LLMClient(self.settings)

    def _detector(self, strict: bool = False) -> PIIDetector:
        # Names we already know about are caught even without "Mr." or a label.
        return PIIDetector(extra_names=self.vault.known_values("PERSON"), strict=strict)

    def _query_tokenizer(self):
        """Reuse vault tokens for known values, but never write to the vault from
        a question (otherwise asking about an erased person would restore them)."""
        local: dict[tuple[str, str], str] = {}

        def tok(etype: str, value: str) -> str:
            known = self.vault.find_token(etype, value)
            if known:
                return known
            key = (etype, normalise(etype, value))
            if key not in local:
                local[key] = f"[{etype}_Q{sum(1 for k in local if k[0] == etype) + 1}]"
            return local[key]
        return tok

    # ------------------------------------------------------------------ #
    # Ingestion
    # ------------------------------------------------------------------ #
    def preview(self, text: str):
        """Show what would be redacted, without storing anything."""
        return redact(text, self._detector())

    def ingest(self, filename: str, text: str, actor: str = "analyst") -> dict:
        result = redact(text, self._detector(), tokenizer=self.vault)
        doc_id, n_chunks = self.store.add_document(
            filename, result.text, result.counts(), list(result.replacements),
            self.settings.chunk_size, self.settings.chunk_overlap,
        )
        self.audit.log(
            "document_ingested", actor, doc_id=doc_id, filename=filename,
            chars=len(text), chunks=n_chunks, pii_found=result.counts(),
            raw_text_stored=False,
        )
        return {"doc_id": doc_id, "chunks": n_chunks, "pii_found": result.counts(),
                "redacted_text": result.text}

    # ------------------------------------------------------------------ #
    # Question answering
    # ------------------------------------------------------------------ #
    def ask(self, question: str, actor: str = "analyst", role: str = "analyst",
            reveal: bool = False) -> Answer:
        t0 = time.perf_counter()
        detector = self._detector(strict=True)
        tokenizer = self._query_tokenizer()
        q = redact(question, detector, tokenizer=tokenizer)
        self.audit.log("query_received", actor, role=role, pii_in_question=q.counts(),
                       question_sha256=sha256_text(q.text))

        # Guard: the question names someone who is in none of the documents.
        # Answering anyway would describe a *different* person, so stop here.
        tokens = PLACEHOLDER_RE.findall(q.text)
        unknown_people = [t for t in tokens if t.startswith("[PERSON_Q")]
        known_people = [t for t in tokens if t.startswith("[PERSON_") and not t.startswith("[PERSON_Q")]
        if unknown_people and not known_people:
            self.audit.log("query_unknown_subject", actor, tokens=unknown_people)
            msg = ("No document mentions this person, so I can't answer about them. "
                   "Check the spelling, or load the documents that are about them.")
            return Answer(q.text, msg, msg, [], False, 0, self.llm.provider,
                          int((time.perf_counter() - t0) * 1000))

        chunks = self.store.search(q.text, k=self.settings.top_k)
        self.audit.log("retrieval", actor, chunks=[f"{c.doc_id}#{c.index}" for c in chunks],
                       scores=[round(c.score, 3) for c in chunks])

        prompt = build_prompt(q.text, chunks)

        # Leak guard: re-scan the exact outgoing payload. Anything that still
        # looks like personal data is pseudonymised before it can leave.
        guard = self._detector()
        leaks = guard.contains_pii(prompt)
        if leaks:
            prompt = redact(prompt, guard, tokenizer=tokenizer).text
            self.audit.log("leak_guard_triggered", actor, count=len(leaks),
                           types=sorted({e.type for e in leaks}))

        try:
            raw_answer = self.llm.complete(prompt, question=q.text, chunks=chunks)
            status = "ok"
        except LLMError as exc:
            raw_answer, status = f"LLM error: {exc}", "error"

        self.audit.log(
            "llm_call", actor, provider=self.llm.provider, model=self.llm.model, status=status,
            prompt_sha256=sha256_text(prompt), prompt_chars=len(prompt),
            pii_sent=0, placeholders_sent=len(set(PLACEHOLDER_RE.findall(prompt))),
        )

        # Placeholders in the answer must never be invented by the model.
        answer_redacted = raw_answer
        display, revealed = answer_redacted, False
        if reveal:
            if role in ROLES_ALLOWED_TO_REVEAL:
                display = reidentify(answer_redacted, self.vault.reveal)
                revealed = True
                self.audit.log("reidentification", actor, role=role,
                               tokens=sorted(set(PLACEHOLDER_RE.findall(answer_redacted))))
            else:
                self.audit.log("reidentification_denied", actor, role=role)

        return Answer(q.text, answer_redacted, display, chunks, revealed, len(leaks),
                      self.llm.provider, int((time.perf_counter() - t0) * 1000))

    # ------------------------------------------------------------------ #
    # Data-subject rights & retention
    # ------------------------------------------------------------------ #
    def _find_subject_token(self, value: str) -> str | None:
        if PLACEHOLDER_RE.fullmatch(value.strip()):
            return value.strip()
        for etype in ENTITY_TYPES:
            token = self.vault.find_token(etype, normalise(etype, value))
            if token:
                return token
        return None

    def subject_access(self, value: str, actor: str = "dpo") -> dict:
        """GDPR Art. 15 — which documents hold data about this person?"""
        token = self._find_subject_token(value)
        docs = self.store.documents_with_token(token) if token else []
        self.audit.log("subject_access_request", actor, token=token, documents=docs)
        return {"token": token, "documents": docs}

    def erase_subject(self, value: str, delete_documents: bool = False, actor: str = "dpo") -> dict:
        """GDPR Art. 17 — right to erasure (crypto-shredding of the vault entry)."""
        token = self._find_subject_token(value)
        if not token:
            self.audit.log("erasure_request", actor, result="not_found")
            return {"token": None, "erased": False, "documents_deleted": []}
        erased = self.vault.erase(token)
        deleted = []
        if delete_documents:
            for doc_id in self.store.documents_with_token(token):
                if self.store.delete_document(doc_id):
                    deleted.append(doc_id)
        self.audit.log("erasure_request", actor, token=token, vault_erased=erased, documents_deleted=deleted)
        return {"token": token, "erased": erased, "documents_deleted": deleted}

    def delete_document(self, doc_id: str, actor: str = "analyst") -> bool:
        ok = self.store.delete_document(doc_id)
        self.audit.log("document_deleted", actor, doc_id=doc_id, success=ok)
        return ok

    def purge_expired(self, actor: str = "system") -> list[str]:
        """Storage limitation (Art. 5(1)(e)) — drop documents past retention."""
        expired = self.store.expired_documents(self.settings.retention_days)
        for doc_id in expired:
            self.store.delete_document(doc_id)
        self.audit.log("retention_purge", actor, retention_days=self.settings.retention_days,
                       documents_deleted=expired)
        return expired
