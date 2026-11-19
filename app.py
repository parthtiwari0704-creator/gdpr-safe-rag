"""Streamlit web UI.   Run:  streamlit run app.py"""
from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from gdpr_rag import GDPRAssistant
from gdpr_rag.loaders import SUPPORTED, load_bytes, load_path
from gdpr_rag.pii import spacy_available
from gdpr_rag.pipeline import ROLES_ALLOWED_TO_REVEAL

st.set_page_config(page_title="GDPR-safe Document Assistant", page_icon="🔒", layout="wide")


def md_table(rows: list[dict]) -> str:
    """Markdown table — avoids pandas/pyarrow, which Windows Smart App Control can block."""
    if not rows:
        return "_No rows_"
    cols = list(rows[0])
    esc = lambda v: str(v).replace("|", "\\|").replace("\n", " ")
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    lines += ["| " + " | ".join(esc(r[c]) for c in cols) + " |" for r in rows]
    return "\n".join(lines)


@st.cache_resource
def get_app() -> GDPRAssistant:
    return GDPRAssistant()


app = get_app()

# --------------------------------------------------------------------------- #
# Sidebar
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.title("🔒 GDPR-safe RAG")
    st.caption("Personal data is pseudonymised locally before anything reaches the LLM.")
    user = st.text_input("User", value="analyst.1")
    role = st.selectbox("Role", ["analyst", "compliance_officer", "dpo"],
                        help="Only compliance_officer and dpo may re-identify placeholders.")
    providers = ["offline", "anthropic", "openai", "ollama"]
    current = app.settings.llm_provider if app.settings.llm_provider in providers else "offline"
    app.settings.llm_provider = st.selectbox("LLM provider", providers, index=providers.index(current))
    reveal = st.toggle("Show real values in answers", value=False,
                       disabled=role not in ROLES_ALLOWED_TO_REVEAL)
    st.divider()
    ok, msg = app.audit.verify()
    st.metric("Documents", len(app.store.list_documents()))
    st.metric("Identifiers in vault", sum(app.vault.stats().values()))
    (st.success if ok else st.error)(("Audit chain intact" if ok else "Audit chain BROKEN"), icon="🧾")
    st.caption(f"NER: {'spaCy + rules' if spacy_available() else 'rules (install spaCy for more recall)'}")

tab_chat, tab_docs, tab_preview, tab_audit, tab_rights = st.tabs(
    ["💬 Ask", "📄 Documents", "🕵️ Redaction preview", "🧾 Audit log", "⚖️ Data-subject rights"]
)

# --------------------------------------------------------------------------- #
# Chat
# --------------------------------------------------------------------------- #
with tab_chat:
    if "history" not in st.session_state:
        st.session_state.history = []
    if not app.store.list_documents():
        st.info("No documents yet — open the **Documents** tab and load the sample bank documents.")
    for turn in st.session_state.history:
        with st.chat_message("user"):
            st.write(turn["question"])
        with st.chat_message("assistant"):
            st.write(turn["answer"])
            with st.expander("What the LLM actually saw"):
                st.code(turn["sent"], language=None)
                st.caption(f"Provider: {turn['provider']} · {turn['latency']} ms · "
                           f"leak guard hits: {turn['leaks']} · re-identified: {turn['revealed']}")
                for src in turn["sources"]:
                    st.markdown(f"**{src['file']}** (chunk {src['idx']}, score {src['score']:.3f})")
                    st.text(src["text"])

    question = st.chat_input("Ask about the documents, e.g. 'What happened to Emma Visser's account?'")
    if question:
        with st.spinner("Pseudonymising, retrieving and asking the LLM..."):
            ans = app.ask(question, actor=user, role=role, reveal=reveal)
        st.session_state.history.append({
            "question": question, "answer": ans.answer_display, "sent": ans.question_redacted,
            "provider": ans.provider, "latency": ans.latency_ms, "leaks": ans.leak_guard_hits,
            "revealed": ans.revealed,
            "sources": [{"file": c.filename, "idx": c.index, "score": c.score, "text": c.text} for c in ans.sources],
        })
        st.rerun()
    if st.session_state.history and st.button("Clear chat"):
        st.session_state.history = []
        st.rerun()

# --------------------------------------------------------------------------- #
# Documents
# --------------------------------------------------------------------------- #
with tab_docs:
    col1, col2 = st.columns([2, 1])
    with col1:
        files = st.file_uploader("Upload documents", type=[e.strip(".") for e in SUPPORTED], accept_multiple_files=True)
        if files and st.button("Redact & index uploaded files", type="primary"):
            for f in files:
                try:
                    res = app.ingest(f.name, load_bytes(f.name, f.getvalue()), actor=user)
                    st.success(f"{f.name}: {res['chunks']} chunks · removed {res['pii_found']}")
                except Exception as exc:  # noqa: BLE001
                    st.error(f"{f.name}: {exc}")
    with col2:
        sample_dir = Path(__file__).parent / "data" / "sample_docs"
        st.write("Synthetic bank documents (fictional people):")
        if st.button("Load sample documents"):
            existing = {d["filename"] for d in app.store.list_documents()}
            for path in sorted(sample_dir.glob("*.txt")) + sorted((sample_dir.parent / "sample_docs_india").glob("*.txt")):
                if path.name not in existing:
                    app.ingest(path.name, load_path(path), actor=user)
            st.rerun()

    st.subheader("Indexed documents (stored only in redacted form)")
    for d in app.store.list_documents():
        with st.expander(f"{d['filename']} — {d['chunks']} chunks — PII removed: {d['pii_counts']}"):
            st.text(app.store.get_document_text(d["doc_id"]))
            if st.button("Delete document", key=f"del-{d['doc_id']}"):
                app.delete_document(d["doc_id"], actor=user)
                st.rerun()

# --------------------------------------------------------------------------- #
# Redaction preview
# --------------------------------------------------------------------------- #
with tab_preview:
    st.write("Paste any text to see exactly what would be removed. Nothing is stored.")
    sample = ("Dear Mr. Jansen,\nYour payment from NL91ABNA0417164300 to Lisa de Boer "
              "(lisa.deboer@example.nl, +31 6 23456789) was blocked.\nBSN: 111222333 · "
              "Card 4111 1111 1111 1111 · Login from 81.204.12.7")
    text = st.text_area("Original text", value=sample, height=180)
    if text:
        res = app.preview(text)
        c1, c2 = st.columns(2)
        c1.markdown("**Original (never leaves this machine)**")
        c1.code(text, language=None)
        c2.markdown("**Sent to the LLM**")
        c2.code(res.text, language=None)
        if res.entities:
            token_of = {value: token for token, value in res.replacements.items()}
            rows = [{"type": e.type, "placeholder": token_of.get(e.value, ""), "detected value": text[e.start:e.end]}
                    for e in res.entities]
            st.markdown(md_table(rows))

# --------------------------------------------------------------------------- #
# Audit log
# --------------------------------------------------------------------------- #
with tab_audit:
    ok, msg = app.audit.verify()
    (st.success if ok else st.error)(msg)
    st.caption("Each entry stores the SHA-256 hash of the previous one. Editing or deleting any line breaks the chain. "
               "The log holds counts, IDs, tokens and hashes — never personal data.")
    entries = app.audit.entries()
    if entries:
        actions = st.multiselect("Filter actions", sorted({e["action"] for e in entries}))
        rows = [{"time (UTC)": e["ts"][:19].replace("T", " "), "actor": e["actor"], "action": e["action"],
                 "details": json.dumps(e["details"])[:160], "hash": e["hash"][:12]}
                for e in reversed(entries) if not actions or e["action"] in actions]
        st.markdown(md_table(rows[:200]))
        st.download_button("Download audit log (JSONL)", app.settings.audit_path.read_bytes(),
                           file_name="audit_log.jsonl")

# --------------------------------------------------------------------------- #
# Data-subject rights
# --------------------------------------------------------------------------- #
with tab_rights:
    if role != "dpo":
        st.warning("Switch the role to **dpo** (Data Protection Officer) to handle data-subject requests.")
    else:
        st.subheader("Right of access (Art. 15)")
        subject = st.text_input("Name, e-mail, IBAN or phone of the data subject", key="sar")
        if st.button("Find documents") and subject:
            res = app.subject_access(subject, actor=user)
            if res["token"]:
                names = {d["doc_id"]: d["filename"] for d in app.store.list_documents()}
                st.success(f"Placeholder {res['token']} appears in: " +
                           (", ".join(names.get(i, i) for i in res["documents"]) or "no documents"))
            else:
                st.info("No data held for this value.")

        st.subheader("Right to erasure (Art. 17)")
        target = st.text_input("Value to erase", key="erase")
        also_docs = st.checkbox("Also delete every document that mentions this person")
        if st.button("Erase", type="primary") and target:
            res = app.erase_subject(target, delete_documents=also_docs, actor=user)
            if res["token"]:
                st.success(f"{res['token']} can no longer be re-identified. Documents deleted: {res['documents_deleted']}")
            else:
                st.info("Nothing found to erase.")

        st.subheader("Storage limitation (Art. 5(1)(e))")
        st.write(f"Retention period: **{app.settings.retention_days} days** (set RETENTION_DAYS in .env)")
        if st.button("Purge expired documents"):
            st.success(f"Deleted: {app.purge_expired(actor=user) or 'nothing expired'}")
