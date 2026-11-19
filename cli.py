"""Command-line interface.

    python cli.py ingest data/sample_docs/*.txt
    python cli.py ask "Why was Thomas Bakker charged twice?"
    python cli.py ask "..." --role dpo --reveal
    python cli.py redact "Dear Mr. Jansen, your IBAN NL91ABNA0417164300 ..."
    python cli.py docs | audit | verify | stats
    python cli.py access "Emma Visser"      # GDPR Art. 15
    python cli.py erase  "Emma Visser"      # GDPR Art. 17
    python cli.py purge                      # retention policy
    python cli.py gen-key
"""
from __future__ import annotations

import argparse
import glob
import json
import sys

from gdpr_rag.loaders import load_path
from gdpr_rag.vault import generate_master_key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="GDPR-safe document assistant")
    parser.add_argument("--user", default="cli-user", help="actor name written to the audit log")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("ingest", help="redact and index documents")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("ask", help="ask a question")
    p.add_argument("question")
    p.add_argument("--role", default="analyst", choices=["analyst", "dpo", "compliance_officer"])
    p.add_argument("--reveal", action="store_true", help="re-identify placeholders (dpo/compliance only)")
    p.add_argument("--show-prompt-context", action="store_true")

    p = sub.add_parser("redact", help="preview redaction of a text (nothing stored)")
    p.add_argument("text")

    sub.add_parser("docs", help="list indexed documents")
    p = sub.add_parser("audit", help="show the audit log")
    p.add_argument("-n", type=int, default=20)
    sub.add_parser("verify", help="verify the audit hash chain")
    sub.add_parser("stats", help="vault statistics")

    p = sub.add_parser("access", help="subject access request (Art. 15)")
    p.add_argument("value")
    p = sub.add_parser("erase", help="right to erasure (Art. 17)")
    p.add_argument("value")
    p.add_argument("--delete-documents", action="store_true")
    p = sub.add_parser("delete-doc", help="delete one document")
    p.add_argument("doc_id")
    sub.add_parser("purge", help="delete documents older than RETENTION_DAYS")
    sub.add_parser("gen-key", help="print a new master key for .env")

    args = parser.parse_args(argv)

    if args.cmd == "gen-key":
        print(f"GDPR_RAG_MASTER_KEY={generate_master_key()}")
        return 0

    from gdpr_rag import GDPRAssistant

    app = GDPRAssistant()

    if args.cmd == "ingest":
        paths = [f for pattern in args.paths for f in (glob.glob(pattern) or [pattern])]
        for path in paths:
            res = app.ingest(path.replace("\\", "/").split("/")[-1], load_path(path), actor=args.user)
            print(f"✔ {path}: {res['chunks']} chunks, PII removed: {res['pii_found']}")
    elif args.cmd == "ask":
        ans = app.ask(args.question, actor=args.user, role=args.role, reveal=args.reveal)
        print(f"\nQuestion sent to LLM : {ans.question_redacted}")
        print(f"Provider             : {ans.provider}  ({ans.latency_ms} ms)")
        if ans.leak_guard_hits:
            print(f"Leak guard           : caught {ans.leak_guard_hits} item(s) before sending")
        print("\n" + ans.answer_display)
        if args.reveal and not ans.revealed:
            print("\n(re-identification denied for role '%s' — logged)" % args.role)
        print("\nSources: " + ", ".join(sorted({c.filename for c in ans.sources})) if ans.sources else "")
        if args.show_prompt_context:
            for c in ans.sources:
                print(f"\n--- {c.filename}#{c.index} score={c.score:.3f}\n{c.text}")
    elif args.cmd == "redact":
        res = app.preview(args.text)
        print(res.text)
        print(json.dumps(res.counts()))
    elif args.cmd == "docs":
        for d in app.store.list_documents():
            print(f"{d['doc_id']}  {d['filename']:<40} chunks={d['chunks']}  pii={d['pii_counts']}")
    elif args.cmd == "audit":
        for e in app.audit.entries()[-args.n:]:
            print(f"{e['ts'][:19]}  {e['actor']:<12} {e['action']:<26} {json.dumps(e['details'])[:110]}")
    elif args.cmd == "verify":
        ok, msg = app.audit.verify()
        print(("✔ " if ok else "✘ ") + msg)
        return 0 if ok else 1
    elif args.cmd == "stats":
        print(json.dumps(app.vault.stats(), indent=2))
    elif args.cmd == "access":
        print(json.dumps(app.subject_access(args.value, actor=args.user), indent=2))
    elif args.cmd == "erase":
        print(json.dumps(app.erase_subject(args.value, args.delete_documents, actor=args.user), indent=2))
    elif args.cmd == "delete-doc":
        print("deleted" if app.delete_document(args.doc_id, actor=args.user) else "not found")
    elif args.cmd == "purge":
        print(f"Deleted: {app.purge_expired(actor=args.user)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
