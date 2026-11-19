"""Lightweight web UI using only Python's standard library (no Streamlit/pyarrow).

Works on Windows machines where Smart App Control blocks pyarrow.

    python web.py            ->  opens http://localhost:8000
    python web.py --port 9000 --no-browser
"""
from __future__ import annotations

import argparse
import base64
import json
import socket
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from gdpr_rag import GDPRAssistant
from gdpr_rag.loaders import load_bytes, load_path
from gdpr_rag.pipeline import ROLES_ALLOWED_TO_REVEAL

ROOT = Path(__file__).resolve().parent
SAMPLE_SETS = {"eu": ROOT / "data" / "sample_docs", "india": ROOT / "data" / "sample_docs_india"}
APP = GDPRAssistant()
LOCK = threading.Lock()


def state() -> dict:
    ok, msg = APP.audit.verify()
    return {
        "documents": APP.store.list_documents(),
        "vault": APP.vault.stats(),
        "audit_ok": ok, "audit_msg": msg,
        "provider": APP.settings.llm_provider,
        "retention_days": APP.settings.retention_days,
    }


def handle(path: str, body: dict) -> dict:
    user = body.get("user") or "analyst.1"
    role = body.get("role") or "analyst"

    if path == "/api/state":
        return state()
    if path == "/api/ask":
        if body.get("provider"):
            APP.settings.llm_provider = body["provider"]
        ans = APP.ask(body.get("question", ""), actor=user, role=role, reveal=bool(body.get("reveal")))
        return {
            "answer": ans.answer_display, "sent": ans.question_redacted, "revealed": ans.revealed,
            "provider": ans.provider, "latency": ans.latency_ms, "leaks": ans.leak_guard_hits,
            "sources": [{"file": c.filename, "idx": c.index, "score": round(c.score, 3), "text": c.text}
                        for c in ans.sources],
        }
    if path == "/api/load_samples":
        existing = {d["filename"] for d in APP.store.list_documents()}
        added = []
        for p in sorted(SAMPLE_SETS.get(body.get("set", "eu"), SAMPLE_SETS["eu"]).glob("*.txt")):
            if p.name not in existing:
                APP.ingest(p.name, load_path(p), actor=user)
                added.append(p.name)
        return {"added": added}
    if path == "/api/upload":
        data = base64.b64decode(body["content_b64"])
        res = APP.ingest(body["filename"], load_bytes(body["filename"], data), actor=user)
        return {"chunks": res["chunks"], "pii_found": res["pii_found"]}
    if path == "/api/delete":
        return {"ok": APP.delete_document(body["doc_id"], actor=user)}
    if path == "/api/document":
        return {"text": APP.store.get_document_text(body["doc_id"])}
    if path == "/api/preview":
        text = body.get("text", "")
        res = APP.preview(text)
        token_of = {v: k for k, v in res.replacements.items()}
        return {"redacted": res.text,
                "entities": [{"type": e.type, "token": token_of.get(e.value, ""), "value": text[e.start:e.end]}
                             for e in res.entities]}
    if path == "/api/audit":
        return {"entries": list(reversed(APP.audit.entries()))[:300]}

    # Data-subject rights: Data Protection Officer only
    if path in ("/api/access", "/api/erase", "/api/purge"):
        if role != "dpo":
            APP.audit.log("dsar_denied", user, role=role, endpoint=path)
            return {"error": "Only the 'dpo' role can handle data-subject requests."}
        if path == "/api/access":
            res = APP.subject_access(body.get("value", ""), actor=user)
            names = {d["doc_id"]: d["filename"] for d in APP.store.list_documents()}
            res["filenames"] = [names.get(i, i) for i in res["documents"]]
            return res
        if path == "/api/erase":
            return APP.erase_subject(body.get("value", ""), bool(body.get("delete_documents")), actor=user)
        return {"deleted": APP.purge_expired(actor=user)}
    return {"error": f"unknown endpoint {path}"}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, payload: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif self.path.startswith("/api/"):
            self._json(self.path, {})
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            body = {}
        self._json(self.path, body)

    def _json(self, path: str, body: dict) -> None:
        try:
            with LOCK:
                out = handle(path, body)
            code = 200
        except Exception as exc:  # noqa: BLE001
            out, code = {"error": f"{type(exc).__name__}: {exc}"}, 500
        self._send(code, json.dumps(out, ensure_ascii=False).encode(), "application/json")

    def log_message(self, fmt: str, *args) -> None:  # keep the console quiet
        pass


PAGE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GDPR-safe Document Assistant</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202a;--muted:#5d6b78;--line:#e2e6ea;--accent:#ff6200;--accent2:#0b5394;--ok:#1a7f37;--bad:#c62828;--chip:#fff3e8}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--ink)}
header{background:#14202b;color:#fff;padding:14px 24px;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
header h1{font-size:18px;margin:0;font-weight:650}header .sub{color:#aab6c1;font-size:13px}
header .ctrls{margin-left:auto;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
header select,header input{padding:6px 8px;border-radius:6px;border:1px solid #3a4856;background:#1e2c39;color:#fff}
header label{font-size:13px;color:#cfd8df;display:flex;gap:6px;align-items:center}
nav{display:flex;gap:4px;padding:0 24px;background:#fff;border-bottom:1px solid var(--line);flex-wrap:wrap}
nav button{border:0;background:none;padding:12px 14px;font:inherit;color:var(--muted);cursor:pointer;border-bottom:3px solid transparent}
nav button.on{color:var(--ink);border-bottom-color:var(--accent);font-weight:600}
main{max-width:1150px;margin:20px auto;padding:0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:18px;margin-bottom:16px}
.row{display:flex;gap:16px;flex-wrap:wrap}.row>*{flex:1;min-width:280px}
.btn{background:var(--accent);color:#fff;border:0;border-radius:7px;padding:9px 16px;font:inherit;font-weight:600;cursor:pointer}
.btn.sec{background:#e9edf1;color:var(--ink)}.btn.danger{background:var(--bad)}.btn:disabled{opacity:.5;cursor:default}
input[type=text],textarea{width:100%;padding:10px;border:1px solid var(--line);border-radius:7px;font:inherit}
textarea{min-height:140px;font-family:Consolas,ui-monospace,monospace;font-size:13px}
pre{background:#f3f5f7;border:1px solid var(--line);border-radius:7px;padding:12px;white-space:pre-wrap;word-break:break-word;font:13px/1.45 Consolas,ui-monospace,monospace;margin:8px 0}
.msg{margin:14px 0}.q{font-weight:600}.a{background:#fff;border-left:4px solid var(--accent);padding:10px 14px;border-radius:6px;white-space:pre-wrap}
details{margin-top:8px}summary{cursor:pointer;color:var(--accent2);font-size:14px}
.meta{color:var(--muted);font-size:13px}.chip{display:inline-block;background:var(--chip);border:1px solid #ffd2b0;border-radius:99px;padding:1px 9px;font-size:12px;margin:2px}
.tok{background:#fff0e3;color:#a34400;border-radius:4px;padding:0 3px;font-weight:600}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{background:#f3f5f7;font-weight:600}td code{font-size:12px}
.stat{display:flex;gap:12px;flex-wrap:wrap}.stat div{background:#fff;border:1px solid var(--line);border-radius:8px;padding:10px 14px;min-width:140px}
.stat b{display:block;font-size:22px}.good{color:var(--ok)}.badc{color:var(--bad)}
.hidden{display:none}.ask{display:flex;gap:8px}.ask input{flex:1}
</style></head><body>
<header>
  <div><h1>🔒 GDPR-safe Document Assistant</h1><div class="sub">Personal data is pseudonymised locally before anything reaches the LLM · GDPR (EU) &amp; DPDP Act 2023 (India)</div></div>
  <div class="ctrls">
    <label>User <input id="user" value="analyst.1" size="10"></label>
    <label>Role <select id="role"><option>analyst</option><option>compliance_officer</option><option>dpo</option></select></label>
    <label>LLM <select id="provider"><option>offline</option><option>anthropic</option><option>openai</option><option>ollama</option></select></label>
    <label><input type="checkbox" id="reveal"> Show real values</label>
  </div>
</header>
<nav id="tabs">
  <button data-t="ask" class="on">💬 Ask</button><button data-t="docs">📄 Documents</button>
  <button data-t="preview">🕵️ Redaction preview</button><button data-t="audit">🧾 Audit log</button>
  <button data-t="rights">⚖️ Data-subject rights</button>
</nav>
<main>
  <div class="stat card" id="stats"></div>

  <section id="t-ask">
    <div class="card">
      <div class="ask"><input type="text" id="q" placeholder="e.g. What happened to Rahul Sharma's UPI transaction?"><button class="btn" id="askbtn">Ask</button></div>
      <div class="meta" style="margin-top:6px">🇮🇳 India: <a href="#" class="ex">What happened to Rahul Sharma's UPI transaction?</a> · <a href="#" class="ex">Is Amit Patel's KYC complete?</a> · <a href="#" class="ex">What loan amount did Priya Verma apply for?</a> · <a href="#" class="ex">Will Sneha Reddy get her annual fee back?</a></div>
      <div class="meta" style="margin-top:4px">🇪🇺 EU: <a href="#" class="ex">Why was Thomas Bakker charged twice?</a> · <a href="#" class="ex">What is the risk rating of Chidi Okafor?</a> · <a href="#" class="ex">What happened to Emma Visser's account?</a></div>
    </div>
    <div id="chat"></div>
  </section>

  <section id="t-docs" class="hidden">
    <div class="card row">
      <div><h3>Upload documents</h3><input type="file" id="files" multiple accept=".txt,.md,.csv,.json,.eml,.pdf,.docx"><br><br><button class="btn" id="upbtn">Redact &amp; index</button></div>
      <div><h3>Sample bank documents</h3><p class="meta">Synthetic documents with fictional people. India: Aadhaar, PAN, UPI, account numbers. EU: IBAN, BSN, cards.</p>
        <button class="btn sec" id="samplebtn-india">🇮🇳 Load India samples</button> <button class="btn sec" id="samplebtn">🇪🇺 Load EU samples</button></div>
    </div>
    <div class="card"><h3>Indexed documents <span class="meta">(stored only in redacted form)</span></h3><div id="doclist"></div></div>
  </section>

  <section id="t-preview" class="hidden">
    <div class="card"><p class="meta">Paste any text to see what would be removed. Nothing is stored.</p>
      <textarea id="ptext">Dear Mr. Jansen,
Your payment from NL91ABNA0417164300 to Lisa de Boer (lisa.deboer@example.nl, +31 6 23456789) was blocked.
BSN: 111222333 · Card 4111 1111 1111 1111 · Login from 81.204.12.7

Customer Name: Arjun Mehta
PAN: ABCPM5678Q · Aadhaar: 2345 6789 0124 · UPI ID: arjun.m@okhdfcbank
Mobile: +91 98765 43210 · Savings account no: 50100234567891 (IFSC HDFC0001234)
Address: 21, MG Road, Pune - 411001</textarea>
      <br><br><button class="btn" id="pbtn">Preview redaction</button></div>
    <div class="card hidden" id="pout"><div class="row"><div><b>Original (never leaves this machine)</b><pre id="porig"></pre></div><div><b>Sent to the LLM</b><pre id="pred"></pre></div></div><div id="ptable"></div></div>
  </section>

  <section id="t-audit" class="hidden">
    <div class="card"><div id="auditstatus"></div><p class="meta">Each entry stores the SHA-256 hash of the previous one, so editing or deleting a line breaks the chain. The log holds counts, IDs, tokens and hashes, never personal data.</p>
      <button class="btn sec" id="auditbtn">Refresh</button><div id="auditlist" style="margin-top:12px;overflow-x:auto"></div></div>
  </section>

  <section id="t-rights" class="hidden">
    <div class="card" id="rightswarn"><b>Switch the role to <code>dpo</code></b> (Data Protection Officer) to handle data-subject requests.</div>
    <div class="card"><h3>Right of access <span class="meta">GDPR Art. 15 · DPDP Act s.11</span></h3><div class="ask"><input type="text" id="sar" placeholder="Name, e-mail, phone, IBAN, PAN, Aadhaar or UPI ID"><button class="btn" id="sarbtn">Find documents</button></div><div id="sarout" class="msg"></div></div>
    <div class="card"><h3>Right to erasure <span class="meta">GDPR Art. 17 · DPDP Act s.12</span></h3><div class="ask"><input type="text" id="er" placeholder="Value to erase, e.g. Rahul Sharma"><button class="btn danger" id="erbtn">Erase</button></div>
      <label class="meta"><input type="checkbox" id="erdocs"> Also delete every document that mentions this person</label><div id="erout" class="msg"></div></div>
    <div class="card"><h3>Storage limitation <span class="meta">GDPR Art. 5(1)(e) · DPDP Act s.8(7)</span></h3><p id="ret" class="meta"></p><button class="btn sec" id="purgebtn">Purge expired documents</button><div id="purgeout" class="msg"></div></div>
  </section>
</main>
<script>
const $=s=>document.querySelector(s);
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const hl=s=>esc(s).replace(/\[[A-Z_]+_Q?\d+\]/g,m=>`<span class="tok">${m}</span>`);
const ctx=()=>({user:$("#user").value,role:$("#role").value,provider:$("#provider").value,reveal:$("#reveal").checked});
async function api(path,body={}){const r=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...ctx(),...body})});return r.json();}

document.querySelectorAll("#tabs button").forEach(b=>b.onclick=()=>{
  document.querySelectorAll("#tabs button").forEach(x=>x.classList.toggle("on",x===b));
  document.querySelectorAll("main section").forEach(s=>s.classList.toggle("hidden",s.id!=="t-"+b.dataset.t));
  if(b.dataset.t==="audit")loadAudit(); if(b.dataset.t==="docs")refresh();
});
function syncRole(){const r=$("#role").value;const can=["dpo","compliance_officer"].includes(r);$("#reveal").disabled=!can;if(!can)$("#reveal").checked=false;$("#rightswarn").classList.toggle("hidden",r==="dpo");}
$("#role").onchange=syncRole;

async function refresh(){
  const s=await api("/api/state");
  $("#provider").value=$("#provider").dataset.set?$("#provider").value:s.provider;$("#provider").dataset.set=1;
  const n=Object.values(s.vault).reduce((a,b)=>a+b,0);
  $("#stats").innerHTML=`<div><b>${s.documents.length}</b>documents</div><div><b>${n}</b>identifiers in encrypted vault</div><div><b class="${s.audit_ok?"good":"badc"}">${s.audit_ok?"✔ intact":"✘ broken"}</b>audit hash chain</div>`;
  $("#ret").textContent=`Retention period: ${s.retention_days} days (set RETENTION_DAYS in .env)`;
  $("#doclist").innerHTML=s.documents.length?`<table><tr><th>File</th><th>Chunks</th><th>PII removed</th><th></th></tr>${s.documents.map(d=>`<tr><td>${esc(d.filename)}</td><td>${d.chunks}</td><td>${Object.entries(d.pii_counts).map(([k,v])=>`<span class="chip">${k} × ${v}</span>`).join("")}</td><td style="white-space:nowrap"><button class="btn sec" onclick="viewDoc('${d.doc_id}',this)">View</button> <button class="btn sec" onclick="delDoc('${d.doc_id}')">Delete</button></td></tr><tr class="hidden" id="v-${d.doc_id}"><td colspan="4"><pre></pre></td></tr>`).join("")}</table>`:`<p class="meta">No documents yet. Load the samples above.</p>`;
}
async function viewDoc(id){const row=$("#v-"+id);if(!row.classList.contains("hidden")){row.classList.add("hidden");return;}const r=await api("/api/document",{doc_id:id});row.querySelector("pre").innerHTML=hl(r.text);row.classList.remove("hidden");}
async function delDoc(id){await api("/api/delete",{doc_id:id});refresh();}

async function ask(){
  const q=$("#q").value.trim();if(!q)return;$("#askbtn").disabled=true;
  const box=document.createElement("div");box.className="card msg";box.innerHTML=`<div class="q">${esc(q)}</div><div class="meta">Pseudonymising, retrieving and asking the LLM…</div>`;$("#chat").prepend(box);
  const r=await api("/api/ask",{question:q});$("#askbtn").disabled=false;$("#q").value="";
  if(r.error){box.innerHTML=`<div class="q">${esc(q)}</div><div class="a badc">${esc(r.error)}</div>`;return;}
  box.innerHTML=`<div class="q">${esc(q)}</div><div class="a">${hl(r.answer)}</div>
   <details><summary>What the LLM actually saw</summary><pre>${hl(r.sent)}</pre>
   <div class="meta">Provider: ${esc(r.provider)} · ${r.latency} ms · leak-guard hits: ${r.leaks} · re-identified: ${r.revealed}</div>
   ${r.sources.map(s=>`<p class="meta"><b>${esc(s.file)}</b> (chunk ${s.idx}, score ${s.score})</p><pre>${hl(s.text)}</pre>`).join("")}</details>`;
  refresh();
}
$("#askbtn").onclick=ask;$("#q").onkeydown=e=>{if(e.key==="Enter")ask();};
document.querySelectorAll(".ex").forEach(a=>a.onclick=e=>{e.preventDefault();$("#q").value=a.textContent;ask();});

$("#samplebtn").onclick=async()=>{await api("/api/load_samples",{set:"eu"});refresh();};
$("#samplebtn-india").onclick=async()=>{await api("/api/load_samples",{set:"india"});refresh();};
$("#upbtn").onclick=async()=>{
  for(const f of $("#files").files){
    const b64=await new Promise(res=>{const fr=new FileReader();fr.onload=()=>res(fr.result.split(",")[1]);fr.readAsDataURL(f);});
    const r=await api("/api/upload",{filename:f.name,content_b64:b64});if(r.error)alertBox(r.error);
  }
  $("#files").value="";refresh();
};
function alertBox(m){$("#doclist").insertAdjacentHTML("beforebegin",`<p class="badc">${esc(m)}</p>`);}

$("#pbtn").onclick=async()=>{
  const t=$("#ptext").value;const r=await api("/api/preview",{text:t});
  $("#pout").classList.remove("hidden");$("#porig").textContent=t;$("#pred").innerHTML=hl(r.redacted);
  $("#ptable").innerHTML=r.entities.length?`<table><tr><th>Type</th><th>Placeholder</th><th>Detected value</th></tr>${r.entities.map(e=>`<tr><td>${e.type}</td><td><span class="tok">${esc(e.token)}</span></td><td>${esc(e.value)}</td></tr>`).join("")}</table>`:"<p>No personal data found.</p>";
};

async function loadAudit(){
  const s=await api("/api/state");const r=await api("/api/audit");
  $("#auditstatus").innerHTML=`<b class="${s.audit_ok?"good":"badc"}">${s.audit_ok?"✔":"✘"} ${esc(s.audit_msg)}</b>`;
  $("#auditlist").innerHTML=`<table><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Details</th><th>Hash</th></tr>${r.entries.map(e=>`<tr><td>${e.ts.slice(0,19).replace("T"," ")}</td><td>${esc(e.actor)}</td><td>${esc(e.action)}</td><td><code>${esc(JSON.stringify(e.details)).slice(0,220)}</code></td><td><code>${e.hash.slice(0,12)}</code></td></tr>`).join("")}</table>`;
}
$("#auditbtn").onclick=loadAudit;

$("#sarbtn").onclick=async()=>{const r=await api("/api/access",{value:$("#sar").value});$("#sarout").innerHTML=r.error?`<span class="badc">${esc(r.error)}</span>`:r.token?`Placeholder <span class="tok">${esc(r.token)}</span> appears in: ${esc(r.filenames.join(", ")||"no documents")}`:"No data held for this value.";};
$("#erbtn").onclick=async()=>{const r=await api("/api/erase",{value:$("#er").value,delete_documents:$("#erdocs").checked});$("#erout").innerHTML=r.error?`<span class="badc">${esc(r.error)}</span>`:r.token?`<span class="good">✔ <span class="tok">${esc(r.token)}</span> can no longer be re-identified.</span> Documents deleted: ${r.documents_deleted.length}`:"Nothing found to erase.";refresh();};
$("#purgebtn").onclick=async()=>{const r=await api("/api/purge");$("#purgeout").innerHTML=r.error?`<span class="badc">${esc(r.error)}</span>`:`Deleted: ${r.deleted.length?esc(r.deleted.join(", ")):"nothing expired"}`;refresh();};

syncRole();refresh();
</script></body></html>"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    # Threaded, so an idle browser pre-connection can't block other requests.
    # (handle() itself is serialised by LOCK.) Falls back to the next free port.
    class Server(ThreadingHTTPServer):
        daemon_threads = True
        # On Windows SO_REUSEADDR lets two programs share a port, so an old copy of the
        # app would keep answering. Refuse that and move to the next free port instead.
        allow_reuse_address = sys.platform != "win32"

        def server_bind(self):
            if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            super().server_bind()

    server, port = None, args.port
    for port in range(args.port, args.port + 20):
        try:
            server = Server(("127.0.0.1", port), Handler)
            break
        except OSError:
            continue
    if server is None:
        raise SystemExit(f"No free port between {args.port} and {args.port + 19}")
    url = f"http://localhost:{port}"
    if port != args.port:
        print(f"NOTE: port {args.port} is busy (an older copy is probably still running).")
    print(f"GDPR-safe Document Assistant running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
