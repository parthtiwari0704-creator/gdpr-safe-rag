# 🔒 GDPR-safe Document Assistant

A RAG (retrieval-augmented generation) chatbot for banking documents that **removes personal data before anything reaches the LLM** and **writes every action to an audit log that shows if anyone has tampered with it**.

Built for privacy-first fintech settings in two jurisdictions:

- **India**: banks and fintechs (HDFC, ICICI, SBI, Paytm, PhonePe, Razorpay) under the **Digital Personal Data Protection (DPDP) Act 2023** and RBI data-localisation rules
- **EU / Netherlands**: banks (ING, ABN AMRO, Rabobank) under the **GDPR (AVG)**, DNB supervision and the EU AI Act

```
upload ─► extract text ─► detect PII ─► pseudonymise (encrypted vault) ─► chunk + index
question ─► pseudonymise ─► retrieve ─► leak guard ─► LLM ─► re-identify (authorised roles only)
                     every step ─► hash-chained audit log (no personal data in it)
```

## Features

| Area | What it does | GDPR principle |
|---|---|---|
| **PII detection** | IBAN (mod-97 checksum), card numbers (Luhn), Dutch BSN (11-proef), e-mail, phone, IP, street address, postcode, date of birth, person names (titles such as Mr./Dhr./Mevr., labels such as "Account holder:", greetings, sign-offs, optional spaCy NER). The checksums mean random numbers are **not** over-redacted. | Data minimisation, Art. 5(1)(c) |
| **Consistent pseudonyms** | The same person or IBAN always gets the same placeholder (`[PERSON_3]`, `[IBAN_1]`) across all documents, so the LLM can still reason about "who did what". "Mr. Bakker" links to "Thomas Bakker". | Pseudonymisation, Art. 4(5) & 32 |
| **Encrypted vault** | Original values are stored only locally, Fernet-encrypted, and indexed by a keyed HMAC (no plain-text lookup column). | Security of processing, Art. 32 |
| **Leak guard** | The exact prompt is scanned again just before it is sent. Anything that still looks like PII is pseudonymised and logged. Questions use a stricter name detector. | Privacy by design, Art. 25 |
| **Role-based re-identification** | Analysts only ever see placeholders. `dpo` / `compliance_officer` can reveal real values, and each reveal is logged (denied attempts too). | Access control / accountability |
| **Tamper-evident audit log** | JSONL file in which each entry holds the SHA-256 hash of the previous entry. `verify` points to the exact line that was edited or deleted. It stores counts, IDs and hashes, **never personal data**. | Accountability, Art. 5(2) & 30 |
| **Right of access** | Find every document that holds data about a person. | Art. 15 |
| **Right to erasure** | "Crypto-shredding": the ciphertext and lookup hash are deleted, so the placeholder can never be linked back to the person. Optionally deletes the documents too. A later question about the person cannot restore them. | Art. 17 |
| **Retention purge** | Deletes documents older than `RETENTION_DAYS`. | Storage limitation, Art. 5(1)(e) |
| **Pluggable LLM** | `offline` (no key needed, extractive), `anthropic`, `openai`, or `ollama` (a fully local model, so data never leaves the laptop). | Third-country transfers, Ch. V |

## India support 🇮🇳

| Identifier | How it is detected |
|---|---|
| **Aadhaar** | 12 digits, first digit 2–9, **Verhoeff check digit** (the algorithm UIDAI uses). Random 12-digit numbers are not redacted. |
| **PAN** | `AAAAA9999A`, 4th letter = holder type (P person, C company ...) |
| **UPI ID** | `name@okhdfcbank`, `name@ybl`, told apart from e-mail (no dot after `@`) |
| **Bank account** | digits after "A/c", "account no", "savings account" ... |
| **Mobile** | `+91 98765 43210`, `9812345670`, normalised so all formats get one token |
| **GSTIN, Passport, Voter ID (EPIC), PIN code, full address lines** | format + context |
| **Names** | Shri, Smt., Kumari, S/o, D/o, W/o, plus labels such as Borrower, Complainant, Father's Name |

**IFSC codes are kept on purpose:** they identify a bank branch, not a person, so analysts can still see which bank received a fraudulent transfer.

| DPDP Act 2023 | Feature |
|---|---|
| s.4 & s.6: lawful purpose, consent | Only pseudonymised data is processed by the LLM |
| s.8(5): reasonable security safeguards | Encrypted vault, leak guard, role-based re-identification |
| s.8(7): erase when the purpose is served | Retention purge |
| s.11: right to access information | Subject access search |
| s.12: right to correction and erasure | Crypto-shredding erasure |
| s.16: cross-border transfer | `ollama` provider keeps all processing inside India / on-premises |

Sample documents in `data/sample_docs_india/`: a home loan application, a UPI fraud complaint, a Re-KYC review and a credit-card complaint. Example questions:

- *What happened to Rahul Sharma's UPI transaction?*
- *Is Amit Patel's KYC complete?*
- *What loan amount did Priya Verma apply for?*
- *Will Sneha Reddy get her annual fee back?*

## Quick start

**Windows:** double-click `run_windows.bat`
**macOS / Linux:** `./run.sh`

Or by hand:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # Windows: copy .env.example .env
streamlit run app.py
```

**Windows "Application Control policy has blocked this file" (pyarrow)?** Windows Smart App Control blocks
pyarrow, which Streamlit needs. Use the built-in web UI instead. It needs no extra packages:

```bash
python web.py            # opens http://localhost:8000
```

Then open http://localhost:8501 (or :8000 for `web.py`), go to **Documents → Load sample documents**, and ask questions in **Ask**.
It runs in `offline` mode out of the box, with no API key.

### Using a real LLM

Edit `.env`:

```env
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-ant-...
```

or run fully locally with [Ollama](https://ollama.com): `ollama pull llama3.1`, then set `LLM_PROVIDER=ollama`.
You can also switch providers in the app's sidebar.

For anything beyond a demo, set a real vault key: `python cli.py gen-key` and paste the output into `.env`.

### Docker

```bash
docker build -t gdpr-rag .
docker run -p 8501:8501 --env-file .env gdpr-rag
```

## CLI

```bash
python cli.py ingest "data/sample_docs/*.txt" "data/sample_docs_india/*.txt"
python cli.py ask "Why was Thomas Bakker charged twice?"
python cli.py ask "What happened to Emma Visser's account?" --role dpo --reveal
python cli.py redact "Beste Lisa de Boer, uw IBAN NL91ABNA0417164300"
python cli.py docs
python cli.py audit -n 20
python cli.py verify                       # check the audit hash chain
python cli.py access "t.bakker@example.org" # Art. 15
python cli.py erase "Emma Visser" --delete-documents   # Art. 17
python cli.py purge                         # retention policy
```

Example of what the LLM receives:

```
Question sent to LLM : What happened to [PERSON_1]'s account?
- ... SEPA transfers totalling EUR 14,200 were made from the account of Ms. [PERSON_1] ...
- Account: [IBAN_1]
```

## Tests

```bash
pytest -q
```

25 tests cover the checksum validators, name detection and linking, **a check that no PII from the sample documents reaches the LLM prompt**, role-based reveal, erasure that cannot be undone, the subject access request, tamper detection in the audit log, an audit log with no PII in it, and the retention purge, plus India checks: Aadhaar Verhoeff, PAN/UPI/GSTIN/account detection, UPI vs e-mail, Indian titles, IFSC kept, and no leak from the India documents.

## Project structure

```
gdpr-safe-rag/
├── web.py                  Zero-dependency web UI (standard library http.server)
├── app.py                  Streamlit UI (Ask, Documents, Redaction preview, Audit log, Data-subject rights)
├── cli.py                  Command-line interface
├── gdpr_rag/
│   ├── pii.py              PII detection, validators, pseudonymisation, re-identification
│   ├── vault.py            Encrypted PII vault (Fernet + HMAC lookup), crypto-shredding
│   ├── audit.py            Hash-chained, tamper-evident audit log
│   ├── store.py            Redacted-only document store + TF-IDF retriever (offline)
│   ├── llm.py              offline / Anthropic / OpenAI / Ollama back-ends
│   ├── pipeline.py         GDPRAssistant: ingest, ask, leak guard, DSAR, erasure, retention
│   ├── loaders.py          .txt .md .csv .json .eml .pdf .docx
│   └── config.py           Settings from .env
├── data/sample_docs/       Synthetic EU bank documents (fictional people, test-format numbers)
├── data/sample_docs_india/ Synthetic Indian bank documents (fictional people, checksum-valid dummy IDs)
├── tests/                  pytest suite
├── requirements.txt  .env.example  Dockerfile  run.sh  run_windows.bat
```

## Design decisions (useful in interviews)

- **Why pseudonymise and not just delete?** With consistent placeholders, the LLM can still answer "did `[PERSON_2]` report the fraud?" Plain `***` masking would destroy that link.
- **Why TF-IDF and not an embedding API?** Embedding redacted text through an external API is still a data transfer. TF-IDF runs locally, keeps the placeholders as exact tokens, and is enough for a demo corpus. Local `sentence-transformers` embeddings are the next step for semantic recall ("borrow" ≈ "loan").
- **Why checksum validation?** Banks are full of 9-digit reference numbers. Redacting only those that pass the 11-proef / mod-97 / Luhn checks keeps amounts and case numbers usable.
- **Why a hash chain?** It is a lightweight version of the integrity guarantees an auditor expects (append-only, tamper-evident), with no blockchain or database needed.
- **Limits:** rule-based name detection misses names that have no title, label or earlier mention. Installing spaCy (`en_core_web_sm` / `nl_core_news_sm`) improves recall. The strict leak guard on questions reduces the risk further. This is a portfolio project, not a certified production system.

## Possible extensions

- Microsoft Presidio or a fine-tuned Dutch NER model
- Local embeddings + hybrid search
- FastAPI REST endpoint and SSO roles
- Per-tenant vault keys stored in a KMS / HSM
- DPIA template and Art. 30 record-of-processing export generated from the audit log

---
All sample data is synthetic. The IBANs, card and BSN numbers are public test numbers. The Aadhaar and PAN numbers are made up; they only satisfy the format and checksum rules.
