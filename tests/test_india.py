from pathlib import Path

from gdpr_rag.config import Settings
from gdpr_rag.loaders import load_path
from gdpr_rag.pii import PIIDetector, aadhaar_is_valid, redact
from gdpr_rag.pipeline import GDPRAssistant

INDIA = Path(__file__).resolve().parent.parent / "data" / "sample_docs_india"


def types(text):
    return {e.type for e in PIIDetector().detect(text)}


def test_aadhaar_verhoeff():
    assert aadhaar_is_valid("2345 6789 0124")
    assert not aadhaar_is_valid("2345 6789 0125")   # wrong check digit
    assert not aadhaar_is_valid("1234 5678 9012")   # cannot start with 1
    # an invalid 12-digit reference number is NOT redacted
    assert "AADHAAR" not in types("Reference 2345 6789 0125")


def test_indian_identifiers():
    text = ("PAN: ABCPV1234K, UPI ID: rahul88@okicici, Mobile: +91 98765 43210, "
            "GSTIN 24BQXPP4567M1Z5, Savings account no: 50100234567891, Passport No: K4567812")
    assert {"PAN", "UPI", "PHONE", "GSTIN", "ACCOUNT", "PASSPORT"} <= types(text)


def test_upi_is_not_confused_with_email():
    t = types("Mail a.b@example.in or pay ab@ybl")
    assert {"EMAIL", "UPI"} <= t


def test_indian_titles_and_relations():
    out = redact("Applicant: Priya Verma\nSmt. Anjali Verma and S/o Ramesh Gupta signed.").text
    for name in ("Priya Verma", "Anjali Verma", "Ramesh Gupta"):
        assert name not in out


def test_ifsc_is_kept():
    # IFSC identifies a bank branch, not a person, so it stays useful for analysis.
    assert "HDFC0001234" in redact("IFSC: HDFC0001234").text


def test_india_pipeline_no_leak(tmp_path, monkeypatch):
    app = GDPRAssistant(Settings(data_dir=tmp_path, master_key="k", llm_provider="offline"))
    for p in sorted(INDIA.glob("*.txt")):
        app.ingest(p.name, load_path(p))
    sent = []
    monkeypatch.setattr(app.llm, "complete", lambda prompt, **kw: sent.append(prompt) or "ok")
    app.ask("What happened to Rahul Sharma's UPI payments from rahulsharma88@okicici?")
    for raw in ("Rahul Sharma", "rahulsharma88@okicici", "3456 7890 1238", "9812345670", "Sector 62"):
        assert raw not in sent[0]
    assert any("upi_fraud" in line for line in sent[0].splitlines())
    assert app.erase_subject("ABCPV1234K")["erased"]


def test_lowercase_known_name_in_question(tmp_path):
    app = GDPRAssistant(Settings(data_dir=tmp_path, master_key="k", llm_provider="offline"))
    for p in sorted(INDIA.glob("*.txt")):
        app.ingest(p.name, load_path(p))
    ans = app.ask("what is the risk rating of rahul sharma")
    assert "rahul sharma" not in ans.question_redacted.lower()
    assert "[PERSON_" in ans.question_redacted
