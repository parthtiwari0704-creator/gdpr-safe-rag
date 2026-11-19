import json

from gdpr_rag.pii import PIIDetector


def test_question_is_pseudonymised_and_answer_uses_placeholders(assistant):
    ans = assistant.ask("Why was Thomas Bakker charged twice?")
    assert "Thomas Bakker" not in ans.question_redacted
    assert "Thomas Bakker" not in ans.answer_display            # analyst: no reveal
    assert any("customer_complaint" in c.filename for c in ans.sources)


def test_nothing_personal_reaches_the_llm(assistant, monkeypatch):
    sent = []
    monkeypatch.setattr(assistant.llm, "complete",
                        lambda prompt, **kw: sent.append(prompt) or "ok")
    assistant.ask("What happened to the account of Emma Visser, emma.visser@example.com?")
    prompt = sent[0]
    for raw in ("Emma Visser", "emma.visser@example.com", "NL91ABNA0417164300", "4111 1111 1111 1111"):
        assert raw not in prompt
    assert PIIDetector().contains_pii(prompt) == []


def test_reveal_only_for_authorised_roles(assistant):
    denied = assistant.ask("What happened to the account of Emma Visser?", role="analyst", reveal=True)
    assert not denied.revealed
    allowed = assistant.ask("What happened to the account of Emma Visser?", role="dpo", reveal=True)
    assert allowed.revealed and "Emma Visser" in allowed.answer_display
    actions = [e["action"] for e in assistant.audit.entries()]
    assert "reidentification_denied" in actions and "reidentification" in actions


def test_erasure_makes_subject_unrecoverable(assistant):
    res = assistant.erase_subject("Emma Visser")
    assert res["erased"]
    assert assistant.vault.reveal(res["token"]) is None
    # asking again must not restore the erased person
    ans = assistant.ask("What happened to Emma Visser?", role="dpo", reveal=True)
    assert "Emma Visser" not in ans.answer_display
    assert assistant.vault.reveal(res["token"]) is None


def test_erasure_can_delete_documents(assistant):
    res = assistant.erase_subject("NL91ABNA0417164300", delete_documents=True)
    assert len(res["documents_deleted"]) == 1
    assert all("fraud" not in d["filename"] for d in assistant.store.list_documents())


def test_subject_access(assistant):
    res = assistant.subject_access("t.bakker@example.org")
    assert res["token"] and len(res["documents"]) == 1


def test_audit_log_has_no_personal_data(assistant):
    assistant.ask("Is Chidi Okafor a PEP?")
    raw = assistant.settings.audit_path.read_text()
    for value in ("Chidi Okafor", "c.okafor@okafortrading.example", "NL44RABO0123456789"):
        assert value not in raw
    assert assistant.audit.verify()[0]
    assert all("hash" in json.loads(line) for line in raw.splitlines())


def test_retention_purge(assistant):
    assistant.settings.retention_days = -1   # everything is "expired"
    deleted = assistant.purge_expired()
    assert len(deleted) == 4 and assistant.store.list_documents() == []


def test_unknown_person_is_not_answered(assistant):
    ans = assistant.ask("What loan amount did Priya Verma apply for?")   # only EU docs loaded
    assert "No document mentions this person" in ans.answer_display
    assert ans.sources == []
