from gdpr_rag.pii import PIIDetector, bsn_is_valid, iban_is_valid, luhn_is_valid, redact


def types(text, **kw):
    return {e.type for e in PIIDetector(**kw).detect(text)}


def test_validators():
    assert iban_is_valid("NL91 ABNA 0417 1643 00")
    assert not iban_is_valid("NL92ABNA0417164300")       # wrong checksum
    assert luhn_is_valid("4111 1111 1111 1111")
    assert not luhn_is_valid("4111 1111 1111 1112")
    assert bsn_is_valid("111222333")
    assert not bsn_is_valid("123456789")


def test_detects_core_identifiers():
    text = "Mail jan@example.nl, IBAN NL91ABNA0417164300, call +31 6 12345678, IP 10.0.0.12"
    assert {"EMAIL", "IBAN", "PHONE", "IP"} <= types(text)


def test_invalid_numbers_are_not_redacted():
    # A random 9-digit reference that fails the 11-proef must survive.
    out = redact("Reference 123456789 and amount EUR 385,000").text
    assert "123456789" in out and "385,000" in out


def test_names_by_title_label_and_greeting():
    text = "Applicant: Jan de Vries\nDear Mevr. Sophie Bakker,\nMr. de Vries signed."
    res = redact(text)
    assert "Jan de Vries" not in res.text
    assert "Sophie Bakker" not in res.text
    assert "de Vries signed" not in res.text


def test_surname_links_to_full_name():
    res = redact("Account holder: Thomas Bakker\nMr. Bakker asked for a refund.")
    tokens = [t for t in res.replacements if t.startswith("[PERSON")]
    assert len(tokens) == 1, res.text


def test_same_value_same_token():
    res = redact("From NL91ABNA0417164300 to NL91 ABNA 0417 1643 00")
    assert res.text.count("[IBAN_1]") == 2


def test_strict_mode_catches_untitled_names():
    assert "PERSON" not in types("Is Karel Peeters a customer?")
    assert "PERSON" in types("Is Karel Peeters a customer?", strict=True)


def test_no_pii_left_in_sample_docs(assistant):
    detector = PIIDetector()
    for doc in assistant.store.list_documents():
        text = assistant.store.get_document_text(doc["doc_id"])
        assert detector.contains_pii(text) == [], doc["filename"]
        for raw in ("NL91ABNA0417164300", "emma.visser@example.com", "111222333", "Jan de Vries"):
            assert raw not in text


def test_possessive_names():
    res = redact("Applicant: Emma Visser\nEmma Visser's account was blocked.")
    assert len([t for t in res.replacements if t.startswith("[PERSON")]) == 1
    assert "Visser" not in res.text
