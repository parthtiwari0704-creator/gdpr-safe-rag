import json

from gdpr_rag.audit import AuditLog


def test_hash_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.log("event", "tester", n=i)
    assert log.verify()[0]

    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    entry = json.loads(lines[2])
    entry["details"]["n"] = 999                      # tamper with one entry
    lines[2] = json.dumps(entry)
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    ok, msg = log.verify()
    assert not ok and "Entry 3" in msg


def test_deleted_line_breaks_chain(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(4):
        log.log("event", n=i)
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    del lines[1]
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")
    assert not log.verify()[0]
