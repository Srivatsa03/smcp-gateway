import json

from smcp_gateway.audit import AuditLog, verify_log
from smcp_gateway.crypto import generate_key, public_b64


def make_log(tmp_path, n=5):
    key = generate_key()
    log = AuditLog(tmp_path / "a.jsonl", key, "G2TEST")
    for i in range(n):
        log.append("TOOL_CALL", toolName=f"t{i}", actionCode="SUCCESS" if i % 2 else "DENIED")
    return tmp_path / "a.jsonl", {"G2TEST": public_b64(key)}, key


def test_clean_log_verifies_and_continues_after_reopen(tmp_path):
    path, keys, key = make_log(tmp_path)
    AuditLog(path, key, "G2TEST").append("TOOL_CALL", toolName="later")
    r = verify_log(path, keys)
    assert r.ok and r.entries == 6


def test_edit_delete_reorder_detected(tmp_path):
    path, keys, _ = make_log(tmp_path)
    lines = path.read_text().splitlines()

    e = json.loads(lines[2]); e["actionCode"] = "SUCCESS"
    path.write_text("\n".join(lines[:2] + [json.dumps(e)] + lines[3:]) + "\n")
    assert verify_log(path, keys).bad_line == 3

    path.write_text("\n".join(lines[:1] + lines[2:]) + "\n")
    assert not verify_log(path, keys).ok

    path.write_text("\n".join([lines[1], lines[0]] + lines[2:]) + "\n")
    assert not verify_log(path, keys).ok


def test_wrong_signer_key_detected(tmp_path):
    path, _, _ = make_log(tmp_path)
    assert not verify_log(path, {"G2TEST": public_b64(generate_key())}).ok


def test_tail_truncation_is_a_known_gap(tmp_path):
    path, keys, _ = make_log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    assert verify_log(path, keys).ok  # documented in docs/LIMITATIONS.md
