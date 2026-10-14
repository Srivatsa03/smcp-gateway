import json

import pytest

from smcp_gateway.audit import AuditIntegrityError, AuditLog, verify_log
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


def test_tail_truncation_needs_a_checkpoint(tmp_path):
    path, keys, _ = make_log(tmp_path)
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    assert verify_log(path, keys).ok  # the chain alone cannot see it


def test_checkpoint_catches_truncation(tmp_path):
    key = generate_key()
    keys = {"G2TEST": public_b64(key)}
    path, cp = tmp_path / "a.jsonl", tmp_path / "witness" / "a.cp.json"
    log = AuditLog(path, key, "G2TEST", checkpoint=cp, fsync=True)
    for i in range(3):
        log.append("TOOL_CALL", toolName=f"t{i}")
    older = json.loads(cp.read_text())
    log.append("TOOL_CALL", toolName="t3")
    checkpoint = json.loads(cp.read_text())
    assert checkpoint["count"] == 4 and verify_log(path, keys, checkpoint).ok

    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]) + "\n")
    r = verify_log(path, keys, checkpoint)
    assert not r.ok and "truncated" in r.reason
    assert verify_log(path, keys, older).ok  # rolled back together: why the checkpoint belongs off-host

    with pytest.raises(AuditIntegrityError):  # the gateway will not write over the evidence
        AuditLog(path, key, "G2TEST", checkpoint=cp)


def test_checkpoint_signature_and_divergence(tmp_path):
    key = generate_key()
    keys = {"G2TEST": public_b64(key)}
    path, cp = tmp_path / "a.jsonl", tmp_path / "a.cp.json"
    log = AuditLog(path, key, "G2TEST", checkpoint=cp)
    log.append("TOOL_CALL", toolName="t0")
    log.append("TOOL_CALL", toolName="t1")
    checkpoint = json.loads(cp.read_text())
    forged = {**checkpoint, "count": 1}
    assert "signature" in verify_log(path, keys, forged).reason

    other = AuditLog(tmp_path / "b.jsonl", key, "G2TEST")  # a different log, same length, same key
    other.append("TOOL_CALL", toolName="x0")
    other.append("TOOL_CALL", toolName="x1")
    path.write_text((tmp_path / "b.jsonl").read_text())
    assert "differs from the checkpoint" in verify_log(path, keys, checkpoint).reason


def test_checkpoint_interval(tmp_path):
    key = generate_key()
    cp = tmp_path / "a.cp.json"
    log = AuditLog(tmp_path / "a.jsonl", key, "G2TEST", checkpoint=cp, checkpoint_every=3)
    for i in range(5):
        log.append("TOOL_CALL", toolName=f"t{i}")
    assert json.loads(cp.read_text())["count"] == 3  # written at 3; 4 and 5 are not covered yet


def test_two_processes_share_one_log(tmp_path):
    """Two gateways on one config (one per client connection) keep the chain linear."""
    import subprocess
    import sys
    from smcp_gateway.crypto import save_key
    key = generate_key()
    save_key(key, tmp_path / "k.pem")
    script = (
        "import sys\n"
        "from smcp_gateway.audit import AuditLog\n"
        "from smcp_gateway.crypto import load_key\n"
        f"log = AuditLog({str(tmp_path / 'a.jsonl')!r}, load_key({str(tmp_path / 'k.pem')!r}), 'G2TEST',\n"
        f"             checkpoint={str(tmp_path / 'cp.json')!r})\n"
        "for i in range(150):\n"
        "    log.append('TOOL_CALL', toolName=sys.argv[1] + str(i))\n"
    )
    procs = [subprocess.Popen([sys.executable, "-c", script, name]) for name in ("a", "b", "c")]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    checkpoint = json.loads((tmp_path / "cp.json").read_text())
    r = verify_log(tmp_path / "a.jsonl", {"G2TEST": public_b64(key)}, checkpoint)
    assert r.ok and r.entries == 450 and checkpoint["count"] == 450
