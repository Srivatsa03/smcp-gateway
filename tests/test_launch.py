"""Server artifact pins and signed configuration."""

import json
import subprocess
import sys

import pytest
import yaml

from smcp_gateway.client import ProtocolError, SMCPClient
from smcp_gateway.gateway import Deployment
from smcp_gateway.launch import ConfigSignatureError, FileVerifier, artifact_digest, check_artifact, sign_file
from smcp_gateway.crypto import generate_key, public_b64


def test_artifact_digest(tmp_path):
    d = tmp_path / "srv"
    (d / "pkg").mkdir(parents=True)
    (d / "server.py").write_text("print(1)\n")
    (d / "pkg" / "util.py").write_text("x = 1\n")
    first = artifact_digest(d)
    (d / "pkg" / "__pycache__").mkdir()
    (d / "pkg" / "__pycache__" / "util.cpython-312.pyc").write_bytes(b"junk")
    assert artifact_digest(d) == first  # caches do not count
    (d / "pkg" / "util.py").write_text("x = 2\n")
    assert artifact_digest(d) != first
    assert check_artifact(d, first) and "spoofed or changed" in check_artifact(d, first)
    assert check_artifact(d, None) is None
    assert "names no serverArtifact" in check_artifact(None, first)


def test_spoofed_install_refused_over_stdio(world):
    spoof = world.install("t-spoof", spoofed=True)
    cfg = world.write("t-launch", profile="extended", install=spoof)
    c = SMCPClient(world.gateway_cmd(cfg), agent_id=world.report.id, agent_key=world.report.key,
                   registry=world.registry(cfg), delegation=[world.delegate(world.alice, world.report, [])])
    with pytest.raises(ProtocolError, match="spoofed or changed install"):
        c.start()
    c.close()
    events = [json.loads(line)["event"] for line in world.audit_path(cfg).read_text().splitlines()]
    assert events == ["SERVER_REJECTED"]
    assert not (world.root / "captured-t-spoof.jsonl").exists()


def test_file_verifier(tmp_path):
    key = generate_key()
    f = tmp_path / "policy.yaml"
    f.write_text("rules: []\n")
    verifier = FileVerifier("G1X", public_b64(key))
    with pytest.raises(ConfigSignatureError, match="no readable signature"):
        verifier(f, f.read_bytes())
    sign_file(f, key, "G1X")
    verifier(f, f.read_bytes())
    f.write_text("rules: []\nflow: {}\n")
    with pytest.raises(ConfigSignatureError, match="unsigned edit"):
        verifier(f, f.read_bytes())
    sign_file(f, generate_key(), "G1X")  # right name, wrong key
    with pytest.raises(ConfigSignatureError, match="not signed by the configured signer"):
        verifier(f, f.read_bytes())


def test_unsigned_registry_refused_at_start_and_rejected_at_reload(world):
    cfg = world.write("t-signed", profile="extended")
    reg = world.registry_path(cfg)
    world.edit_registry(cfg, lambda d: d.update(note="unreviewed"), sign=False)
    with pytest.raises(ConfigSignatureError):
        Deployment.load(cfg)

    world.sign(reg)
    d = Deployment.load(cfg)
    before = d.registry.fingerprint
    world.edit_registry(cfg, lambda d: d.update(note="drift"), sign=False)
    assert d.registry.reload_if_changed() is False
    assert "unsigned edit" in d.registry.pop_rejection() and d.registry.fingerprint == before
    world.sign(reg)  # signing alone (the YAML did not change again) is picked up
    assert d.registry.reload_if_changed() is True and d.registry.fingerprint != before


def test_bad_yaml_keeps_last_good(tmp_path, world):
    cfg = world.write("t-yaml")
    d = Deployment.load(cfg)
    world.registry_path(cfg).write_text("entities: [unclosed\n")
    assert d.registry.reload_if_changed() is False and d.registry.pop_rejection()
    assert d.registry.active(world.report.id) is not None


def test_cli_sign_and_artifact(tmp_path, world):
    f = tmp_path / "p.yaml"
    f.write_text("rules: []\n")
    run = lambda *a: subprocess.run([sys.executable, "-m", "smcp_gateway", *a], capture_output=True, text=True)
    out = run("sign-config", "--key", str(world.root / "keys" / "governance.pem"), "--signer", world.governance.id, str(f))
    assert out.returncode == 0 and (tmp_path / "p.yaml.sig").exists()
    anchor = yaml.safe_load(out.stdout.splitlines()[-1].split(": ", 1)[1])
    FileVerifier(anchor["id"], anchor["publicKey"])(f, f.read_bytes())
    out = run("artifact", str(world.genuine))
    assert out.stdout.strip() == world.genuine_sha256
