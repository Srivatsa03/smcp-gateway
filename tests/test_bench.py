"""The bench is the claim. Pin every outcome so a change that moves one is visible."""

from smcp_gateway.bench.run import run_scenarios
from smcp_gateway.bench.world import World

# risk: (paper design, with extensions)
EXPECTED = {
    "Unauthenticated Access": ("blocked", "blocked"),
    "Session Management Flaws": ("blocked", "blocked"),
    "Namespace Typosquatting": ("blocked", "blocked"),
    "Tool Name Conflict": ("blocked", "blocked"),
    "Tool Poisoning": ("missed", "partial"),
    "Command Injection": ("missed", "blocked"),
    "Rug Pulls": ("blocked", "blocked"),
    "Cross-Server Shadowing": ("missed", "partial"),
    "Prompt Injection": ("missed", "blocked"),
    "Indirect Prompt Injection": ("missed", "blocked"),
    "Installer Spoofing": ("missed", "blocked"),
    "Preference Manipulation": ("missed", "partial"),
    "Remote Code Execution": ("not tested", "not tested"),
    "SQL Injection": ("missed", "blocked"),
    "Credential Theft": ("missed", "missed"),
    "Sandbox Escape": ("not tested", "not tested"),
    "Tool Chaining Abuse": ("missed", "blocked"),
    "Unauthorized Access": ("blocked", "blocked"),
    "Privilege Abuse": ("blocked", "blocked"),
    "Path Traversal": ("missed", "partial"),
    "Resource Content Poisoning": ("missed", "partial"),
    "Token Passthrough": ("blocked", "blocked"),
    "Cross-Tenant Data Exposure": ("blocked", "blocked"),
    "Vulnerable Versions": ("partial", "blocked"),
    "Privilege Persistence": ("blocked", "blocked"),
    "Configuration Drift": ("missed", "blocked"),
}

CHECKS = {
    "Response tampering in transit": ("detected", "detected"),
    "Audit log tampering": ("partly detected", "detected"),
    "Server-initiated sampling request": ("not blocked", "blocked"),
    "Handshake replay to a second HTTP session": ("detected", "detected"),
}


def test_bench_outcomes(tmp_path):
    rows, checks, benign = run_scenarios(World(tmp_path))
    got = {r.risk: (r.paper, r.extended) for r in rows}
    assert len(got) == 26
    assert got == EXPECTED
    for r in rows:
        if r.paper != "not tested":
            assert r.baseline and r.baseline != "-"
        for v in r.variants:  # every variant worked against the bare server and got a verdict
            assert v["outcome"] in ("blocked", "missed"), v
        if r.extended == "partial" and r.paper != "partial":
            assert any(v["outcome"] == "missed" for v in r.variants), r.risk  # partial means a variant won
    assert {c["check"]: (c["paper"], c["extended"]) for c in checks} == CHECKS
    assert {k: (v["calls"], v["denied"], v["approvals"]) for k, v in benign.items()} == {
        "paper": (15, 0, 0), "extended": (15, 0, 3)}
