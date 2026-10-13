"""The bench is the claim. Pin every outcome so a change that moves one is visible."""

from smcp_gateway.bench.run import run_scenarios
from smcp_gateway.bench.world import World

EXPECTED = {
    "Unauthenticated Access": "blocked",
    "Session Management Flaws": "blocked",
    "Namespace Typosquatting": "blocked",
    "Tool Name Conflict": "blocked",
    "Tool Poisoning": "missed",
    "Command Injection": "missed",
    "Rug Pulls": "blocked",
    "Cross-Server Shadowing": "missed",
    "Prompt Injection": "missed",
    "Indirect Prompt Injection": "missed",
    "Installer Spoofing": "not tested",
    "Preference Manipulation": "not tested",
    "Remote Code Execution": "not tested",
    "SQL Injection": "missed",
    "Credential Theft": "missed",
    "Sandbox Escape": "not tested",
    "Tool Chaining Abuse": "missed",
    "Unauthorized Access": "blocked",
    "Privilege Abuse": "blocked",
    "Path Traversal": "missed",
    "Resource Content Poisoning": "missed",
    "Token Passthrough": "blocked",
    "Cross-Tenant Data Exposure": "blocked",
    "Vulnerable Versions": "partial",
    "Privilege Persistence": "blocked",
    "Configuration Drift": "not tested",
}


def test_bench_outcomes(tmp_path):
    rows, integrity = run_scenarios(World(tmp_path))
    got = {r.risk: r.smcp for r in rows}
    assert len(got) == 26
    assert got == EXPECTED
    for r in rows:
        if r.smcp != "not tested":
            assert r.baseline and r.baseline != "-"
    assert [i["result"] for i in integrity] == ["detected", "detected"]
