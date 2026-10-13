"""A complete SMCP deployment on disk: keys, registry, policy and gateway configs.

Used by the bench, the tests and ``smcp-gateway init``. Everything is generated
fresh, so no key in this repository is ever reused.

Cast:
    alice     user, ORG-ACME, data_analyst
    bob       user, ORG-ACME, admin
    mallory   user, ORG-GLOBEX, data_analyst (another tenant)
    report    agent, aal2, allowed on the sales tools
    helper    agent, aal1
    rogue     agent, aal2, registered but not allowed on the sales tools
    gateway   the SMCP gateway (policy point) that signs sessions, responses and audit entries
    acme      the MCP server behind the gateway
    payments  a second MCP server; owns transfer_funds
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..context import issue_delegation
from ..crypto import generate_key, load_key, public_b64, save_key
from ..identity import make_id
from ..registry import Registry, definition_hash
from . import upstream

SERVER_VERSION = "1.4.2"


@dataclass
class Actor:
    alias: str
    id: str
    key: object | None


def _security(report_id: str) -> dict[str, dict]:
    audit = {"recordParamsSummary": True, "recordResultSummary": True,
             "recordCallerContext": True, "minRetentionDays": 365}
    keep = {"allowLongTermStorage": True, "allowIntoAgentLongTermMemory": False,
            "allowForModelTraining": False, "requiresRedaction": False}
    redact = {**keep, "requiresRedaction": True}
    acme_users = {"subjectType": "user", "allowedOrgIds": ["ORG-ACME"]}
    return {
        "query_sales": {
            "sensitivityLevel": "internal", "minIdentityAssurance": "aal2",
            "allowedDelegators": [{**acme_users, "allowedRoles": ["data_analyst", "admin"]},
                                  {"subjectType": "agent", "allowedAgentIds": [report_id]}],
            "requiredScopes": ["sales_reporting"], "dataPolicy": keep, "auditRequirement": audit},
        "lookup_customer": {
            "sensitivityLevel": "sensitive", "minIdentityAssurance": "aal2",
            "allowedDelegators": [acme_users], "requiredScopes": ["crm_read"],
            "dataPolicy": redact, "auditRequirement": audit},
        "read_file": {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1",
                      "dataPolicy": redact, "auditRequirement": audit},
        "http_post": {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1"},
        "send_email": {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1"},
        "fetch_url": {"sensitivityLevel": "public"},
        "run_report": {
            "sensitivityLevel": "internal", "minIdentityAssurance": "aal2",
            "allowedDelegators": [acme_users], "requiredScopes": ["sales_reporting"]},
        "convert_file": {"sensitivityLevel": "internal", "minIdentityAssurance": "aal1"},
        "delete_user": {
            "sensitivityLevel": "highly_sensitive", "minIdentityAssurance": "aal2",
            "allowedDelegators": [{**acme_users, "allowedRoles": ["admin"]}],
            "requiredScopes": ["user_admin"], "auditRequirement": audit},
        "get_weather": {"sensitivityLevel": "public"},
        "format_text": {"sensitivityLevel": "public"},
        "echo": {"sensitivityLevel": "public", "auditRequirement": {"recordParamsSummary": False}},
    }


POLICY = {
    "rules": [
        {"id": "POLICY-ACME-HIGHLY-SENSITIVE",
         "description": "Highly sensitive tools need a user at the root of the chain and risk at medium or lower.",
         "match": {"sensitivityLevel": ["highly_sensitive"]},
         "require": [{"attr": "chainRootType", "op": "eq", "value": "user"},
                     {"attr": "riskLevel", "op": "lte", "value": "medium"}]},
        {"id": "POLICY-ACME-SALES-AGGREGATE",
         "description": "Sales queries return at most 12 rows.",
         "match": {"tool": ["query_sales"]},
         "obligations": [{"maxRows": 12}]},
        {"id": "POLICY-ACME-CRM-PII",
         "description": "Customer lookups never return the SSN field.",
         "match": {"tool": ["lookup_customer"]},
         "obligations": [{"redactFields": ["ssn"]}]},
    ]
}


class World:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        keys = self.root / "keys"
        existing = (keys / "gateway.pem").exists()

        def actor(alias: str, etype: str, registrant: str, with_key: bool = True) -> Actor:
            ids_file = self.root / "ids.yaml"
            ids = yaml.safe_load(ids_file.read_text()) if ids_file.exists() else {}
            code = ids.get(alias) or make_id(etype, registrant)
            ids[alias] = code
            ids_file.write_text(yaml.safe_dump(ids, sort_keys=True))
            key = None
            if with_key:
                path = keys / f"{alias}.pem"
                if existing and path.exists():
                    key = load_key(path)
                else:
                    key = generate_key()
                    save_key(key, path)
            return Actor(alias, code, key)

        self.alice = actor("alice", "U1", "ACME")
        self.bob = actor("bob", "U1", "ACME")
        self.mallory = actor("mallory", "U1", "GLOBEX")
        self.report = actor("report", "A2", "ACME")
        self.helper = actor("helper", "A1", "ACME")
        self.rogue = actor("rogue", "A1", "ACME")
        self.gateway = actor("gateway", "G2", "ACME")
        self.acme = actor("acme", "T1", "ACME", with_key=False)
        self.payments = actor("payments", "T1", "ACME", with_key=False)
        (self.root / "policy.yaml").write_text(yaml.safe_dump(POLICY, sort_keys=False))

    # --- registry and config ---------------------------------------------------

    def registry_data(self, *, pin_variant: str = "clean", server_version: str = SERVER_VERSION,
                      revoked: tuple[str, ...] = ()) -> dict:
        def ent(a: Actor, **extra) -> dict:
            d = {"id": a.id, "alias": a.alias, **extra}
            if a.key is not None:
                d["publicKey"] = public_b64(a.key)
            if a.alias in revoked:
                d["status"] = "revoked"
            return d

        security = _security(self.report.id)
        pinned = {t["name"]: t for t in upstream.tools_for(pin_variant)}
        acme_tools = []
        for i, tool in enumerate(upstream.BASE_TOOLS, 1):
            name = tool["name"]
            acme_tools.append({
                "name": name,
                "toolId": f"TOOL-ACME-{name.upper().replace('_', '-')}-{i:03d}",
                "version": "2026.1",
                "definitionSha256": definition_hash(pinned[name]),
                "security": security[name],
            })
        transfer = next(t for t in upstream.tools_for("conflict") if t["name"] == "transfer_funds")
        return {
            "authority": "SMCP",
            "entities": [
                ent(self.alice, org="ORG-ACME", roles=["data_analyst"]),
                ent(self.bob, org="ORG-ACME", roles=["admin"]),
                ent(self.mallory, org="ORG-GLOBEX", roles=["data_analyst"]),
                ent(self.report, assurance="aal2", org="ORG-ACME", roles=["entry_agent"]),
                ent(self.helper, assurance="aal1", org="ORG-ACME", roles=["helper_agent"]),
                ent(self.rogue, assurance="aal2", org="ORG-ACME", roles=["entry_agent"]),
                ent(self.gateway, roles=["policy_enforcement_point"]),
                ent(self.acme),
                ent(self.payments),
            ],
            "servers": [
                {"id": self.acme.id, "alias": "acme", "serverVersion": server_version, "tools": acme_tools},
                {"id": self.payments.id, "alias": "payments", "tools": [{
                    "name": "transfer_funds", "toolId": "TOOL-PAY-TRANSFER-001", "version": "2026.1",
                    "definitionSha256": definition_hash(transfer),
                    "security": {"sensitivityLevel": "highly_sensitive", "minIdentityAssurance": "aal3"}}]},
            ],
        }

    def write(self, name: str = "default", *, pin_variant: str = "clean", ttl: float = 900,
              server_version: str = SERVER_VERSION, legacy: dict | None = None,
              revoked: tuple[str, ...] = ()) -> Path:
        reg = self.root / f"registry-{name}.yaml"
        reg.write_text(yaml.safe_dump(self.registry_data(pin_variant=pin_variant,
                                                         server_version=server_version,
                                                         revoked=revoked), sort_keys=False))
        cfg = {
            "gateway": {
                "id": self.gateway.id,
                "privateKey": "keys/gateway.pem",
                "server": self.acme.id,
                "sessionTtlSeconds": ttl,
                "clockSkewSeconds": 120,
                "legacyClients": legacy if legacy else "deny",
            },
            "registry": reg.name,
            "policy": "policy.yaml",
            "audit": f"audit/{name}.jsonl",
        }
        path = self.root / f"smcp-{name}.yaml"
        path.write_text(yaml.safe_dump(cfg, sort_keys=False))
        return path

    def revoke(self, config: Path, alias: str) -> None:
        reg_path = config.parent / yaml.safe_load(config.read_text())["registry"]
        data = yaml.safe_load(reg_path.read_text())
        target = getattr(self, alias).id
        for e in data["entities"]:
            if e["id"] == target:
                e["status"] = "revoked"
        reg_path.write_text(yaml.safe_dump(data, sort_keys=False))

    def registry(self, config: Path) -> Registry:
        return Registry.load(config.parent / yaml.safe_load(config.read_text())["registry"])

    def audit_path(self, config: Path) -> Path:
        return config.parent / yaml.safe_load(config.read_text())["audit"]

    # --- commands and tokens -----------------------------------------------------

    @staticmethod
    def upstream_cmd(variant: str = "clean", version: str = SERVER_VERSION, log: Path | None = None) -> list[str]:
        cmd = [sys.executable, "-m", "smcp_gateway.bench.upstream", "--variant", variant, "--version", version]
        return cmd + (["--log", str(log)] if log else [])

    def gateway_cmd(self, config: Path, variant: str = "clean", version: str = SERVER_VERSION,
                    log: Path | None = None) -> list[str]:
        return [sys.executable, "-m", "smcp_gateway", "run", "-c", str(config), "--",
                *self.upstream_cmd(variant, version, log)]

    def delegate(self, user: Actor, agent: Actor, scopes: list[str], ttl: float = 3600) -> dict:
        return issue_delegation(user.key, user.id, agent.id, scopes, ttl_seconds=ttl)
