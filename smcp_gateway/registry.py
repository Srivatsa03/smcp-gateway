"""Trusted Component Registry (paper section 4.1).

The registry is the source of truth for who exists, what key they hold, whether
they are still active, and which tools each server is allowed to expose. It is a
YAML file here. The paper describes a registry service; a file that the gateway
re-reads when it changes is the smallest thing that still makes revocation take
effect mid-session.

Each registered tool pins a SHA-256 of its definition (name, description and
input schema) taken at registration time. A server that later serves a different
definition under the same name fails vetting. That is the rug-pull check.
"""

from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .crypto import digest
from .identity import kind_of, parse_id

STATUSES = ("active", "suspended", "revoked")


@dataclass(frozen=True)
class Entity:
    id: str
    kind: str
    alias: str = ""
    public_key: str | None = None
    status: str = "active"
    assurance: str = "aal1"
    org: str | None = None
    roles: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return self.alias or self.id


@dataclass(frozen=True)
class ToolRecord:
    server_id: str
    name: str
    tool_id: str
    version: str | None = None
    definition_sha256: str | None = None
    security: dict = field(default_factory=dict)

    @property
    def sensitivity(self) -> str:
        return self.security.get("sensitivityLevel", "internal")


def definition_hash(tool: dict) -> str:
    return digest({
        "name": tool.get("name"),
        "description": tool.get("description", ""),
        "inputSchema": tool.get("inputSchema", {}),
    })


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


_CONFUSABLE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "-": "_", ".": "_"})


def _skeleton(name: str) -> str:
    folded = unicodedata.normalize("NFKC", name).lower().translate(_CONFUSABLE)
    return folded.replace("rn", "m").replace("i", "l")


class RegistryError(ValueError):
    pass


class Registry:
    def __init__(self, data: dict, path: Path | None = None) -> None:
        self.path = Path(path) if path else None
        self._stamp = self._file_stamp()
        self._load(data)

    @classmethod
    def load(cls, path: Path) -> "Registry":
        path = Path(path)
        return cls(yaml.safe_load(path.read_text()) or {}, path)

    def _file_stamp(self) -> tuple[int, int] | None:
        if self.path is None:
            return None
        st = os.stat(self.path)
        return (st.st_mtime_ns, st.st_size)

    def reload_if_changed(self) -> bool:
        """Re-read the file if it changed, so revocations apply to live sessions."""
        if self.path is None:
            return False
        stamp = self._file_stamp()
        if stamp == self._stamp:
            return False
        self._load(yaml.safe_load(self.path.read_text()) or {})
        self._stamp = stamp
        return True

    def _load(self, data: dict) -> None:
        entities: dict[str, Entity] = {}
        for raw in data.get("entities") or []:
            code = raw.get("id", "")
            try:
                parse_id(code)
            except ValueError as e:
                raise RegistryError(f"entity {raw.get('alias') or code!r}: {e}") from None
            status = raw.get("status", "active")
            if status not in STATUSES:
                raise RegistryError(f"entity {code}: status must be one of {STATUSES}")
            entities[code] = Entity(
                id=code,
                kind=kind_of(code),
                alias=raw.get("alias", ""),
                public_key=raw.get("publicKey"),
                status=status,
                assurance=raw.get("assurance", "aal1"),
                org=raw.get("org"),
                roles=tuple(raw.get("roles") or ()),
            )

        tools: dict[tuple[str, str], ToolRecord] = {}
        servers: dict[str, dict] = {}
        for server in data.get("servers") or []:
            sid = server.get("id", "")
            if sid not in entities or entities[sid].kind != "tool":
                raise RegistryError(f"server {sid!r} must also be registered as a tool-type entity")
            servers[sid] = {k: v for k, v in server.items() if k != "tools"}
            for t in server.get("tools") or []:
                name = t["name"]
                tools[(sid, name)] = ToolRecord(
                    server_id=sid,
                    name=name,
                    tool_id=t.get("toolId", name),
                    version=t.get("version"),
                    definition_sha256=t.get("definitionSha256"),
                    security=dict(t.get("security") or {}),
                )

        self.data = data
        self.entities = entities
        self.tools = tools
        self.servers = servers
        self.fingerprint = digest(data)

    # --- lookups -------------------------------------------------------------

    def entity(self, code: str | None) -> Entity | None:
        return self.entities.get(code or "")

    def active(self, code: str | None) -> Entity | None:
        e = self.entity(code)
        return e if e is not None and e.status == "active" else None

    def tool(self, server_id: str, name: str) -> ToolRecord | None:
        return self.tools.get((server_id, name))

    def label(self, code: str | None) -> str:
        e = self.entity(code)
        return e.label if e else str(code)

    # --- vetting -------------------------------------------------------------

    def vet(self, server_id: str, tool: dict) -> tuple[ToolRecord | None, str | None]:
        """Decide whether a tool a server advertises may be shown to the agent.

        Returns the registry record, or None plus the reason it was rejected.
        """
        name = tool.get("name", "")
        record = self.tools.get((server_id, name))
        if record is None:
            owners = [s for (s, n) in self.tools if n == name and s != server_id]
            if owners:
                return None, (f"name_conflict: '{name}' is registered to "
                              f"{self.label(owners[0])}, not to this server")
            near = self._lookalike(name)
            if near:
                return None, f"typosquat: '{name}' imitates registered tool '{near}'"
            return None, f"unregistered: '{name}' is not in the trusted component registry"
        if record.definition_sha256 and definition_hash(tool) != record.definition_sha256:
            return None, (f"definition_changed: '{name}' no longer matches the definition "
                          f"pinned at registration (possible rug pull)")
        return record, None

    def _lookalike(self, name: str) -> str | None:
        skel = _skeleton(name)
        best: tuple[int, str] | None = None
        for (_, registered) in self.tools:
            if registered == name:
                continue
            if _skeleton(registered) == skel:
                return registered
            d = _levenshtein(name.lower(), registered.lower())
            if d <= 2 and (best is None or d < best[0]):
                best = (d, registered)
        return best[1] if best else None
