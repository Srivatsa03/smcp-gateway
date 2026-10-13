"""Structured 32-character identity codes (paper section 4.1.3).

The paper fixes the length (32), the alphabet ([0-9A-Z]), the list of fields and
the MOD 97-10 checksum. It does not fix the field widths. This module picks
widths that add up to 32. Two registries that want to interoperate would have
to agree on the same layout.

    TT V AAAA RRRRRR YYYY SSSSSSSS IIIII CC
    |  | |    |      |    |        |     check digits, ISO 7064 MOD 97-10
    |  | |    |      |    |        instance serial
    |  | |    |      |    package or account serial
    |  | |    |      registration year
    |  | |    registrant
    |  | issuing authority
    |  version
    entity type
"""

from __future__ import annotations

import datetime as _dt
import secrets
from dataclasses import dataclass

LENGTH = 32
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
FIELDS = (
    ("type", 2),
    ("version", 1),
    ("authority", 4),
    ("registrant", 6),
    ("year", 4),
    ("serial", 8),
    ("instance", 5),
)

ENTITY_TYPES = {
    "U1": "user.human",
    "U2": "user.organization",
    "A1": "agent.general",
    "A2": "agent.domain",
    "T1": "tool.mcp_server",
    "T2": "tool.api",
    "T3": "service.model",
    "T4": "service.data",
    "G1": "governance.identity",
    "G2": "governance.policy",
    "G3": "governance.audit",
}
KINDS = {"U": "user", "A": "agent", "T": "tool", "G": "governance"}


@dataclass(frozen=True)
class IdentityCode:
    code: str
    type: str
    version: str
    authority: str
    registrant: str
    year: str
    serial: str
    instance: str
    check: str

    @property
    def kind(self) -> str:
        return KINDS[self.type[0]]

    @property
    def type_name(self) -> str:
        return ENTITY_TYPES[self.type]


def _numeric(text: str) -> str:
    return "".join(str(ALPHABET.index(c)) for c in text)


def check_digits(body: str) -> str:
    return f"{98 - int(_numeric(body) + '00') % 97:02d}"


def _field(value: object, width: int, name: str) -> str:
    text = str(value).upper()
    if len(text) > width:
        raise ValueError(f"{name} {text!r} is longer than {width} characters")
    if any(c not in ALPHABET for c in text):
        raise ValueError(f"{name} {text!r} uses characters outside [0-9A-Z]")
    return text.rjust(width, "0")


def make_id(
    entity_type: str,
    registrant: str,
    *,
    authority: str = "SMCP",
    year: int | None = None,
    serial: str | None = None,
    instance: int | str = 1,
    version: str = "1",
) -> str:
    if entity_type not in ENTITY_TYPES:
        raise ValueError(f"unknown entity type {entity_type!r}; use one of {sorted(ENTITY_TYPES)}")
    values = {
        "type": entity_type,
        "version": version,
        "authority": authority,
        "registrant": registrant,
        "year": year if year is not None else _dt.date.today().year,
        "serial": serial if serial is not None else "".join(secrets.choice(ALPHABET) for _ in range(8)),
        "instance": instance,
    }
    body = "".join(_field(values[name], width, name) for name, width in FIELDS)
    return body + check_digits(body)


def parse_id(code: str) -> IdentityCode:
    if not isinstance(code, str) or len(code) != LENGTH:
        raise ValueError(f"identity code must be {LENGTH} characters")
    if any(c not in ALPHABET for c in code):
        raise ValueError("identity code uses characters outside [0-9A-Z]")
    if int(_numeric(code)) % 97 != 1:
        raise ValueError("identity code checksum does not verify")
    parts: dict[str, str] = {}
    pos = 0
    for name, width in FIELDS:
        parts[name] = code[pos:pos + width]
        pos += width
    if parts["type"] not in ENTITY_TYPES:
        raise ValueError(f"unknown entity type {parts['type']!r}")
    return IdentityCode(code=code, check=code[pos:], **parts)


def is_valid(code: object) -> bool:
    try:
        parse_id(code)  # type: ignore[arg-type]
        return True
    except ValueError:
        return False


def kind_of(code: str) -> str:
    return parse_id(code).kind
