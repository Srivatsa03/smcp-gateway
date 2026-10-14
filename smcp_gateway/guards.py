"""Argument guards. An extension: the paper's design never looks at argument content.

SMCP decides who may call a tool. It does not decide what they may pass. That is
why command injection, SQL injection and path traversal go straight through it
(see docs/RESULTS.md). A gateway sees every argument, so it can enforce a
narrower contract than the server does:

* ``schema``  extra JSON Schema checks on top of the server's own input schema,
              usually a ``pattern`` that allowlists what an argument may contain
* ``paths``   the argument must resolve inside one of the allowed roots
* ``urls``    the argument must be an http(s) URL on an allowed host
* ``emails``  every recipient must be on an allowed domain

All four are lexical. The gateway cannot see the server's filesystem, so a
symlink inside an allowed root still escapes it. The server has to resolve real
paths itself. A guard narrows what reaches a vulnerable server; it does not make
the server safe.
"""

from __future__ import annotations

import posixpath
import re
from urllib.parse import urlsplit

GUARD_KEYS = ("schema", "paths", "urls", "emails")

_TYPES = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "null": lambda v: v is None,
}


class GuardConfigError(ValueError):
    pass


def ecma_pattern(pattern: str) -> str:
    """Translate a JSON Schema (ECMA-262) pattern for Python's ``re``.

    The one difference that matters for a guard: in Python ``$`` also matches
    just before a final newline, so ``^[a-z]+$`` would accept ``"report\\n"``.
    In ECMA-262 it matches only at the end. Each unescaped ``$`` outside a
    character class becomes ``\\Z``.
    """
    out, i, in_class = [], 0, False
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out.append(pattern[i:i + 2])
            i += 2
            continue
        if c == "[" and not in_class:
            in_class = True
        elif c == "]" and in_class:
            in_class = False
        elif c == "$" and not in_class:
            c = "\\Z"
        out.append(c)
        i += 1
    return "".join(out)


def validate(value: object, schema: object, where: str = "arguments") -> list[str]:
    """Check ``value`` against a JSON Schema subset.

    Supported: type, enum, const, minLength, maxLength, pattern, minimum,
    maximum, exclusiveMinimum, exclusiveMaximum, required, properties,
    additionalProperties, items, minItems, maxItems, allOf, anyOf, oneOf.
    Anything else (``$ref``, formats) is not enforced.
    """
    if schema is True or schema is None:
        return []
    if schema is False:
        return [f"{where} is not allowed"]
    if not isinstance(schema, dict):
        return []
    out: list[str] = []

    t = schema.get("type")
    if t is not None:
        types = t if isinstance(t, list) else [t]
        if not any(_TYPES.get(name, lambda v: True)(value) for name in types):
            return [f"{where} must be of type {t}"]
    if "enum" in schema and value not in schema["enum"]:
        out.append(f"{where} must be one of {schema['enum']}")
    if "const" in schema and value != schema["const"]:
        out.append(f"{where} must equal {schema['const']!r}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            out.append(f"{where} is shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            out.append(f"{where} is longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(ecma_pattern(schema["pattern"]), value):
            out.append(f"{where} {_short(value)} does not match the allowed pattern {schema['pattern']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            out.append(f"{where} is below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            out.append(f"{where} is above {schema['maximum']}")
        if "exclusiveMinimum" in schema and value <= schema["exclusiveMinimum"]:
            out.append(f"{where} must be above {schema['exclusiveMinimum']}")
        if "exclusiveMaximum" in schema and value >= schema["exclusiveMaximum"]:
            out.append(f"{where} must be below {schema['exclusiveMaximum']}")

    if isinstance(value, dict):
        props = schema.get("properties") or {}
        for name in schema.get("required") or []:
            if name not in value:
                out.append(f"{where}.{name} is required")
        extra = schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                out += validate(v, props[k], f"{where}.{k}")
            elif extra is False:
                out.append(f"{where}.{k} is not an allowed argument")
            elif isinstance(extra, dict):
                out += validate(v, extra, f"{where}.{k}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            out.append(f"{where} has fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            out.append(f"{where} has more than {schema['maxItems']} items")
        if isinstance(schema.get("items"), dict):
            for i, item in enumerate(value):
                out += validate(item, schema["items"], f"{where}[{i}]")

    for sub in schema.get("allOf") or []:
        out += validate(value, sub, where)
    if schema.get("anyOf") and not any(not validate(value, s, where) for s in schema["anyOf"]):
        out.append(f"{where} matches none of the allowed forms")
    if schema.get("oneOf") and sum(not validate(value, s, where) for s in schema["oneOf"]) != 1:
        out.append(f"{where} must match exactly one allowed form")
    return out


def _short(value: str, n: int = 60) -> str:
    return repr(value if len(value) <= n else value[:n] + "...")


# --- paths, URLs, email recipients -------------------------------------------------

_ENCODED = re.compile(r"%(2e|2f|5c|00)", re.IGNORECASE)


def check_path(value: object, roots: list[str]) -> str | None:
    if not isinstance(value, str):
        return "must be a string path"
    if "\x00" in value:
        return f"{_short(value)} contains a NUL byte"
    if "\\" in value:
        return f"{_short(value)} contains a backslash"
    if _ENCODED.search(value):
        return f"{_short(value)} contains percent-encoded path characters"
    if value.startswith("~"):
        return f"{_short(value)} is relative to a home directory"
    base = posixpath.normpath(roots[0])
    full = posixpath.normpath(value if value.startswith("/") else posixpath.join(base, value))
    if full.startswith("//"):
        full = "/" + full.lstrip("/")
    for root in roots:
        r = posixpath.normpath(root)
        if full == r or full.startswith(r.rstrip("/") + "/"):
            return None
    return f"{_short(value)} resolves to {full}, outside the allowed roots {roots}"


def _host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for a in allowed:
        a = a.lower()
        if a.startswith(".") and (host.endswith(a) or host == a[1:]):
            return True
        if host == a:
            return True
    return False


_URL_CHARS = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")


def check_url(value: object, hosts: list[str]) -> str | None:
    """The URL must be http(s), on an allowed host, and plain enough that every
    parser agrees on the host: no backslashes, spaces or control characters
    (Python and Node split ``http://a\\@b/`` differently), and no user info."""
    if not isinstance(value, str):
        return "must be a string URL"
    if not _URL_CHARS.match(value):
        return f"{_short(value)} contains characters that parsers disagree on"
    try:
        parts = urlsplit(value)
        host = parts.hostname or ""
    except ValueError:
        return f"{_short(value)} is not a valid URL"
    if parts.scheme not in ("http", "https"):
        return f"{_short(value)} is not an http(s) URL"
    if "@" in parts.netloc:
        return f"{_short(value)} carries user info before the host"
    if not host or not _host_allowed(host, hosts):
        return f"host {host or '(none)'} is not an allowed destination {hosts}"
    return None


_ADDRESS = re.compile(r"^[^@\s<>\"]+@([A-Za-z0-9.-]+)$")


def check_emails(value: object, domains: list[str]) -> str | None:
    if not isinstance(value, str):
        return "must be a string of recipients"
    for raw in re.split(r"[,;]", value):
        addr = raw.strip()
        m = re.search(r"<([^<>]+)>\s*$", addr)
        if m:
            addr = m.group(1).strip()
        if not addr:
            continue
        hit = _ADDRESS.match(addr)
        if hit is None:
            return f"{_short(raw.strip())} is not a plain email address"
        if not _host_allowed(hit.group(1), domains):
            return f"recipient {addr} is outside the allowed domains {domains}"
    return None


# --- the guard set for one tool ---------------------------------------------------


def check_config(guards: object, where: str) -> None:
    """Raise GuardConfigError if a registry entry's guards are malformed."""
    if not isinstance(guards, dict):
        raise GuardConfigError(f"{where}: argumentGuards must be a mapping")
    for key, spec in guards.items():
        if key not in GUARD_KEYS:
            raise GuardConfigError(f"{where}: unknown guard {key!r}; use {GUARD_KEYS}")
        if key == "schema":
            _check_patterns(spec, where)
            continue
        list_key = {"paths": "roots", "urls": "hosts", "emails": "domains"}[key]
        if not isinstance(spec, dict) or not spec.get("args") or not spec.get(list_key):
            raise GuardConfigError(f"{where}: {key} needs args and {list_key}")


def _check_patterns(schema: object, where: str) -> None:
    if isinstance(schema, dict):
        if "pattern" in schema:
            try:
                re.compile(ecma_pattern(schema["pattern"]))
            except re.error as e:
                raise GuardConfigError(f"{where}: bad pattern {schema['pattern']!r}: {e}") from None
        for v in schema.values():
            _check_patterns(v, where)
    elif isinstance(schema, list):
        for v in schema:
            _check_patterns(v, where)


def check(guards: dict | None, args: dict, input_schema: dict | None = None) -> list[str]:
    """Every problem with ``args``. Empty means the arguments pass.

    ``input_schema`` is the server's own (pinned) schema. When given it is
    enforced first, so a server that forgets to validate its inputs still gets
    the contract it advertised.
    """
    problems: list[str] = []
    if input_schema:
        problems += validate(args, input_schema)
    guards = guards or {}
    if guards.get("schema"):
        problems += validate(args, guards["schema"])
    for key, check_one, list_key in (("paths", check_path, "roots"), ("urls", check_url, "hosts"),
                                     ("emails", check_emails, "domains")):
        spec = guards.get(key)
        if not spec:
            continue
        for name in spec["args"]:
            if name not in args:
                continue
            values = args[name] if isinstance(args[name], list) else [args[name]]  # e.g. a list of paths
            for i, value in enumerate(values):
                problem = check_one(value, list(spec[list_key]))
                if problem:
                    where = f"arguments.{name}" + (f"[{i}]" if isinstance(args[name], list) else "")
                    problems.append(f"{where}: {problem}")
    return problems
