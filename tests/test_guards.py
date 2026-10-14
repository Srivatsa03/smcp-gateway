import pytest

from smcp_gateway.guards import GuardConfigError, check, check_config, check_emails, check_path, check_url, validate


def test_schema_subset():
    schema = {"type": "object", "required": ["path"], "additionalProperties": False,
              "properties": {"path": {"type": "string", "maxLength": 10},
                             "n": {"type": "integer", "minimum": 1},
                             "mode": {"enum": ["r", "w"]},
                             "tags": {"type": "array", "items": {"type": "string"}, "maxItems": 2}}}
    assert validate({"path": "a.txt", "n": 2, "mode": "r", "tags": ["x"]}, schema) == []
    problems = validate({"n": 0, "mode": "x", "extra": 1, "tags": ["a", 2, "c"]}, schema)
    text = " | ".join(problems)
    for needle in ("arguments.path is required", "below 1", "one of", "extra is not an allowed",
                   "more than 2 items", "tags[1] must be of type string"):
        assert needle in text
    assert validate(True, {"type": "integer"}) == ["arguments must be of type integer"]  # bool is not an int
    assert validate("x", {"anyOf": [{"type": "integer"}, {"type": "string"}]}) == []
    assert validate(1.5, {"oneOf": [{"type": "number"}, {"type": "integer"}]}) == []
    assert validate(1, {"oneOf": [{"type": "number"}, {"type": "integer"}]}) != []


@pytest.mark.parametrize("path,ok", [
    ("/app/notes.txt", True), ("notes/q3.csv", True), ("/data", True), ("/app", True),
    ("../../etc/passwd", False), ("/app/../etc/passwd", False), ("/etc/passwd", False),
    ("/application/x", False),  # a prefix is not a parent
    ("..%2f..%2fetc/passwd", False), ("..%2E/x", False), ("\\..\\x", False), ("~/x", False),
    ("/app/\x00x", False), ("//etc/passwd", False),
])
def test_paths(path, ok):
    assert (check_path(path, ["/app", "/data"]) is None) is ok


@pytest.mark.parametrize("url,ok", [
    ("https://reports.acme.example/up", True), ("http://acme.example/x", True),
    ("https://evil.test/", False), ("https://acme.example.evil.test/", False),
    ("https://reports.acme.example@evil.test/", False),  # userinfo trick
    ("ftp://reports.acme.example/", False), ("javascript:alert(1)", False), ("not a url", False),
    ("http://evil.com\\@reports.acme.example/x", False),  # Python and Node disagree on this host
    ("https://u@reports.acme.example/", False), ("https://reports.acme.example/a b", False),
    ("https://reports.acme.example/q?x=%2F", True),
])
def test_urls(url, ok):
    assert (check_url(url, [".acme.example"]) is None) is ok


@pytest.mark.parametrize("to,ok", [
    ("dana@acme.example", True), ("Dana Ops <dana@acme.example>", True), ("a@acme.example, b@acme.example", True),
    ("a@acme.example; x@evil.test", False), ("dana@acme.example.evil.test", False),
    ("dana@ACME.example", True), ("not-an-address", False),
])
def test_emails(to, ok):
    assert (check_emails(to, ["acme.example"]) is None) is ok


def test_check_combines_schema_and_guards():
    guards = {"schema": {"properties": {"filename": {"pattern": "^[a-z]+$"}}},
              "paths": {"args": ["path"], "roots": ["/app"]}}
    assert check(guards, {"filename": "q", "path": "/app/x"}) == []
    problems = check(guards, {"filename": "q;id", "path": "/etc/x"},
                     {"type": "object", "required": ["filename", "path"]})
    assert len(problems) == 2 and "arguments.path" in problems[1]


def test_pattern_end_anchor_is_ecma():
    """Python's $ also matches before a final newline; a guard must not."""
    schema = {"properties": {"f": {"pattern": "^[a-z.]+$"}}}
    assert validate({"f": "report.pdf"}, schema) == []
    assert validate({"f": "report.pdf\n"}, schema)
    assert validate({"f": "a$"}, {"pattern": "^a[$]$"}) == []  # a $ inside a class is a character


def test_list_arguments_check_every_item():
    guards = {"paths": {"args": ["paths"], "roots": ["/app"]}}
    assert check(guards, {"paths": ["/app/a", "/app/b"]}) == []
    problems = check(guards, {"paths": ["/app/a", "/etc/passwd"]})
    assert len(problems) == 1 and problems[0].startswith("arguments.paths[1]")


def test_config_errors():
    check_config({"paths": {"args": ["p"], "roots": ["/a"]}}, "t")
    for bad in ({"nope": {}}, {"paths": {"args": ["p"]}}, {"schema": {"properties": {"x": {"pattern": "("}}}}, []):
        with pytest.raises(GuardConfigError):
            check_config(bad, "t")
