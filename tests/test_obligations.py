import json

from smcp_gateway.obligations import apply, redact_secrets


def text_result(obj):
    return {"content": [{"type": "text", "text": json.dumps(obj)}], "isError": False}


def test_redact_fields_and_cap_rows():
    res = text_result({"rows": [{"id": i, "ssn": "x"} for i in range(20)]})
    out, applied = apply(res, [{"redactFields": ["ssn"]}, {"maxRows": 5}])
    rows = json.loads(out["content"][0]["text"])["rows"]
    assert len(rows) == 5 and all(r["ssn"] == "[REDACTED]" for r in rows)
    assert applied["truncated"] and applied["redactedFields"] == ["ssn"]
    assert json.loads(res["content"][0]["text"])["rows"][0]["ssn"] == "x"  # input untouched


def test_secret_patterns():
    text = ("AWS_ACCESS_KEY_ID=AKIAZ7Q3EXAMPLE4KEY0\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY99\n"
            "token: ghp_" + "a" * 36 + "\nkey sk-ant-" + "b" * 30)
    masked, found = redact_secrets(text)
    assert "AKIAZ7Q3" not in masked and "wJalr" not in masked and "ghp_" not in masked and "sk-ant-" not in masked
    assert {"aws_access_key", "aws_secret", "github_token", "llm_api_key"} <= set(found)


def test_plain_text_left_alone_without_obligations():
    res = {"content": [{"type": "text", "text": "hello"}]}
    out, applied = apply(res, [])
    assert out is res and not applied["truncated"]


def test_structured_content():
    res = {"content": [], "structuredContent": {"rows": [{"ssn": 1}, {"ssn": 2}]}}
    out, _ = apply(res, [{"redactFields": ["ssn"]}, {"maxRows": 1}])
    assert out["structuredContent"] == {"rows": [{"ssn": "[REDACTED]"}]}
