import pytest

from smcp_gateway.identity import LENGTH, is_valid, make_id, parse_id


def test_make_and_parse_round_trip():
    code = make_id("A2", "ACME", year=2026, serial="00AB12CD", instance=7)
    assert len(code) == LENGTH
    ident = parse_id(code)
    assert ident.type == "A2" and ident.kind == "agent" and ident.type_name == "agent.domain"
    assert ident.registrant == "00ACME" and ident.year == "2026" and ident.instance == "00007"


def test_checksum_catches_single_substitutions_and_transpositions():
    code = make_id("U1", "ACME", year=2026, serial="ZZ9PLURA")
    for i in range(LENGTH - 2):  # every body position
        c = code[i]
        swapped = code[:i] + ("1" if c != "1" else "2") + code[i + 1:]
        assert not is_valid(swapped)
    for i in range(LENGTH - 3):
        if code[i] != code[i + 1]:
            t = code[:i] + code[i + 1] + code[i] + code[i + 2:]
            assert not is_valid(t), i


@pytest.mark.parametrize("bad", ["", "short", "a" * 32, "Q1" + "0" * 30])
def test_rejects_malformed(bad):
    assert not is_valid(bad)


def test_rejects_unknown_type_and_wide_fields():
    with pytest.raises(ValueError):
        make_id("X9", "ACME")
    with pytest.raises(ValueError):
        make_id("A1", "TOOLONGREGISTRANT")
