import pytest
import yaml

from scanner.config import RuleError, load_rules, parse_rules

VALID = """
rules:
  - id: t.sqli
    severity: critical
    cwe: CWE-89
    message: m
    kind: taint
    sources: [{pattern: flask.request.args.get}]
    sinks: [{pattern: "*.execute", arg: 0}]
"""


def parse(text):
    return parse_rules(yaml.safe_load(text))


def test_valid_rules_load():
    rules, warnings = parse(VALID)
    assert [r.id for r in rules] == ["t.sqli"]
    assert warnings == []


def test_repo_rules_file_loads():
    rules, warnings = load_rules("rules.yaml")
    assert warnings == []
    assert {r.kind for r in rules} == {"taint", "pattern"}


@pytest.mark.parametrize(
    "mutation, expected",
    [
        (lambda r: r.pop("severity"), "field 'severity': is required"),
        (lambda r: r.update(severity="urgent"), "field 'severity': must be one of"),
        (lambda r: r.update(cwe="89"), "field 'cwe': must look like 'CWE-<digits>'"),
        (lambda r: r.update(kind="magic"), "field 'kind': unknown kind 'magic'"),
        (lambda r: r.update(sources=[]), "field 'sources': must be a non-empty list"),
        (lambda r: r.update(sinks=[]), "field 'sinks': must be a non-empty list"),
        (lambda r: r["sinks"][0].update(arg=-1), "field 'sinks[0].arg': must be a non-negative integer or 'any'"),
        (lambda r: r["sinks"][0].update(arg="first"), "must be a non-negative integer or 'any'"),
        (lambda r: r["sinks"][0].update(pattern="a..b"), "empty segment"),
        (lambda r: r["sinks"][0].update(pattern="a.**"), "'**'"),
        (lambda r: r["sinks"][0].update(pattern=".a"), "leading or trailing dot"),
        (lambda r: r["sinks"][0].update(pattern="a."), "leading or trailing dot"),
        (lambda r: r["sinks"][0].update(pattern="os.exec*"), "'*' must be a whole segment"),
        (lambda r: r.pop("message"), "field 'message': is required"),
    ],
)
def test_invalid_rules_name_rule_and_field(mutation, expected):
    doc = yaml.safe_load(VALID)
    mutation(doc["rules"][0])
    with pytest.raises(RuleError) as info:
        parse_rules(doc)
    text = str(info.value)
    assert "t.sqli" in text
    assert expected in text


def test_duplicate_ids_rejected():
    doc = yaml.safe_load(VALID)
    doc["rules"].append(dict(doc["rules"][0]))
    with pytest.raises(RuleError, match="duplicate rule id 't.sqli'"):
        parse_rules(doc)


def test_unknown_top_level_rule_key_warns_but_loads():
    doc = yaml.safe_load(VALID)
    doc["rules"][0]["future_option"] = True
    rules, warnings = parse_rules(doc)
    assert rules and any("future_option" in w for w in warnings)


def test_all_errors_reported_together():
    doc = yaml.safe_load(VALID)
    doc["rules"][0]["severity"] = "nope"
    doc["rules"][0]["cwe"] = "x"
    with pytest.raises(RuleError) as info:
        parse_rules(doc)
    assert "severity" in str(info.value) and "cwe" in str(info.value)


def test_pattern_kind_validation():
    doc = yaml.safe_load(
        """
rules:
  - id: t.secret
    severity: high
    cwe: CWE-798
    message: m
    kind: pattern
    match: {assigned_to: [], value: literal_int, min_entropy: -1}
"""
    )
    with pytest.raises(RuleError) as info:
        parse_rules(doc)
    text = str(info.value)
    assert "match.assigned_to" in text and "match.value" in text and "match.min_entropy" in text


def test_when_condition_validation():
    doc = yaml.safe_load(VALID)
    doc["rules"][0]["sinks"][0]["when"] = {"kwarg": "shell"}
    with pytest.raises(RuleError, match="exactly one of is_true, in, not_in"):
        parse_rules(doc)


def test_missing_file_is_rule_error(tmp_path):
    with pytest.raises(RuleError, match="not found"):
        load_rules(str(tmp_path / "nope.yaml"))


def test_bad_yaml_is_rule_error(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text("rules: [\n", encoding="utf-8")
    with pytest.raises(RuleError, match="invalid YAML"):
        load_rules(str(p))
