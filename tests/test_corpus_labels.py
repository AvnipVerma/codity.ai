"""The labelled corpus stays consistent with its labels file."""

import json

from scanner.config import load_rules

from .conftest import REPO, RULES_PATH

CORPUS = REPO / "corpus"
LABELS = json.loads((CORPUS / "labels.json").read_text(encoding="utf-8"))


def test_every_corpus_file_is_labelled_exactly_once():
    on_disk = sorted(p.relative_to(CORPUS).as_posix() for p in CORPUS.rglob("*.py"))
    labelled = [entry["file"] for entry in LABELS["files"]]
    assert sorted(labelled) == on_disk
    assert len(labelled) == len(set(labelled))


def test_corpus_size_and_balance():
    files = [e["file"] for e in LABELS["files"]]
    assert len(files) >= 40
    vulnerable = [f for f in files if f.startswith("vulnerable/")]
    safe = [f for f in files if f.startswith("safe/")]
    assert len(vulnerable) >= 20 and len(safe) >= 20


def test_safe_files_expect_nothing():
    for entry in LABELS["files"]:
        if entry["file"].startswith("safe/"):
            assert entry["expected"] == [], entry["file"]


def test_labels_point_at_the_named_code():
    rules = {r.id for r in load_rules(str(RULES_PATH))[0]}
    for entry in LABELS["files"]:
        lines = (CORPUS / entry["file"]).read_text(encoding="utf-8").splitlines()
        for e in entry["expected"]:
            assert e["rule_id"] in rules
            assert 1 <= e["line"] <= len(lines), entry["file"]
            assert e["snippet"] in lines[e["line"] - 1], (entry["file"], e["line"], lines[e["line"] - 1])


def test_every_rule_has_three_vulnerable_and_three_safe_files():
    rules = [r.id for r in load_rules(str(RULES_PATH))[0]]
    prefixes = {
        "py.sql-injection": "sqli_",
        "py.command-injection": "cmd_",
        "py.path-traversal": "path_",
        "py.ssrf": "ssrf_",
        "py.xss-template": "xss_",
        "py.insecure-deserialization": "deser_",
        "py.hardcoded-secret": "secret_",
    }
    assert set(prefixes) == set(rules)
    for rule_id, prefix in prefixes.items():
        vulnerable = {e["file"] for e in LABELS["files"] if any(x["rule_id"] == rule_id for x in e["expected"])}
        safe = [e["file"] for e in LABELS["files"] if e["file"].startswith("safe/" + prefix)]
        assert len(vulnerable) >= 3, rule_id
        assert len(safe) >= 3, rule_id
