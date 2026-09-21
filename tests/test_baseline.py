"""Finding identity under edits (Part 5). See DECISIONS.md for the scheme."""

import json
import textwrap

from scanner import baseline
from scanner.cli import main
from scanner.engine import ScanOptions, scan

from .conftest import RULES_PATH

V1 = """
import sqlite3
from flask import request

def get_user():
    uid = request.args.get("id")
    sqlite3.connect("db").execute("SELECT * FROM users WHERE id = " + uid)

def other():
    return 1
"""


def write(root, rel, code):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8", newline="\n")


def new_findings(tmp_path, rules, before: dict, after: dict):
    root = tmp_path / "proj"
    for rel, code in before.items():
        write(root, rel, code)
    first = scan(str(root), rules, ScanOptions())
    counts = baseline.load_text(baseline.dumps(baseline.build(first.findings)))
    for rel in before:
        (root / rel).unlink()
    for rel, code in after.items():
        write(root, rel, code)
    second = scan(str(root), rules, ScanOptions(baseline=counts))
    return first, second


def test_baseline_suppresses_everything_unchanged(tmp_path, repo_rules):
    first, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": V1})
    assert len(first.findings) == 1
    assert second.findings == [] and second.baselined == 1


def test_prepending_twenty_lines(tmp_path, repo_rules):
    shifted = "\n".join(f"# filler line {i}" for i in range(20)) + "\n" + textwrap.dedent(V1).lstrip("\n")
    first, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": shifted})
    assert second.findings == []
    assert second.baselined == 1


def test_renaming_the_enclosing_function(tmp_path, repo_rules):
    _, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": V1.replace("get_user", "fetch_user_by_id")})
    assert second.findings == []


def test_reformatting_whitespace_blank_lines_and_comments(tmp_path, repo_rules):
    reformatted = """
import sqlite3
from flask import request


def get_user():
    # look the user up
    uid = request.args.get( "id" )

    sqlite3.connect( "db" ).execute(
        "SELECT * FROM users WHERE id = "   +   uid   # concatenation
    )


def other():
    return 1
"""
    _, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": reformatted})
    assert second.findings == []


def test_moving_the_function(tmp_path, repo_rules):
    moved = """
import sqlite3
from flask import request

def other():
    return 1

def helper():
    return 2

def get_user():
    uid = request.args.get("id")
    sqlite3.connect("db").execute("SELECT * FROM users WHERE id = " + uid)
"""
    _, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": moved})
    assert second.findings == []


def test_new_vulnerable_line_is_exactly_one_new_finding(tmp_path, repo_rules):
    added = V1 + '\ndef delete():\n    sqlite3.connect("db").execute("DELETE FROM t WHERE id = " + request.args["id"])\n'
    _, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": added})
    assert [(f.rule_id, f.location.line) for f in second.findings] == [("py.sql-injection", 12)]


def test_duplicate_identical_sinks_compared_as_multiset(tmp_path, repo_rules):
    sink = '    sqlite3.connect("db").execute("SELECT * FROM t WHERE id = " + request.args["id"])\n'
    two = "import sqlite3\nfrom flask import request\n\ndef a():\n" + sink + "\ndef b():\n" + sink
    three = two + "\ndef c():\n" + sink
    first, second = new_findings(tmp_path, repo_rules, {"app.py": two}, {"app.py": three})
    assert len(first.findings) == 2
    assert len({f.fingerprint for f in first.findings}) == 1  # identical text -> identical fingerprint
    assert [f.location.line for f in second.findings] == [11]  # the latest occurrence is the new one
    assert second.baselined == 2


def test_duplicate_inserted_above_still_reports_only_one(tmp_path, repo_rules):
    sink = '    sqlite3.connect("db").execute("SELECT * FROM t WHERE id = " + request.args["id"])\n'
    two = "import sqlite3\nfrom flask import request\n\ndef a():\n" + sink + "\ndef b():\n" + sink
    three = "import sqlite3\nfrom flask import request\n\ndef z():\n" + sink + two.split("request\n", 1)[1]
    _, second = new_findings(tmp_path, repo_rules, {"app.py": two}, {"app.py": three})
    assert len(second.findings) == 1


def test_changing_the_query_text_is_a_new_finding(tmp_path, repo_rules):
    changed = V1.replace("SELECT * FROM users WHERE id = ", "SELECT name FROM users WHERE id = ")
    _, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"app.py": changed})
    assert len(second.findings) == 1


def test_renaming_the_file_is_a_known_break(tmp_path, repo_rules):
    # The path is part of the identity, so a moved file looks new (see DECISIONS.md).
    _, second = new_findings(tmp_path, repo_rules, {"app.py": V1}, {"views.py": V1})
    assert len(second.findings) == 1


def test_secret_fingerprint_survives_moves_but_not_value_changes(tmp_path, repo_rules):
    code = 'API_KEY = "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1"\n'
    _, moved = new_findings(tmp_path / "a", repo_rules, {"s.py": code}, {"s.py": "import os\n\n\n" + code})
    assert moved.findings == []
    _, rotated = new_findings(tmp_path / "b", repo_rules, {"s.py": code}, {"s.py": code.replace("Zx81", "Qq81")})
    assert len(rotated.findings) == 1


def test_baseline_file_is_sorted_redacted_and_deterministic(tmp_path, repo_rules):
    write(tmp_path, "b.py", 'API_KEY = "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1"\n')
    write(tmp_path, "a.py", V1)
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    text = baseline.dumps(baseline.build(result.findings))
    assert text.endswith("\n")
    doc = json.loads(text)
    assert doc["version"] == 1
    assert [e["file"] for e in doc["entries"]] == ["a.py", "b.py"]
    assert "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1" not in text
    assert text == baseline.dumps(baseline.build(scan(str(tmp_path), repo_rules, ScanOptions()).findings))


def test_cli_baseline_round_trip(tmp_path, capsysbinary):
    root = tmp_path / "proj"
    write(root, "app.py", V1)
    assert main(["baseline", "--rules", str(RULES_PATH), str(root)]) == 0
    base = tmp_path / ".scanner-baseline.json"
    base.write_bytes(capsysbinary.readouterr().out)
    shifted = "\n\n\n" + textwrap.dedent(V1).lstrip("\n")
    write(root, "app.py", shifted)
    code = main(["scan", "--rules", str(RULES_PATH), "--baseline", str(base), "--fail-on", "low", str(root)])
    out = capsysbinary.readouterr().out.decode("utf-8")
    assert code == 0, out
    assert "1 in baseline" in out
