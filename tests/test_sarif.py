import json
from collections import Counter
from pathlib import Path

import jsonschema
import pytest

from scanner.engine import ScanOptions, scan
from scanner.output.sarif import render_sarif

from .conftest import REPO, write_tree

SCHEMA = json.loads((REPO / "schemas" / "sarif-2.1.0.json").read_text(encoding="utf-8"))

PROJECT = {
    "app/__init__.py": "",
    "app/views.py": """
        import sqlite3, subprocess, pickle
        from flask import Flask, request
        from .db import run_query

        app = Flask(__name__)
        API_TOKEN = "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1"

        @app.route("/u")
        def user():
            uid = request.args.get("id")
            query = f"SELECT * FROM users WHERE id = {uid}"
            sqlite3.connect("x").execute(query)
            run_query(request.form["name"])
            subprocess.run("ls " + request.args["d"], shell=True)  # codity: ignore[py.command-injection] admin only
            pickle.loads(request.data)  # codity: ignore[py.insecure-deserialization]
        """,
    "app/db.py": """
        import sqlite3

        def run_query(name):
            sqlite3.connect("x").execute("SELECT * FROM t WHERE n = '%s'" % name)
        """,
    "broken.py": "def (:\n",
}


def validate(doc):
    jsonschema.Draft4Validator(SCHEMA).validate(doc)


@pytest.fixture
def project_result(tmp_path, repo_rules):
    write_tree(tmp_path, PROJECT)
    return tmp_path, scan(str(tmp_path), repo_rules, ScanOptions())


def test_sarif_validates_against_official_schema(project_result):
    _, result = project_result
    doc = json.loads(render_sarif(result))
    validate(doc)
    kinds = Counter(r["ruleId"] for r in doc["runs"][0]["results"])
    assert kinds["py.sql-injection"] == 2
    assert kinds["py.hardcoded-secret"] == 1
    assert kinds["scanner.suppression-missing-reason"] == 1


def test_empty_scan_validates(tmp_path, repo_rules):
    doc = json.loads(render_sarif(scan(str(tmp_path), repo_rules, ScanOptions())))
    validate(doc)
    assert doc["runs"][0]["results"] == []


def test_results_carry_required_fields_and_code_flows(project_result):
    _, result = project_result
    doc = json.loads(render_sarif(result))
    run = doc["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for res in run["results"]:
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert res["level"] in ("error", "warning", "note")
        assert res["message"]["text"]
        loc = res["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uriBaseId"] == "SRCROOT"
        assert {"startLine", "startColumn", "endLine", "endColumn"} <= set(loc["region"])
        assert len(res["partialFingerprints"]["codityFinding/v1"]) == 64
    sqli = [r for r in run["results"] if r["ruleId"] == "py.sql-injection"]
    for res in sqli:
        steps = res["codeFlows"][0]["threadFlows"][0]["locations"]
        assert steps[0]["kinds"] == ["source"]
        assert steps[-1]["kinds"] == ["sink"]
        assert steps[-1]["location"]["physicalLocation"] == res["locations"][0]["physicalLocation"]
    cross = next(r for r in sqli if r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/db.py")
    files = [s["location"]["physicalLocation"]["artifactLocation"]["uri"] for s in cross["codeFlows"][0]["threadFlows"][0]["locations"]]
    assert files[0] == "app/views.py" and files[-1] == "app/db.py"


def test_rule_metadata_includes_cwe(project_result):
    _, result = project_result
    rules = {r["id"]: r for r in json.loads(render_sarif(result))["runs"][0]["tool"]["driver"]["rules"]}
    sqli = rules["py.sql-injection"]
    assert sqli["properties"]["cwe"] == "CWE-89"
    assert "CWE-89" in sqli["properties"]["tags"]
    assert sqli["properties"]["security-severity"] == "9.5"
    assert sqli["defaultConfiguration"]["level"] == "error"
    assert rules["py.hardcoded-secret"]["properties"]["security-severity"] == "8.0"


def test_suppressed_results_are_marked_not_dropped(project_result):
    _, result = project_result
    doc = json.loads(render_sarif(result))
    cmd = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "py.command-injection")
    assert cmd["suppressions"] == [{"justification": "admin only", "kind": "inSource", "status": "accepted"}]


def test_no_absolute_paths_or_timestamps(project_result):
    root, result = project_result
    text = render_sarif(result)
    assert str(root) not in text and str(root).replace("\\", "/") not in text
    assert "Time" not in text  # no startTimeUtc / endTimeUtc


def test_parse_failures_become_notifications(project_result):
    _, result = project_result
    inv = json.loads(render_sarif(result))["runs"][0]["invocations"][0]
    assert inv["executionSuccessful"] is True
    notes = inv["toolExecutionNotifications"]
    assert any("broken.py" == n["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for n in notes)


def test_columns_are_one_based(run_scan):
    result = run_scan("import os\nfrom flask import request\ndef f():\n    os.system(request.args['c'])\n")
    region = json.loads(render_sarif(result))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    # `os.system(...)` starts at 0-based column 4 in the source
    assert region["startLine"] == 4 and region["startColumn"] == 5


def test_columns_count_code_points_not_bytes(run_scan):
    code = "import os\nfrom flask import request\ndef f():\n    x = 'é'; os.system(request.args['c'])\n"
    result = run_scan(code)
    region = json.loads(render_sarif(result))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    line = code.splitlines()[3]
    assert region["startColumn"] == line.index("os.system") + 1


def test_uri_is_percent_encoded(run_scan):
    result = run_scan({"my dir/app file.py": "import os\nfrom flask import request\nos.system(request.args['c'])\n"})
    uri = json.loads(render_sarif(result))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "my%20dir/app%20file.py"


def test_baseline_state_marked_new(tmp_path, repo_rules):
    write_tree(tmp_path, {"a.py": "import os\nfrom flask import request\nos.system(request.args['c'])\n"})
    result = scan(str(tmp_path), repo_rules, ScanOptions(baseline=Counter()))
    doc = json.loads(render_sarif(result))
    validate(doc)
    assert doc["runs"][0]["results"][0]["baselineState"] == "new"
