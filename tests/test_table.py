import os
from pathlib import Path

from scanner.engine import ScanOptions, scan
from scanner.output.table import ASCII, render_table

from .conftest import write_tree

SNAPSHOT = Path(__file__).parent / "snapshots" / "table.txt"

PROJECT = {
    "views.py": """
        import sqlite3
        from flask import request

        AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


        def show():
            user_id = request.args.get("id")
            query = f"SELECT * FROM users WHERE id = {user_id}"
            sqlite3.connect("db").execute(query)
        """
}


def _result(tmp_path, repo_rules):
    write_tree(tmp_path, PROJECT)
    return scan(str(tmp_path), repo_rules, ScanOptions())


def test_table_snapshot_without_colour(tmp_path, repo_rules):
    text = render_table(_result(tmp_path, repo_rules), width=100)
    if os.environ.get("UPDATE_SNAPSHOTS"):
        SNAPSHOT.parent.mkdir(exist_ok=True)
        SNAPSHOT.write_text(text, encoding="utf-8", newline="\n")
    assert text == SNAPSHOT.read_text(encoding="utf-8")


def test_no_ansi_codes_without_colour(tmp_path, repo_rules):
    assert "\x1b[" not in render_table(_result(tmp_path, repo_rules), colour=False)


def test_colour_codes_by_severity(tmp_path, repo_rules):
    text = render_table(_result(tmp_path, repo_rules), colour=True)
    assert "\x1b[1;91mCRITICAL" in text
    assert "\x1b[31mHIGH" in text


def test_lines_fit_the_width(tmp_path, repo_rules):
    result = _result(tmp_path, repo_rules)
    for width in (60, 80, 120):
        for line in render_table(result, width=width).splitlines()[:-1]:  # summary line excluded
            assert len(line) <= width, (width, line)


def test_paths_can_be_hidden(tmp_path, repo_rules):
    text = render_table(_result(tmp_path, repo_rules), show_paths=False)
    assert "source" not in text and "CRITICAL" in text


def test_ascii_fallback(tmp_path, repo_rules):
    text = render_table(_result(tmp_path, repo_rules), glyphs=ASCII)
    assert "─" not in text and "├" not in text and "|-" in text


def test_secret_value_is_redacted_in_table(tmp_path, repo_rules):
    text = render_table(_result(tmp_path, repo_rules), width=200)
    assert "wJalrXUtnFEMI" not in text
    assert 'AWS_SECRET_KEY = "wJal…(40 chars)"' in text


def test_no_findings_message(tmp_path, repo_rules):
    write_tree(tmp_path, {"ok.py": "x = 1\n"})
    text = render_table(scan(str(tmp_path), repo_rules, ScanOptions()))
    assert text.startswith(" ✓ No findings")
    assert "0 findings" in text


def test_sorted_by_severity_then_location(tmp_path, repo_rules):
    lines = [l for l in render_table(_result(tmp_path, repo_rules)).splitlines() if l[1:9] in ("CRITICAL", "HIGH    ")]
    assert [l.split()[0] for l in lines] == ["CRITICAL", "HIGH"]


def test_long_source_text_is_truncated_not_split_at_a_dot(run_scan):
    code = "import os\nfrom flask import request\nos.system(request.args.get('host', '127.0.0.1.example.internal'))\n"
    [f] = run_scan(code).findings
    assert f.summary.startswith("request.args.get(")
