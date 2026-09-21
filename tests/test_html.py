from html.parser import HTMLParser

from scanner.cli import main
from scanner.engine import ScanOptions, scan
from scanner.output.html import render_html

from .conftest import RULES_PATH, write_tree

SECRET = "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1"
CODE = f"""
import os
from flask import request

API_KEY = "{SECRET}"

def view():
    banner = "<script>alert(1)</script>"
    os.system("echo " + request.args["msg"])
"""
VOID = {"meta", "input", "br", "link", "img", "hr"}


class _Balance(HTMLParser):
    def __init__(self):
        super().__init__()
        self.stack, self.errors = [], []

    def handle_starttag(self, tag, attrs):
        if tag not in VOID:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(tag)
        else:
            self.stack.pop()


def _report(tmp_path, repo_rules):
    write_tree(tmp_path, {"app.py": CODE})
    return render_html(scan(str(tmp_path), repo_rules, ScanOptions()))


def test_html_report_structure(tmp_path, repo_rules):
    text = _report(tmp_path, repo_rules)
    assert text.startswith("<!doctype html>")
    assert text.count('class="finding sev-') == 2
    assert 'id="show-critical"' in text and 'for="show-critical"' in text
    assert "<details open><summary>Route:" in text
    checker = _Balance()
    checker.feed(text)
    assert checker.errors == [] and checker.stack == []


def test_source_code_is_escaped(tmp_path, repo_rules):
    text = _report(tmp_path, repo_rules)
    assert "<script>alert(1)</script>" not in text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text


def test_secret_lines_are_withheld(tmp_path, repo_rules):
    # the secret sits right above a sink, inside that finding's code context
    code = (
        "import os\nfrom flask import request\n\ndef view():\n"
        f'    token = "{SECRET}"\n'
        '    os.system("echo " + request.args["msg"])\n'
    )
    write_tree(tmp_path, {"app.py": code})
    text = render_html(scan(str(tmp_path), repo_rules, ScanOptions()))
    assert SECRET not in text
    assert "line hidden: contains a hard-coded secret" in text
    assert "hardcoded-secret" in text and "command-injection" in text


def test_html_is_deterministic_and_has_no_timestamps(tmp_path, repo_rules):
    first = _report(tmp_path / "a", repo_rules)
    second = _report(tmp_path / "b", repo_rules)
    assert first == second
    assert str(tmp_path) not in first


def test_cli_html_format(tmp_path, capsysbinary):
    write_tree(tmp_path / "src", {"app.py": CODE})
    out = tmp_path / "report.html"
    assert main(["scan", str(tmp_path / "src"), "--rules", str(RULES_PATH), "--format", "html", "-o", str(out)]) == 0
    assert "command-injection" in out.read_text(encoding="utf-8")


def test_empty_report(tmp_path, repo_rules):
    write_tree(tmp_path, {"ok.py": "x = 1\n"})
    assert "No findings." in render_html(scan(str(tmp_path), repo_rules, ScanOptions()))
