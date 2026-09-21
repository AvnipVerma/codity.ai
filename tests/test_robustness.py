import os
import time

import pytest

from scanner.engine import ScanOptions, scan
from scanner.kinds import RuleKind, register_kind, unregister_kind

from .conftest import rules_from_yaml, write_tree

VULN = "import os\nfrom flask import request\nos.system(request.args['c'])\n"


def test_syntax_error_is_skipped_with_warning(tmp_path, repo_rules):
    write_tree(tmp_path, {"bad.py": "def broken(:\n    pass\n", "good.py": VULN})
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert [f.location.file for f in result.findings] == ["good.py"]
    assert [d.file for d in result.diagnostics] == ["bad.py"]
    assert "syntax error" in result.diagnostics[0].message


def test_python2_file_is_skipped(tmp_path, repo_rules):
    write_tree(tmp_path, {"py2.py": 'print "hello"\nexec "code"\n', "good.py": VULN})
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert len(result.findings) == 1 and result.diagnostics[0].file == "py2.py"


def test_encoding_cookie_is_honoured(tmp_path, repo_rules):
    code = "# -*- coding: latin-1 -*-\nimport os\nfrom flask import request\nx = 'café'\nos.system(request.args['c'])\n"
    (tmp_path / "latin.py").write_bytes(code.encode("latin-1"))
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert result.diagnostics == []
    assert [f.location.line for f in result.findings] == [5]


def test_undecodable_file_is_skipped(tmp_path, repo_rules):
    (tmp_path / "binary.py").write_bytes(b"x = '\xff\xfe\xfa'\n")
    write_tree(tmp_path, {"good.py": VULN})
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert len(result.findings) == 1
    assert [d.file for d in result.diagnostics] == ["binary.py"]


def test_bom_file(tmp_path, repo_rules):
    (tmp_path / "bom.py").write_bytes(b"\xef\xbb\xbf" + VULN.encode())
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert result.diagnostics == [] and len(result.findings) == 1


def test_empty_comment_only_and_init_files(tmp_path, repo_rules):
    write_tree(tmp_path, {"empty.py": "", "comments.py": "# nothing here\n# at all\n", "pkg/__init__.py": ""})
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert result.findings == [] and result.diagnostics == []
    assert result.files == ["comments.py", "empty.py", "pkg/__init__.py"]


def test_deeply_nested_expressions_never_crash(tmp_path, repo_rules):
    long_chain = "def f(a):\n    return " + " + ".join(["a"] * 900) + "\n"
    huge_chain = "x = " + "+".join(["a"] * 20000) + "\n"
    write_tree(tmp_path, {"long.py": long_chain, "huge.py": huge_chain, "good.py": VULN})
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert [f.location.file for f in result.findings] == ["good.py"]
    for d in result.diagnostics:
        assert d.file in ("long.py", "huge.py")


def test_crashing_rule_kind_is_reported_and_scan_continues(tmp_path, repo_rules):
    class Boom(RuleKind):
        name = "boom"

        def validate(self, rule):
            return []

        def analyze(self, module, rules):
            raise RuntimeError("kaboom")

    register_kind(Boom())
    try:
        rules = list(repo_rules) + rules_from_yaml(
            "rules:\n  - {id: t.boom, severity: low, cwe: CWE-1, message: m, kind: boom}\n"
        )
        write_tree(tmp_path, {"good.py": VULN})
        result = scan(str(tmp_path), rules, ScanOptions())
    finally:
        unregister_kind("boom")
    assert len(result.findings) == 1
    assert any("kaboom" in d.message for d in result.diagnostics)


def test_symlink_outside_root_is_not_followed(tmp_path, repo_rules):
    outside = tmp_path / "outside"
    root = tmp_path / "root"
    write_tree(outside, {"evil.py": VULN})
    write_tree(root, {"ok.py": "x = 1\n"})
    try:
        os.symlink(outside / "evil.py", root / "link.py")
        os.symlink(outside, root / "linkdir", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not available on this system")
    result = scan(str(root), repo_rules, ScanOptions())
    assert result.files == ["ok.py"]


def test_type_annotations_and_typing_do_not_cause_taint(run_scan):
    code = (
        "from typing import Dict, List, Optional\nimport sqlite3\nfrom flask import request\n"
        "def f(q: Optional[str] = None) -> List[Dict[str, int]]:\n"
        "    rows: List[Dict[str, int]] = []\n"
        "    sqlite3.connect('x').execute('SELECT 1')\n"
        "    return rows\n"
    )
    result = run_scan(code)
    assert result.findings == [] and result.diagnostics == []


def test_python_syntax_warnings_are_not_printed(tmp_path, repo_rules, capfd):
    write_tree(tmp_path, {"w.py": "import re\nPATTERN = '\\d+\\s'\n"})  # invalid escapes in the scanned file
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert result.diagnostics == []
    assert "SyntaxWarning" not in capfd.readouterr().err


def test_growing_alias_chain_in_nested_loops_converges(tmp_path, repo_rules):
    # h = h.set(...) would otherwise invent a longer name (X.set.set...) every pass
    code = (
        "from lib import hamt\n\ndef stress(n):\n    h = hamt()\n"
        "    for a in range(n):\n        for b in range(n):\n            for c in range(n):\n"
        "                h = h.set(a, b).set(b, c)\n                h = h.delete(c)\n    return h\n"
    )
    write_tree(tmp_path, {"stress.py": code})
    started = time.perf_counter()
    result = scan(str(tmp_path), repo_rules, ScanOptions())
    assert result.diagnostics == []
    assert time.perf_counter() - started < 5


def test_large_class_hierarchy_stays_fast(tmp_path, repo_rules):
    classes = "\n".join(
        f"class Case{i}(Base):\n    def setUp(self):\n        self.value{i} = {i}\n"
        f"    def test(self):\n        return self.value{i} + self.shared\n"
        for i in range(300)
    )
    code = "class Base:\n    def __init__(self):\n        self.shared = 1\n\n" + classes
    write_tree(tmp_path, {"cases.py": code})
    started = time.perf_counter()
    scan(str(tmp_path), repo_rules, ScanOptions())
    assert time.perf_counter() - started < 10
