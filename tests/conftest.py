from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from scanner.config import load_rules, parse_rules
from scanner.engine import ScanOptions, scan

REPO = Path(__file__).resolve().parents[1]
RULES_PATH = REPO / "rules.yaml"


def write_tree(root: Path, files: dict[str, str]) -> Path:
    for rel, code in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(code).lstrip("\n"), encoding="utf-8", newline="\n")
    return root


@pytest.fixture(scope="session")
def repo_rules():
    rules, _ = load_rules(str(RULES_PATH))
    return rules


def rules_from_yaml(text: str):
    import yaml

    rules, _ = parse_rules(yaml.safe_load(textwrap.dedent(text)))
    return rules


@pytest.fixture
def run_scan(tmp_path, repo_rules):
    """Write files under tmp_path/proj and scan them with the repo's rules."""

    counter = {"n": 0}

    def _run(files, rules=None, **options):
        if isinstance(files, str):
            files = {"app.py": files}
        counter["n"] += 1
        root = tmp_path / f"proj{counter['n']}"
        write_tree(root, files)
        return scan(str(root), rules if rules is not None else repo_rules, ScanOptions(**options))

    return _run


def hits(result, rule_id: str | None = None) -> list[tuple[str, str, int]]:
    """(rule_id, file, line) of every reported finding, optionally filtered."""
    return [
        (f.rule_id, f.location.file, f.location.line)
        for f in result.findings
        if rule_id is None or f.rule_id == rule_id
    ]


def marked_lines(code: str, marker: str = "# SINK") -> list[int]:
    lines = textwrap.dedent(code).lstrip("\n").splitlines()
    return [i + 1 for i, line in enumerate(lines) if marker in line]


@pytest.fixture
def check(run_scan):
    """Scan one snippet; assert findings of ``rule`` are exactly the ``# SINK`` lines."""

    def _check(code: str, rule: str = "py.sql-injection", files: dict | None = None, target: str = "app.py"):
        tree = dict(files or {})
        tree[target] = code
        result = run_scan(tree)
        assert result.diagnostics == [], [d.render() for d in result.diagnostics]
        got = sorted(f.location.line for f in result.findings if f.rule_id == rule and f.location.file == target)
        assert got == marked_lines(code), f"expected {marked_lines(code)}, got {got}"
        return result

    return _check
