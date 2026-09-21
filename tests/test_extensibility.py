"""Proof that a third rule kind needs no engine changes.

The ``call`` kind below is defined entirely in this test file: it flags every
call whose resolved name matches one of the rule's patterns (``eval``, say).
It is registered through the public registry, loaded from YAML like any other
rule, and run by the unmodified engine.
"""

import ast
from pathlib import Path

import pytest

from scanner.engine import ScanOptions, scan
from scanner.kinds import REGISTRY, RuleKind, register_kind, unregister_kind
from scanner.model import Finding
from scanner.patterns import PatternError, PatternIndex, compile_pattern
from scanner.resolve import candidate_names

from .conftest import rules_from_yaml, write_tree

ENGINE_SOURCE = Path(__file__).resolve().parents[1] / "src" / "scanner" / "engine.py"


class CallKind(RuleKind):
    name = "call"
    fields = frozenset({"calls"})

    def validate(self, rule):
        calls = rule.get("calls")
        if not isinstance(calls, list) or not calls:
            return [("calls", "must be a non-empty list of patterns")]
        issues = []
        for i, pat in enumerate(calls):
            try:
                compile_pattern(pat)
            except PatternError as exc:
                issues.append((f"calls[{i}]", str(exc)))
        return issues

    def compile(self, rule):
        index = PatternIndex()
        for pat in rule.raw["calls"]:
            index.add(pat, rule.id)
        return index

    def analyze(self, module, rules):
        res = module.resolver
        out = []
        for node in ast.walk(module.tree):
            if not isinstance(node, ast.Call):
                continue
            names = candidate_names(res.refs_for(node.func, res.module_lookup))
            for rule in rules:
                if rule.compiled.match(names):
                    out.append(
                        Finding(
                            rule_id=rule.id,
                            severity=rule.severity,
                            cwe=rule.cwe,
                            message=rule.message,
                            location=module.location(node),
                            identity=(module.unparse(node),),
                        )
                    )
        return out


@pytest.fixture
def call_kind():
    kind = register_kind(CallKind())
    yield kind
    unregister_kind("call")


def test_third_kind_runs_through_unmodified_engine(tmp_path, call_kind):
    rules = rules_from_yaml(
        """
        rules:
          - id: test.no-eval
            severity: medium
            cwe: CWE-95
            message: "eval() is banned"
            kind: call
            calls: ["eval", "os.system"]
        """
    )
    write_tree(tmp_path, {"m.py": "import os\nx = eval(input())\nos.system('ls')\nprint(1)\n"})
    result = scan(str(tmp_path), rules, ScanOptions())
    assert [(f.rule_id, f.location.line) for f in result.findings] == [
        ("test.no-eval", 2),
        ("test.no-eval", 3),
    ]


def test_third_kind_coexists_with_builtin_kinds(tmp_path, call_kind, repo_rules):
    extra = rules_from_yaml(
        """
        rules:
          - id: test.no-eval
            severity: low
            cwe: CWE-95
            message: "eval() is banned"
            kind: call
            calls: ["eval"]
        """
    )
    write_tree(tmp_path, {"m.py": "api_key = 'Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1'\neval('1')\n"})
    result = scan(str(tmp_path), list(repo_rules) + extra, ScanOptions())
    ids = sorted(f.rule_id for f in result.findings)
    assert "test.no-eval" in ids and "py.hardcoded-secret" in ids


def test_unregistered_kind_is_rejected_at_load_time():
    from scanner.config import RuleError

    assert "call" not in REGISTRY
    with pytest.raises(RuleError, match="unknown kind 'call'"):
        rules_from_yaml(
            """
            rules:
              - {id: t, severity: low, cwe: CWE-1, message: m, kind: call, calls: [eval]}
            """
        )


def test_engine_has_no_kind_specific_code():
    text = ENGINE_SOURCE.read_text(encoding="utf-8").lower()
    assert "taint" not in text
    assert "pattern" not in text
    assert "kind ==" not in text and "kind==" not in text
