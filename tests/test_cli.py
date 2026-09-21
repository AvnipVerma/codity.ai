import json

import pytest

from scanner.cli import main

from .conftest import RULES_PATH, write_tree


def test_empty_directory_exits_zero(tmp_path, capsysbinary):
    assert main(["scan", str(tmp_path), "--rules", str(RULES_PATH)]) == 0
    out = capsysbinary.readouterr().out.decode("utf-8")
    assert "No findings" in out


def test_missing_target_exits_two(tmp_path):
    assert main(["scan", str(tmp_path / "missing"), "--rules", str(RULES_PATH)]) == 2


def test_invalid_rules_exit_two(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - id: x\n    kind: taint\n", encoding="utf-8")
    assert main(["scan", str(tmp_path), "--rules", str(bad)]) == 2
    assert "rule 'x'" in capsys.readouterr().err


def test_usage_error_exits_two(capsys):
    with pytest.raises(SystemExit) as info:
        main(["scan"])
    assert info.value.code == 2


def test_sarif_output_is_json(tmp_path, capsysbinary):
    write_tree(tmp_path, {"a.py": "x = 1\n"})
    assert main(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--format", "sarif"]) == 0
    doc = json.loads(capsysbinary.readouterr().out)
    assert doc["version"] == "2.1.0"
