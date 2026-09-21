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


VULN = "import os\nfrom flask import request\nos.system(request.args['c'])\n"
SECRET = 'API_KEY = "Zx81kQp0Lm2Vb7Nc4Rt6Yh9Wd3Fs5Gj1"\n'


def run(args, capsysbinary):
    code = main(args)
    captured = capsysbinary.readouterr()
    return code, captured.out.decode("utf-8"), captured.err.decode("utf-8")


@pytest.mark.parametrize(
    "files, fail_on, expected",
    [
        ({"a.py": VULN}, "critical", 1),
        ({"a.py": VULN}, "low", 1),
        ({"a.py": SECRET}, "critical", 0),  # high finding, critical threshold
        ({"a.py": SECRET}, "high", 1),
        ({"a.py": SECRET}, "medium", 1),
        ({"a.py": "x = 1\n"}, "low", 0),
        ({"a.py": VULN.replace("])\n", "])  # codity: ignore[py.command-injection] ok\n")}, "low", 0),
    ],
)
def test_fail_on_exit_codes(tmp_path, capsysbinary, files, fail_on, expected):
    write_tree(tmp_path, files)
    code, _, _ = run(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--fail-on", fail_on], capsysbinary)
    assert code == expected


def test_no_fail_on_means_exit_zero_even_with_findings(tmp_path, capsysbinary):
    write_tree(tmp_path, {"a.py": VULN})
    code, out, _ = run(["scan", str(tmp_path), "--rules", str(RULES_PATH)], capsysbinary)
    assert code == 0 and "py.command-injection" in out


def test_missing_reason_meta_finding_counts_for_fail_on_low(tmp_path, capsysbinary):
    write_tree(tmp_path, {"a.py": VULN.replace("])\n", "])  # codity: ignore[py.command-injection]\n")})
    code, out, _ = run(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--fail-on", "low"], capsysbinary)
    assert code == 1 and "scanner.suppression-missing-reason" in out
    code, _, _ = run(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--fail-on", "medium"], capsysbinary)
    assert code == 0


def test_output_file_and_timing_on_stderr(tmp_path, capsysbinary):
    write_tree(tmp_path / "src", {"a.py": VULN})
    out_file = tmp_path / "r.sarif"
    code, out, err = run(["scan", str(tmp_path / "src"), "--rules", str(RULES_PATH), "--format", "sarif", "-o", str(out_file)], capsysbinary)
    assert code == 0 and out == ""
    assert json.loads(out_file.read_text(encoding="utf-8"))["runs"][0]["results"]
    assert "Scanned 1 files" in err
    assert b"\r\n" not in out_file.read_bytes()


def test_quiet_suppresses_stderr(tmp_path, capsysbinary):
    write_tree(tmp_path, {"a.py": VULN, "bad.py": "def (:\n"})
    _, _, err = run(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--quiet"], capsysbinary)
    assert err == ""
    _, _, err = run(["scan", str(tmp_path), "--rules", str(RULES_PATH)], capsysbinary)
    assert "warning: bad.py" in err


def test_exclude_and_no_paths(tmp_path, capsysbinary):
    write_tree(tmp_path, {"a.py": VULN, "tests/test_a.py": VULN})
    _, out, _ = run(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--exclude", "tests", "--no-paths"], capsysbinary)
    assert "tests/test_a.py" not in out and "a.py:3" in out
    assert "source" not in out


def test_table_output_is_plain_when_not_a_tty(tmp_path, capsysbinary):
    write_tree(tmp_path, {"a.py": VULN})
    _, out, _ = run(["scan", str(tmp_path), "--rules", str(RULES_PATH)], capsysbinary)
    assert "\x1b[" not in out


def test_bad_baseline_exits_two(tmp_path, capsysbinary):
    bad = tmp_path / "b.json"
    bad.write_text("{not json", encoding="utf-8")
    code, _, err = run(["scan", str(tmp_path), "--rules", str(RULES_PATH), "--baseline", str(bad)], capsysbinary)
    assert code == 2 and "baseline" in err


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as info:
        main(["--version"])
    assert info.value.code == 0
    assert "scanner 0.1.0" in capsys.readouterr().out
