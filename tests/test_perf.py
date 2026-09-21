"""Performance: a generated 500-file project scans in under 60 seconds.

Opt-in because it takes a while: ``pytest -m slow``.
"""

import importlib.util
import time

import pytest

from scanner.engine import ScanOptions, scan

from .conftest import REPO

pytestmark = pytest.mark.slow


def _generator():
    spec = importlib.util.spec_from_file_location("gen_large_repo", REPO / "bench" / "gen_large_repo.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_500_files_under_60_seconds(tmp_path, repo_rules):
    counts = _generator().generate(tmp_path / "large", files=500, seed=1234)
    assert counts["files"] == 500
    started = time.perf_counter()
    result = scan(str(tmp_path / "large"), repo_rules, ScanOptions())
    elapsed = time.perf_counter() - started
    print(f"\n500 files / {counts['lines']} lines scanned in {elapsed:.2f}s, {len(result.findings)} findings")
    assert len(result.files) == 500
    assert result.diagnostics == []
    assert result.findings
    assert elapsed < 60
