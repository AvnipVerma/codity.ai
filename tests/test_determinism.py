"""Same input, same bytes: across processes with different hash seeds."""

import os
import subprocess
import sys

from .conftest import REPO, RULES_PATH


def _run(args, seed):
    env = dict(os.environ, PYTHONHASHSEED=str(seed))
    proc = subprocess.run(
        [sys.executable, "-m", "scanner.cli", *args],
        cwd=REPO,
        env=env,
        capture_output=True,
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc.stdout


def test_sarif_is_byte_identical_across_hash_seeds():
    args = ["scan", "corpus", "--rules", str(RULES_PATH), "--format", "sarif", "--quiet"]
    outputs = {_run(args, seed) for seed in (0, 1, 4242)}
    assert len(outputs) == 1
    out = outputs.pop()
    assert out.endswith(b"\n") and b"\r\n" not in out
    assert b'"results": [' in out


def test_table_and_baseline_are_byte_identical_across_hash_seeds():
    table = {_run(["scan", "corpus", "--rules", str(RULES_PATH), "--quiet"], seed) for seed in (0, 99)}
    assert len(table) == 1
    base = {_run(["baseline", "corpus", "--rules", str(RULES_PATH), "--quiet"], seed) for seed in (0, 99)}
    assert len(base) == 1
