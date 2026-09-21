"""BENCHMARK.md must contain the evaluator's current output, verbatim."""

import importlib.util

from .conftest import REPO


def _evaluator():
    spec = importlib.util.spec_from_file_location("evaluate", REPO / "bench" / "evaluate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_benchmark_numbers_match_evaluator_output():
    ev = _evaluator()
    report = ev.evaluate(REPO / "corpus", REPO / "corpus" / "labels.json", REPO / "rules.yaml")
    assert report["diagnostics"] == []
    expected = ev.render_markdown(report)
    doc = (REPO / "BENCHMARK.md").read_text(encoding="utf-8")
    begin, end = "<!-- evaluate:begin -->\n", "<!-- evaluate:end -->"
    embedded = doc[doc.index(begin) + len(begin): doc.index(end)]
    assert embedded == expected, "BENCHMARK.md is stale: paste the output of `python bench/evaluate.py`"
