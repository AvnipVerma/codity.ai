"""Score the scanner against the labelled corpus.

    python bench/evaluate.py                 # markdown report on stdout
    python bench/evaluate.py --json          # machine-readable numbers

Matching: a reported finding is a true positive when its file, rule id and
sink line equal an expected entry in corpus/labels.json. Several findings on
the same (file, rule, line) — one sink reached from two sources — count once.
Anything else reported is a false positive; unmatched expectations are false
negatives. Meta-findings about suppression comments are not scored.

The markdown output is pasted into BENCHMARK.md unmodified; a test checks the
two stay in sync.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
try:
    from scanner.config import load_rules
    from scanner.engine import ScanOptions, scan
except ImportError:  # allow running from a checkout without installing
    sys.path.insert(0, str(REPO / "src"))
    from scanner.config import load_rules
    from scanner.engine import ScanOptions, scan


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


def _f1(p: float | None, r: float | None) -> float | None:
    if p is None or r is None or p + r == 0:
        return None if p is None or r is None else 0.0
    return 2 * p * r / (p + r)


def evaluate(corpus: Path, labels_path: Path, rules_path: Path) -> dict:
    labels = json.loads(labels_path.read_text(encoding="utf-8"))
    rules, _ = load_rules(str(rules_path))
    result = scan(str(corpus), rules, ScanOptions())

    expected = set()
    labelled = set()
    notes = {}
    for entry in labels["files"]:
        labelled.add(entry["file"])
        if "note" in entry:
            notes[entry["file"]] = entry["note"]
        for e in entry["expected"]:
            expected.add((entry["file"], e["rule_id"], e["line"]))
    unlabelled = sorted(set(result.files) - labelled)
    if unlabelled:
        raise SystemExit(f"corpus files missing from labels.json: {unlabelled}")

    reported = {
        (f.location.file, f.rule_id, f.location.line)
        for f in result.findings
        if not f.rule_id.startswith("scanner.")
    }
    tp, fp, fn = reported & expected, reported - expected, expected - reported

    per_rule = {}
    for rule in rules:
        t = sum(1 for x in tp if x[1] == rule.id)
        p = sum(1 for x in fp if x[1] == rule.id)
        n = sum(1 for x in fn if x[1] == rule.id)
        prec, rec = _ratio(t, t + p), _ratio(t, t + n)
        per_rule[rule.id] = {"tp": t, "fp": p, "fn": n, "precision": prec, "recall": rec, "f1": _f1(prec, rec)}

    prec, rec = _ratio(len(tp), len(tp) + len(fp)), _ratio(len(tp), len(tp) + len(fn))
    files = sorted(labelled)
    return {
        "files": len(files),
        "vulnerable_files": sum(1 for f in files if f.startswith("vulnerable/")),
        "safe_files": sum(1 for f in files if f.startswith("safe/")),
        "expected": len(expected),
        "tp": len(tp),
        "fp": len(fp),
        "fn": len(fn),
        "precision": prec,
        "recall": rec,
        "f1": _f1(prec, rec),
        "per_rule": per_rule,
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
        "notes": notes,
        "diagnostics": [d.render() for d in result.diagnostics],
    }


def render_markdown(report: dict) -> str:
    lines = [
        f"Corpus: {report['files']} files ({report['vulnerable_files']} under vulnerable/, "
        f"{report['safe_files']} under safe/), {report['expected']} expected findings.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| True positives | {report['tp']} |",
        f"| False positives | {report['fp']} |",
        f"| False negatives | {report['fn']} |",
        f"| Precision | {_fmt(report['precision'])} |",
        f"| Recall | {_fmt(report['recall'])} |",
        f"| F1 | {_fmt(report['f1'])} |",
        "",
        "| Rule | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---|---|---|---|---|---|",
    ]
    for rule_id, r in report["per_rule"].items():
        lines.append(
            f"| {rule_id} | {r['tp']} | {r['fp']} | {r['fn']} | {_fmt(r['precision'])} | {_fmt(r['recall'])} | {_fmt(r['f1'])} |"
        )
    lines += ["", "False positives:", ""]
    lines += [f"- `{f}:{line}` {rule}" for f, rule, line in report["false_positives"]] or ["- none"]
    lines += ["", "False negatives:", ""]
    lines += [f"- `{f}:{line}` {rule}" for f, rule, line in report["false_negatives"]] or ["- none"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--corpus", default=str(REPO / "corpus"))
    parser.add_argument("--labels", default=str(REPO / "corpus" / "labels.json"))
    parser.add_argument("--rules", default=str(REPO / "rules.yaml"))
    parser.add_argument("--json", action="store_true", help="print JSON instead of markdown")
    args = parser.parse_args(argv)
    report = evaluate(Path(args.corpus), Path(args.labels), Path(args.rules))
    if args.json:
        text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        text = render_markdown(report)
    sys.stdout.buffer.write(text.encode("utf-8"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
