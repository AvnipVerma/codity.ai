"""Baselines: remember today's findings so later scans report only new ones.

Finding identity
----------------
``fingerprint = sha256("codity/v1" | rule_id | file | *identity)`` where
``identity`` is supplied by the rule kind and contains no positions:

* taint findings: ``ast.unparse`` of the sink call and of the source
  expression. ``ast.unparse`` output does not depend on whitespace, comments or
  line numbers, and the enclosing function's name is never included, so
  adding lines, reformatting, moving or renaming the function all keep the
  fingerprint.
* secret findings: the variable name plus the sha256 of the literal (never the
  secret itself).

Identical fingerprints (the same sink text twice in a file) are compared as a
multiset: the baseline stores a count, and if a scan finds more than that
count, the surplus findings with the *latest* positions are reported as new.
We deliberately avoid an occurrence index: inserting one identical finding
above the others would shift every index and make all of them look new.

``hashlib.sha256`` is used everywhere; Python's ``hash()`` is randomised per
process and would break determinism.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter

from . import TOOL_NAME, __version__
from .model import Finding

BASELINE_VERSION = 1
FINGERPRINT_VERSION = "codity/v1"
SEP = "\x1f"


class BaselineError(Exception):
    pass


def fingerprint(finding: Finding) -> str:
    parts = (FINGERPRINT_VERSION, finding.rule_id, finding.location.file, *finding.identity)
    return hashlib.sha256(SEP.join(parts).encode("utf-8")).hexdigest()


def build(findings: list[Finding]) -> dict:
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if not f.suppressed:
            groups.setdefault(f.fingerprint, []).append(f)
    entries = []
    for fp, group in groups.items():
        first = min(group, key=lambda f: (f.location.line, f.location.col))
        entries.append(
            {
                "fingerprint": fp,
                "rule_id": first.rule_id,
                "file": first.location.file,
                "count": len(group),
                "snippet": first.snippet,
            }
        )
    entries.sort(key=lambda e: (e["file"], e["rule_id"], e["fingerprint"]))
    return {"version": BASELINE_VERSION, "tool": f"{TOOL_NAME} {__version__}", "entries": entries}


def dumps(document: dict) -> str:
    return json.dumps(document, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def load(path: str) -> Counter:
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        raise BaselineError(f"baseline file not found: {path}") from None
    except OSError as exc:
        raise BaselineError(f"cannot read baseline {path}: {exc}") from None
    return load_text(text, path)


def load_text(text: str, source: str = "baseline") -> Counter:
    """Parse a baseline document into ``{fingerprint: count}``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"cannot read baseline {source}: {exc}") from None
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise BaselineError(f"{source}: unsupported baseline format (expected version {BASELINE_VERSION})")
    counts: Counter = Counter()
    for entry in data.get("entries", []):
        try:
            counts[str(entry["fingerprint"])] += int(entry.get("count", 1))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise BaselineError(f"{source}: malformed baseline entry {entry!r}") from None
    return counts


def filter_new(findings: list[Finding], counts: Counter) -> tuple[list[Finding], int]:
    """Split findings into (new, number matched by the baseline)."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.fingerprint, []).append(f)
    new: list[Finding] = []
    matched = 0
    for fp, group in groups.items():
        group.sort(key=lambda f: (f.location.line, f.location.col, f.location.end_line, f.location.end_col))
        allowed = min(counts.get(fp, 0), len(group))
        matched += allowed
        new.extend(group[allowed:])
    return new, matched
