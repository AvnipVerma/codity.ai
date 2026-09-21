"""Scan orchestration.

1. discover files, read and parse each one exactly once;
2. group the loaded rules by their ``kind`` and look each group's handler up in
   the registry;
3. run every handler's whole-program ``prepare`` hook, then its per-module
   ``analyze`` hook;
4. apply inline suppressions, compute fingerprints, filter by baseline, sort.

This module deliberately contains no knowledge of any particular rule kind:
no kind names, no branching on them. A new kind is added by registering a
handler (see ``tests/test_extensibility.py``), never by editing this file.
"""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, field

from . import baseline as baseline_mod
from .config import Rule
from .context import ProgramContext, build_program
from .discovery import discover
from .kinds import get_kind
from .model import Diagnostic, Finding
from .suppress import apply_suppressions, parse_suppressions


@dataclass
class ScanOptions:
    excludes: tuple[str, ...] = ()
    baseline: Counter | None = None
    report_unused_suppressions: bool = False


@dataclass
class ScanResult:
    root: str
    files: list[str]
    rules: list[Rule]
    findings: list[Finding]  # reported: not suppressed, not in the baseline
    suppressed: list[Finding] = field(default_factory=list)
    baselined: int = 0
    diagnostics: list[Diagnostic] = field(default_factory=list)
    baseline_used: bool = False
    elapsed: float = 0.0
    # Source lines of files that have findings (for reports that show code).
    lines: dict[str, list[str]] = field(default_factory=dict)

    @property
    def all_findings(self) -> list[Finding]:
        """Reported plus suppressed findings (what a baseline is built from)."""
        return sorted(self.findings + self.suppressed, key=Finding.sort_key)


def _group_by_handler(rules: list[Rule]) -> dict[str, list[Rule]]:
    groups: dict[str, list[Rule]] = {}
    for rule in rules:
        groups.setdefault(rule.kind, []).append(rule)
    return groups


def run_handlers(program: ProgramContext, rules: list[Rule]) -> list[Finding]:
    groups = _group_by_handler(rules)
    names = sorted(groups)
    active = []
    for name in names:
        handler = get_kind(name)
        if handler is None:  # validated at load time; defensive only
            program.warn(None, f"no handler registered for rule kind {name!r}")
            continue
        try:
            handler.prepare(program, groups[name])
            active.append((name, handler))
        except (RecursionError, MemoryError) as exc:
            program.warn(None, f"handler {name!r} failed during prepare: {exc.__class__.__name__}")
        except Exception as exc:  # a handler bug must not kill the scan
            program.warn(None, f"handler {name!r} failed during prepare: {exc.__class__.__name__}: {exc}")

    findings: list[Finding] = []
    for module in program.modules:
        for name, handler in active:
            try:
                findings.extend(handler.analyze(module, groups[name]))
            except (RecursionError, MemoryError) as exc:
                program.warn(module.path, f"handler {name!r} skipped this file: {exc.__class__.__name__}")
            except Exception as exc:
                program.warn(module.path, f"handler {name!r} failed on this file: {exc.__class__.__name__}: {exc}")
    return findings


def scan(target: str, rules: list[Rule], options: ScanOptions | None = None) -> ScanResult:
    options = options or ScanOptions()
    started = time.perf_counter()
    root, files = discover(target, options.excludes)
    program = build_program(root, files)
    raw = run_handlers(program, rules)

    by_file: dict[str, list[Finding]] = {}
    for f in raw:
        by_file.setdefault(f.location.file, []).append(f)
    everything: list[Finding] = []
    for module in program.modules:
        file_findings = by_file.pop(module.path, [])
        try:
            # Only files mentioning the directive are tokenized (a speed-up, not the
            # parser: comments are still found with tokenize).
            sups = parse_suppressions(module.text) if "codity" in module.text.lower() else []
        except Exception as exc:  # tokenize.TokenError, IndentationError...
            program.warn(module.path, f"cannot read suppression comments: {exc}")
            sups = []
        meta = apply_suppressions(file_findings, sups, module.path, options.report_unused_suppressions)
        everything.extend(file_findings)
        everything.extend(meta)
    for leftovers in by_file.values():  # findings located outside parsed modules
        everything.extend(leftovers)

    for f in everything:
        f.fingerprint = baseline_mod.fingerprint(f)

    suppressed = [f for f in everything if f.suppressed]
    active = [f for f in everything if not f.suppressed]
    baselined = 0
    if options.baseline is not None:
        active, baselined = baseline_mod.filter_new(active, options.baseline)

    active.sort(key=Finding.sort_key)
    suppressed.sort(key=Finding.sort_key)
    diagnostics = sorted(program.diagnostics, key=lambda d: (d.file or "", d.message))
    wanted = {f.location.file for f in active + suppressed}
    wanted |= {s.location.file for f in active for s in f.path}
    lines = {m.path: m.lines for m in program.modules if m.path in wanted}
    return ScanResult(
        root=root,
        files=[m.path for m in program.modules],
        rules=list(rules),
        findings=active,
        suppressed=suppressed,
        baselined=baselined,
        diagnostics=diagnostics,
        baseline_used=options.baseline is not None,
        elapsed=time.perf_counter() - started,
        lines=lines,
    )
