"""Command-line interface.

Exit codes
----------
0  the scan ran and found nothing at or above ``--fail-on`` (or no --fail-on)
1  at least one new, unsuppressed finding at or above ``--fail-on``
2  usage error, invalid rules file, invalid baseline, missing target
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys

from . import __version__
from . import baseline as baseline_mod
from .config import RuleError, load_rules
from .discovery import TargetError
from .engine import ScanOptions, ScanResult, scan
from .model import SEVERITY_NAMES, Severity

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="Static taint analyzer for Python: finds untrusted input that reaches dangerous operations.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    def common(p: argparse.ArgumentParser) -> None:
        p.add_argument("target", help="file or directory to scan")
        p.add_argument("--rules", default="rules.yaml", help="rules file (default: ./rules.yaml)")
        p.add_argument(
            "--exclude",
            action="append",
            default=[],
            metavar="GLOB",
            help="skip files/directories matching GLOB (repeatable); matched against names and relative paths",
        )
        p.add_argument("-o", "--output", metavar="FILE", help="write the report to FILE instead of stdout")
        p.add_argument("--quiet", action="store_true", help="suppress warnings and timing on stderr")

    scan_p = sub.add_parser("scan", help="scan a target and report findings")
    common(scan_p)
    scan_p.add_argument("--format", choices=("table", "sarif", "html"), default="table")
    scan_p.add_argument(
        "--fail-on",
        choices=SEVERITY_NAMES,
        metavar="SEVERITY",
        help="exit 1 if a finding at or above SEVERITY is reported (critical, high, medium, low)",
    )
    scan_p.add_argument("--baseline", metavar="FILE", help="report only findings not in this baseline")
    scan_p.add_argument("--no-color", action="store_true", help="disable ANSI colours in table output")
    scan_p.add_argument("--no-paths", action="store_true", help="table output: hide taint paths")
    scan_p.add_argument(
        "--report-unused-suppressions",
        action="store_true",
        help="report suppression comments that matched no finding",
    )

    base_p = sub.add_parser("baseline", help="write a baseline of current findings (JSON) to stdout")
    common(base_p)
    return parser


def _stderr(message: str) -> None:
    sys.stderr.write(message + "\n")
    sys.stderr.flush()


def _enable_windows_ansi() -> bool:
    if os.name != "nt":
        return True
    try:  # enable VT processing on Windows 10+ consoles
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def _write(text: str, output: str | None) -> None:
    """Write bytes, never letting the platform translate newlines.

    Non-terminal output is always UTF-8 with ``\\n`` line endings so a report
    is byte-identical on every OS.
    """
    if output:
        with open(output, "wb") as fh:
            fh.write(text.encode("utf-8"))
        return
    stream = sys.stdout
    if stream.isatty():
        encoding = stream.encoding or "utf-8"
        data = text.encode(encoding, errors="replace")
    else:
        data = text.encode("utf-8")
    stream.flush()
    stream.buffer.write(data)
    stream.buffer.flush()


def _glyphs_for_tty():
    from .output.table import ASCII, UNICODE

    enc = sys.stdout.encoding or "ascii"
    try:
        "─├└·…✓".encode(enc)
        return UNICODE
    except (UnicodeEncodeError, LookupError):
        return ASCII


def _exit_code(result: ScanResult, fail_on: str | None) -> int:
    if not fail_on:
        return EXIT_OK
    threshold = Severity.parse(fail_on)
    return EXIT_FINDINGS if any(f.severity >= threshold for f in result.findings) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        rules, warnings = load_rules(args.rules)
    except RuleError as exc:
        _stderr(f"error: {exc}")
        return EXIT_USAGE
    if not args.quiet:
        for w in warnings:
            _stderr(f"warning: {w}")

    counts = None
    if getattr(args, "baseline", None):
        try:
            counts = baseline_mod.load(args.baseline)
        except baseline_mod.BaselineError as exc:
            _stderr(f"error: {exc}")
            return EXIT_USAGE

    options = ScanOptions(
        excludes=tuple(args.exclude),
        baseline=counts,
        report_unused_suppressions=getattr(args, "report_unused_suppressions", False),
    )
    try:
        result = scan(args.target, rules, options)
    except TargetError as exc:
        _stderr(f"error: {exc}")
        return EXIT_USAGE

    if not args.quiet:
        for diag in result.diagnostics:
            _stderr(diag.render())

    if args.command == "baseline":
        _write(baseline_mod.dumps(baseline_mod.build(result.findings)), args.output)
        if not args.quiet:
            _stderr(f"baseline: {len(result.findings)} findings from {len(result.files)} files")
        return EXIT_OK

    timing = f"Scanned {len(result.files)} files in {result.elapsed:.2f}s"
    if args.format == "sarif":
        from .output.sarif import render_sarif

        _write(render_sarif(result), args.output)
        if not args.quiet:
            _stderr(timing)
    elif args.format == "html":
        from .output.html import render_html

        _write(render_html(result), args.output)
        if not args.quiet:
            _stderr(timing)
    else:
        from .output.table import UNICODE, render_table

        to_tty = not args.output and sys.stdout.isatty()
        colour = to_tty and not args.no_color and "NO_COLOR" not in os.environ and _enable_windows_ansi()
        glyphs = _glyphs_for_tty() if to_tty else UNICODE
        width = shutil.get_terminal_size((100, 24)).columns if to_tty else 100
        text = render_table(
            result,
            colour=colour,
            show_paths=not args.no_paths,
            width=width,
            glyphs=glyphs,
            timing=timing if to_tty and not args.quiet else None,
        )
        _write(text, args.output)
        if not to_tty and not args.quiet:
            _stderr(timing)
    return _exit_code(result, args.fail_on)


def entry() -> None:  # pragma: no cover
    sys.exit(main())


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
