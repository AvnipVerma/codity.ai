"""Human-readable table output, stdlib only.

Column widths are computed from the content and every cell is truncated with
an ellipsis so columns never run into each other at the given width. Colour is
decided by the caller (TTY, ``NO_COLOR``, ``--no-color``) and applied after
layout, so widths are always computed on plain text.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..engine import ScanResult
from ..model import Finding, Severity

RESET = "\x1b[0m"
BOLD = "\x1b[1m"
DIM = "\x1b[2m"
GREEN = "\x1b[32m"
SEVERITY_COLOURS = {
    Severity.CRITICAL: "\x1b[1;91m",
    Severity.HIGH: "\x1b[31m",
    Severity.MEDIUM: "\x1b[33m",
    Severity.LOW: "\x1b[34m",
}


@dataclass(frozen=True)
class Glyphs:
    rule: str
    tee: str
    elbow: str
    dot: str
    ellipsis: str
    ok: str


UNICODE = Glyphs("─", "├─", "└─", "·", "…", "✓")
ASCII = Glyphs("-", "|-", "`-", "|", "...", "OK")


def truncate(text: str, width: int, glyphs: Glyphs = UNICODE) -> str:
    text = " ".join(str(text).split())
    if width <= 0:
        return ""
    if len(text) <= width:
        return text
    if width <= len(glyphs.ellipsis):
        return text[:width]
    return text[: width - len(glyphs.ellipsis)] + glyphs.ellipsis


def _paint(text: str, code: str, colour: bool) -> str:
    return f"{code}{text}{RESET}" if colour and code else text


def render_table(
    result: ScanResult,
    *,
    colour: bool = False,
    show_paths: bool = True,
    width: int = 100,
    glyphs: Glyphs = UNICODE,
    timing: str | None = None,
) -> str:
    width = max(width, 60)
    findings = result.findings
    lines: list[str] = []

    if findings:
        sev_w = 10
        rule_w = min(max([len("RULE")] + [len(f.rule_id) for f in findings]), 34)
        loc_w = min(max([len("LOCATION")] + [len(f.location.short()) for f in findings]), 40)
        # On narrow terminals shrink RULE and LOCATION before MESSAGE gets too small.
        while width - (sev_w + rule_w + loc_w + 4) < 24 and (rule_w > 12 or loc_w > 12):
            if loc_w >= rule_w and loc_w > 12:
                loc_w -= 1
            else:
                rule_w -= 1
        msg_w = max(width - (1 + sev_w + 1 + rule_w + 1 + loc_w + 1), 10)

        def row(sev: str, rule: str, loc: str, msg: str) -> str:
            return " ".join(
                [
                    "",
                    truncate(sev, sev_w, glyphs).ljust(sev_w),
                    truncate(rule, rule_w, glyphs).ljust(rule_w),
                    truncate(loc, loc_w, glyphs).ljust(loc_w),
                    truncate(msg, msg_w, glyphs),
                ]
            ).rstrip()

        lines.append(_paint(row("SEVERITY", "RULE", "LOCATION", "MESSAGE"), BOLD, colour))
        lines.append(
            _paint(
                " ".join(["", glyphs.rule * sev_w, glyphs.rule * rule_w, glyphs.rule * loc_w, glyphs.rule * msg_w]),
                DIM,
                colour,
            )
        )
        for f in findings:
            text = row(f.severity.name, f.rule_id, f.location.short(), f.summary or f.message)
            if colour:
                sev_cell = truncate(f.severity.name, sev_w, glyphs).ljust(sev_w)
                text = " " + _paint(sev_cell, SEVERITY_COLOURS[f.severity], True) + text[1 + sev_w:]
            lines.append(text)
            if show_paths and f.path:
                lines.extend(_path_lines(f, sev_w, width, colour, glyphs))
                lines.append("")
        if lines[-1] != "":
            lines.append("")
    else:
        lines.append(_paint(f" {glyphs.ok} No findings", GREEN, colour))
        lines.append("")

    lines.append(_paint(glyphs.rule * width, DIM, colour))
    counts = {s: 0 for s in Severity}
    for f in findings:
        counts[f.severity] += 1
    n = len(findings)
    sep = f"  {glyphs.dot}  "
    parts = [f"{n} finding{'s' if n != 1 else ''}"] + [
        f"{counts[s]} {s.label}" for s in sorted(Severity, reverse=True)
    ]
    extras = [f"{len(result.suppressed)} suppressed"]
    if result.baseline_used:
        extras.append(f"{result.baselined} in baseline")
    lines.append(" " + sep.join(parts) + "     (" + ", ".join(extras) + ")")
    if timing:
        lines.append(" " + timing)
    return "\n".join(lines) + "\n"


def _path_lines(f: Finding, sev_w: int, width: int, colour: bool, glyphs: Glyphs) -> list[str]:
    indent = " " * (sev_w + 2)
    kind_w = 8
    loc_w = min(max(len(s.location.short()) for s in f.path), 44)
    out = []
    last = len(f.path) - 1
    for i, step in enumerate(f.path):
        branch = glyphs.elbow if i == last else glyphs.tee
        prefix_len = len(indent) + len(branch) + 1 + kind_w + 1 + loc_w + 2
        msg_w = max(width - prefix_len, 10)
        loc = truncate(step.location.short(), loc_w, glyphs).ljust(loc_w)
        msg = truncate(step.message, msg_w, glyphs)
        branch_txt = _paint(branch, DIM, colour)
        kind = step.kind.value.ljust(kind_w)
        out.append(f"{indent}{branch_txt} {kind} {loc}  {msg}".rstrip())
    return out
