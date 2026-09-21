"""Self-contained HTML report (stdlib only, no JavaScript).

* Everything taken from scanned code is passed through ``html.escape``.
* Lines containing a detected hard-coded secret are never shown: code context
  for other findings could otherwise reveal them.
* Severity filters are CSS-only (hidden checkboxes + ``:checked`` selectors);
  routes are collapsible ``<details>`` elements.
* No timestamps or machine-specific values, so the bytes are deterministic.
"""

from __future__ import annotations

from html import escape

from .. import TOOL_NAME, __version__
from ..engine import ScanResult
from ..model import Finding, Severity

CONTEXT = 2  # lines of code shown around a sink

CSS = """
:root { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --border:#d1d9e0; --panel:#f6f8fa;
  --hl:#fff8c5; --critical:#b3261e; --high:#d1242f; --medium:#9a6700; --low:#0969da; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --border:#3d444d; --panel:#151b23;
    --hl:#3a2f0b; --critical:#ff7b72; --high:#f85149; --medium:#d29922; --low:#58a6ff; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; }
.wrap { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:22px; margin:0 0 4px; }
.sub { color:var(--muted); margin:0 0 16px; }
.toggle { position:absolute; opacity:0; pointer-events:none; }
.chips { display:flex; flex-wrap:wrap; gap:8px; margin:0 0 20px; }
.chip { cursor:pointer; border:1px solid var(--border); border-radius:999px; padding:4px 12px;
  user-select:none; background:var(--panel); }
.chip b { margin-left:6px; }
.badge { display:inline-block; min-width:78px; text-align:center; font-weight:600; font-size:12px;
  letter-spacing:.04em; border-radius:4px; padding:1px 6px; color:#fff; }
.sev-critical .badge, .chip.sev-critical b { background:var(--critical); color:#fff; border-radius:4px; padding:0 6px; }
.sev-high .badge, .chip.sev-high b { background:var(--high); color:#fff; border-radius:4px; padding:0 6px; }
.sev-medium .badge, .chip.sev-medium b { background:var(--medium); color:#fff; border-radius:4px; padding:0 6px; }
.sev-low .badge, .chip.sev-low b { background:var(--low); color:#fff; border-radius:4px; padding:0 6px; }
#show-critical:not(:checked) ~ main .finding.sev-critical,
#show-high:not(:checked) ~ main .finding.sev-high,
#show-medium:not(:checked) ~ main .finding.sev-medium,
#show-low:not(:checked) ~ main .finding.sev-low { display:none; }
#show-critical:not(:checked) ~ .chips label[for=show-critical],
#show-high:not(:checked) ~ .chips label[for=show-high],
#show-medium:not(:checked) ~ .chips label[for=show-medium],
#show-low:not(:checked) ~ .chips label[for=show-low] { opacity:.45; text-decoration:line-through; }
.toggle:focus-visible + * { outline:2px solid var(--low); }
.finding { border:1px solid var(--border); border-radius:8px; margin:0 0 14px; overflow:hidden; }
.finding > header { padding:10px 14px; background:var(--panel); border-bottom:1px solid var(--border); }
.finding .rule { font-weight:600; margin:0 8px; }
.finding .loc { color:var(--muted); font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:13px; }
.finding .msg { margin:6px 0 0; overflow-wrap:anywhere; }
.body { padding:10px 14px; }
details summary { cursor:pointer; color:var(--muted); }
ol.path { margin:8px 0 0; padding-left:22px; }
ol.path li { margin:0 0 6px; }
.kind { display:inline-block; min-width:58px; font-size:12px; color:var(--muted); text-transform:uppercase; }
.steploc { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:12px; color:var(--muted); }
code, pre { font-family:ui-monospace, SFMono-Regular, Consolas, monospace; font-size:13px; }
pre.code { margin:10px 0 0; padding:8px 0; background:var(--panel); border-radius:6px; overflow-x:auto; }
pre.code span { display:block; padding:0 12px; white-space:pre; }
pre.code span.hl { background:var(--hl); }
pre.code span i { font-style:normal; color:var(--muted); display:inline-block; min-width:44px; }
.hidden-line { color:var(--muted); font-style:italic; }
.empty { padding:24px; border:1px dashed var(--border); border-radius:8px; text-align:center; }
footer { color:var(--muted); margin-top:28px; font-size:13px; }
footer ul { padding-left:18px; }
"""


def _secret_lines(result: ScanResult) -> set[tuple[str, int]]:
    """(file, line) pairs that hold a detected secret; their text is never shown."""
    out = set()
    for f in result.findings + result.suppressed:
        if not f.path and f.cwe == "CWE-798":
            for line in range(f.location.line, f.location.end_line + 1):
                out.add((f.location.file, line))
    return out


def _line_text(result: ScanResult, secret: set, file: str, line: int) -> str | None:
    lines = result.lines.get(file)
    if not lines or not 1 <= line <= len(lines) or (file, line) in secret:
        return None
    return lines[line - 1]


def _code_context(result: ScanResult, secret: set, f: Finding) -> str:
    loc = f.location
    lines = result.lines.get(loc.file)
    if not lines:
        return ""
    rows = []
    for n in range(max(1, loc.line - CONTEXT), min(len(lines), loc.end_line + CONTEXT) + 1):
        cls = ' class="hl"' if loc.line <= n <= loc.end_line else ""
        if (loc.file, n) in secret:
            text = '<em class="hidden-line">line hidden: contains a hard-coded secret</em>'
        else:
            text = escape(lines[n - 1])
        rows.append(f"<span{cls}><i>{n}</i>{text}</span>")
    return '<pre class="code">' + "".join(rows) + "</pre>"


def _finding(result: ScanResult, secret: set, f: Finding) -> str:
    sev = f.severity.label
    parts = [
        f'<article class="finding sev-{sev}">',
        "<header>",
        f'<span class="badge">{escape(f.severity.name)}</span>',
        f'<span class="rule">{escape(f.rule_id)}</span>',
        f'<span class="loc">{escape(f.location.short())}</span>',
        f'<p class="msg">{escape(f.message)}</p>',
        "</header>",
        '<div class="body">',
    ]
    if f.path:
        parts.append(f"<details open><summary>Route: {len(f.path)} steps</summary><ol class=\"path\">")
        for step in f.path:
            text = _line_text(result, secret, step.location.file, step.location.line)
            code = f"<br><code>{escape(text.strip())}</code>" if text is not None and text.strip() else ""
            parts.append(
                f'<li><span class="kind">{escape(step.kind.value)}</span> '
                f'<span class="steploc">{escape(step.location.short())}</span> '
                f"{escape(step.message)}{code}</li>"
            )
        parts.append("</ol></details>")
        parts.append(_code_context(result, secret, f))
    else:
        parts.append(f"<code>{escape(f.snippet)}</code>")
    parts.append("</div></article>")
    return "\n".join(parts)


def render_html(result: ScanResult) -> str:
    secret = _secret_lines(result)
    counts = {s: 0 for s in Severity}
    for f in result.findings:
        counts[f.severity] += 1
    order = sorted(Severity, reverse=True)
    n = len(result.findings)
    out = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Scan report</title>",
        f"<style>{CSS}</style>",
        "</head>",
        "<body>",
        '<div class="wrap">',
        f"<h1>{escape(TOOL_NAME)} report</h1>",
        f'<p class="sub">{n} finding{"s" if n != 1 else ""} in {len(result.files)} scanned files '
        f"&middot; {len(result.suppressed)} suppressed"
        + (f" &middot; {result.baselined} in baseline" if result.baseline_used else "")
        + f" &middot; {escape(TOOL_NAME)} {escape(__version__)}</p>",
    ]
    for s in order:
        out.append(f'<input type="checkbox" class="toggle" id="show-{s.label}" checked>')
    out.append('<nav class="chips" aria-label="Filter by severity">')
    for s in order:
        out.append(
            f'<label class="chip sev-{s.label}" for="show-{s.label}">{s.name.title()}<b>{counts[s]}</b></label>'
        )
    out.append("</nav>")
    out.append("<main>")
    if result.findings:
        for f in result.findings:
            out.append(_finding(result, secret, f))
    else:
        out.append('<div class="empty">No findings.</div>')
    out.append("</main>")
    out.append("<footer>")
    if result.diagnostics:
        out.append("<p>Warnings:</p><ul>")
        for d in result.diagnostics:
            out.append(f"<li>{escape(d.render())}</li>")
        out.append("</ul>")
    out.append(f"<p>Generated by {escape(TOOL_NAME)} {escape(__version__)}.</p>")
    out.append("</footer>")
    out.append("</div>")
    out.append("</body>")
    out.append("</html>")
    return "\n".join(out) + "\n"
