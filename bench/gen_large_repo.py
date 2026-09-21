"""Generate a realistic, deterministic 500-file Python project for timing.

    python bench/gen_large_repo.py [OUT_DIR] [--files 500] [--seed 1234]

The project has packages of modules that import each other, classes with
methods, Flask views reading request data, helpers that build strings, and a
sprinkling of real vulnerabilities (SQL, command, path, SSRF, deserialization,
secrets) next to safe variants. File sizes vary from ~40 to ~600 lines.
"""

from __future__ import annotations

import argparse
import random
import shutil
from pathlib import Path

HEADER = '''"""Generated module {pkg}.{mod}."""
import json
import os
import sqlite3
import subprocess

import requests
from flask import Blueprint, request

from {pkg} import {sibling} as sibling

bp = Blueprint("{pkg}_{mod}", __name__)
DB_PATH = "{pkg}.db"
ALLOWED_{upper} = ("id", "name", "created")
'''

HELPER = '''

def normalise_{i}(value, suffix="_{i}"):
    text = str(value).strip().lower()
    if not text:
        return "default{i}"
    parts = [p for p in text.split(",") if p]
    return "-".join(parts) + suffix
'''

BUILDER = '''

def build_query_{i}(table, column, value):
    clause = column + " = '" + value + "'"
    return "SELECT * FROM " + table + " WHERE " + clause
'''

CLASS = '''

class Repository{i}:
    table = "items_{i}"

    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(path)
        self.cache = {{}}

    def find(self, key):
        if key in self.cache:
            return self.cache[key]
        row = self.conn.execute("SELECT * FROM " + self.table + " WHERE id = ?", (key,)).fetchone()
        self.cache[key] = row
        return row

    def search(self, term):
        return self.conn.execute(build_query_{b}(self.table, "name", term)).fetchall()

    def summary(self):
        rows = self.conn.execute("SELECT count(*) FROM " + self.table).fetchone()
        return {{"table": self.table, "rows": rows[0] if rows else 0}}
'''

SAFE_VIEW = '''

@bp.route("/{mod}/safe{i}")
def safe_view_{i}():
    ident = int(request.args.get("id", 0))
    sort = request.args.get("sort", "id")
    if sort not in ALLOWED_{upper}:
        sort = "id"
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(f"SELECT * FROM t{i} WHERE id = {{ident}} ORDER BY {{sort}}").fetchall()
    subprocess.run(["echo", str(ident)], check=False)
    payload = json.loads(request.data or b"{{}}")
    return {{"rows": rows, "keys": sorted(payload), "n": normalise_{h}(sort)}}
'''

VULN_VIEWS = [
    '''

@bp.route("/{mod}/v{i}")
def vuln_sql_{i}():
    term = request.args.get("q", "")
    repo = Repository{c}()
    return {{"rows": repo.search(normalise_{h}(term))}}
''',
    '''

@bp.route("/{mod}/v{i}")
def vuln_cmd_{i}():
    host = request.form.get("host", "localhost")
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return {{"out": out.decode()}}
''',
    '''

@bp.route("/{mod}/v{i}")
def vuln_path_{i}():
    name = request.args["file"]
    with open(os.path.join("/srv/data", name)) as fh:
        return fh.read()
''',
    '''

@bp.route("/{mod}/v{i}")
def vuln_ssrf_{i}():
    target = sibling.relay_{sib_i}(request.args.get("url"))
    return requests.get(target, timeout=3).text
''',
]

RELAY = '''

def relay_{i}(value):
    if value is None:
        return "http://localhost"
    return value.strip()
'''

SECRET = '''

SERVICE_{i}_API_KEY = "{secret}"
'''

LOOP = '''

def aggregate_{i}(items):
    totals = {{}}
    for index, item in enumerate(items):
        key = item.get("kind", "other")
        totals[key] = totals.get(key, 0) + index
        while totals[key] > 1000:
            totals[key] -= 1000
    try:
        report = json.dumps(totals)
    except (TypeError, ValueError):
        report = "{{}}"
    return report
'''


def _secret(rng: random.Random) -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(rng.choice(alphabet) for _ in range(32))


def generate(out: Path, files: int = 500, seed: int = 1234) -> dict:
    rng = random.Random(seed)
    if out.exists():
        shutil.rmtree(out)
    n_pkgs = max(1, files // 50)
    per_pkg = files // n_pkgs
    counts = {"files": 0, "lines": 0, "vulnerable_views": 0}
    for p in range(n_pkgs):
        pkg = f"pkg{p:02d}"
        pkg_dir = out / pkg
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "__init__.py").write_text(f'"""Package {pkg}."""\n', encoding="utf-8")
        counts["files"] += 1
        modules = [f"mod{m:03d}" for m in range(per_pkg - 1)]
        for m, mod in enumerate(modules):
            sibling = modules[(m + 1) % len(modules)]
            parts = [HEADER.format(pkg=pkg, mod=mod, sibling=sibling, upper=mod.upper())]
            size = rng.choice((1, 2, 3, 4, 6, 10))  # mixed file sizes
            for k in range(size):
                i = k
                parts.append(HELPER.format(i=i))
                parts.append(BUILDER.format(i=i))
                parts.append(RELAY.format(i=i))
                parts.append(CLASS.format(i=i, b=rng.randrange(k + 1)))
                parts.append(LOOP.format(i=i))
                parts.append(SAFE_VIEW.format(i=i, mod=mod, upper=mod.upper(), h=rng.randrange(k + 1)))
                if rng.random() < 0.3:
                    template = rng.choice(VULN_VIEWS)
                    parts.append(
                        template.format(i=i, mod=mod, c=rng.randrange(k + 1), h=rng.randrange(k + 1), sib_i=0)
                    )
                    counts["vulnerable_views"] += 1
                if rng.random() < 0.05:
                    parts.append(SECRET.format(i=i, secret=_secret(rng)))
            text = "".join(parts)
            (pkg_dir / f"{mod}.py").write_text(text, encoding="utf-8")
            counts["files"] += 1
            counts["lines"] += text.count("\n")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("out", nargs="?", default=str(Path(__file__).parent / "large_repo"))
    parser.add_argument("--files", type=int, default=500)
    parser.add_argument("--seed", type=int, default=1234)
    args = parser.parse_args()
    counts = generate(Path(args.out), args.files, args.seed)
    print(f"wrote {counts['files']} files, {counts['lines']} lines, {counts['vulnerable_views']} vulnerable views to {args.out}")


if __name__ == "__main__":
    main()
