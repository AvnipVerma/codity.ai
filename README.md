# codity scanner

A static taint analyzer for Python, written in Python. It parses code with the
standard `ast` module, tracks untrusted data from where it enters (Flask,
Django, DRF, aiohttp and Starlette request data, `input()`, `sys.argv`,
environment variables) through assignments,
string building, containers, attributes and function calls, within a file and
across files, and reports the flows that reach a dangerous operation (SQL
execution, shell commands, file paths, outbound URLs, template rendering,
deserialization) without passing a sanitizer. Each finding carries the full
route. Rules are YAML; output is SARIF 2.1.0, a readable table, or an HTML report; inline
suppressions and position-independent baselines keep repeat scans quiet. The
only runtime dependency is PyYAML.

## Install, run, test

```
pip install -e ".[test]"
scanner scan ./target --rules rules.yaml --format table
pytest
```

Python 3.10 or newer. `pytest` runs the full suite except the 500-file timing
test, which is opt-in: `pytest -m slow`.

## Usage

```
scanner scan TARGET [--rules rules.yaml] [--format table|sarif|html] [-o FILE]
                    [--fail-on critical|high|medium|low] [--baseline FILE]
                    [--exclude GLOB]... [--no-color] [--no-paths] [--quiet]
                    [--report-unused-suppressions]
scanner baseline TARGET [--rules rules.yaml] [--exclude GLOB]... [-o FILE]
scanner --version
```

`TARGET` is a directory or a single file; only `*.py` files are scanned.
`.git`, `.venv`, `venv`, `env`, `node_modules`, `__pycache__`, `build`, `dist`,
`.tox` and `site-packages` are always skipped. `--exclude` adds globs matched
against names and relative paths (`--exclude tests --exclude "*_pb2.py"`).
Symlinked directories are not followed, and symlinked files pointing outside
the target are skipped.

**Table** (the default), shown here on `corpus/vulnerable/sqli_helper_function.py`:

```
 SEVERITY   RULE             LOCATION                      MESSAGE
 ────────── ──────────────── ───────────────────────────── ─────────────────────────────────────────
 CRITICAL   py.sql-injection sqli_helper_function.py:16:16 request.args.get('q', '') reaches conn.e…
            ├─ source   sqli_helper_function.py:23:12  untrusted data from `request.args.get('q', '…
            ├─ step     sqli_helper_function.py:23:5   assigned to `term`
            ├─ call     sqli_helper_function.py:24:41  passed to `build_search()` as `term`
            ├─ step     sqli_helper_function.py:8:18   enters `build_search()` as parameter `term`
            ├─ step     sqli_helper_function.py:9:14   concatenated with `+`
            ├─ step     sqli_helper_function.py:9:5    assigned to `clause`
            ├─ step     sqli_helper_function.py:10:12  concatenated with `+`
            ├─ return   sqli_helper_function.py:10:5   returned from `build_search()`
            ├─ call     sqli_helper_function.py:24:28  passed to `run()` as `sql`
            ├─ step     sqli_helper_function.py:13:9   enters `run()` as parameter `sql`
            └─ sink     sqli_helper_function.py:16:16  conn.execute(sql) [arg 0]

────────────────────────────────────────────────────────────────────────────────────────────────────
 1 finding  ·  1 critical  ·  0 high  ·  0 medium  ·  0 low     (0 suppressed)
```

Colour is used only when stdout is a terminal, and never with `--no-color` or
`NO_COLOR`. Columns are sized to the terminal (100 columns when not a
terminal) and cells are truncated with `…`. `--no-paths` hides the route
trees. The `Scanned N files in T` line goes to stderr when stdout is not a
terminal, so redirected output stays byte-identical between runs.

**SARIF** (`--format sarif`) is SARIF 2.1.0 and validates against the official
schema (vendored in `schemas/`, checked by `tests/test_sarif.py`). Each result
has `ruleId`, `ruleIndex`, `level`, `message`, a `physicalLocation` (relative
URI with `uriBaseId: SRCROOT`, 1-based line and column, `columnKind:
unicodeCodePoints`) and `partialFingerprints.codityFinding/v1`, plus the route
as `codeFlows[0].threadFlows[0].locations` (first entry the source, last the
sink, each with its own location and message). Rule metadata goes in
`tool.driver.rules` and includes the CWE, `security-severity` (critical 9.5,
high 8.0, medium 5.5, low 3.0), precision and help text. Suppressed findings
are included with `suppressions: [{kind: inSource}]`; with `--baseline`,
reported results carry `baselineState: new`. Parse failures appear as
`toolExecutionNotifications`. There are no timestamps and no absolute paths:
`originalUriBaseIds.SRCROOT` has a description but no URI, so the same checkout
gives the same bytes on any machine. Secret-pattern results have no
`codeFlows`.

**HTML** (`--format html -o report.html`) is a single self-contained page with
no JavaScript: severity filter chips (pure CSS), each finding's route as a
collapsible list with the code of every step, and the sink line highlighted in
its context. Everything taken from scanned code is HTML-escaped. Lines holding
a detected secret are never shown, even as another finding's context. The page
has no timestamps, so it is deterministic too.

**Exit codes:** `0` the scan ran and nothing at or above `--fail-on` was
reported (always 0 without `--fail-on`); `1` at least one new, unsuppressed
finding at or above `--fail-on`; `2` usage error, invalid rules file, invalid
baseline, or missing target. Unparseable files (syntax errors, Python 2,
undecodable bytes) are skipped with a warning on stderr and do not change the
exit code.

### Suppressions

```python
cursor.execute(query)  # codity: ignore[py.sql-injection] query is built from an allowlisted column name
```

A `# codity: ignore[rule-id, other-id] reason` comment suppresses findings of
exactly those rules whose reported span (for taint findings, the sink call)
contains the comment's line, or starts on the line right after a comment-only
line. For a call split over several lines, a comment on any of its lines works.
Comments are found with `tokenize`, never by searching the text, so the
directive inside a string does nothing. A suppression without a reason still
suppresses, but is reported as a low-severity
`scanner.suppression-missing-reason` finding. A malformed one (no brackets,
unclosed bracket, empty id, unknown directive) suppresses nothing and is
reported under the same rule. `--report-unused-suppressions` also reports
suppressions that matched nothing.

### Baselines

```
scanner baseline --rules rules.yaml ./target > .scanner-baseline.json
scanner scan --rules rules.yaml --baseline .scanner-baseline.json ./target
```

The second command reports only findings that are not in the baseline.
Identity does not depend on line numbers: adding code above, reformatting,
renaming or moving the enclosing function all keep a finding's identity.
DECISIONS.md explains the scheme and what breaks it; `tests/test_baseline.py`
demonstrates each case. Baselines are sorted, redacted JSON.

## Architecture

```
 files ──► discovery ──► parse once (ast + tokenize.open) ──► ModuleContext per file
                                                                  │  (tree, lines, resolver, node list)
                         rules.yaml ──► config ──► kind registry  │
                                                   │   REGISTRY["taint"]   REGISTRY["pattern"]   ...
                                                   ▼
                             engine: for each kind → prepare(program) → analyze(module)
                                                   │
       taint kind: function table → worklist fixpoint over summaries ──┐
       pattern kind: one pass over each module's node list ────────────┤
                                                                       ▼
                   findings ──► suppressions ──► fingerprints ──► baseline filter ──► sort
                                                                       ▼
                                                            SARIF 2.1.0  |  table
```

**Engine and rule kinds.** `engine.py` reads each file once and hands the
parsed modules to rule-kind handlers looked up in `scanner.kinds.REGISTRY` by
each rule's `kind:` field. A handler validates and compiles its rules, may run
a whole-program `prepare` pass, and returns findings per module from
`analyze`. The engine contains no kind names and no kind-specific branches (a
test checks its source). `tests/test_extensibility.py` defines a third kind in
the test file, registers it, and runs it through the unmodified engine. Adding
a kind means writing one `RuleKind` subclass and calling `register_kind()`.

**Name resolution** (`resolve.py`) maps expressions to dotted names using
module-level imports, aliases and definitions, and the taint engine tracks
local aliases flow-sensitively. Patterns (`patterns.py`) are dotted paths in
which `*` matches one segment, compiled once and indexed by final segment.

**Taint analysis** (`taint/`) is an abstract interpretation over each function
body. A value's taint is a set of facts, each recording where the data came
from, which rules it is still dangerous for, and the route it took. Variables
keep separate taint per attribute, constant dict key and tuple position.
Branches are joined, loops iterate to a fixpoint, and `return`/`raise`/
`break`/`abort()` end a path. Every function (including methods, nested
functions, named lambdas, and a `<module>` pseudo-function per file) gets a
summary: parameter-to-return and parameter-to-sink flows, source-to-return
flows, sanitizing, and writes to `self` fields. A dependency-driven worklist
re-analyses a function whenever a summary, class field, module global or
enclosing scope it read has changed, until nothing changes. Calls to functions
in the scanned project apply their summary; calls to anything else follow
conservative library defaults (`taint/models.py`). The **pattern kind**
(`kinds/pattern.py`) matches literal strings bound to credential-like names,
with Shannon entropy (`entropy.py`) and YAML-configurable ignore and force
lists.

## Writing rules

A new vulnerability class of an existing kind is a YAML edit only.

```yaml
- id: py.open-redirect            # unique
  severity: medium                # critical | high | medium | low
  cwe: CWE-601
  message: "Untrusted input controls a redirect target"
  kind: taint
  sources:
    - pattern: flask.request.args.get
      when: {kwarg: type, not_in: [int]}     # optional; calls only
    - patterns: [django.http.HttpRequest.GET, django.http.HttpRequest.GET.*]   # several at once
  typed_parameters:               # optional: parameters injected by frameworks
    - {name: request, type: django.http.HttpRequest, module_imports: [django]}
  sinks:
    - pattern: flask.redirect
      arg: 0                      # int, [ints], any (default), or receiver
      kwarg: location             # optional keyword equivalent(s) of arg
      # optional conditions on other arguments: is_true | in | not_in, optional pos
      # when: {kwarg: shell, is_true: true}
  sanitizers:
    - pattern: myapp.urls.safe_next
  # optional: a string whose constant leading text matches is safe for this rule
  safe_prefixes: ["https://www.example.com/*"]
```

* **Patterns** are dotted paths; `*` matches exactly one segment, and partial
  wildcards such as `exec*` are rejected. `open` means `builtins.open`.
  `*.execute` matches any `.execute()` call whose receiver is not a class
  defined in the scan, including receivers of unknown type. Methods on values
  returned by a library call are named after the call:
  `requests.Session().get` is `requests.Session.get`.
* A source matches a **call** (the return value is tainted) or a **read** of
  the name (`request.args` makes `request.args["q"]` tainted). Source and
  sanitizer entries may use `patterns: [...]` instead of `pattern:`, so
  rules.yaml defines each source group once with a YAML anchor and reuses it.
* **`typed_parameters`** type the parameters that frameworks inject. In a
  module importing one of `module_imports`, a parameter called `name` is an
  instance of `type`, so `request.GET.get("q")` resolves to
  `django.http.HttpRequest.GET.get` and ordinary patterns apply. A parameter
  with an annotation (`request: Request`) is typed from the annotation.
* **`when`** conditions: `is_true` holds for a truthy constant or any
  non-constant expression (so `shell=flag` counts); `in`/`not_in` compare the
  argument's resolved name with patterns (`Loader=yaml.SafeLoader`). An absent
  argument fails `is_true`/`in` and satisfies `not_in`. Values that cannot be
  resolved satisfy the condition: when unsure, report. On a source,
  a failing condition means "not a source", and the call's result is clean for
  that rule.
* Loading fails with exit code 2 and a message naming the rule and field for
  missing fields, an unknown kind or severity, a malformed CWE, duplicate ids,
  empty sources or sinks, bad patterns, or a bad `arg`. Unknown top-level keys
  only warn.

Pattern rules (`kind: pattern`) use a `match:` block:

```yaml
match:
  assigned_to: ["*_key", "*secret*", "*password*", "*token*"]   # fnmatch on names, case-insensitive
  value: literal_string
  min_entropy: 3.5
  min_length: 8                   # optional
  ignore_names: ["*_url", "*_field"]          # optional
  ignore_values: ["changeme", "<*>", "* *"]   # optional, matched against the value
  force_values: ["ghp_????????????????????*"] # optional: report anywhere, regardless of name/entropy
  forms: [assign, attribute, subscript, keyword, dict_key, default, compare]   # optional
```

`assigned_to` globs match identifier names (`*` = any run of characters),
which is intentionally different from the dotted-path `*`. Matched values are
redacted in every output: at most four leading characters plus the length.

## Name resolution: what it follows and what it does not

| Construct | Behaviour |
|---|---|
| `import subprocess as sp; sp.run(...)` | resolves to `subprocess.run` |
| `from flask import request as req; req.form` | resolves to `flask.request.form` |
| `from os import system as run_cmd; run_cmd(x)` | resolves to `os.system` |
| `import os.path; os.path.join` | resolves to `os.path.join` |
| `from .db import query` / `from ..pkg import g` | resolved against the file's package; used to find project functions across files |
| `r = request; r.args.get()` (inside a function) | local aliases are tracked flow-sensitively |
| `try: import ujson as json` / `except: import json` | the name has both candidates; a pattern matches either |
| `open`, `eval`, `input` | `builtins.*`, unless shadowed by an import, definition, assignment or parameter |
| `def view(request): request.args` | a parameter shadows the import, so this is **not** a Flask source |
| `getattr(os, "system")(x)` | constant attribute names are followed |
| `getattr(obj, name)`, `obj.__dict__[k]`, `setattr` | not followed |
| `cur = conn.cursor(); cur.execute(q)` | the type of `cur` is unknown, so it is matched as `<unknown>.execute` (only `*.execute` applies). This finds most real SQL and also causes the worst false positive (BENCHMARK.md §3). |
| `repo = Repository(); repo.find(x)` | calls to a class defined in the scan produce an instance; its methods are resolved, including inherited ones and `super()` |
| `from x import *` | not resolved; the names it brings in are unknown |
| `importlib.import_module(name)`, `__import__(name)` | not followed |
| monkey-patching, decorators that replace a function, metaclasses, `@property` bodies | not followed; decorated functions are assumed to keep their behaviour |
| `def view(request):` in a module importing `django` / `rest_framework` / `aiohttp` | typed by the rules' `typed_parameters`: `request.GET[...]`, `request.data[...]`, `request.query[...]` are sources |
| `async def hook(request: Request):` | typed from the annotation (Starlette/FastAPI `Request`, or any class) |
| FastAPI implicit parameters (`def search(q: str)` under `@app.get`) | not sources; only the `Request` object is modelled |

## Where the analysis stops

* **Within a function:** flow-sensitive, and path-insensitive except for a few
  guards (`if x in CONSTANT_COLLECTION`, `x == "literal"`, `x.isdigit()`,
  their negations, and `and`/`or`). Loops iterate to a fixpoint (at most 10
  passes). Implicit flows (`if secret == "x": y = "a"`) are not tracked, on
  purpose.
* **Between functions, same file:** summaries for every function, method,
  nested function and named lambda, with (mutual) recursion solved by the
  worklist. Keyword arguments, defaults, `*args` and `**kwargs` are mapped to
  parameters.
* **Across files:** imports between scanned files are resolved (absolute,
  relative, re-exports through `__init__.py`, import cycles, `src/` layouts,
  same-named modules in different directories).
* **Objects:** `self.x` fields are shared by all instances of a class family
  (object-insensitive). A field written from a parameter becomes concrete only
  when the constructor or method is called with tainted data. Writes through
  aliases (`b = a; b.append(t)` does not taint `a`) are not tracked.
* **Closures** see the enclosing function's variables only when those hold
  data from a real source, not the enclosing function's parameters
  (`tests/test_taint_propagation.py::test_nonlocal_and_closures_over_params_are_not_tracked`).
* **Third-party code** (anything not in the scan) is never analysed. Calls into
  it return the combined taint of their arguments and receiver, unless listed
  as non-propagating (`len`, `startswith`, `isdigit`, `hexdigest`...). Mutating
  methods (`append`, `update`...) taint their receiver.
* **Not tracked at all:** exceptions (`raise ValueError(t)`, then `str(e)`),
  `eval`-generated code, reflection, template files (`{{ x|safe }}`),
  `sys.path` changes.

## Known to be broken or missing

Each of these is pinned by a test or a corpus file:

* Validation hidden in a helper (`if is_valid(col):`) is not understood
  (`corpus/safe/sqli_validator_function.py`,
  `tests/test_taint_limits.py::test_validation_through_a_function_is_not_understood`).
* `realpath(p).startswith(BASE)` guards are not recognised
  (`corpus/safe/path_realpath_guard.py`).
* `.execute()` on any unknown third-party object is a SQL sink
  (`corpus/safe/sqli_executor_task.py`).
* `subprocess.run(["sh", "-c", cmd])` is missed (`corpus/vulnerable/cmd_sh_dash_c.py`).
* Low-entropy real passwords are missed (`corpus/vulnerable/secret_weak_password.py`),
  and password *hashes* and public keys such as `pk_live_...` are reported
  (pygoat triage, `corpus/safe/secret_public_values.py`).
* FastAPI's implicit query parameters are not sources, and a framework
  `request` parameter is only recognised when it is literally called
  `request` (or annotated).
* A file whose path changes looks new to a baseline
  (`tests/test_baseline.py::test_renaming_the_file_is_a_known_break`).
* Functions nested more than ~800 levels deep in one expression are skipped
  with a warning instead of analysed (the recursion limit is left at its
  default; see the robustness tests).
* Environment variables count as untrusted for SQL and command injection,
  which produces false positives in CLI and library code (two in pallets/flask).

## Performance

A generated 500-file project (153,198 lines, `bench/gen_large_repo.py`) scans
in 19.1–19.4 s on an AMD Ryzen 5 5500U laptop (Windows 11, Python 3.13,
single-threaded). pallets/flask (83 files, 18k lines) takes 1.06 s.
`tests/test_perf.py` (`pytest -m slow`) asserts the 60 s budget. The first
working version took 50.2 s; what brought it down:

* **Each file is parsed once.** The tree, source lines, resolver and a flat
  node list are computed once and shared by all rule kinds, instead of several
  `ast.walk` passes (a plain iterative walk is several times faster than
  `ast.walk`'s nested generators).
* **Patterns compile once.** They are bucketed by final segment (wildcard-final
  ones by first segment), and each lookup is memoised per candidate-name list.
* **The fixpoint visits most functions once.** It runs in callee-first order,
  from call edges collected during the scope walk that happens anyway;
  re-analysis happens only when something a function read has changed. On the
  benchmark project, 4,271 functions take 4,271 analyses.
* **Tokenizing is skipped where it can't matter.** Suppression comments are
  tokenized only in files containing the text `codity`.
* **Work is only done on tainted values.** No path steps or messages are built
  for clean values, and forced secret formats are pre-filtered by their
  literal prefix before `fnmatch`.

**Scaling fixes found on CPython's standard library.** The stdlib is 1,742
files and 901k lines, including thousands of `unittest.TestCase` subclasses.
The first attempt to scan it did not finish in 10 minutes; it now takes 120 s
(no internal errors). Three fixes:

* **Per-class field stores.** Self-field stores are per class. A method sees
  its class, its ancestors and its descendants (at most 64), and seeds only
  the `self.<attr>` names it uses. Previously every class sharing a base
  shared one store: every TestCase method copied every test's fields, and
  each field write re-queued all of them.
* **Re-analysis only on new facts.** Dependents are re-analysed only when
  facts are added, not when an existing fact gets a shorter route. Field and
  global driven re-analysis waits until summary-driven work is done, so many
  callers' contributions are absorbed at once.
* **A cap on derived names.** `h = h.set(...)` in a loop built ever-longer
  derived names (`X.set.set...`), so loop fixpoints never converged. Such
  names are capped at 8 segments.

Output is byte-identical before and after all of these changes on the
benchmark project, and the public-repository findings are unchanged. Findings are sorted by a total key, all hashing is sha256, output is
written as UTF-8 bytes with `\n`, and a test runs the CLI under three
`PYTHONHASHSEED` values and compares the bytes.

## Repository map

| Path | What |
|---|---|
| `src/scanner/` | the scanner (`engine.py`, `kinds/`, `taint/`, `resolve.py`, `output/`...) |
| `rules.yaml` | shipped rules: SQL injection, command injection, path traversal, SSRF, XSS/SSTI, insecure deserialization, hard-coded secrets |
| `corpus/` + `corpus/labels.json` | labelled benchmark corpus (90 files) |
| `bench/evaluate.py` | precision/recall on the corpus; `bench/gen_large_repo.py` timing project; `bench/public_repos.md` triage |
| `tests/` | 393 tests (392 by default + the opt-in timing test), one file per component |
| `BENCHMARK.md`, `DECISIONS.md` | measured results and design decisions |
