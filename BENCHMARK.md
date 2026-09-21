# Benchmark

Every number here was produced by running the code in this repository;
the commands to reproduce each one are at the end. The corpus table between
the `evaluate` markers is `python bench/evaluate.py` output pasted unmodified,
and `tests/test_benchmark_doc.py` fails if it drifts from what the evaluator
prints today.

## 1. The corpus

80 files written for this project, labelled in `corpus/labels.json` (file,
rule id, sink line, plus a snippet that the test-suite checks against the
file). `vulnerable/` holds code with at least one real vulnerability (some
of these files also contain safe decoys, such as the parameterized query in
`shop/repository.py`). `safe/` holds code that looks dangerous but is not:
parameterized queries, sanitized paths, taint killed by reassignment,
allowlists, constants that look like secrets.

| Rule | vulnerable/ files | safe/ files | expected findings |
|---|---|---|---|
| py.sql-injection | 11 (+ the 3-file `shop/` package, `mixed_two_sinks.py`) | 12 | 14 |
| py.command-injection | 6 (+ `mixed_two_sinks.py`) | 5 | 7 |
| py.path-traversal | 5 | 6 | 5 |
| py.ssrf | 4 | 4 | 4 |
| py.xss-template | 3 | 3 | 3 |
| py.insecure-deserialization | 4 | 4 | 4 |
| py.hardcoded-secret | 5 | 4 | 7 |

The corpus deliberately includes cases I expected the scanner to get wrong,
each annotated with a `note` in labels.json. Labels describe the code, not
the scanner, and were not changed after the scanner was run.

**Matching rule.** A reported finding is a true positive when its file, rule
id and sink line equal an expected entry; otherwise it is a false positive.
Unmatched expectations are false negatives. When one sink is reached from two
sources (two findings on one line), the line is counted once. Meta-findings
about suppression comments are not scored.

## 2. Results

<!-- evaluate:begin -->
Corpus: 90 files (47 under vulnerable/, 43 under safe/), 49 expected findings.

| Metric | Value |
|---|---|
| True positives | 47 |
| False positives | 4 |
| False negatives | 2 |
| Precision | 0.922 |
| Recall | 0.959 |
| F1 | 0.940 |

| Rule | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| py.sql-injection | 15 | 2 | 0 | 0.882 | 1.000 | 0.938 |
| py.command-injection | 7 | 0 | 1 | 1.000 | 0.875 | 0.933 |
| py.path-traversal | 6 | 1 | 0 | 0.857 | 1.000 | 0.923 |
| py.ssrf | 5 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.xss-template | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.insecure-deserialization | 4 | 0 | 0 | 1.000 | 1.000 | 1.000 |
| py.hardcoded-secret | 6 | 1 | 1 | 0.857 | 0.857 | 0.857 |

False positives:

- `safe/path_realpath_guard.py:14` py.path-traversal
- `safe/secret_public_values.py:4` py.hardcoded-secret
- `safe/sqli_executor_task.py:13` py.sql-injection
- `safe/sqli_validator_function.py:20` py.sql-injection

False negatives:

- `vulnerable/cmd_sh_dash_c.py:12` py.command-injection
- `vulnerable/secret_weak_password.py:6` py.hardcoded-secret
<!-- evaluate:end -->

All seven remaining errors were predicted in the labels' notes before the
scanner was run on the corpus.

**How the numbers moved, and why.** The first run of the finished engine on
the finished corpus scored P 0.872 / R 0.932 / F1 0.901 (6 FP, 3 FN). Two
changes followed:

1. `ORDERINGS.get(user_key, default)` on a module-level constant dict was a
   false positive. Subscripting the same dict was already treated as clean,
   and `.get()` was not. This was an engine bug, fixed (P 0.891).
2. `safe/ssrf_fixed_host_path.py` (a user name in the path of a hard-coded
   `https://api.github.com/...` URL) was a predicted false positive. The same
   pattern produced the only finding in a real project, microblog (see
   section 6). I added a general rule option, `safe_prefixes`, rather than a
   corpus-specific fix (P 0.911).

The corpus stayed the same throughout. Other improvements made in the same
period (library session objects, `type=int` conversions, forced secret
formats) do not affect any corpus case, and the corpus numbers did not change
when they landed.

## 3. Worst false positive: `safe/sqli_executor_task.py:13`

```python
runner = get_runner("default")

@app.route("/jobs/run", methods=["POST"])
def run_job():
    job_name = request.form["job"]
    runner.execute(job_name)
```

```
 CRITICAL   py.sql-injection sqli_executor_task.py:13:5 request.form['job'] reaches runner.execute(…
            ├─ source   sqli_executor_task.py:12:16  untrusted data from `request.form['job']`
            ├─ step     sqli_executor_task.py:12:5   assigned to `job_name`
            └─ sink     sqli_executor_task.py:13:5   runner.execute(job_name) [arg 0]
```

**Why it happens.** The SQL rule's main sink is `*.execute`, and the resolver
cannot infer the type of `runner`: it is the return value of a function from
a package outside the scan. An unknown receiver is presented to patterns as
`<unknown>.execute`, and `*` matches it. This is a deliberate trade:
`cur = conn.cursor(); cur.execute(q)` is how most SQL is run, and the cursor's
type is almost never inferable without type information either. It is my worst
false positive because it is systemic, not a corner case. Every `.execute()`
on any object with a tainted first argument is reported: job runners,
GraphQL's `schema.execute(request.json["query"])`, command objects. When the
object's class *is* in the scan, the engine resolves the method and analyses
its body instead (`tests/test_interproc.py::test_project_class_with_execute_method_is_not_a_db_sink`),
so the false positive is confined to third-party objects.

**What would fix it.** Receiver typing for the DB-API: a small table of
constructor return types (`sqlite3.connect` → Connection, `.cursor()` → Cursor,
`psycopg2.connect`, SQLAlchemy engines and sessions), after which `*.execute`
would be replaced by typed sinks, with the wildcard kept only for receivers
whose names suggest a cursor. The engine already names methods on library
return values (`requests.Session.get`), so most of the plumbing exists; the
work is the type table and deciding what to do with receivers that stay
unknown.

(Runner-up: `safe/sqli_validator_function.py`, where the column is validated by
`if not is_sortable(column): abort(400)`. Branch narrowing only understands
membership tests written inline. Fixing it needs "guard summaries": a
function whose boolean result implies a fact about its argument.)

## 4. Worst false negative: `vulnerable/sqli_django_view.py:9`

```python
def search_customers(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT id, name FROM customers WHERE name LIKE '%%" + name + "%%'")
```

Output: nothing.

**Why it happens.** Sources are dotted names such as `flask.request.args.get`.
In Django, `request` is not imported from anywhere; the framework passes it to
the view as a parameter. A parameter has no dotted name, so no rule can name
it. This is my worst false negative because it covers an entire framework, not
a coding pattern: on the public Django app pygoat every Django-side injection
(`raw()` SQL, `pickle.loads` of a cookie, `Popen(shell=True)`, `eval`) is
missed (section 6). FastAPI query parameters and aiohttp handlers have the
same problem.

**What would fix it.** A parameter-source form in the rule schema, for
example `{parameter: request, attribute: GET.*, in_function: {first_param: true, module_imports: django}}`,
evaluated when a function is seeded (the engine already seeds every parameter
with a symbolic origin; a matching one would get a concrete source fact
instead). For FastAPI, "every parameter of a function decorated with
`@app.get`/`@router.post`" is a source. Both are contained changes to the
seeding step plus the schema.

## 5. Other known misses and noise

* `vulnerable/cmd_sh_dash_c.py`: `subprocess.run(["sh", "-c", cmd])` has no
  `shell=True`, so the `when` condition fails. A rule would need to express
  "argument 0 is a list whose first elements are a shell and `-c`".
* `vulnerable/secret_weak_password.py`: `db_pass = "hunter2"` has low entropy
  and a name outside the globs. Lowering the threshold would flag every
  `password = "password"` in form code.
* `safe/secret_public_values.py`: a Stripe *publishable* key (`pk_live_...`)
  looks exactly like a secret.
* `safe/path_realpath_guard.py`: `realpath(...).startswith(BASE)` containment
  checks are not recognised as guards.

## 6. Public repositories

Full per-finding triage is in [bench/public_repos.md](bench/public_repos.md).

| Repository | Files | Lines | Time | Findings | TP | FP |
|---|---|---|---|---|---|---|
| we45/Vulnerable-Flask-App @ b6a4f97a | 3 | 420 | 0.07s | 3 | 3 | 0 |
| fportantier/vulpy @ 5249cc8b | 57 | 2,373 | 0.57s | 8 | 8 | 0 |
| adeyosemanputra/pygoat @ 19d17cc8 | 80 | 4,013 | 0.36s | 9 | 3 | 6 |
| postmanlabs/httpbin @ f8ec666b | 8 | 3,292 | 0.21s | 0 | 0 | 0 |
| miguelgrinberg/microblog @ a975ef64 | 34 | 1,843 | 0.21s | 0 | 0 | 0 |
| pallets/flask @ d73fa1cd | 83 | 18,345 | 1.06s | 2 | 0 | 2 |
| **Total** | 265 | 30,286 | | **22** | **14** | **8** |

Notable: cross-file SQL injection in vulpy is reported with the full route
from `request.form` in one module to `cursor.execute` in another. On the
maintained projects (httpbin, microblog, flask) there are no true positives;
the two false positives in Flask come from treating environment variables as
untrusted for command injection, and the six in pygoat are password hashes.
The first run also missed an SSTI in Vulnerable-Flask-App (`request.url` was
not a source) and reported one false SSRF in microblog; both were fixed with
general rule changes, disclosed in bench/public_repos.md.

## 7. Performance

Machine: AMD Ryzen 5 5500U (6 cores / 12 threads, laptop), 15.3 GB RAM,
Windows 11, Python 3.13.3. The scanner runs single-threaded.

| Target | Files | Lines | Wall clock (scanner's own timing) |
|---|---|---|---|
| Generated project (`bench/gen_large_repo.py`, seed 1234) | 500 | 153,198 | 19.1–19.4s (3 runs) |
| Same project, before the optimisation pass | 500 | 153,198 | 50.2s |
| Labelled corpus | 80 | 1,151 | 0.17s |
| pallets/flask | 83 | 18,345 | 1.06s |

Inside pytest (`pytest -m slow`), the same 500-file scan measured 25.8s,
because Windows Defender also scans the freshly generated files. The budget
is 60s. What made it fast is described in README.md ("Performance").

## 8. Reproducing every number

```
pip install -e ".[test]"
python bench/evaluate.py                      # section 2 (add --json for raw numbers)
scanner scan corpus/safe/sqli_executor_task.py --rules rules.yaml   # section 3
scanner scan corpus/vulnerable/sqli_django_view.py --rules rules.yaml  # section 4
python bench/gen_large_repo.py bench/large_repo  # section 7
scanner scan bench/large_repo --rules rules.yaml --format sarif -o large.sarif
pytest -m slow                                # the 60s assertion
# section 6: clone each repository at the listed commit into bench/repos/, then
scanner scan bench/repos/<name> --rules rules.yaml
```
