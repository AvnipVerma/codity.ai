# Public repositories: runs and manual triage

Six public Python repositories were scanned with the shipped `rules.yaml`: two
intentionally vulnerable Flask apps, one intentionally vulnerable Django app,
and three real, maintained Flask projects. Every finding was triaged by hand
by reading the code (22 findings in total, all of them triaged below).

Clones live in `bench/repos/` (git-ignored; no third-party code is committed).
To reproduce:

```
git clone https://github.com/we45/Vulnerable-Flask-App bench/repos/Vulnerable-Flask-App
git -C bench/repos/Vulnerable-Flask-App checkout b6a4f97afd466e83e1f60781494252dec1c37039
# ...likewise for the others, then:
scanner scan bench/repos/Vulnerable-Flask-App --rules rules.yaml --format table
```

Timings are wall-clock numbers printed by the scanner on the machine described
in README.md (AMD Ryzen 5 5500U, Windows 11, Python 3.13).

| Repository | Commit | .py files | Lines | Scan time | Findings |
|---|---|---|---|---|---|
| [we45/Vulnerable-Flask-App](https://github.com/we45/Vulnerable-Flask-App) | `b6a4f97a` | 3 | 420 | 0.07s | 3 |
| [fportantier/vulpy](https://github.com/fportantier/vulpy) | `5249cc8b` | 57 | 2,373 | 0.57s | 8 |
| [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | `19d17cc8` | 80 | 4,013 | 0.36s | 9 |
| [postmanlabs/httpbin](https://github.com/postmanlabs/httpbin) | `f8ec666b` | 8 | 3,292 | 0.21s | 0 |
| [miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) | `a975ef64` | 34 | 1,843 | 0.21s | 0 |
| [pallets/flask](https://github.com/pallets/flask) | `d73fa1cd` | 83 | 18,345 | 1.06s | 2 |

**Triage summary: 22 findings, 14 true positives, 8 false positives, 0 unsure
(precision 64% on this sample).** Seven of the eight false positives come from
two deliberate choices: environment variables as a command-injection source (2)
and password *hashes* looking like passwords (6).

## How the rules changed during this exercise (full disclosure)

The first run found 2 findings in Vulnerable-Flask-App and 1 in microblog.
Triage showed two gaps, both fixed by general changes rather than special
cases, after which everything was re-run (the numbers above are the re-run):

1. **Missing sources.** The Vulnerable-Flask-App 404 handler renders
   `request.url` with `render_template_string` (SSTI). `request.url`, `.path`,
   `.full_path`, `.query_string`, `.base_url`, `.referrer` and `.user_agent`
   were not listed as sources. They are attacker-controlled, so they were added
   to every rule. Re-run: the SSTI is now reported (finding 3 below).
2. **Fixed-host URLs.** microblog's `translate()` sends user-chosen language
   codes in the query string of a hard-coded Microsoft Translator URL, which
   was reported as SSRF. The same false-positive class was already predicted in
   the corpus (`safe/ssrf_fixed_host_path.py`). A new optional rule field,
   `safe_prefixes`, removes a rule's taint from strings whose constant leading
   text matches a glob; the SSRF rule uses `["http://*/*", "https://*/*"]`
   (scheme and host fixed). Re-run: microblog is clean. `"https://" + host`
   and `f"https://{host}/..."` are still reported (tested).

## Triage

### we45/Vulnerable-Flask-App: 3 findings, 3 TP

| # | Rule | Location | Verdict | Reason |
|---|---|---|---|---|
| 1 | py.sql-injection | app/app.py:265 | TP | `content['search']` from `request.json` is `%`-formatted into a query passed to `db.engine.execute`. |
| 2 | py.insecure-deserialization | app/app.py:329 | TP | An uploaded file is saved and its contents passed to `yaml.load()` without a safe loader. The path runs through `secure_filename()`, which sanitizes only path traversal. |
| 3 | py.xss-template | app/app.py:114 | TP | 404 handler: `'...%s...' % request.url` rendered with `render_template_string` (SSTI). |

Missed (false negatives): the `/search` error handler renders `str(e)` of a
database exception containing the user's input with `render_template_string`.
Taint does not flow through exceptions, a documented limit. Hard-coded HMAC
keys `'secret'` and `'am0r3C0mpl3xK3y'` and the seeded `password = 'admin123'`
fall below the 3.5-bit entropy threshold. JWT `verify=False` and XXE are not
among the shipped rule classes.

### fportantier/vulpy: 8 findings, 8 TP

| # | Rule | Location | Verdict | Reason |
|---|---|---|---|---|
| 4 | py.sql-injection | bad/libuser.py:12 | TP | `login()` formats `username` into `SELECT ... WHERE username = '{}'`; source `request.form.get('username')` in bad/mod_user.py (cross-file). |
| 5 | py.sql-injection | bad/libuser.py:12 | TP | Same sink, second source: `request.get_json()` in bad/mod_api.py via `libapi.keygen()` (two files, three functions). |
| 6 | py.sql-injection | bad/libuser.py:12 | TP | Same sink, `password` from `request.form`. |
| 7 | py.sql-injection | bad/libuser.py:25 | TP | `create()`: `%`-formatted INSERT with the password from the registration form. |
| 8 | py.sql-injection | bad/libuser.py:25 | TP | Same sink, username. |
| 9 | py.sql-injection | bad/libuser.py:53 | TP | `password_change()`: `.format()` into an UPDATE. |
| 10 | py.path-traversal | bad/libapi.py:22 | TP | `Path('/tmp/vulpy.apikey.{}.{}'.format(username, key)).touch()`; a username containing `../` creates files outside /tmp. |
| 11 | py.hardcoded-secret | good/vulpy.py:17 | TP | Flask `SECRET_KEY` hard-coded (64 hex chars), even in the "good" variant. |

Worth noting: `bad/` and `good/` both contain `libuser.py`, `libapi.py` and so
on. Each blueprint's `import libuser` resolves to its own sibling directory,
so nothing is reported for `good/libuser.py`, which uses parameters.
Missed: stored XSS through Jinja's `|safe` in `bad/templates/*.html`
(templates are not analysed), the unsigned base64 session cookie, and CSRF.
None of these is a Python source-to-sink flow.

### adeyosemanputra/pygoat: 9 findings, 3 TP, 6 FP

| # | Rule | Location | Verdict | Reason |
|---|---|---|---|---|
| 12 | py.insecure-deserialization | dockerized_labs/insec_des_lab/main.py:36 | TP | Flask lab: `pickle.loads(base64.b64decode(request.form.get('serialized_data')))`. |
| 13 | py.hardcoded-secret | dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8 | TP | Hard-coded Django `SECRET_KEY`. |
| 14 | py.hardcoded-secret | pygoat/settings.py:25 | TP | Hard-coded Django `SECRET_KEY`. |
| 15 | py.hardcoded-secret | introduction/views.py:870 | FP | `sql_lab_table(id="slinky", password="b4f9...")` seeds an MD5 *hash* into a demo table; not a usable credential. |
| 16 | py.hardcoded-secret | introduction/views.py:872 | FP | Same, another seeded MD5 hash. |
| 17 | py.hardcoded-secret | introduction/views.py:1164 | FP | `USER_A7_LAB3[...]["password"]`: SHA-256 hash in a demo user table. |
| 18 | py.hardcoded-secret | introduction/views.py:1165 | FP | Same. |
| 19 | py.hardcoded-secret | introduction/views.py:1166 | FP | Same. |
| 20 | py.hardcoded-secret | introduction/views.py:1167 | FP | Same. |

The false positives are hex digests under a `password` key. Hex alone does not
tell a digest from a key: the vulpy `SECRET_KEY` above is also 64 hex
characters and is a real secret. Telling them apart needs different thresholds
per name group, which the rule format does not have (see DECISIONS.md).

Missed: pygoat is mostly Django. Its views receive `request` as a parameter,
which is not a modelled source, so the Django SQL injection
(`introduction/views.py:162`, `login.objects.raw(sql_query)`), cookie
unpickling (`views.py:214`), `subprocess.Popen(..., shell=True)`
(`views.py:430`, `mitre.py:233`) and `eval()` (`mitre.py:218`) are all false
negatives. This is the largest known gap; README.md describes what supporting
it would take.

### postmanlabs/httpbin: 0 findings

httpbin echoes request data back in JSON responses and never builds queries,
commands or paths from it. No findings is correct; no false positives on 3.3k
lines of request-heavy Flask code.

### miguelgrinberg/microblog: 0 findings (after the `safe_prefixes` change)

The first run reported `app/translate.py:14` (SSRF), a false positive
explained above. The app uses the SQLAlchemy ORM throughout, and nothing else
was reported.

### pallets/flask: 2 findings, 2 FP

| # | Rule | Location | Verdict | Reason |
|---|---|---|---|---|
| 21 | py.command-injection | src/flask/cli.py:1023 | FP | `flask shell` evaluates the file named by `$PYTHONSTARTUP`, mirroring the Python REPL. The environment is controlled by the operator. |
| 22 | py.command-injection | src/flask/config.py:209 | FP | `Config.from_envvar()` executes the config file named by an environment variable, by design. The finding is interprocedural (`from_envvar` -> `from_pyfile`). |

Both follow from listing `os.environ` as a command-injection source, as the
brief's example rule does for SQL injection. For library and CLI code that
choice is noisy; for web code it catches real bugs. DECISIONS.md discusses the
trade-off.
