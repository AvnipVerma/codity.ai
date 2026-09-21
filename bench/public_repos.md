# Public repositories: runs and manual triage

Six public Python repositories were scanned with the shipped `rules.yaml`: two
intentionally vulnerable Flask apps, one intentionally vulnerable Django app,
and three real, maintained Flask projects. Every finding was triaged by hand
by reading the code (35 findings in total, all of them triaged below).

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
| [adeyosemanputra/pygoat](https://github.com/adeyosemanputra/pygoat) | `19d17cc8` | 80 | 4,013 | 0.40s | 22 |
| [postmanlabs/httpbin](https://github.com/postmanlabs/httpbin) | `f8ec666b` | 8 | 3,292 | 0.21s | 0 |
| [miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) | `a975ef64` | 34 | 1,843 | 0.21s | 0 |
| [pallets/flask](https://github.com/pallets/flask) | `d73fa1cd` | 83 | 18,345 | 1.06s | 2 |

**Triage summary: 35 findings, 27 true positives, 8 false positives, 0 unsure
(precision 77% on this sample).** All eight false positives come from two
deliberate choices: environment variables as a command-injection source (2)
and password *hashes* looking like passwords (6).

## How the rules changed during this exercise (full disclosure)

The first run found 2 findings in Vulnerable-Flask-App, 1 in microblog and
9 in pygoat. Triage showed three gaps, each fixed by a general change rather
than a special case, after which everything was re-run (the numbers above are
from the final run):

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
3. **Framework request objects.** Every Django-side injection in pygoat was a
   false negative, because Django passes `request` to views as a parameter.
   Rules gained `typed_parameters` (in a module importing `django`, a
   parameter named `request` is a `django.http.HttpRequest`; likewise DRF and
   aiohttp), annotated parameters are typed from their annotation, and Django
   sources, XSS sinks and sanitizers were added. Re-run: 13 new pygoat
   findings, all true positives (findings 15–27 below).

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

### adeyosemanputra/pygoat: 22 findings, 16 TP, 6 FP

| # | Rule | Location | Verdict | Reason |
|---|---|---|---|---|
| 12 | py.insecure-deserialization | dockerized_labs/insec_des_lab/main.py:36 | TP | Flask lab: `pickle.loads(base64.b64decode(request.form.get('serialized_data')))`. |
| 13 | py.hardcoded-secret | dockerized_labs/sensitive_data_exposure/sensitive_data_lab/settings.py:8 | TP | Hard-coded Django `SECRET_KEY`. |
| 14 | py.hardcoded-secret | pygoat/settings.py:25 | TP | Hard-coded Django `SECRET_KEY`. |
| 15 | py.sql-injection | introduction/views.py:162 | TP | Login lab: `request.POST.get('name')` concatenated into the query passed to `login.objects.raw(sql_query)`. |
| 16 | py.sql-injection | introduction/views.py:162 | TP | Same sink, the password field. |
| 17 | py.insecure-deserialization | introduction/views.py:214 | TP | `token = request.COOKIES.get('token')`, base64-decoded, then `pickle.loads(token)` (the `if token == None` branch is correctly treated as clean). |
| 18 | py.command-injection | introduction/views.py:430 | TP | `domain` from `request.POST` (a regex strips only the protocol prefix) goes into `"dig {}".format(domain)` and `Popen(..., shell=True)`. |
| 19 | py.command-injection | introduction/views.py:460 | TP | `eval(request.POST.get('val'))`. |
| 20 | py.insecure-deserialization | introduction/views.py:560 | TP | `yaml.load(request.FILES["file"], yaml.Loader)` on an upload. |
| 21 | py.sql-injection | introduction/views.py:878 | TP | Second SQL lab: `sql_lab_table.objects.raw(...)` built from `request.POST['name']`. |
| 22 | py.sql-injection | introduction/views.py:878 | TP | Same sink, the password field. |
| 23 | py.path-traversal | introduction/views.py:927 | TP | `open(os.path.join(dirname, request.POST["blog"]))`: arbitrary file read. |
| 24 | py.ssrf | introduction/views.py:963 | TP | `requests.get(request.POST["url"])`. |
| 25 | py.command-injection | introduction/mitre.py:218 | TP | `eval(request.POST.get('expression'))`. |
| 26 | py.command-injection | introduction/mitre.py:233 | TP | `"nmap " + request.POST.get('ip')` passed to helper `command_out()`, which runs `Popen(command, shell=True)` (interprocedural). |
| 27 | py.path-traversal | introduction/playground/ssrf/main.py:8 | TP | The code-checker API extracts `value="..."` attributes from user-supplied HTML (`request.POST['html_code']`, introduction/apis.py:27) and passes each to `main.ssrf_lab()`, which opens it as a file name. Crosses two modules and a star-imported helper. |
| 28 | py.hardcoded-secret | introduction/views.py:870 | FP | `sql_lab_table(id="slinky", password="b4f9...")` seeds an MD5 *hash* into a demo table; not a usable credential. |
| 29 | py.hardcoded-secret | introduction/views.py:872 | FP | Same, another seeded MD5 hash. |
| 30 | py.hardcoded-secret | introduction/views.py:1164 | FP | `USER_A7_LAB3[...]["password"]`: SHA-256 hash in a demo user table. |
| 31 | py.hardcoded-secret | introduction/views.py:1165 | FP | Same. |
| 32 | py.hardcoded-secret | introduction/views.py:1166 | FP | Same. |
| 33 | py.hardcoded-secret | introduction/views.py:1167 | FP | Same. |

The false positives are hex digests under a `password` key. Hex alone does not
tell a digest from a key: the vulpy `SECRET_KEY` above is also 64 hex
characters and is a real secret. Telling them apart needs different thresholds
per name group, which the rule format does not have (see DECISIONS.md).

Missed: `introduction/playground/A9` writes user-submitted code to a `.py`
file that is later imported (code injection through a file write, which no
shipped rule describes); XXE and weak-crypto labs are outside the rule classes.

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
| 34 | py.command-injection | src/flask/cli.py:1023 | FP | `flask shell` evaluates the file named by `$PYTHONSTARTUP`, mirroring the Python REPL. The environment is controlled by the operator. |
| 35 | py.command-injection | src/flask/config.py:209 | FP | `Config.from_envvar()` executes the config file named by an environment variable, by design. The finding is interprocedural (`from_envvar` -> `from_pyfile`). |

Both follow from listing `os.environ` as a command-injection source, as the
brief's example rule does for SQL injection. For library and CLI code that
choice is noisy; for web code it catches real bugs. DECISIONS.md discusses the
trade-off.
