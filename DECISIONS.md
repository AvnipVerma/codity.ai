# Decisions

## 1. How taint is represented, and what I rejected

A value's taint is a set of **facts**. Each fact is keyed by
`(origin, live rule ids)` and maps to a **path**, the steps the data took.
The origin is a concrete source site, or a symbolic "parameter k of function
f", which is how summaries are expressed. Rules travel with the fact: a
sanitizer removes only its own rule ids (`shlex.quote` clears command
injection but not SQL injection), and one pass serves every rule. Where two
routes reach the same key, the shorter one is kept (ties broken by position),
so joins are deterministic and loop fixpoints terminate. Variables keep taint
per access path: `x`, `x.attr`, `x['const']`, `x[*]`, two levels deep. That is
what makes `params['order']` clean while `params['q']` is tainted, and lets a
lookup in a constant table stay clean.

Rejected alternatives:

- **One taint bit per variable.** It loses the path, which the brief values
  most, and it loses per-rule sanitizing.
- **Full SSA with a separate dataflow framework.** Better precision at merge
  points, but too much machinery for the time; walking the AST with
  copy-on-branch states gets most of the benefit.
- **Re-analysing callees at every call site (inlining).** Precise, but it
  blows up on real call graphs, whereas summaries plus a dependency-driven
  worklist visit most functions once.
- **Any dataflow library.** Not allowed.

## 2. Finding identity for baselines, and what breaks it

`fingerprint = sha256("codity/v1" | rule id | relative path | identity...)`.
For taint findings the identity is `ast.unparse` of the sink call and of the
source expression; for secrets, the variable name plus the sha256 of the value
(the value itself never appears). `ast.unparse` normalises whitespace and
comments, and no line numbers or function names are involved, so moving code,
reformatting, renaming or reordering functions keep the identity. Identical
fingerprints are compared as a **multiset**: the baseline stores counts, and
any surplus in a scan is reported, choosing the latest positions. I rejected
an occurrence index, because inserting one duplicate above the others would
renumber them all.

What breaks it: renaming or moving the file (the path is part of the
identity; fixing it would mean matching unmatched baseline entries by
sink+source text across files, which risks conflating real duplicates);
changing the sink call's text (intended: the statement changed); changing the
source expression; and two genuinely different flows with identical text in
one file, which share a fingerprint (the counts still keep the arithmetic
right).

## 3. Precision over recall

The brief says a scanner that cries wolf gets switched off, so where a choice
had to be made I chose precision:

- Calls known to return non-injectable values (`len`, `startswith`,
  `isdigit`, `hexdigest`) return clean values.
- Dict keys and tuple positions are tracked separately.
- `subprocess.*` is a sink only when `shell=True` could hold.
- `yaml.load` is a sink only without a safe loader.
- `request.args.get(x, type=int)` is not a source.
- A URL with a constant scheme and host is not SSRF.
- Membership in a constant collection, equality with a constant and
  `isdigit()` are treated as validation in the guarded branch.
- Environment variables are untrusted only for SQL and command injection.
- A framework's `request` parameter is a source only in modules that import
  that framework.
- A sink consumes its rule's taint, so `execute(text(q))` is one finding.

What this costs in recall: `subprocess.run(["sh", "-c", cmd])`, low-entropy
passwords, and flows through exceptions are missed. Where precision would have
needed information the engine lacks, I kept recall: `*.execute` still matches
receivers of unknown type, which is my worst false positive. The measured
result on my corpus is P 0.922 / R 0.959.

## 4. The rule I most wanted to write

**Reflected XSS through a view's return value**:
`return "<h1>Hello " + request.args["name"] + "</h1>"` in a Flask route. It is
the most common XSS in small Flask apps, and the schema cannot express it,
because sinks are call arguments and here the dangerous operation is the
`return` of a function the framework calls. The engine would need a
*return sink*: "the return value of a function decorated with `*.route`
(or `*.get`, `*.post`...)", checked where the summary's return taint is
already computed. It would also need content-type awareness to avoid flagging
`return jsonify(...)` or plain-text responses (Flask's default for a
returned `str` is `text/html`). I first wanted Django views, whose `request`
parameter has no dotted name; that turned out to need only a small
`typed_parameters` extension, now shipped.

## 5. What I cut, and what another week would bring

Cut:

- Receiver typing beyond classes in the scan.
- Guard summaries (validation inside helper functions).
- Heap aliasing (`b = a; b.append(t)`).
- Taint through exceptions.
- Regex-based validators, which I would have had to interpret.
- Template-file analysis.
- Parallel parsing.

With another week, in order:

1. Return sinks for route handlers (section 4).
2. A DB-API return-type table, so SQL sinks can require a cursor or
   connection receiver.
3. Guard summaries, so `if not is_valid(x): abort()` kills taint.
4. Shape conditions on sink arguments, for `subprocess.run(["sh", "-c", cmd])`.
5. Per-name-group entropy thresholds for secrets, to tell password hashes
   from keys.
6. FastAPI implicit parameters, and matching baseline entries across file
   renames.

## AI assistance

**TODO(candidate): two specific things the AI got wrong that you caught.**
