# Notes for the candidate (not a deliverable — delete before submitting)

A running log of every place the AI assistant corrected its own earlier
approach, made a wrong assumption, introduced a bug, or had to fix a test. Use
it to review the work and to write the "AI assistance" section of
DECISIONS.md yourself.

## Log

1. **PatternIndex ordering (M1).** First version ordered matches by pattern
   *text* while its docstring promised insertion order; two rules sharing the
   same pattern text would then tie and fall back to the order candidate names
   were visited. Rewrote it to carry an explicit insertion sequence number.

2. **Windows newline translation (M1, caught before it shipped).** Writing
   SARIF through `sys.stdout` in text mode on Windows turns `\n` into `\r\n`,
   so the same scan would produce different bytes on Windows and Linux. The CLI
   writes encoded bytes to `sys.stdout.buffer` instead.

3. **Line splitting (M1).** `str.splitlines()` also splits on form feeds,
   the control characters 0x1C-0x1E and U+2028, which would shift our line numbers away from
   `ast`'s for files containing those characters. Replaced with a split on
   `\n` / `\r\n` / `\r` only (`context.split_lines`).

4. **`"***"` in `ignore_values` (M4).** The first draft of the secret rule put
   `"***"` in the placeholder list meaning "a value of asterisks". As an
   `fnmatch` glob it matches *every* string, which would have silently disabled
   the whole rule. Replaced with the escaped glob `"[*][*][*]*"`; a test now
   checks that a real secret is still reported with the shipped rules.

5. **First commit too large.** The M1 "skeleton" commit also contained first
   drafts of suppress.py, baseline.py, the SARIF/table writers and the pattern
   kind. They were written at that point but untested; each gets its tests and
   fixes in its own later milestone commit. History was not rewritten.

6. **Summary dataclass default (M5).** `Summary.ret` defaulted to the shared
   `EMPTY` TaintValue; dataclasses reject unhashable defaults, so the whole
   taint pass crashed on first run (the engine caught it and printed a warning
   instead of findings). Fixed with `default_factory`.

7. **Source reported at the wrong node (M5).** `request.form["name"]` was
   reported as source `request.form` because the attribute matched the source
   pattern before the subscript was applied. Facts created by that exact read
   are now re-rooted at the enclosing subscript (`widen_source`).

8. **Module-level instances were untyped (M10).** `db = Database(...)` at
   module level stayed "result of calling Database", so `db.query(q)` inside a
   function missed the method summary, and `executor.execute(task)` on a
   project class fell back to the `*.execute` SQL sink — a false positive the
   design was supposed to prevent. Added a class oracle so calls to project
   classes yield instance references everywhere (module bindings included).

9. **`super().__init__(q)` lost field writes (M10).** The base constructor's
   `self.q = q` was only instantiated into the class field store, which keeps
   concrete facts; the parameter-derived write never reached the child's own
   summary. Writes through `self.method()`/`super()` now also update the
   caller's `self`.

10. **Same module name in two directories (M11).** Qualified names like
    `utils.q` collided for `tool_a/utils.py` and `tool_b/utils.py`; lookups
    went to whichever was registered first. Function/class lookup is now per
    file, using the importing file's directory to pick the right module.

11. **Test expectation wrong (M10).** A test asserted the call step was on
    line 9; counting the snippet's leading blank line, it is line 10. The code
    was right, the test was wrong.

12. **Nested sinks reported twice (M12).** `engine.execute(text(q))` produced
    two findings (inner `text()` and outer `execute()`) for one bug. Sinks now
    consume their rule's taint on their return value.

13. **First corpus run (M13): P 0.872 / R 0.932 / F1 0.901.** Labels were
    written before running the scanner and were not changed afterwards. One
    false positive was a genuine engine bug: `LOOKUP.get(user_key, default)` on
    a module-level constant dict was treated as a library call (subscripting
    the same dict was already clean). Fixed; now P 0.891 / R 0.932 / F1 0.911.
    The remaining 5 FP / 3 FN are all cases predicted in the labels' notes.

14. **Real-world idioms added after reviewing the corpus (M13).** Not corpus
    tuning (none of these occur in the corpus, numbers unchanged): methods on
    library-constructed objects (`requests.Session().get`), `when:` conditions
    on sources (`request.args.get("n", type=int)`), `force_values` for PEM
    private keys and provider-prefixed tokens (the "* *" prose filter would
    otherwise hide PEM blocks, which contain spaces), `.hexdigest()` as
    non-injectable, `with X() as s:` aliasing.

15. **`type=int` source exclusion leaked receiver taint (M13).** After a call
    stopped being a source because of `type=int`, the receiver
    `request.args` (itself a source) flowed into the result through the
    library default. Excluded sources now act as sanitizers for their rule.

16. **Broken test fixture (M13).** A test spliced a PEM string with real
    newlines into a one-line Python literal and produced unparseable source;
    the scanner correctly reported a syntax error. Fixed the test.

17. **GitHub push protection (M13).** A test used a Stripe-format live key
    (`sk_live_…`, a variant of Stripe's documentation key) as a literal; GitHub
    rejected the push. The token is now assembled at runtime in the test. The
    commit containing it had not been pushed, so that single local commit was
    amended (the only amend in the history; order of work unchanged).
