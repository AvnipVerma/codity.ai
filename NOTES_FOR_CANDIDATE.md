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
