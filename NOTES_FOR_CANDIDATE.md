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
   `\x1c`–`\x1e`, ` ` etc., which would shift our line numbers away from
   `ast`'s for files containing those characters. Replaced with a split on
   `\n` / `\r\n` / `\r` only (`context.split_lines`).
