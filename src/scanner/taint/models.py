"""Built-in knowledge about library behaviour that is not a rule.

Rules (sources, sinks, sanitizers) live in rules.yaml. What lives here are
facts about Python itself that every rule relies on, kept in one place so they
are easy to audit:

* calls whose result cannot carry an injection payload (``len(x)``,
  ``s.startswith(p)``, ``s.isdigit()``...), which return a clean value even
  when their input is tainted (a precision choice);
* methods that mutate their receiver (``lst.append(x)``) so the receiver
  becomes tainted;
* container accessors that are field-sensitive on constant keys;
* checks that prove a value is safe inside the guarded branch;
* calls that never return (``flask.abort``), which end a control-flow path.
"""

from __future__ import annotations

# Methods returning bool / int / None whatever the receiver holds.
NON_PROPAGATING_METHODS = frozenset(
    {
        "startswith",
        "endswith",
        "isdigit",
        "isdecimal",
        "isnumeric",
        "isalnum",
        "isalpha",
        "isascii",
        "isidentifier",
        "islower",
        "isupper",
        "isspace",
        "istitle",
        "isprintable",
        "count",
        "find",
        "rfind",
        "index",
        "rindex",
        "__len__",
        "__contains__",
        "exists",
        "is_file",
        "is_dir",
        "hexdigest",
        "digest",
    }
)

# Functions returning bool / int / None (or a fresh object unrelated to input).
NON_PROPAGATING_CALLS = frozenset(
    {
        "builtins.len",
        "builtins.bool",
        "builtins.isinstance",
        "builtins.issubclass",
        "builtins.hasattr",
        "builtins.callable",
        "builtins.id",
        "builtins.hash",
        "builtins.type",
        "builtins.print",
        "builtins.any",
        "builtins.all",
        "os.path.exists",
        "os.path.isfile",
        "os.path.isdir",
        "os.path.islink",
        "os.path.isabs",
        "os.path.getsize",
        "os.path.getmtime",
        "hmac.compare_digest",
        "secrets.compare_digest",
    }
)

# Methods that store their arguments into the receiver.
MUTATING_METHODS = frozenset(
    {"append", "extend", "insert", "add", "update", "setdefault", "appendleft", "extendleft", "write", "writelines"}
)

# Container reads: ``d.get("k")`` reads field "k"; the others read everything.
KEYED_GETTERS = frozenset({"get", "pop"})
WHOLE_GETTERS = frozenset({"values", "items", "keys", "copy", "popitem"})

# ``if x.isdigit():`` proves ``x`` holds no injection payload inside the branch.
VALIDATING_METHODS = frozenset({"isdigit", "isdecimal", "isnumeric", "isalnum", "isalpha", "isidentifier"})

# Calls that never return normally; the statement after them is unreachable.
NORETURN_CALLS = frozenset(
    {
        "flask.abort",
        "werkzeug.exceptions.abort",
        "sys.exit",
        "builtins.exit",
        "builtins.quit",
        "os._exit",
        "os.abort",
    }
)

# Human-readable step descriptions for string building.
FORMAT_METHODS = {
    "format": "formatted with str.format()",
    "format_map": "formatted with str.format_map()",
    "join": "joined into a string",
}
