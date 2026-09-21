"""Name resolution: map expressions to fully-qualified dotted names.

What this module follows
------------------------
* ``import a.b`` / ``import a.b as x`` / ``from a import b as c`` at module
  level, including inside ``if``/``try``/``with`` blocks. Conditional imports
  (``try: import ujson as json`` / ``except ImportError: import json``) give a
  name *several* candidates; a pattern matches if any candidate does.
* Relative imports (``from .db import q``, ``from .. import x``), resolved
  against the importing file's package.
* Module-level aliases: ``req = flask.request`` makes ``req.args`` resolve to
  ``flask.request.args``. Inside functions the taint engine tracks the same
  aliases flow-sensitively (``r = request`` then ``r.args.get``).
* Unshadowed builtins resolve to ``builtins.<name>``.
* ``getattr(obj, "constant")`` resolves like ``obj.constant``.
* Calls produce a :data:`RET` reference ("the value returned by calling X"),
  which the taint engine turns into an instance reference when X is a class
  defined in the scanned project.

What it does not follow (documented in README.md)
-------------------------------------------------
* The types of arbitrary objects. ``cur = conn.cursor(); cur.execute(q)``
  leaves ``cur`` unresolved; the call is presented to patterns as
  ``<unknown>.execute``, which only ``*`` can match.
* ``getattr``/``setattr`` with non-constant names, ``obj.__dict__[...]``,
  ``importlib.import_module``/``__import__`` with dynamic strings.
* ``from x import *`` (names it brings in stay unknown).
* Monkey-patching, decorators that replace functions, metaclasses.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Iterable

from .patterns import BUILTIN_NAMES

if TYPE_CHECKING:  # pragma: no cover
    from .context import ModuleContext

PATH = "path"  # a dotted name: module, module attribute, function, class...
INST = "inst"  # an instance of the class with this dotted name
BOUND = "bound"  # attribute ``name`` looked up on an instance (Class.attr)
RET = "ret"  # the value returned by calling the callable with this name


@dataclass(frozen=True, slots=True, order=True)
class Ref:
    kind: str
    name: str


NO_REFS: frozenset[Ref] = frozenset()
Lookup = Callable[[str], "frozenset[Ref] | None"]
ClassOracle = Callable[[str], "str | None"]


def target_names(target: ast.AST) -> list[str]:
    """Every plain name bound by an assignment target."""
    out: list[str] = []
    stack = [target]
    while stack:
        node = stack.pop()
        if isinstance(node, ast.Name):
            out.append(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            stack.extend(reversed(node.elts))
        elif isinstance(node, ast.Starred):
            stack.append(node.value)
    return out


def is_dotted(node: ast.AST) -> bool:
    while isinstance(node, ast.Attribute):
        node = node.value
    return isinstance(node, ast.Name)


class ModuleResolver:
    """Module-level (flow-insensitive) bindings plus expression resolution."""

    def __init__(self, module_name: str, is_package: bool, tree: ast.Module) -> None:
        self.module_name = module_name
        self.package = module_name if is_package else module_name.rpartition(".")[0]
        self.bindings: dict[str, frozenset[Ref]] = {}
        # Names bound at module level by something other than an import/alias
        # (plain assignments, loop variables...). They shadow builtins.
        self.assigned: set[str] = set()
        # Names of functions/classes/lambdas defined at module level.
        self.defined: dict[str, str] = {}
        self._collect(tree)

    # -- imports ---------------------------------------------------------------

    def absolute_module(self, module: str | None, level: int) -> str | None:
        if not level:
            return module
        base = self.package.split(".") if self.package else []
        if level - 1 > len(base):
            return None
        base = base[: len(base) - (level - 1)]
        if module:
            base = base + module.split(".")
        return ".".join(base) if base else None

    def import_bindings(self, node: ast.Import | ast.ImportFrom) -> list[tuple[str, Ref | None]]:
        """``(local name, reference)`` pairs bound by an import statement.

        The reference is ``None`` when the target cannot be resolved (a relative
        import climbing above the top-level package).
        """
        out: list[tuple[str, Ref | None]] = []
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    out.append((alias.asname, Ref(PATH, alias.name)))
                else:
                    top = alias.name.split(".")[0]
                    out.append((top, Ref(PATH, top)))
            return out
        mod = self.absolute_module(node.module, node.level)
        for alias in node.names:
            if alias.name == "*":
                continue
            local = alias.asname or alias.name
            out.append((local, Ref(PATH, f"{mod}.{alias.name}") if mod else None))
        return out

    # -- module-level collection -------------------------------------------------

    def _bind(self, name: str, refs: Iterable[Ref]) -> None:
        refs = frozenset(refs)
        if refs:
            self.bindings[name] = self.bindings.get(name, NO_REFS) | refs

    def _collect(self, tree: ast.Module) -> None:
        pending: list[tuple[str, ast.expr]] = []
        mod = self.module_name

        def visit(stmts: list[ast.stmt]) -> None:
            for s in stmts:
                if isinstance(s, (ast.Import, ast.ImportFrom)):
                    for name, ref in self.import_bindings(s):
                        if ref is None:
                            self.assigned.add(name)
                        else:
                            self._bind(name, [ref])
                elif isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._bind(s.name, [Ref(PATH, f"{mod}.{s.name}")])
                    self.defined[s.name] = "function"
                elif isinstance(s, ast.ClassDef):
                    self._bind(s.name, [Ref(PATH, f"{mod}.{s.name}")])
                    self.defined[s.name] = "class"
                elif isinstance(s, (ast.Assign, ast.AnnAssign)):
                    targets = s.targets if isinstance(s, ast.Assign) else [s.target]
                    value = s.value
                    for t in targets:
                        if isinstance(t, ast.Name) and value is not None:
                            if isinstance(value, ast.Lambda):
                                self._bind(t.id, [Ref(PATH, f"{mod}.{t.id}")])
                                self.defined[t.id] = "lambda"
                            elif is_dotted(value) or isinstance(value, ast.Call):
                                pending.append((t.id, value))
                                if isinstance(value, ast.Call):
                                    self.assigned.add(t.id)  # a value, not a pure alias
                            else:
                                self.assigned.add(t.id)
                        else:
                            self.assigned.update(target_names(t))
                elif isinstance(s, ast.AugAssign):
                    self.assigned.update(target_names(s.target))
                elif isinstance(s, (ast.For, ast.AsyncFor)):
                    self.assigned.update(target_names(s.target))
                    visit(s.body)
                    visit(s.orelse)
                elif isinstance(s, (ast.While, ast.If)):
                    visit(s.body)
                    visit(s.orelse)
                elif isinstance(s, (ast.With, ast.AsyncWith)):
                    for item in s.items:
                        if item.optional_vars is not None:
                            self.assigned.update(target_names(item.optional_vars))
                    visit(s.body)
                elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
                    visit(s.body)
                    for h in s.handlers:
                        if h.name:
                            self.assigned.add(h.name)
                        visit(h.body)
                    visit(s.orelse)
                    visit(s.finalbody)
                elif isinstance(s, ast.Match):
                    for case in s.cases:
                        visit(case.body)

        visit(tree.body)
        # Aliases may refer to each other (a = x.y; b = a.z), so resolve twice.
        for _ in range(2):
            for name, value in pending:
                refs = self.refs_for(value, self.module_lookup)
                if refs:
                    self._bind(name, refs)
        for name, value in pending:
            if name not in self.bindings:
                self.assigned.add(name)

    # -- lookup ------------------------------------------------------------------

    def module_lookup(self, name: str) -> frozenset[Ref] | None:
        refs = self.bindings.get(name)
        if refs:
            return refs
        if name in BUILTIN_NAMES and name not in self.assigned:
            return frozenset({Ref(PATH, f"builtins.{name}")})
        return None

    def refs_for(self, expr: ast.AST, lookup: Lookup, classes: ClassOracle | None = None) -> frozenset[Ref]:
        """Resolve an expression to references, using ``lookup`` for bare names.

        ``classes`` optionally maps a dotted callee name to the qualified name
        of a class defined in the scanned project; calling such a name yields
        an :data:`INST` reference instead of an opaque :data:`RET` one.
        """
        if isinstance(expr, ast.Name):
            return lookup(expr.id) or NO_REFS
        if isinstance(expr, ast.Attribute):
            base = self.refs_for(expr.value, lookup, classes)
            return attr_refs(base, expr.attr)
        if isinstance(expr, ast.Call):
            func = expr.func
            # getattr(obj, "name") with a constant name is resolved like obj.name
            if (
                isinstance(func, ast.Name)
                and func.id == "getattr"
                and len(expr.args) >= 2
                and isinstance(expr.args[1], ast.Constant)
                and isinstance(expr.args[1].value, str)
                and Ref(PATH, "builtins.getattr") in (lookup("getattr") or NO_REFS)
            ):
                return attr_refs(self.refs_for(expr.args[0], lookup, classes), expr.args[1].value)
            out = set()
            for r in self.refs_for(func, lookup, classes):
                if r.kind == PATH:
                    cls = classes(r.name) if classes is not None else None
                    out.add(Ref(INST, cls) if cls else Ref(RET, r.name))
                elif r.kind == BOUND:
                    out.add(Ref(RET, r.name))
            return frozenset(out)
        return NO_REFS


def attr_refs(base: Iterable[Ref], attr: str) -> frozenset[Ref]:
    out = set()
    for r in base:
        if r.kind == PATH:
            out.add(Ref(PATH, f"{r.name}.{attr}"))
        elif r.kind == INST:
            out.add(Ref(BOUND, f"{r.name}.{attr}"))
    return frozenset(out)


def candidate_names(refs: Iterable[Ref]) -> list[tuple[str, ...]]:
    """Dotted names (as segment tuples) that patterns are matched against."""
    names = {tuple(r.name.split(".")) for r in refs if r.kind in (PATH, BOUND)}
    return sorted(names)


class ProjectIndex:
    """Maps dotted module names to the scanned files that define them."""

    def __init__(self, modules: "list[ModuleContext]") -> None:
        self.by_name: dict[str, list[ModuleContext]] = {}
        for mod in modules:
            self.by_name.setdefault(mod.module_name, []).append(mod)
        for mods in self.by_name.values():
            mods.sort(key=lambda m: m.path)

    def module(self, name: str, near: str | None = None) -> "ModuleContext | None":
        mods = self.by_name.get(name)
        if not mods:
            return None
        if len(mods) > 1 and near is not None:
            near_dir = near.rpartition("/")[0]
            for m in mods:
                if m.path.rpartition("/")[0] == near_dir:
                    return m
        return mods[0]

    def split(self, dotted: str, near: str | None = None) -> "tuple[ModuleContext, list[str]] | None":
        """Split ``a.b.c.d`` into (the longest project module prefix, rest)."""
        parts = dotted.split(".")
        for i in range(len(parts), 0, -1):
            mod = self.module(".".join(parts[:i]), near)
            if mod is not None:
                return mod, parts[i:]
        return None

    def canonical(self, dotted: str, near: str | None = None, _depth: int = 0) -> str:
        """Follow re-exports: ``pkg.helper`` -> ``pkg.utils.helper``.

        If ``pkg/__init__.py`` does ``from .utils import helper``, a reference
        to ``pkg.helper`` is rewritten to where the function is defined.
        """
        if _depth > 5:
            return dotted
        found = self.split(dotted, near)
        if found is None:
            return dotted
        mod, rest = found
        if not rest:
            return dotted
        head = rest[0]
        res = mod.resolver
        if head in res.defined:
            return dotted
        refs = sorted(r for r in res.bindings.get(head, NO_REFS) if r.kind == PATH)
        if not refs:
            return dotted
        target = ".".join([refs[0].name] + rest[1:])
        if target == dotted:
            return dotted
        return self.canonical(target, mod.path, _depth + 1)
