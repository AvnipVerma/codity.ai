"""Whole-program taint analysis: function table, summaries and the fixpoint.

Every function in every scanned file (module-level functions, methods, nested
functions, lambdas bound to names, plus one ``<module>`` pseudo-function per
file for top-level code) is analysed by :class:`FunctionAnalyzer`, producing a
summary and the findings located in it.

Analyses depend on each other: a call site reads its callee's summary, a
method reads the taint stored on ``self`` fields by other methods, a function
reads module globals, a nested function reads its parent's locals. We run a
worklist: every function starts queued (callees first, from a syntactic call
graph); whenever an analysis changes something another analysis consumed, the
consumers are re-queued. Everything is monotone (facts only accumulate, paths
only get shorter), so this reaches a fixpoint; a per-function visit cap is a
safety net. Unanalysed callees contribute nothing (the least fixpoint starts
from "no flows"), never the conservative library default.

The findings recorded by each function's *last* analysis are final: that
analysis ran with inputs that did not change afterwards.
"""

from __future__ import annotations

import ast
import heapq
from collections import Counter
from dataclasses import dataclass

from ..model import Finding, PathStep, StepKind
from ..resolve import BOUND, INST, PATH, RET, Ref
from .intra import FunctionAnalyzer, is_constant_collection_literal
from .models import MUTATING_METHODS
from .spec import TaintRuleSet
from .summaries import BOTTOM, Summary
from .values import SourceSite, TaintValue, VarVal, better

MAX_VISITS = 40


@dataclass(slots=True)
class Param:
    name: str
    key: int
    kind: str  # "pos" | "kwonly" | "vararg" | "kwarg"
    node: ast.arg
    default: ast.expr | None
    implicit: bool = False  # the self/cls parameter of a method


def _decorator_names(node: ast.AST) -> set[str]:
    out = set()
    for d in getattr(node, "decorator_list", ()):
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Name):
            out.add(target.id)
        elif isinstance(target, ast.Attribute):
            out.add(target.attr)
    return out


def scope_facts(body: list, params: list[str]):
    """Names bound in a function body (Python's scoping rules, simplified).

    Returns ``(locals, globals, nonlocals, has_nested, const_collections)``.
    ``const_collections`` are locals assigned exactly once, to a literal
    collection of constants, and never mutated in place.
    """
    local = set(params)
    globals_: set[str] = set()
    nonlocals: set[str] = set()
    has_nested = False
    stores: Counter = Counter()
    const_candidates: dict[str, bool] = {}
    mutated: set[str] = set()
    stack = list(body)
    while stack:
        node = stack.pop()
        t = type(node)
        if t in (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef):
            local.add(node.name)
            stores[node.name] += 1
            has_nested = True
            stack.extend(node.decorator_list)
            if t is ast.ClassDef:
                stack.extend(node.bases)
            else:
                stack.extend(node.args.defaults)
                stack.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        if t is ast.Lambda:
            has_nested = True
            stack.extend(node.args.defaults)
            stack.extend(d for d in node.args.kw_defaults if d is not None)
            continue
        if t in (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp):
            for sub in ast.walk(node):
                if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                    local.add(sub.target.id)
                    stores[sub.target.id] += 1
                elif isinstance(sub, ast.Lambda):
                    has_nested = True
            continue
        if t is ast.Global:
            globals_.update(node.names)
            continue
        if t is ast.Nonlocal:
            nonlocals.update(node.names)
            continue
        if t is ast.Name:
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                local.add(node.id)
                stores[node.id] += 1
            continue
        if t in (ast.Import, ast.ImportFrom):
            for alias in node.names:
                if alias.name != "*":
                    name = alias.asname or alias.name.split(".")[0]
                    local.add(name)
                    stores[name] += 1
            continue
        if t is ast.ExceptHandler and node.name:
            local.add(node.name)
            stores[node.name] += 1
        elif t in (ast.MatchAs, ast.MatchStar) and node.name:
            local.add(node.name)
            stores[node.name] += 1
        elif t is ast.MatchMapping and node.rest:
            local.add(node.rest)
            stores[node.rest] += 1
        elif t in (ast.Assign, ast.AnnAssign):
            targets = node.targets if t is ast.Assign else [node.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                const_candidates[targets[0].id] = is_constant_collection_literal(node.value)
        elif t is ast.Call:
            f = node.func
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.attr in MUTATING_METHODS:
                mutated.add(f.value.id)
        stack.extend(ast.iter_child_nodes(node))
    local -= globals_ | nonlocals
    consts = frozenset(n for n, ok in const_candidates.items() if ok and stores[n] == 1 and n not in mutated)
    return frozenset(local), frozenset(globals_), frozenset(nonlocals), has_nested, consts


class ClassInfo:
    def __init__(self, qualname: str, module, node: ast.ClassDef) -> None:
        self.qualname = qualname
        self.module = module
        self.node = node
        self.methods: dict[str, FunctionInfo] = {}
        _, _, _, _, consts = scope_facts(
            [s for s in node.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))], []
        )
        self.const_attrs = consts
        self.bases: list[ClassInfo] | None = None


class FunctionInfo:
    def __init__(
        self,
        qualname: str,
        display: str,
        module,
        node: ast.AST,
        kind: str,
        class_info: ClassInfo | None = None,
        method_kind: str | None = None,
        parent: "FunctionInfo | None" = None,
    ) -> None:
        self.qualname = qualname
        self.display = display
        self.module = module
        self.node = node
        self.kind = kind  # "function" | "lambda" | "module"
        self.class_info = class_info
        self.method_kind = method_kind  # "instance" | "class" | "static" | None
        self.parent = parent
        self.params: list[Param] = []
        if kind != "module":
            self._build_params()
        if kind == "module":
            body = node.body
        elif kind == "lambda":
            body = [node.body]
        else:
            body = node.body
        local, globs, nonloc, has_nested, consts = scope_facts(body, [p.name for p in self.params])
        self.local_names = local
        self.global_decls = globs
        self.nonlocal_decls = nonloc
        self.has_nested = has_nested and kind != "module"
        self.const_collections = consts
        self.positional = [p for p in self.params if p.kind == "pos"]
        self.named = [p for p in self.params if p.kind in ("pos", "kwonly")]
        self.by_name = {p.name: p for p in self.named}
        self.vararg = next((p for p in self.params if p.kind == "vararg"), None)
        self.kwarg = next((p for p in self.params if p.kind == "kwarg"), None)

    def __repr__(self) -> str:
        return f"<FunctionInfo {self.qualname}>"

    def _build_params(self) -> None:
        args = self.node.args
        positional = args.posonlyargs + args.args
        defaults = [None] * (len(positional) - len(args.defaults)) + list(args.defaults)
        key = 0
        for i, (a, d) in enumerate(zip(positional, defaults)):
            implicit = i == 0 and self.method_kind in ("instance", "class")
            self.params.append(Param(a.arg, key, "pos", a, d, implicit))
            key += 1
        for a, d in zip(args.kwonlyargs, args.kw_defaults):
            self.params.append(Param(a.arg, key, "kwonly", a, d))
            key += 1
        if args.vararg is not None:
            self.params.append(Param(args.vararg.arg, -1, "vararg", args.vararg, None))
        if args.kwarg is not None:
            self.params.append(Param(args.kwarg.arg, -2, "kwarg", args.kwarg, None))

    def param_name(self, key: int) -> str:
        for p in self.params:
            if p.key == key:
                return ("*" if p.kind == "vararg" else "**" if p.kind == "kwarg" else "") + p.name
        return f"arg {key}"


class TaintProgram:
    def __init__(self, ctx, rules) -> None:
        self.ctx = ctx
        self.rules = TaintRuleSet(rules)
        self.functions: dict[str, FunctionInfo] = {}
        self.classes: dict[str, ClassInfo] = {}
        self.func_by_node: dict[int, FunctionInfo] = {}
        self.class_by_node: dict[int, ClassInfo] = {}
        self.module_consts: dict[str, frozenset] = {}
        # Per-file tables keyed by the name *inside* the module ("f", "C.m"),
        # so two files with the same module name never collide.
        self.module_functions: dict[str, dict[str, FunctionInfo]] = {}
        self.module_classes: dict[str, dict[str, ClassInfo]] = {}
        self._oracles: dict[str, object] = {}
        self.summaries: dict[str, Summary] = {}
        self.fn_findings: dict[str, dict] = {}
        self.fields: dict[str, dict] = {}
        self.globals: dict[tuple, VarVal] = {}
        self.deps: dict[tuple, set] = {}
        self.dirty: set = set()
        self._family: dict[str, str] = {}
        self._canonical: dict[tuple, str] = {}
        self._by_file: dict[str, list[Finding]] = {}

    # ------------------------------------------------------------ building

    def build(self) -> None:
        for mod in self.ctx.modules:
            modfn = FunctionInfo(f"{mod.module_name}.<module>", "<module>", mod, mod.tree, "module")
            self._add(modfn)
            self._collect(mod, mod.tree.body, mod.module_name, None, None)
            self.module_consts[mod.path] = self._module_consts(mod)
        for cls in self.classes.values():
            self._resolve_bases(cls)
        self._build_families()

    def _add(self, fi: FunctionInfo) -> None:
        q = fi.qualname
        if q in self.functions:  # redefinition, or two files with one module name
            n = 2
            while f"{q}#{n}" in self.functions:
                n += 1
            fi.qualname = f"{q}#{n}"
        self.functions[fi.qualname] = fi
        self.func_by_node[id(fi.node)] = fi
        if fi.kind != "module":
            self.module_functions.setdefault(fi.module.path, {}).setdefault(fi.display, fi)

    def _add_class(self, ci: ClassInfo, local: str) -> None:
        q = ci.qualname
        if q in self.classes:
            n = 2
            while f"{q}#{n}" in self.classes:
                n += 1
            ci.qualname = f"{q}#{n}"
        self.classes[ci.qualname] = ci
        self.class_by_node[id(ci.node)] = ci
        self.module_classes.setdefault(ci.module.path, {}).setdefault(local, ci)

    def _collect(self, mod, stmts: list, prefix: str, parent: FunctionInfo | None, cls: ClassInfo | None) -> None:
        base = mod.module_name + "."
        for s in stmts:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}.{s.name}"
                method_kind = None
                if cls is not None:
                    decos = _decorator_names(s)
                    method_kind = "static" if "staticmethod" in decos else "class" if "classmethod" in decos else "instance"
                fi = FunctionInfo(qual, qual[len(base):], mod, s, "function", cls, method_kind, parent)
                self._add(fi)
                if cls is not None:
                    cls.methods[s.name] = fi
                self._collect(mod, s.body, f"{qual}.<locals>", fi, None)
            elif isinstance(s, ast.ClassDef):
                qual = f"{prefix}.{s.name}"
                ci = ClassInfo(qual, mod, s)
                self._add_class(ci, qual[len(base):])
                self._collect(mod, s.body, ci.qualname, parent, ci)
            elif isinstance(s, (ast.Assign, ast.AnnAssign)) and isinstance(s.value, ast.Lambda):
                targets = s.targets if isinstance(s, ast.Assign) else [s.target]
                for t in targets:
                    if isinstance(t, ast.Name):
                        qual = f"{prefix}.{t.id}"
                        fi = FunctionInfo(qual, qual[len(base):], mod, s.value, "lambda", None, None, parent)
                        self._add(fi)
                        break
            else:
                for field in ("body", "orelse", "finalbody"):
                    sub = getattr(s, field, None)
                    if isinstance(sub, list) and sub and isinstance(sub[0], ast.stmt):
                        self._collect(mod, sub, prefix, parent, cls)
                for h in getattr(s, "handlers", ()):
                    self._collect(mod, h.body, prefix, parent, cls)
                for case in getattr(s, "cases", ()):
                    self._collect(mod, case.body, prefix, parent, cls)

    def _module_consts(self, mod) -> frozenset:
        body = [s for s in mod.tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        _, _, _, _, consts = scope_facts(body, [])
        # a function mutating the collection (ALLOWED.add(x)) disqualifies it
        mutated = set()
        for node in ast.walk(mod.tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                f = node.func
                if isinstance(f.value, ast.Name) and f.attr in MUTATING_METHODS:
                    mutated.add(f.value.id)
            elif isinstance(node, ast.Global):
                mutated.update(node.names)
        return frozenset(consts - mutated)

    def is_const_global(self, dotted_name: str, near: str) -> bool:
        split = self.ctx.index.split(dotted_name, near)
        if split is None:
            return False
        mod, rest = split
        if len(rest) == 1:
            return rest[0] in self.module_consts.get(mod.path, ())
        if len(rest) == 2:
            cls = self.module_classes.get(mod.path, {}).get(rest[0])
            return cls is not None and rest[1] in cls.const_attrs
        return False

    def canonical(self, name: str, near: str) -> str:
        key = (name, near)
        got = self._canonical.get(key)
        if got is None:
            got = self._canonical[key] = self.ctx.index.canonical(name, near)
        return got

    def project_object(self, name: str, near: str):
        """Resolve a dotted name to ``("function", fi)``, ``("class", ci)``,
        ``("method", (ci, attr))`` or ``None`` for names outside the scan."""
        split = self.ctx.index.split(self.canonical(name, near), near)
        if split is None:
            return None
        mod, rest = split
        if not rest:
            return None
        local = ".".join(rest)
        fi = self.module_functions.get(mod.path, {}).get(local)
        if fi is not None:
            return ("function", fi)
        classes = self.module_classes.get(mod.path, {})
        ci = classes.get(local)
        if ci is not None:
            return ("class", ci)
        if len(rest) >= 2:
            ci = classes.get(".".join(rest[:-1]))
            if ci is not None:
                return ("method", (ci, rest[-1]))
        return None

    def class_for(self, name: str, near: str) -> ClassInfo | None:
        got = self.project_object(name, near)
        return got[1] if got is not None and got[0] == "class" else None

    def class_oracle(self, near: str):
        """Callable mapping a dotted callee name to a project class qualname."""
        oracle = self._oracles.get(near)
        if oracle is None:
            cache: dict = {}

            def oracle(name: str):
                if name not in cache:
                    cls = self.class_for(name, near)
                    cache[name] = cls.qualname if cls is not None else None
                return cache[name]

            self._oracles[near] = oracle
        return oracle

    def promote(self, refs, near: str):
        """Turn module-level ``RET`` references to project classes into instances."""
        if not refs or not any(r.kind == RET for r in refs):
            return refs
        oracle = self.class_oracle(near)
        out = set()
        for r in refs:
            if r.kind == RET:
                cls = oracle(r.name)
                out.add(Ref(INST, cls) if cls else r)
            else:
                out.add(r)
        return frozenset(out)

    def _resolve_bases(self, cls: ClassInfo) -> None:
        res = cls.module.resolver
        bases = []
        for expr in cls.node.bases:
            for r in sorted(res.refs_for(expr, res.module_lookup)):
                if r.kind == PATH:
                    base = self.class_for(r.name, cls.module.path)
                    if base is not None and base is not cls:
                        bases.append(base)
            if not bases and isinstance(expr, ast.Name):
                # a base class defined in the same enclosing scope
                base = self.classes.get(f"{cls.qualname.rpartition('.')[0]}.{expr.id}")
                if base is not None and base is not cls:
                    bases.append(base)
        cls.bases = bases

    def mro(self, cls: ClassInfo) -> list[ClassInfo]:
        out: list[ClassInfo] = []
        stack = [cls]
        while stack:
            c = stack.pop(0)
            if c in out:
                continue
            out.append(c)
            stack[0:0] = c.bases or []
        return out

    def lookup_method(self, cls: ClassInfo, name: str) -> FunctionInfo | None:
        for c in self.mro(cls):
            fi = c.methods.get(name)
            if fi is not None:
                return fi
        return None

    def _build_families(self) -> None:
        parent: dict[str, str] = {q: q for q in self.classes}

        def find(q: str) -> str:
            while parent[q] != q:
                parent[q] = parent[parent[q]]
                q = parent[q]
            return q

        for q, cls in sorted(self.classes.items()):
            for base in cls.bases or ():
                a, b = find(q), find(base.qualname)
                if a != b:
                    parent[max(a, b)] = min(a, b)
        self._family = {q: find(q) for q in self.classes}

    def family(self, cls: ClassInfo) -> str:
        return self._family.get(cls.qualname, cls.qualname)

    # ---------------------------------------------------------- resolution

    def targets_for(self, refs, func: ast.AST, analyzer: FunctionAnalyzer | None) -> list:
        """Project functions a call may invoke: ``[(FunctionInfo|None, offset, ctor_class|None)]``.

        ``offset`` is 1 when the first parameter is supplied implicitly
        (bound methods, classmethods, constructors).
        """
        out = []
        if (
            analyzer is not None
            and isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Call)
            and isinstance(func.value.func, ast.Name)
            and func.value.func.id == "super"
            and analyzer.fn.class_info is not None
        ):
            for base in self.mro(analyzer.fn.class_info)[1:]:
                m = base.methods.get(func.attr)
                if m is not None:
                    out.append((m, 0 if m.method_kind == "static" else 1, None))
                    break
            return out
        if not refs:
            return out
        near = analyzer.mod.path if analyzer is not None else ""
        for r in sorted(refs):
            if r.kind == PATH:
                got = self.project_object(r.name, near)
                if got is None:
                    continue
                kind, obj = got
                if kind == "function":
                    out.append((obj, 1 if obj.method_kind == "class" else 0, None))
                elif kind == "class":
                    out.append((self.lookup_method(obj, "__init__"), 1, obj))
                else:
                    m = self.lookup_method(obj[0], obj[1])
                    if m is not None:
                        out.append((m, 1 if m.method_kind == "class" else 0, None))
            elif r.kind == BOUND:
                prefix, _, attr = r.name.rpartition(".")
                cls = self.classes.get(prefix)
                if cls is not None:
                    m = self.lookup_method(cls, attr)
                    if m is not None:
                        out.append((m, 0 if m.method_kind == "static" else 1, None))
        return out

    # ------------------------------------------------------- shared stores

    def contribute_field(self, family: str, sels: tuple, tv: TaintValue) -> None:
        tv = tv.concrete()
        if not tv:
            return
        store = self.fields.setdefault(family, {})
        cur = store.get(sels)
        new = tv if cur is None else cur.join(tv)
        if cur is None or new != cur:
            store[sels] = new
            self.dirty.add(("fld", family))

    def contribute_global(self, module: str, name: str, vv: VarVal) -> None:
        key = (module, name)
        cur = self.globals.get(key)
        new = vv if cur is None else cur.join(vv)
        if cur is None or new != cur:
            self.globals[key] = new
            self.dirty.add(("glb", module, name))

    # ------------------------------------------------------------- fixpoint

    def _order(self) -> dict[str, int]:
        """Callees before callers, from a syntactic call graph (efficiency only)."""
        edges: dict[str, list[str]] = {}
        for q, fi in self.functions.items():
            res = fi.module.resolver
            first = fi.params[0].name if fi.params and fi.params[0].implicit else None
            callees = set()
            for node in _body_nodes(fi):
                if not isinstance(node, ast.Call):
                    continue
                refs = res.refs_for(node.func, res.module_lookup)
                f = node.func
                if first and isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id == first:
                    refs = refs | {Ref(BOUND, f"{fi.class_info.qualname}.{f.attr}")}
                for target, _, _ in self.targets_for(refs, f, None):
                    if target is not None:
                        callees.add(target.qualname)
            edges[q] = sorted(callees)
        order: dict[str, int] = {}
        for root in sorted(self.functions):
            if root in order:
                continue
            stack = [(root, iter(edges[root]))]
            seen = {root}
            while stack:
                node, it = stack[-1]
                nxt = next(it, None)
                if nxt is None:
                    stack.pop()
                    order.setdefault(node, len(order))
                elif nxt not in seen and nxt not in order:
                    seen.add(nxt)
                    stack.append((nxt, iter(edges.get(nxt, ()))))
        return order

    def run(self) -> None:
        self.build()
        order = self._order()
        heap = [(order[q], q) for q in self.functions]
        heapq.heapify(heap)
        queued = set(self.functions)
        visits: Counter = Counter()
        while heap:
            _, q = heapq.heappop(heap)
            queued.discard(q)
            fi = self.functions[q]
            visits[q] += 1
            if visits[q] > MAX_VISITS:
                continue
            self.dirty = set()
            analyzer = FunctionAnalyzer(fi, self)
            try:
                summary = analyzer.run()
            except RecursionError:
                self.ctx.warn(fi.module.path, f"skipped function {fi.display}: expression nesting too deep")
                summary = BOTTOM
                analyzer.findings = {}
            for dep in analyzer.deps:
                self.deps.setdefault(dep, set()).add(q)
            self.fn_findings[q] = analyzer.findings
            if summary != self.summaries.get(q, BOTTOM):
                self.summaries[q] = summary
                self.dirty.add(("sum", q))
            for key in self.dirty:
                for dependent in self.deps.get(key, ()):
                    if dependent not in queued:
                        queued.add(dependent)
                        heapq.heappush(heap, (order.get(dependent, 0), dependent))
        self._finalize()

    # ------------------------------------------------------------ findings

    def _finalize(self) -> None:
        best: dict = {}
        for q in sorted(self.fn_findings):
            for key, (path, site) in self.fn_findings[q].items():
                cur = best.get(key)
                if cur is None or better(path, cur[0]):
                    best[key] = (path, site)
        for (rule_id, _, origin), (path, site) in best.items():
            finding = self._make_finding(rule_id, origin, path, site)
            self._by_file.setdefault(site.location.file, []).append(finding)

    def _make_finding(self, rule_id: str, origin: SourceSite, path: tuple, site) -> Finding:
        rule = self.rules.rules[rule_id]
        source_step = PathStep(origin.location, StepKind.SOURCE, f"untrusted data from `{origin.text}`")
        steps = (source_step,) + path + (site.step,)
        seen: list[str] = []
        for step in path:
            if step.var and step.var not in seen and step.kind is StepKind.STEP:
                seen.append(step.var)
        if origin.location.file == site.location.file:
            where = f"line {origin.location.line}"
        else:
            where = origin.location.short()
        via = f" via {', '.join(seen[:3])}" if seen else ""
        message = f"{rule.message}: `{origin.text}` ({where}) flows into `{site.callee}()` {site.arg}{via}"
        return Finding(
            rule_id=rule_id,
            severity=rule.severity,
            cwe=rule.cwe,
            message=message,
            location=site.location,
            path=steps,
            identity=(site.text, origin.text),
            snippet=site.text,
            summary=f"{_short(origin.text)} reaches {_short(site.callee)}() {site.arg}",
        )

    def findings_for(self, path: str) -> list[Finding]:
        return list(self._by_file.get(path, ()))


def _short(text: str, limit: int = 32) -> str:
    """``sqlite3.connect('db').execute`` -> ``….execute`` for one-line summaries."""
    if len(text) <= limit:
        return text
    head, dot, tail = text.rpartition(".")
    if dot and len(tail) < limit - 2:
        return "…." + tail
    return text[: limit - 1] + "…"


def _body_nodes(fi: FunctionInfo):
    """Nodes of a function body, not descending into nested functions/classes."""
    if fi.kind == "lambda":
        stack = [fi.node.body]
    else:
        stack = list(fi.node.body)
    while stack:
        node = stack.pop()
        yield node
        for child in ast.iter_child_nodes(node):
            if not isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
                stack.append(child)
