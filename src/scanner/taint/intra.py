"""Intraprocedural taint analysis: transfer functions over one function body.

The analyser walks a function's statements in order, keeping an abstract
:class:`~scanner.taint.values.State`. Branches are analysed separately and
joined; loops iterate to a fixpoint (bounded); ``return``/``raise``/``break``
make the current path unreachable. Every expression evaluates to a
:class:`TaintValue`; assignments store :class:`VarVal` so dict keys, tuple
positions and attributes are tracked separately.

Calls are where the rules come in: a call can be a source (its result is a
fresh fact), a sink (its dangerous arguments are checked), a sanitizer (the
listed rules are removed from the result), a call to a function defined in
the scanned project (its summary is applied), or an unknown library call
(the result carries the taint of the arguments and receiver, unless the call
is known to return a non-injectable value).
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from ..model import PathStep, StepKind
from ..patterns import UNKNOWN, dotted, matches
from ..resolve import BOUND, INST, NO_REFS, PATH, RET, Ref, candidate_names
from .models import (
    FORMAT_METHODS,
    KEYED_GETTERS,
    MUTATING_METHODS,
    NON_PROPAGATING_CALLS,
    NON_PROPAGATING_METHODS,
    NORETURN_CALLS,
    VALIDATING_METHODS,
    WHOLE_GETTERS,
)
from .summaries import BOTTOM, SinkHit, SinkSite, Summary
from .values import (
    ANY_KEY,
    CLEAN,
    EMPTY,
    MAX_DEPTH,
    ParamOrigin,
    SourceSite,
    State,
    TaintValue,
    VarVal,
    better,
    extend,
    join_all,
)

if TYPE_CHECKING:  # pragma: no cover
    from .inter import FunctionInfo, TaintProgram

MAX_LOOP_PASSES = 10
CONSTANT_TYPES = (str, bytes, int, float, complex, bool, type(None))


def const_key(node: ast.AST) -> str | None:
    """Selector for a constant subscript/dict key, or None if not constant."""
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes, int, bool)):
        return f"[{node.value!r}]"
    return None


def access_path(node: ast.AST) -> tuple[str, tuple[str, ...]] | None:
    """``a.b['k'][i]`` -> ``("a", (".b", "['k']", "[*]"))``; None if not rooted at a name."""
    sels: list[str] = []
    while True:
        if isinstance(node, ast.Attribute):
            sels.append("." + node.attr)
            node = node.value
        elif isinstance(node, ast.Subscript):
            sels.append(const_key(node.slice) or ANY_KEY)
            node = node.value
        elif isinstance(node, ast.Name):
            sels.reverse()
            return node.id, tuple(sels)
        else:
            return None


def is_constant(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, CONSTANT_TYPES)


def is_constant_collection_literal(node: ast.AST | None) -> bool:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(is_constant(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and is_constant(k) for k in node.keys)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in ("frozenset", "set", "tuple", "list", "dict")
        and len(node.args) == 1
        and not node.keywords
    ):
        return is_constant_collection_literal(node.args[0])
    return False


class LoopCtx:
    __slots__ = ("breaks", "continues")

    def __init__(self) -> None:
        self.breaks: list[State] = []
        self.continues: list[State] = []


class FunctionAnalyzer:
    def __init__(self, fn: "FunctionInfo", prog: "TaintProgram") -> None:
        self.fn = fn
        self.prog = prog
        self.mod = fn.module
        self.res = fn.module.resolver
        self.rules = prog.rules
        self.all_rules = prog.rules.rule_ids
        self.is_module = fn.kind == "module"
        self.ret = EMPTY
        self.hits: dict = {}
        self.findings: dict = {}
        self.deps: set = set()
        self.loops: list[LoopCtx] = []
        self.closure: dict = {}
        self.closure_aliases: dict = {}
        self.defaults: dict = {}
        self.self_name: str | None = None
        self.exit_states: list[State] = []
        self.class_depth = 0
        self._sites: dict = {}
        self.classes = prog.class_oracle(self.mod.path)

    # ------------------------------------------------------------------ entry

    def run(self) -> Summary:
        state = State()
        fn = self.fn
        if not self.is_module:
            self.seed(state)
        if fn.kind == "lambda":
            tv = self.eval(fn.node.body, state)
            if tv:
                self.ret = self.ret.join(tv.with_step(self.return_step(fn.node.body)))
            self.exit_states.append(state)
        else:
            out = self.exec_block(fn.node.body, state)
            if out is not None and self.self_name:
                self.exit_states.append(out)
        return Summary(
            ret=self.ret,
            hits=self.hits,
            self_writes=self.collect_self_writes(),
            defaults=self.defaults,
            closure=self.closure,
            closure_aliases=self.closure_aliases,
        )

    def seed(self, state: State) -> None:
        fn = self.fn
        for p in fn.params:
            if p.implicit:
                cls = fn.class_info
                if fn.method_kind == "instance":
                    self.self_name = p.name
                    state.aliases[p.name] = frozenset({Ref(INST, cls.qualname)})
                    fam = self.prog.family(cls)
                    self.deps.add(("fld", fam))
                    fields = {}
                    loc = self.mod.location(p.node)
                    for sels, tv in self.prog.fields.get(fam, {}).items():
                        if tv:
                            where = p.name + "".join(sels)
                            step = PathStep(loc, StepKind.STEP, f"read from `{where}` in `{fn.display}()`", var=where)
                            fields[sels] = tv.with_step(step)
                    state.vars[p.name] = VarVal(EMPTY, fields)
                else:
                    state.aliases[p.name] = frozenset({Ref(PATH, cls.qualname)})
                continue
            origin = ParamOrigin(fn.qualname, p.key, p.name)
            step = PathStep(
                self.mod.location(p.node),
                StepKind.STEP,
                f"enters `{fn.display}()` as parameter `{p.name}`",
                var=p.name,
            )
            state.vars[p.name] = VarVal(TaintValue.of(origin, self.all_rules, (step,)))
            if p.default is not None:
                tv = self.eval(p.default, State())
                if tv:
                    self.defaults[p.key] = tv

    def return_step(self, node: ast.AST) -> PathStep:
        return PathStep(self.mod.location(node), StepKind.RETURN, f"returned from `{self.fn.display}()`")

    def collect_self_writes(self) -> dict:
        if not self.self_name or not self.exit_states:
            return {}
        merged = State.join_all(self.exit_states)
        vv = merged.vars.get(self.self_name) if merged is not None else None
        if vv is None:
            return {}
        fam = self.prog.family(self.fn.class_info)
        writes = {}
        for sels, tv in vv.fields.items():
            if not sels or not sels[0].startswith("."):
                continue
            concrete = tv.concrete()
            if concrete:
                self.prog.contribute_field(fam, sels, concrete)
            symbolic = TaintValue({k: p for k, p in tv.facts.items() if isinstance(k[0], ParamOrigin)})
            if symbolic:
                writes[sels] = symbolic
        return writes

    # ------------------------------------------------------------- names/vars

    def is_local(self, name: str) -> bool:
        return name in self.fn.local_names

    def lookup(self, name: str, state: State) -> frozenset | None:
        """References a bare name stands for at this point."""
        refs = state.aliases.get(name)
        if refs is not None:
            return refs
        if self.is_local(name):
            return None
        f = self.fn.parent
        while f is not None:
            if name in f.local_names:
                self.deps.add(("sum", f.qualname))
                s = self.prog.summaries.get(f.qualname)
                return s.closure_aliases.get(name) if s is not None else None
            f = f.parent
        return self.prog.promote(self.res.module_lookup(name), self.mod.path)

    def refs_of(self, node: ast.AST, state: State) -> frozenset:
        return self.res.refs_for(node, lambda n: self.lookup(n, state), self.classes)

    def read_var(self, name: str, state: State) -> VarVal | None:
        vv = state.vars.get(name)
        if vv is not None:
            return vv
        if self.is_local(name):
            return None
        f = self.fn.parent
        while f is not None:
            if name in f.local_names:
                self.deps.add(("sum", f.qualname))
                s = self.prog.summaries.get(f.qualname)
                return s.closure.get(name) if s is not None else None
            f = f.parent
        key = (self.mod.module_name, name)
        self.deps.add(("glb",) + key)
        return self.prog.globals.get(key)

    def store_var(self, name: str, vv: VarVal, state: State) -> None:
        state.vars[name] = vv
        if vv.is_empty():
            return
        if self.class_depth == 0 and (self.is_module or name in self.fn.global_decls):
            concrete = vv.concrete()
            if not concrete.is_empty():
                self.prog.contribute_global(self.mod.module_name, name, concrete)
        if self.fn.has_nested:
            concrete = vv.concrete()
            if not concrete.is_empty():
                cur = self.closure.get(name)
                self.closure[name] = concrete if cur is None else cur.join(concrete)

    def set_alias(self, name: str, refs: frozenset, state: State) -> None:
        if refs:
            state.aliases[name] = refs
            if self.fn.has_nested:
                self.closure_aliases[name] = self.closure_aliases.get(name, NO_REFS) | refs
        else:
            state.aliases.pop(name, None)

    def source_value(self, node: ast.AST, refs: frozenset) -> TaintValue:
        names = candidate_names(refs)
        if not names:
            return EMPTY
        matched = self.rules.sources.match(names)
        if not matched:
            return EMPTY
        rules = frozenset(r for _, r in matched)
        origin = SourceSite(self.mod.location(node), self.mod.unparse(node, 120), matched[0][0])
        return TaintValue.of(origin, rules)

    def project_globals(self, refs: frozenset) -> TaintValue:
        """Taint of module-level variables of *other* scanned modules."""
        out = EMPTY
        index = self.prog.ctx.index
        for r in refs:
            if r.kind != PATH:
                continue
            split = index.split(r.name, self.mod.path)
            if split is None:
                continue
            m, rest = split
            if len(rest) == 1 and m is not self.mod and rest[0] in m.resolver.assigned:
                key = (m.module_name, rest[0])
                self.deps.add(("glb",) + key)
                vv = self.prog.globals.get(key)
                if vv is not None:
                    out = out.join(vv.read_all())
        return out

    def instance_fields(self, refs: frozenset, sels: tuple) -> TaintValue:
        out = EMPTY
        for r in refs:
            if r.kind == INST:
                cls = self.prog.classes.get(r.name)
                if cls is None:
                    continue
                fam = self.prog.family(cls)
                self.deps.add(("fld", fam))
                store = self.prog.fields.get(fam)
                if store:
                    out = out.join(VarVal(EMPTY, store).read(sels))
        return out

    # ---------------------------------------------------------------- blocks

    def exec_block(self, stmts: list, state: State | None) -> State | None:
        for stmt in stmts:
            if state is None:
                return None
            handler = _STMT.get(type(stmt))
            if handler is not None:
                state = handler(self, stmt, state)
        return state

    def s_expr(self, node: ast.Expr, state: State) -> State | None:
        self.eval(node.value, state)
        if isinstance(node.value, ast.Call) and self.is_noreturn(node.value, state):
            return None
        return state

    def is_noreturn(self, call: ast.Call, state: State) -> bool:
        return any(dotted(n) in NORETURN_CALLS for n in candidate_names(self.refs_of(call.func, state)))

    def s_assign(self, node: ast.Assign, state: State) -> State:
        value = self.eval_value(node.value, state)
        for target in node.targets:
            self.assign(target, value, state, node.value)
        return state

    def s_annassign(self, node: ast.AnnAssign, state: State) -> State:
        if node.value is not None:
            self.assign(node.target, self.eval_value(node.value, state), state, node.value)
        return state

    def s_augassign(self, node: ast.AugAssign, state: State) -> State:
        old = self.eval(node.target, state)
        new = self.eval(node.value, state)
        combined = old.join(new)
        target = node.target
        if combined:
            text = self.mod.unparse(target, 60)
            if isinstance(node.op, ast.Add):
                msg = f"concatenated into `{text}`"
            else:
                msg = f"combined into `{text}`"
            combined = combined.with_step(PathStep(self.mod.location(node), StepKind.STEP, msg, var=text))
        self.assign(target, VarVal(combined), state, None, message="")
        return state

    def s_for(self, node: ast.For, state: State) -> State | None:
        items = self.eval(node.iter, state)
        element = VarVal(items)
        head = state
        ctx = LoopCtx()
        for _ in range(MAX_LOOP_PASSES):
            ctx = LoopCtx()
            self.loops.append(ctx)
            body = head.copy()
            self.assign(node.target, element, body, None, message="iterated into")
            out = self.exec_block(node.body, body)
            self.loops.pop()
            new_head = State.join_all([head, out] + ctx.continues)
            if new_head == head:
                break
            head = new_head
        exit_state = self.exec_block(node.orelse, head.copy()) if node.orelse else head
        return State.join_all([exit_state] + ctx.breaks)

    def s_while(self, node: ast.While, state: State) -> State | None:
        head = state
        ctx = LoopCtx()
        for _ in range(MAX_LOOP_PASSES):
            ctx = LoopCtx()
            self.loops.append(ctx)
            body = head.copy()
            self.eval(node.test, body)
            out = self.exec_block(node.body, body)
            self.loops.pop()
            new_head = State.join_all([head, out] + ctx.continues)
            if new_head == head:
                break
            head = new_head
        infinite = isinstance(node.test, ast.Constant) and bool(node.test.value)
        exit_state = None if infinite else head
        if node.orelse and exit_state is not None:
            exit_state = self.exec_block(node.orelse, exit_state.copy())
        return State.join_all([exit_state] + ctx.breaks)

    def s_if(self, node: ast.If, state: State) -> State | None:
        self.eval(node.test, state)
        test = node.test
        if isinstance(test, ast.Constant):
            return self.exec_block(node.body if test.value else node.orelse, state)
        true_state, false_state = state.copy(), state.copy()
        self.narrow(test, true_state, false_state)
        s1 = self.exec_block(node.body, true_state)
        s2 = self.exec_block(node.orelse, false_state) if node.orelse else false_state
        return State.join(s1, s2)

    def s_with(self, node: ast.With, state: State) -> State | None:
        for item in node.items:
            tv = self.eval(item.context_expr, state)
            if item.optional_vars is not None:
                self.assign(item.optional_vars, VarVal(tv), state, None)
        return self.exec_block(node.body, state)

    def s_try(self, node: ast.Try, state: State) -> State | None:
        before = state.copy()
        body_out = self.exec_block(node.body, state)
        handler_in = State.join(before, body_out) or before
        outs = []
        for handler in node.handlers:
            hs = handler_in.copy()
            if handler.type is not None:
                self.eval(handler.type, hs)
            if handler.name:
                hs.vars.pop(handler.name, None)
                hs.aliases.pop(handler.name, None)
            outs.append(self.exec_block(handler.body, hs))
        if node.orelse and body_out is not None:
            body_out = self.exec_block(node.orelse, body_out)
        normal = State.join_all([body_out] + outs)
        if node.finalbody:
            if normal is None:
                self.exec_block(node.finalbody, handler_in.copy())
                return None
            return self.exec_block(node.finalbody, normal)
        return normal

    def s_match(self, node: ast.Match, state: State) -> State | None:
        subject = VarVal(self.eval(node.subject, state))
        subject_name = node.subject.id if isinstance(node.subject, ast.Name) else None
        outs = []
        exhaustive = False
        for case in node.cases:
            cs = state.copy()
            for sub in ast.walk(case.pattern):
                name = getattr(sub, "name", None) if isinstance(sub, (ast.MatchAs, ast.MatchStar)) else None
                if isinstance(sub, ast.MatchMapping):
                    name = sub.rest
                if name:
                    self.assign(ast.Name(id=name, ctx=ast.Store(), **_pos(sub)), subject, cs, None, "matched into")
            if subject_name and _literal_pattern(case.pattern):
                cs.vars[subject_name] = CLEAN
            if case.guard is not None:
                self.eval(case.guard, cs)
            outs.append(self.exec_block(case.body, cs))
            if case.guard is None and isinstance(case.pattern, ast.MatchAs) and case.pattern.pattern is None:
                exhaustive = True
        if not exhaustive:
            outs.append(state)
        return State.join_all(outs)

    def s_return(self, node: ast.Return, state: State) -> None:
        if node.value is not None:
            tv = self.eval(node.value, state)
            if tv:
                self.ret = self.ret.join(tv.with_step(self.return_step(node)))
        if self.self_name:
            self.exit_states.append(state)
        return None

    def s_raise(self, node: ast.Raise, state: State) -> None:
        if node.exc is not None:
            self.eval(node.exc, state)
        if node.cause is not None:
            self.eval(node.cause, state)
        return None

    def s_assert(self, node: ast.Assert, state: State) -> State:
        self.eval(node.test, state)
        if node.msg is not None:
            self.eval(node.msg, state)
        self.narrow(node.test, state, None)
        return state

    def s_delete(self, node: ast.Delete, state: State) -> State:
        for target in node.targets:
            if isinstance(target, ast.Name):
                state.vars.pop(target.id, None)
                state.aliases.pop(target.id, None)
                continue
            path = access_path(target)
            if path is not None and path[1]:
                vv = self.read_var(path[0], state)
                if vv is not None:
                    strong = ANY_KEY not in path[1]
                    state.vars[path[0]] = vv.write(path[1], CLEAN, strong)
        return state

    def s_import(self, node: ast.Import | ast.ImportFrom, state: State) -> State:
        for name, ref in self.res.import_bindings(node):
            state.vars.pop(name, None)
            self.set_alias(name, frozenset({ref}) if ref is not None else NO_REFS, state)
        return state

    def s_functiondef(self, node: ast.FunctionDef, state: State) -> State:
        fi = self.prog.func_by_node.get(id(node))
        state.vars.pop(node.name, None)
        self.set_alias(node.name, frozenset({Ref(PATH, fi.qualname)}) if fi else NO_REFS, state)
        return state

    def s_classdef(self, node: ast.ClassDef, state: State) -> State:
        for expr in node.bases:
            self.eval(expr, state)
        inner = state.copy()
        body = [s for s in node.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))]
        self.class_depth += 1
        try:
            self.exec_block(body, inner)
        finally:
            self.class_depth -= 1
        ci = self.prog.class_by_node.get(id(node))
        state.vars.pop(node.name, None)
        self.set_alias(node.name, frozenset({Ref(PATH, ci.qualname)}) if ci else NO_REFS, state)
        return state

    def s_break(self, node: ast.Break, state: State) -> None:
        if self.loops:
            self.loops[-1].breaks.append(state)
        return None

    def s_continue(self, node: ast.Continue, state: State) -> None:
        if self.loops:
            self.loops[-1].continues.append(state)
        return None

    def s_pass(self, node: ast.stmt, state: State) -> State:
        return state

    # ------------------------------------------------------------ assignment

    def assign(
        self,
        target: ast.AST,
        value: VarVal,
        state: State,
        value_node: ast.AST | None,
        message: str | None = None,
    ) -> None:
        if isinstance(target, ast.Name):
            name = target.id
            if message != "" and not value.is_empty():
                text = message or "assigned to"
                value = value.with_step(
                    PathStep(self.mod.location(target), StepKind.STEP, f"{text} `{name}`", var=name)
                )
            self.store_var(name, value, state)
            self.set_alias(name, self.value_refs(value_node, state), state)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            if isinstance(target, ast.Subscript):
                self.eval(target.slice, state)
            path = access_path(target)
            if path is None:
                self.eval(target.value, state)
                return
            root, sels = path
            if message != "" and not value.is_empty():
                text = self.mod.unparse(target, 60)
                value = value.with_step(
                    PathStep(self.mod.location(target), StepKind.STEP, f"stored in `{text}`", var=text)
                )
            strong = ANY_KEY not in sels and len(sels) <= MAX_DEPTH
            base = self.read_var(root, state) or CLEAN
            self.store_var(root, base.write(sels, value, strong), state)
        elif isinstance(target, (ast.Tuple, ast.List)):
            elts = target.elts
            starred = any(isinstance(e, ast.Starred) for e in elts)
            literal = None
            if (
                isinstance(value_node, (ast.Tuple, ast.List))
                and not starred
                and len(value_node.elts) == len(elts)
                and not any(isinstance(e, ast.Starred) for e in value_node.elts)
            ):
                literal = value_node.elts
            for i, elt in enumerate(elts):
                if isinstance(elt, ast.Starred):
                    self.assign(elt.value, VarVal(value.read_all()), state, None, message)
                    continue
                sub = value.subtree((ANY_KEY,) if starred else (f"[{i!r}]",))
                self.assign(elt, sub, state, literal[i] if literal is not None else None, message)
        elif isinstance(target, ast.Starred):
            self.assign(target.value, VarVal(value.read_all()), state, None, message)

    def value_refs(self, node: ast.AST | None, state: State) -> frozenset:
        """Alias information for ``name = node``."""
        if node is None:
            return NO_REFS
        if isinstance(node, ast.Lambda):
            fi = self.prog.func_by_node.get(id(node))
            return frozenset({Ref(PATH, fi.qualname)}) if fi else NO_REFS
        if isinstance(node, (ast.Name, ast.Attribute)):
            return self.refs_of(node, state)
        if isinstance(node, ast.Await):
            return self.value_refs(node.value, state)
        if isinstance(node, ast.Call):
            return frozenset(r for r in self.refs_of(node, state) if r.kind in (INST, RET))
        return NO_REFS

    def eval_value(self, node: ast.AST, state: State, depth: int = 0) -> VarVal:
        """Evaluate keeping structure (dict keys, tuple positions, list contents)."""
        if isinstance(node, ast.Dict) and depth < MAX_DEPTH:
            fields: dict = {}
            for k, v in zip(node.keys, node.values):
                if k is None:
                    _merge_at(fields, ANY_KEY, VarVal(self.eval(v, state)))
                    continue
                key = const_key(k)
                if key is None:
                    key_tv = self.eval(k, state)
                    _merge_at(fields, ANY_KEY, VarVal(self.eval(v, state).join(key_tv)))
                else:
                    _merge_at(fields, key, self.eval_value(v, state, depth + 1))
            return VarVal(EMPTY, fields)
        if isinstance(node, ast.Tuple) and depth < MAX_DEPTH:
            fields = {}
            spread = False
            for i, elt in enumerate(node.elts):
                if isinstance(elt, ast.Starred):
                    spread = True
                    _merge_at(fields, ANY_KEY, VarVal(self.eval(elt.value, state)))
                elif spread:
                    _merge_at(fields, ANY_KEY, VarVal(self.eval(elt, state)))
                else:
                    _merge_at(fields, f"[{i!r}]", self.eval_value(elt, state, depth + 1))
            return VarVal(EMPTY, fields)
        if isinstance(node, (ast.List, ast.Set)):
            tv = EMPTY
            for elt in node.elts:
                tv = tv.join(self.eval(elt.value if isinstance(elt, ast.Starred) else elt, state))
            return VarVal(EMPTY, {(ANY_KEY,): tv}) if tv else CLEAN
        if isinstance(node, ast.Name):
            if node.id not in state.aliases:
                vv = state.vars.get(node.id)
                if vv is not None:
                    return vv
            return VarVal(self.eval(node, state))
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            path = access_path(node)
            if path is not None and path[0] not in state.aliases:
                vv = state.vars.get(path[0])
                if vv is not None:
                    if isinstance(node, ast.Subscript):
                        self.eval(node.slice, state)
                    return vv.subtree(path[1])
            return VarVal(self.eval(node, state))
        if isinstance(node, ast.Lambda) and id(node) in self.prog.func_by_node:
            return CLEAN
        return VarVal(self.eval(node, state))

    # ------------------------------------------------------------- narrowing

    def narrow(self, test: ast.AST, true_state: State | None, false_state: State | None) -> None:
        """Kill taint on names a condition proves safe inside a branch.

        Only a few precise forms are recognised: membership in a constant
        collection (``if col in ALLOWED``), equality with a constant, and
        character-class checks (``if x.isdigit()``); their negations and
        ``and``/``or`` combinations.
        """
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            self.narrow(test.operand, false_state, true_state)
            return
        if isinstance(test, ast.BoolOp):
            if isinstance(test.op, ast.And):
                for value in test.values:
                    self.narrow(value, true_state, None)
            else:
                for value in test.values:
                    self.narrow(value, None, false_state)
            return
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op, left, right = test.ops[0], test.left, test.comparators[0]
            if isinstance(op, (ast.In, ast.NotIn)):
                if isinstance(left, ast.Name) and self.is_constant_collection(right, true_state or false_state):
                    self.clear(left.id, true_state if isinstance(op, ast.In) else false_state)
            elif isinstance(op, (ast.Eq, ast.Is, ast.NotEq, ast.IsNot)):
                name = None
                if isinstance(left, ast.Name) and is_constant(right):
                    name = left.id
                elif isinstance(right, ast.Name) and is_constant(left):
                    name = right.id
                if name is not None:
                    self.clear(name, true_state if isinstance(op, (ast.Eq, ast.Is)) else false_state)
            return
        if (
            isinstance(test, ast.Call)
            and isinstance(test.func, ast.Attribute)
            and test.func.attr in VALIDATING_METHODS
            and isinstance(test.func.value, ast.Name)
            and not test.args
        ):
            self.clear(test.func.value.id, true_state)

    def clear(self, name: str, state: State | None) -> None:
        if state is not None:
            state.vars[name] = CLEAN

    def is_constant_collection(self, node: ast.AST, state: State | None) -> bool:
        if is_constant_collection_literal(node):
            return True
        if isinstance(node, ast.Name):
            name = node.id
            if self.is_local(name):
                return name in self.fn.const_collections
            if name in self.prog.module_consts.get(self.mod.path, ()):
                return True
            refs = self.lookup(name, state) if state is not None else self.res.module_lookup(name)
            return any(self.prog.is_const_global(r.name, self.mod.path) for r in (refs or ()) if r.kind == PATH)
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # self.ALLOWED, Config.ALLOWED, constants.ALLOWED
            if node.value.id == self.self_name and self.fn.class_info is not None:
                return node.attr in self.fn.class_info.const_attrs
            name = node.value.id
            refs = self.lookup(name, state) if state is not None else self.res.module_lookup(name)
            for r in refs or ():
                if r.kind != PATH:
                    continue
                cls = self.prog.class_for(r.name, self.mod.path)
                if cls is not None and node.attr in cls.const_attrs:
                    return True
                if self.prog.is_const_global(f"{r.name}.{node.attr}", self.mod.path):
                    return True
        return False

    # ------------------------------------------------------------ expressions

    def eval(self, node: ast.AST, state: State) -> TaintValue:
        handler = _EXPR.get(type(node))
        if handler is not None:
            return handler(self, node, state)
        out = EMPTY
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out = out.join(self.eval(child, state))
        return out

    def e_constant(self, node: ast.AST, state: State) -> TaintValue:
        return EMPTY

    def e_name(self, node: ast.Name, state: State) -> TaintValue:
        name = node.id
        refs = None
        if name in state.aliases or not self.is_local(name):
            refs = self.lookup(name, state)
            if refs:
                src = self.source_value(node, refs)
                if src:
                    return src
        vv = self.read_var(name, state)
        if vv is not None:
            return vv.read_all()
        if refs:
            return self.project_globals(refs)
        return EMPTY

    def e_attribute(self, node: ast.Attribute, state: State) -> TaintValue:
        path = access_path(node)
        refs = NO_REFS
        if path is None or path[0] in state.aliases or not self.is_local(path[0]):
            refs = self.refs_of(node, state)
            if refs:
                src = self.source_value(node, refs)
                if src:
                    return src
        if path is not None:
            root, sels = path
            vv = self.read_var(root, state)
            tv = vv.read(sels) if vv is not None else EMPTY
            if root != self.self_name and root in state.aliases:
                tv = tv.join(self.instance_fields(state.aliases[root], sels))
            if vv is None and refs:
                tv = tv.join(self.project_globals(refs))
            return tv
        return self.eval(node.value, state)

    def e_subscript(self, node: ast.Subscript, state: State) -> TaintValue:
        self.eval(node.slice, state)
        path = access_path(node)
        if path is not None and path[0] not in state.aliases:
            vv = self.read_var(path[0], state)
            if vv is not None:
                return vv.read(path[1])
        base = self.eval(node.value, state)
        return self.widen_source(base, node.value, node)

    def widen_source(self, tv: TaintValue, inner: ast.AST, outer: ast.AST) -> TaintValue:
        """Report ``request.args['q']`` rather than ``request.args`` as the source.

        A fact created by reading ``inner`` itself (no steps yet) is re-rooted
        at the enclosing subscript so the finding names the value actually read.
        """
        if not tv:
            return tv
        loc = self.mod.location(inner)
        changed = False
        out = {}
        for (origin, rules), path in tv.facts.items():
            if not path and isinstance(origin, SourceSite) and origin.location == loc:
                origin = SourceSite(self.mod.location(outer), self.mod.unparse(outer, 120), origin.pattern)
                changed = True
            out[(origin, rules)] = path
        return TaintValue(out) if changed else tv

    def e_binop(self, node: ast.BinOp, state: State) -> TaintValue:
        tv = self.eval(node.left, state).join(self.eval(node.right, state))
        if tv and isinstance(node.op, (ast.Add, ast.Mod)):
            msg = "concatenated with `+`" if isinstance(node.op, ast.Add) else "formatted with `%`"
            tv = tv.with_step(PathStep(self.mod.location(node), StepKind.STEP, msg))
        return tv

    def e_unaryop(self, node: ast.UnaryOp, state: State) -> TaintValue:
        tv = self.eval(node.operand, state)
        return EMPTY if isinstance(node.op, ast.Not) else tv

    def e_boolop(self, node: ast.BoolOp, state: State) -> TaintValue:
        return join_all(self.eval(v, state) for v in node.values)

    def e_compare(self, node: ast.Compare, state: State) -> TaintValue:
        self.eval(node.left, state)
        for comp in node.comparators:
            self.eval(comp, state)
        return EMPTY

    def e_ifexp(self, node: ast.IfExp, state: State) -> TaintValue:
        self.eval(node.test, state)
        t, f = state.copy(), state.copy()
        self.narrow(node.test, t, f)
        return self.eval(node.body, t).join(self.eval(node.orelse, f))

    def e_joinedstr(self, node: ast.JoinedStr, state: State) -> TaintValue:
        tv = EMPTY
        for value in node.values:
            if isinstance(value, ast.FormattedValue):
                tv = tv.join(self.e_formatted(value, state))
        if tv:
            tv = tv.with_step(PathStep(self.mod.location(node), StepKind.STEP, "interpolated into an f-string"))
        return tv

    def e_formatted(self, node: ast.FormattedValue, state: State) -> TaintValue:
        tv = self.eval(node.value, state)
        if node.format_spec is not None:
            tv = tv.join(self.eval(node.format_spec, state))
        return tv

    def e_sequence(self, node: ast.AST, state: State) -> TaintValue:
        return join_all(self.eval(e, state) for e in node.elts)

    def e_dict(self, node: ast.Dict, state: State) -> TaintValue:
        tv = EMPTY
        for k, v in zip(node.keys, node.values):
            if k is not None:
                tv = tv.join(self.eval(k, state))
            tv = tv.join(self.eval(v, state))
        return tv

    def e_comprehension(self, node: ast.AST, state: State) -> TaintValue:
        inner = state.copy()
        for gen in node.generators:
            items = self.eval(gen.iter, inner)
            self.assign(gen.target, VarVal(items), inner, None, "iterated into")
            for cond in gen.ifs:
                self.eval(cond, inner)
                self.narrow(cond, inner, None)
        if isinstance(node, ast.DictComp):
            tv = self.eval(node.key, inner).join(self.eval(node.value, inner))
        else:
            tv = self.eval(node.elt, inner)
        for sub in ast.walk(node):  # walrus targets bind in the enclosing scope
            if isinstance(sub, ast.NamedExpr) and isinstance(sub.target, ast.Name):
                vv = inner.vars.get(sub.target.id)
                if vv is not None:
                    state.vars[sub.target.id] = vv
        return tv

    def e_lambda(self, node: ast.Lambda, state: State) -> TaintValue:
        if id(node) in self.prog.func_by_node:
            return EMPTY
        inner = state.copy()
        args = node.args
        for a in args.posonlyargs + args.args + args.kwonlyargs + [args.vararg, args.kwarg]:
            if a is not None:
                inner.vars[a.arg] = CLEAN
                inner.aliases.pop(a.arg, None)
        return self.eval(node.body, inner)

    def e_namedexpr(self, node: ast.NamedExpr, state: State) -> TaintValue:
        tv = self.eval(node.value, state)
        self.assign(node.target, VarVal(tv), state, node.value)
        return tv

    def e_await(self, node: ast.Await, state: State) -> TaintValue:
        return self.eval(node.value, state)

    def e_yield(self, node: ast.AST, state: State) -> TaintValue:
        if node.value is not None:
            tv = self.eval(node.value, state)
            if tv:
                self.ret = self.ret.join(tv.with_step(self.return_step(node)))
        return EMPTY

    def e_starred(self, node: ast.Starred, state: State) -> TaintValue:
        return self.eval(node.value, state)

    def e_slice(self, node: ast.Slice, state: State) -> TaintValue:
        for part in (node.lower, node.upper, node.step):
            if part is not None:
                self.eval(part, state)
        return EMPTY

    # ------------------------------------------------------------------ calls

    def e_call(self, node: ast.Call, state: State) -> TaintValue:
        func = node.func
        pos = []
        for a in node.args:
            if isinstance(a, ast.Starred):
                pos.append((self.eval(a.value, state), a, True))
            else:
                pos.append((self.eval(a, state), a, False))
        kws = [(kw.arg, self.eval(kw.value, state), kw) for kw in node.keywords]

        recv = None
        if isinstance(func, ast.Attribute):
            recv = self.eval(func.value, state)
        elif not isinstance(func, ast.Name):
            recv = self.eval(func, state)

        refs = self.refs_of(func, state)
        targets = self.prog.targets_for(refs, func, self)
        names = candidate_names(refs)
        if isinstance(func, ast.Attribute) and not targets:
            names.append((UNKNOWN, func.attr))

        src = san = ()
        fired: set = set()
        if names:
            for _, spec in self.rules.sinks.match(names):
                if self.when_holds(spec, node, state):
                    tv = self.sink_argument(spec, pos, kws, recv)
                    if tv and self.report(spec, tv, node, func):
                        fired.add(spec.rule_id)
            src = self.rules.sources.match(names)
            san = self.rules.sanitizers.match(names)

        if src:
            rules = frozenset(r for _, r in src)
            ret = TaintValue.of(SourceSite(self.mod.location(node), self.mod.unparse(node, 120), src[0][0]), rules)
        elif targets:
            ret = self.apply_targets(targets, node, func, pos, kws, state)
        else:
            ret = self.library_call(node, func, names, pos, kws, recv, state)
        if san:
            ret = ret.without_rules(frozenset(r for _, r in san))
        if fired:
            # A sink consumes its rule's taint: `execute(text(q))` is one
            # vulnerability, reported at the inner sink only.
            ret = ret.without_rules(frozenset(fired))
        return ret

    def when_holds(self, spec, node: ast.Call, state: State) -> bool:
        if not spec.when:
            return True
        splat = any(kw.arg is None for kw in node.keywords)
        for cond in spec.when:
            value = next((kw.value for kw in node.keywords if kw.arg == cond.kwarg), None)
            if value is None and cond.pos is not None:
                plain = [a for a in node.args]
                if any(isinstance(a, ast.Starred) for a in plain[: cond.pos + 1]):
                    splat = True
                elif cond.pos < len(plain):
                    value = plain[cond.pos]
            if cond.op == "is_true":
                if value is None:
                    ok = splat
                elif isinstance(value, ast.Constant):
                    ok = bool(value.value) == cond.expect
                else:
                    ok = True
            else:
                if value is None:
                    ok = cond.op == "not_in" or splat
                elif isinstance(value, ast.Constant):
                    ok = cond.op == "not_in"
                else:
                    names = candidate_names(self.refs_of(value, state))
                    if not names:
                        ok = True
                    else:
                        member = any(matches(p, n) for p in cond.names for n in names)
                        ok = member if cond.op == "in" else not member
            if not ok:
                return False
        return True

    def sink_argument(self, spec, pos: list, kws: list, recv: TaintValue | None) -> TaintValue:
        if spec.receiver:
            return recv or EMPTY
        out = EMPTY
        if spec.positions is None:
            for tv, _, _ in pos:
                out = out.join(tv)
            for _, tv, _ in kws:
                out = out.join(tv)
            return out
        for idx in spec.positions:
            j = 0
            for tv, _, starred in pos:
                if starred:
                    if j <= idx:
                        out = out.join(tv)
                    continue
                if j == idx:
                    out = out.join(tv)
                j += 1
        for name, tv, _ in kws:
            if (name is None and spec.kwargs) or (name is not None and name in spec.kwargs):
                out = out.join(tv)
        return out

    def sink_site(self, spec, node: ast.Call, func: ast.AST) -> SinkSite:
        key = (id(node), spec.describe())
        site = self._sites.get(key)
        if site is None:
            loc = self.mod.location(node)
            text = self.mod.unparse(node, 300)
            arg = spec.describe()
            shown = text if len(text) <= 100 else text[:99] + "…"
            site = SinkSite(
                location=loc,
                callee=self.mod.unparse(func, 80),
                text=text,
                arg=arg,
                step=PathStep(loc, StepKind.SINK, f"{shown} [{arg}]"),
            )
            self._sites[key] = site
        return site

    def report(self, spec, tv: TaintValue, node: ast.Call, func: ast.AST) -> bool:
        """Record findings/summary hits; return whether anything reached the sink."""
        site = None
        for (origin, rules), path in tv.facts.items():
            if spec.rule_id not in rules:
                continue
            site = site or self.sink_site(spec, node, func)
            if isinstance(origin, SourceSite):
                self.add_finding(spec.rule_id, origin, path, site)
            elif origin.function == self.fn.qualname:
                self.add_hit(spec.rule_id, origin.key, path, site)
        return site is not None

    def add_finding(self, rule_id: str, origin: SourceSite, path: tuple, site: SinkSite) -> None:
        key = (rule_id, site.location, origin)
        cur = self.findings.get(key)
        if cur is None or better(path, cur[0]):
            self.findings[key] = (path, site)

    def add_hit(self, rule_id: str, param: int, path: tuple, site: SinkSite) -> None:
        key = (rule_id, param, site.location)
        cur = self.hits.get(key)
        if cur is None or better(path, cur.path):
            self.hits[key] = SinkHit(rule_id, param, path, site)

    # -- calls into the scanned project

    def call_step(self, node: ast.AST, fi: "FunctionInfo", key: int) -> PathStep:
        return PathStep(
            self.mod.location(node),
            StepKind.CALL,
            f"passed to `{fi.display}()` as `{fi.param_name(key)}`",
        )

    def bind_args(self, fi: "FunctionInfo", offset: int, pos: list, kws: list) -> dict:
        binding: dict = {}
        positional = fi.positional
        i = offset
        spread = False
        for tv, anode, starred in pos:
            if starred or spread:
                spread = True
                for p in positional[i:]:
                    binding.setdefault(p.key, []).append((tv, anode))
                if fi.vararg is not None:
                    binding.setdefault(fi.vararg.key, []).append((tv, anode))
                continue
            if i < len(positional):
                binding.setdefault(positional[i].key, []).append((tv, anode))
                i += 1
            elif fi.vararg is not None:
                binding.setdefault(fi.vararg.key, []).append((tv, anode))
        for name, tv, knode in kws:
            if name is None:
                for p in fi.named:
                    if p.key not in binding and not p.implicit:
                        binding.setdefault(p.key, []).append((tv, knode))
                if fi.kwarg is not None:
                    binding.setdefault(fi.kwarg.key, []).append((tv, knode))
                continue
            p = fi.by_name.get(name)
            if p is not None:
                binding.setdefault(p.key, []).append((tv, knode))
            elif fi.kwarg is not None:
                binding.setdefault(fi.kwarg.key, []).append((tv, knode))
        return binding

    def actuals(self, binding: dict, defaults: dict, key: int) -> list:
        got = binding.get(key)
        if got is not None:
            return got
        default = defaults.get(key)
        return [(default, None)] if default else []

    def instantiate(self, tv: TaintValue, fi: "FunctionInfo", binding: dict, defaults: dict, node: ast.AST) -> TaintValue:
        out: dict = {}
        for (origin, rules), path in tv.facts.items():
            if isinstance(origin, ParamOrigin):
                if origin.function != fi.qualname:
                    continue
                for atv, anode in self.actuals(binding, defaults, origin.key):
                    if not atv:
                        continue
                    step = self.call_step(anode if anode is not None else node, fi, origin.key)
                    for (aorigin, arules), apath in atv.facts.items():
                        live = arules & rules
                        if not live:
                            continue
                        new_path = extend(apath, step, *path)
                        key = (aorigin, live)
                        cur = out.get(key)
                        if cur is None or better(new_path, cur):
                            out[key] = new_path
            else:
                key = (origin, rules)
                cur = out.get(key)
                if cur is None or better(path, cur):
                    out[key] = path
        return TaintValue(out)

    def apply_targets(self, targets: list, node: ast.Call, func: ast.AST, pos: list, kws: list, state: State) -> TaintValue:
        ret = EMPTY
        for fi, offset, ctor in targets:
            if fi is None:
                continue
            self.deps.add(("sum", fi.qualname))
            summary = self.prog.summaries.get(fi.qualname, BOTTOM)
            binding = self.bind_args(fi, offset, pos, kws)
            if summary.ret and ctor is None:
                ret = ret.join(self.instantiate(summary.ret, fi, binding, summary.defaults, node))
            for hit in summary.hits.values():
                for tv, anode in self.actuals(binding, summary.defaults, hit.param):
                    step = None
                    for (origin, rules), path in tv.facts.items():
                        if hit.rule_id not in rules:
                            continue
                        step = step or self.call_step(anode if anode is not None else node, fi, hit.param)
                        full = extend(path, step, *hit.path)
                        if isinstance(origin, SourceSite):
                            self.add_finding(hit.rule_id, origin, full, hit.sink)
                        elif origin.function == self.fn.qualname:
                            self.add_hit(hit.rule_id, origin.key, full, hit.sink)
            if fi.class_info is not None:
                fam = self.prog.family(fi.class_info)
                on_self = self.self_name is not None and offset == 1 and ctor is None and (
                    _is_super_call(func)
                    or (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name) and func.value.id == self.self_name)
                )
                for sels, tv in summary.self_writes.items():
                    inst = self.instantiate(tv, fi, binding, summary.defaults, node)
                    if inst:
                        self.prog.contribute_field(fam, sels, inst)
                        if on_self:
                            # self.helper(q) / super().__init__(q): the write lands on
                            # *our* self, so it becomes part of our own summary too.
                            vv = state.vars.get(self.self_name) or CLEAN
                            state.vars[self.self_name] = vv.write(sels, VarVal(inst), strong=False)
                if offset == 1 and ctor is None and isinstance(func, ast.Attribute):
                    p = access_path(func.value)
                    if p is not None and p[0] != self.self_name:
                        vv = self.read_var(p[0], state)
                        if vv is not None:
                            for sels, tv in vv.subtree(p[1]).fields.items():
                                if sels and sels[0].startswith("."):
                                    self.prog.contribute_field(fam, sels, tv)
        return ret

    # -- library calls

    def data_rooted(self, path: tuple | None, state: State) -> bool:
        """Is this access path rooted at a data variable (not a module/import)?"""
        if path is None:
            return False
        refs = state.aliases.get(path[0])
        if refs is None:
            return self.is_local(path[0]) or path[0] in state.vars or self.fn.kind == "module"
        return all(r.kind == INST for r in refs)

    def library_call(self, node, func, names, pos, kws, recv, state) -> TaintValue:
        attr = func.attr if isinstance(func, ast.Attribute) else None
        for n in names:
            if dotted(n) in NON_PROPAGATING_CALLS:
                return EMPTY
        if attr is not None and attr in NON_PROPAGATING_METHODS:
            return EMPTY
        if attr is not None:
            path = access_path(func.value)
            if self.data_rooted(path, state):
                root, sels = path
                if attr in MUTATING_METHODS:
                    self.mutate(root, sels, attr, node, func, pos, kws, state)
                    return EMPTY
                if attr in KEYED_GETTERS or attr in WHOLE_GETTERS:
                    vv = self.read_var(root, state)
                    if vv is not None:
                        if attr in KEYED_GETTERS and pos and not pos[0][2]:
                            key = const_key(node.args[0]) or ANY_KEY
                            tv = vv.read(sels + (key,))
                            for extra, _, _ in pos[1:]:
                                tv = tv.join(extra)
                            for kname, ktv, _ in kws:
                                if kname == "default":
                                    tv = tv.join(ktv)
                            return tv
                        return vv.read(sels)
        args_tv = EMPTY
        for tv, _, _ in pos:
            args_tv = args_tv.join(tv)
        for _, tv, _ in kws:
            args_tv = args_tv.join(tv)
        out = args_tv.join(recv) if recv is not None else args_tv
        if out:
            resolved = any(n[0] != UNKNOWN for n in names)
            if attr in FORMAT_METHODS and not resolved:
                msg = FORMAT_METHODS[attr]
            elif args_tv:
                msg = f"passed through `{self.mod.unparse(func, 60)}()`"
            else:
                msg = None
            if msg:
                out = out.with_step(PathStep(self.mod.location(node), StepKind.STEP, msg))
        return out

    def mutate(self, root: str, sels: tuple, attr: str, node, func, pos: list, kws: list, state: State) -> None:
        if attr == "insert":
            values = [tv for tv, _, _ in pos[1:]]
        elif attr == "setdefault":
            values = [pos[1][0]] if len(pos) > 1 else []
        else:
            values = [tv for tv, _, _ in pos] + [tv for _, tv, _ in kws]
        tv = join_all(values)
        if not tv:
            return
        key = ANY_KEY
        if attr == "setdefault" and pos and not pos[0][2]:
            key = const_key(node.args[0]) or ANY_KEY
        text = self.mod.unparse(func.value, 60)
        step = PathStep(self.mod.location(node), StepKind.STEP, f"added to `{text}` via .{attr}()", var=text)
        base = self.read_var(root, state) or CLEAN
        self.store_var(root, base.write(sels + (key,), VarVal(tv.with_step(step)), strong=False), state)


def _is_super_call(func: ast.AST) -> bool:
    return (
        isinstance(func, ast.Attribute)
        and isinstance(func.value, ast.Call)
        and isinstance(func.value.func, ast.Name)
        and func.value.func.id == "super"
    )


def _merge_at(fields: dict, key: str, vv: VarVal) -> None:
    entries = [((key,), vv.own)] + [(((key,) + k)[:MAX_DEPTH], tv) for k, tv in vv.fields.items()]
    for k, tv in entries:
        if tv:
            fields[k] = fields[k].join(tv) if k in fields else tv


def _literal_pattern(pattern: ast.AST) -> bool:
    if isinstance(pattern, ast.MatchValue):
        return is_constant(pattern.value)
    if isinstance(pattern, ast.MatchSingleton):
        return True
    if isinstance(pattern, ast.MatchOr):
        return all(_literal_pattern(p) for p in pattern.patterns)
    return False


def _pos(node: ast.AST) -> dict:
    return {
        "lineno": getattr(node, "lineno", 1),
        "col_offset": getattr(node, "col_offset", 0),
        "end_lineno": getattr(node, "end_lineno", None),
        "end_col_offset": getattr(node, "end_col_offset", None),
    }


A = FunctionAnalyzer
_STMT = {
    ast.Expr: A.s_expr,
    ast.Assign: A.s_assign,
    ast.AnnAssign: A.s_annassign,
    ast.AugAssign: A.s_augassign,
    ast.For: A.s_for,
    ast.AsyncFor: A.s_for,
    ast.While: A.s_while,
    ast.If: A.s_if,
    ast.With: A.s_with,
    ast.AsyncWith: A.s_with,
    ast.Try: A.s_try,
    ast.Match: A.s_match,
    ast.Return: A.s_return,
    ast.Raise: A.s_raise,
    ast.Assert: A.s_assert,
    ast.Delete: A.s_delete,
    ast.Import: A.s_import,
    ast.ImportFrom: A.s_import,
    ast.FunctionDef: A.s_functiondef,
    ast.AsyncFunctionDef: A.s_functiondef,
    ast.ClassDef: A.s_classdef,
    ast.Break: A.s_break,
    ast.Continue: A.s_continue,
    ast.Pass: A.s_pass,
    ast.Global: A.s_pass,
    ast.Nonlocal: A.s_pass,
}
if hasattr(ast, "TryStar"):
    _STMT[ast.TryStar] = A.s_try

_EXPR = {
    ast.Constant: A.e_constant,
    ast.Name: A.e_name,
    ast.Attribute: A.e_attribute,
    ast.Subscript: A.e_subscript,
    ast.Call: A.e_call,
    ast.BinOp: A.e_binop,
    ast.UnaryOp: A.e_unaryop,
    ast.BoolOp: A.e_boolop,
    ast.Compare: A.e_compare,
    ast.IfExp: A.e_ifexp,
    ast.JoinedStr: A.e_joinedstr,
    ast.FormattedValue: A.e_formatted,
    ast.List: A.e_sequence,
    ast.Tuple: A.e_sequence,
    ast.Set: A.e_sequence,
    ast.Dict: A.e_dict,
    ast.ListComp: A.e_comprehension,
    ast.SetComp: A.e_comprehension,
    ast.GeneratorExp: A.e_comprehension,
    ast.DictComp: A.e_comprehension,
    ast.Lambda: A.e_lambda,
    ast.NamedExpr: A.e_namedexpr,
    ast.Await: A.e_await,
    ast.Yield: A.e_yield,
    ast.YieldFrom: A.e_yield,
    ast.Starred: A.e_starred,
    ast.Slice: A.e_slice,
}
