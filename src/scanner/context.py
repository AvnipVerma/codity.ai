"""Per-file and whole-program context handed to rule kinds.

Every file is read and parsed exactly once, here. Rule kinds share the
resulting ``ast`` tree, source lines and (lazily built) name resolver.
"""

from __future__ import annotations

import ast
import os
import tokenize
from typing import TYPE_CHECKING, Any

from .discovery import SourceFile
from .model import Diagnostic, Location

if TYPE_CHECKING:  # pragma: no cover
    from .resolve import ModuleResolver, ProjectIndex


def walk(root: ast.AST) -> list[ast.AST]:
    """Every node under ``root`` (pre-order), without ``ast.walk``'s generators.

    ``ast.walk`` goes through two nested Python generators per node; on large
    trees this plain loop is several times faster.
    """
    out: list[ast.AST] = []
    stack = [root]
    AST = ast.AST
    while stack:
        node = stack.pop()
        out.append(node)
        for name in node._fields:
            value = getattr(node, name, None)
            if value.__class__ is list:
                for item in reversed(value):
                    if isinstance(item, AST):
                        stack.append(item)
            elif isinstance(value, AST):
                stack.append(value)
    return out


def split_lines(text: str) -> list[str]:
    """Split like the Python tokenizer does (only \\n, \\r\\n and \\r end a line).

    ``str.splitlines`` also splits on form feeds and other characters, which
    would desynchronise our line numbers from ``ast``'s.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


class ModuleContext:
    def __init__(
        self,
        source: SourceFile,
        text: str,
        tree: ast.Module,
        module_name: str,
        is_package: bool,
        program: "ProgramContext",
    ) -> None:
        self.path = source.rel_path
        self.abs_path = source.abs_path
        self.text = text
        self.lines = split_lines(text)
        self.tree = tree
        self.module_name = module_name
        self.is_package = is_package
        self.program = program
        self._resolver: ModuleResolver | None = None
        self._ascii: dict[int, bool] = {}
        self._nodes: list[ast.AST] | None = None

    def __repr__(self) -> str:
        return f"<ModuleContext {self.path} ({self.module_name})>"

    @property
    def resolver(self) -> "ModuleResolver":
        if self._resolver is None:
            from .resolve import ModuleResolver

            self._resolver = ModuleResolver(self.module_name, self.is_package, self.tree)
        return self._resolver

    @property
    def nodes(self) -> list[ast.AST]:
        """All nodes of the module, computed once and shared by rule kinds."""
        if self._nodes is None:
            self._nodes = walk(self.tree)
        return self._nodes

    # -- positions -----------------------------------------------------------

    def _column(self, lineno: int, byte_offset: int) -> int:
        """Convert ast's 0-based UTF-8 byte offset to a 1-based code-point column."""
        if byte_offset is None or byte_offset < 0:
            return 1
        if 1 <= lineno <= len(self.lines):
            flag = self._ascii.get(lineno)
            if flag is None:
                flag = self._ascii[lineno] = self.lines[lineno - 1].isascii()
            if not flag:
                raw = self.lines[lineno - 1].encode("utf-8")[:byte_offset]
                return len(raw.decode("utf-8", "replace")) + 1
        return byte_offset + 1

    def location(self, node: ast.AST, end_node: ast.AST | None = None) -> Location:
        end = end_node if end_node is not None else node
        line = getattr(node, "lineno", 1) or 1
        col = getattr(node, "col_offset", 0) or 0
        end_line = getattr(end, "end_lineno", None) or line
        end_col = getattr(end, "end_col_offset", None)
        if end_col is None:
            end_col = col
        return Location(
            self.path,
            line,
            self._column(line, col),
            end_line,
            self._column(end_line, end_col),
        )

    def unparse(self, node: ast.AST, limit: int = 200) -> str:
        try:
            text = ast.unparse(node)
        except Exception:  # pragma: no cover - defensive, unparse is total in practice
            text = type(node).__name__
        text = " ".join(text.split())
        if len(text) > limit:
            text = text[: limit - 1] + "…"
        return text


class ProgramContext:
    """Everything the scan knows about the whole target."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.modules: list[ModuleContext] = []
        self.diagnostics: list[Diagnostic] = []
        # Rule kinds may keep whole-program state here, keyed by their name.
        self.shared: dict[str, Any] = {}
        self._index: ProjectIndex | None = None

    def warn(self, file: str | None, message: str) -> None:
        self.diagnostics.append(Diagnostic(file, message))

    @property
    def index(self) -> "ProjectIndex":
        if self._index is None:
            from .resolve import ProjectIndex

            self._index = ProjectIndex(self.modules)
        return self._index

    def module(self, rel_path: str) -> ModuleContext | None:
        for mod in self.modules:
            if mod.path == rel_path:
                return mod
        return None


def module_name_for(root: str, rel_path: str, init_files: set[str]) -> tuple[str, bool]:
    """Map a file to the dotted module name Python would import it as.

    Walk up from the file while each directory is a package (contains an
    ``__init__.py``); the first directory that is not a package is taken to be
    on ``sys.path``. If the scan root itself is a package its name is kept as
    the first component.
    """
    parts = rel_path.split("/")
    dirs, fname = parts[:-1], parts[-1]
    stem = fname[:-3] if fname.endswith(".py") else fname
    is_package = stem == "__init__"
    k = len(dirs)
    while k > 0 and "/".join(dirs[:k] + ["__init__.py"]) in init_files:
        k -= 1
    pkg = dirs[k:]
    if k == 0 and "__init__.py" in init_files:
        pkg = [os.path.basename(os.path.normpath(root))] + pkg
    mod_parts = pkg if is_package else pkg + [stem]
    if not mod_parts:
        mod_parts = [os.path.basename(os.path.normpath(root)) or "root"]
    return ".".join(mod_parts), is_package


def read_source(path: str) -> str:
    """Read a Python file honouring PEP 263 encoding cookies and BOMs."""
    with tokenize.open(path) as fh:
        return fh.read()


def build_program(root: str, files: list[SourceFile]) -> ProgramContext:
    program = ProgramContext(root)
    init_files = {f.rel_path for f in files if f.rel_path.split("/")[-1] == "__init__.py"}
    for src in files:
        try:
            text = read_source(src.abs_path)
        except (SyntaxError, UnicodeDecodeError, LookupError) as exc:
            program.warn(src.rel_path, f"skipped, cannot decode file: {exc.__class__.__name__}: {exc}")
            continue
        except OSError as exc:
            program.warn(src.rel_path, f"skipped, cannot read file: {exc}")
            continue
        try:
            tree = ast.parse(text, filename=src.rel_path)
        except SyntaxError as exc:
            where = f" (line {exc.lineno})" if exc.lineno else ""
            program.warn(src.rel_path, f"skipped, syntax error{where}: {exc.msg}")
            continue
        except (ValueError, RecursionError, MemoryError) as exc:
            program.warn(src.rel_path, f"skipped, cannot parse: {exc.__class__.__name__}")
            continue
        name, is_pkg = module_name_for(root, src.rel_path, init_files)
        program.modules.append(ModuleContext(src, text, tree, name, is_pkg, program))
    return program
