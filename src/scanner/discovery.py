"""Find the Python files to scan, deterministically."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass

DEFAULT_EXCLUDES = (
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".tox",
    ".nox",
    ".eggs",
    ".mypy_cache",
    ".pytest_cache",
    "site-packages",
)


@dataclass(frozen=True, slots=True)
class SourceFile:
    abs_path: str
    rel_path: str  # POSIX, relative to the scan root


class TargetError(Exception):
    pass


def _excluded(rel_posix: str, name: str, patterns: tuple[str, ...]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatchcase(name, pat) or fnmatch.fnmatchcase(rel_posix, pat):
            return True
    return False


def discover(target: str, excludes: tuple[str, ...] | list[str] = ()) -> tuple[str, list[SourceFile]]:
    """Return ``(root, files)``.

    ``root`` is the directory paths are reported relative to: the target itself
    for a directory, or the target's parent for a single file. Files are sorted
    by relative path. Symlinked directories are not followed, and symlinked
    files that resolve outside the root are skipped.
    """
    if not os.path.exists(target):
        raise TargetError(f"target does not exist: {target}")
    patterns = tuple(DEFAULT_EXCLUDES) + tuple(excludes)

    if os.path.isfile(target):
        root = os.path.dirname(os.path.abspath(target))
        name = os.path.basename(target)
        return root, [SourceFile(os.path.abspath(target), name)]

    root = os.path.abspath(target)
    real_root = os.path.realpath(root)
    found: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace(os.sep, "/")
        kept = []
        for d in sorted(dirnames):
            rel = f"{rel_dir}/{d}" if rel_dir else d
            if not _excluded(rel, d, patterns):
                kept.append(d)
        dirnames[:] = kept
        for fname in sorted(filenames):
            if not fname.endswith(".py"):
                continue
            rel = f"{rel_dir}/{fname}" if rel_dir else fname
            if _excluded(rel, fname, patterns):
                continue
            abs_path = os.path.join(dirpath, fname)
            if os.path.islink(abs_path):
                real = os.path.realpath(abs_path)
                if os.path.commonpath([real, real_root]) != real_root:
                    continue
            found.append(SourceFile(abs_path, rel))
    found.sort(key=lambda f: f.rel_path)
    return root, found
