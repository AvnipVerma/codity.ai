from scanner.context import module_name_for
from scanner.discovery import discover

from .conftest import write_tree


def test_discovery_sorted_python_only_with_default_excludes(tmp_path):
    write_tree(
        tmp_path,
        {
            "b.py": "",
            "a.py": "",
            "notes.txt": "",
            "pkg/__init__.py": "",
            "pkg/z.py": "",
            ".venv/lib/x.py": "",
            "node_modules/y.py": "",
            "pkg/__pycache__/c.py": "",
        },
    )
    root, files = discover(str(tmp_path))
    assert [f.rel_path for f in files] == ["a.py", "b.py", "pkg/__init__.py", "pkg/z.py"]


def test_exclude_globs(tmp_path):
    write_tree(tmp_path, {"app.py": "", "tests/test_app.py": "", "gen/x_pb2.py": ""})
    _, files = discover(str(tmp_path), ["tests", "*_pb2.py"])
    assert [f.rel_path for f in files] == ["app.py"]


def test_single_file_target(tmp_path):
    write_tree(tmp_path, {"one.py": "x = 1\n"})
    root, files = discover(str(tmp_path / "one.py"))
    assert [f.rel_path for f in files] == ["one.py"]


def test_module_names():
    inits = {"pkg/__init__.py", "pkg/sub/__init__.py"}
    assert module_name_for("/r", "pkg/sub/mod.py", inits) == ("pkg.sub.mod", False)
    assert module_name_for("/r", "pkg/__init__.py", inits) == ("pkg", True)
    assert module_name_for("/r", "scripts/run.py", inits) == ("run", False)
    # src layout: src/ is not a package, so it is the sys.path root
    assert module_name_for("/r", "src/pkg/mod.py", {"src/pkg/__init__.py"}) == ("pkg.mod", False)
