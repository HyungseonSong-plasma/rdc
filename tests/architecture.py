"""P5 import and explicit-registration contracts (not a sandbox)."""

import ast
import sys
from pathlib import Path
from tokenize import open as open_source

ROOT = Path(__file__).resolve().parents[1]
IMPORTS = {
    "__init__.py": frozenset(),
    "models.py": frozenset(),
    "discovery/__init__.py": frozenset(),
    "discovery/elf.py": frozenset({"rdc.filesystem"}),
    "discovery/process.py": frozenset({"rdc.models"}),
    "discovery/trace.py": frozenset({"rdc.discovery.process", "rdc.models"}),
    "discovery/jit.py": frozenset({
        "rdc.discovery.process", "rdc.discovery.trace", "rdc.graph", "rdc.models",
    }),
    "discovery/paths.py": frozenset({"rdc.filesystem", "rdc.models", "rdc.policy"}),
    "discovery/loader.py": frozenset({
        "rdc.discovery.elf", "rdc.discovery.paths", "rdc.graph", "rdc.models",
    }),
    "graph.py": frozenset({"rdc.models"}),
    "filesystem.py": frozenset({"rdc.models"}),
    "policy.py": frozenset({"rdc.models"}),
    "planner.py": frozenset({"rdc.models", "rdc.graph", "rdc.filesystem", "rdc.policy"}),
    "manifest.py": frozenset({"rdc.models"}),
    "collector.py": frozenset({"rdc.models", "rdc.filesystem", "rdc.planner", "rdc.manifest"}),
}


def import_violations(filename, source):
    if filename not in IMPORTS:
        return (f"Undeclared module: {filename}",)
    failures = []
    for item in ast.walk(ast.parse(source, filename=filename)):
        targets = ()
        if isinstance(item, ast.Import):
            targets = tuple(alias.name for alias in item.names)
        elif isinstance(item, ast.ImportFrom):
            if item.level:
                failures.append(f"{filename}:{item.lineno}: use explicit absolute imports")
                continue
            targets = (item.module or "",)
        for target in targets:
            if (target not in IMPORTS[filename]
                    and target.split(".")[0] not in sys.stdlib_module_names):
                failures.append(f"{filename}:{item.lineno}: forbidden import {target}")
        if isinstance(item, ast.Call):
            name = getattr(item.func, "id", getattr(item.func, "attr", ""))
            if name in {"__import__", "import_module", "eval", "exec"}:
                failures.append(f"{filename}:{item.lineno}: dynamic execution/import")
    return tuple(failures)


def repository_violations():
    root = ROOT / "src" / "rdc"
    paths = {path.relative_to(root).as_posix(): path for path in root.rglob("*.py")}
    failures = [f"Missing module: {name}" for name in sorted(set(IMPORTS) - paths.keys())]
    for name, path in sorted(paths.items()):
        with open_source(path) as stream:
            failures.extend(import_violations(name, stream.read()))
    return tuple(failures)


def registration_violations(registry, group="suites"):
    """Compare declared test classes/methods with the actual registered suites."""
    import unittest

    directory = ROOT / "tests" / group
    expected = {}
    for path in sorted(directory.rglob("*.py")):
        if path.name == "__init__.py":
            continue
        module = ".".join(path.relative_to(ROOT).with_suffix("").parts)
        with open_source(path) as stream:
            tree = ast.parse(stream.read(), filename=str(path))
        for item in tree.body:
            if isinstance(item, ast.ClassDef):
                methods = {n.name for n in item.body
                           if isinstance(n, ast.FunctionDef) and n.name.startswith("test_")}
                if methods:
                    expected[(module, item.name)] = methods
        if any(isinstance(item, ast.FunctionDef) and item.name.startswith("test_")
               for item in tree.body):
            return (f"Unregistered module-level tests: {path.name}",)
    actual = {
        (case.__module__, case.__name__): set(unittest.defaultTestLoader.getTestCaseNames(case))
        for case in registry.values()
    }
    return () if expected == actual else ("Registered suite coverage mismatch.",)
