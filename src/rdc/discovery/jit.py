"""Compiler queries and explicit promotion of observed JIT resources."""

import shutil
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path

from rdc.discovery.process import run_tool
from rdc.discovery.trace import Access, Scope, TraceReport
from rdc.graph import DependencyGraph
from rdc.models import Dependency, Edge, Evidence, Resolution, canonical_path


@dataclass(frozen=True, slots=True)
class CompilerItem:
    category: str
    name: str
    reported: str
    path: str | None


@dataclass(frozen=True, slots=True)
class CompilerReport:
    compiler: str
    version: str
    machine: str
    items: tuple[CompilerItem, ...]


def _query(compiler: str, argument: str, workspace: Path,
           environment: Mapping[str, str]) -> str:
    value = run_tool((compiler, argument), workspace, environment).stdout.strip()
    if not value or "\n" in value or "\x00" in value:
        raise ValueError("Invalid single-line compiler query result.")
    return value


def query_compiler(compiler: str, workspace: Path,
                   environment: Mapping[str, str], *,
                   programs: tuple[str, ...] = ("cc1plus", "as", "collect2", "ld"),
                   resources: tuple[str, ...] = ("include", "libgcc.a", "libstdc++.so")
                   ) -> CompilerReport:
    """GCC-style query; unresolved names are evidence, never implicit copies."""
    canonical_path(compiler)
    version = _query(compiler, "-dumpfullversion", workspace, environment)
    machine = _query(compiler, "-dumpmachine", workspace, environment)
    items = []
    for category, names, option in (
        ("program", programs, "-print-prog-name="),
        ("resource", resources, "-print-file-name="),
    ):
        for name in names:
            if not name or "/" in name or "\x00" in name or name.startswith("-"):
                raise ValueError("Expected compiler query basename.")
            result = _query(compiler, option + name, workspace, environment)
            path = None
            if result.startswith("/"):
                # Compiler paths may be lexical aliases; report canonical
                # location separately, without changing the reported evidence.
                candidate = Path(result)
                if candidate.exists():
                    path = str(candidate.resolve(strict=True))
            elif category == "program" and result == name:
                search = environment.get("PATH", "")
                if search and all(part.startswith("/") for part in search.split(":")):
                    found = shutil.which(name, path=search)
                    if found is not None:
                        path = str(Path(found).resolve(strict=True))
            items.append(CompilerItem(category, name, result, path))
    return CompilerReport(compiler, version, machine, tuple(items))


def add_jit_inputs(graph: DependencyGraph, requester: Dependency,
                   inputs: Iterable[Dependency], report: TraceReport,
                   compiler: CompilerReport | None = None) -> None:
    """Attach explicit file selections; observations do not imply necessity."""
    selected = tuple(inputs)
    graph.add_node(requester)
    for node in selected:
        graph.add_node(node)
        graph.add_edge(Edge(requester.source, Evidence("resource", "explicit", node.target),
                            Resolution.RESOLVED, node.source))
        for event in report.events:
            if (event.success and event.scope is Scope.CANDIDATE
                    and event.access in (Access.READ, Access.EXEC)
                    and event.path in (node.source, node.target)):
                graph.add_edge(Edge(
                    requester.source, Evidence("trace", event.access.value, node.target),
                    Resolution.RESOLVED, node.source, required=False,
                ))
        if compiler is not None:
            for item in compiler.items:
                if item.path in (node.source, node.target):
                    graph.add_edge(Edge(
                        requester.source, Evidence("compiler", item.category, item.name),
                        Resolution.RESOLVED, node.source, required=False,
                    ))
