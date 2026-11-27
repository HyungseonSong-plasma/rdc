"""Explicit loader profile and recursive ELF graph discovery (no host fallback)."""

import posixpath
from collections.abc import Iterable
from dataclasses import dataclass

from rdc.discovery.elf import ElfError, ElfMetadata, read_elf
from rdc.discovery.paths import PathLookup, lookup, source_path
from rdc.graph import DependencyGraph
from rdc.models import (
    CollectionPolicy, Dependency, DependencyKind, Edge, Evidence, Resolution, canonical_path,
)


@dataclass(frozen=True, slots=True)
class LoaderProfile:
    source_root: str
    policy: CollectionPolicy
    default_dirs: tuple[str, ...]

    def __post_init__(self) -> None:
        canonical_path(self.source_root)
        for path in self.default_dirs:
            canonical_path(path)
        if len(set(self.default_dirs)) != len(self.default_dirs):
            raise ValueError("Duplicate loader search directory.")


@dataclass(frozen=True, slots=True)
class ElfDiscovery:
    graph: DependencyGraph
    roots: tuple[str, ...]


def _normalize(path: str) -> str:
    if not path.startswith("/") or path.startswith("//") or "$" in path:
        raise ElfError(f"Unsupported loader path: {path}")
    parts: list[str] = []
    for component in path.split("/")[1:]:
        if component == "..":
            if not parts:
                raise ElfError("Loader path escapes root.")
            parts.pop()
        elif component not in ("", "."):
            parts.append(component)
    return "/" + "/".join(parts)


def _directories(profile: LoaderProfile, target: str,
                 metadata: ElfMetadata) -> tuple[str, ...]:
    if metadata.rpath is not None and metadata.runpath is None:
        raise ElfError("Legacy inherited DT_RPATH requires a separate resolution model.")
    paths: list[str] = []
    if metadata.runpath is not None:
        origin = posixpath.dirname(target)
        for value in metadata.runpath.split(":"):
            if not value:
                raise ElfError("Empty RUNPATH component depends on working directory.")
            value = value.replace("${ORIGIN}", origin)
            # Only an exact ORIGIN token is supported.
            if "$ORIGIN" in value:
                if value != "$ORIGIN" and not value.startswith("$ORIGIN/"):
                    raise ElfError("Unsupported ORIGIN token placement.")
                value = value.replace("$ORIGIN", origin, 1)
            paths.append(_normalize(value))
    if not metadata.nodeflib:
        paths.extend(profile.default_dirs)
    return tuple(dict.fromkeys(paths))


class _Discovery:
    """One graph per explicit profile; keep file identity separate from ELF role."""

    def __init__(self, profile: LoaderProfile) -> None:
        self.profile = profile
        self.nodes: dict[str, Dependency] = {}
        self.edges: set[Edge] = set()
        self.pending: list[str] = []
        self.visited: set[str] = set()

    def _add(self, node: Dependency) -> None:
        previous = self.nodes.get(node.source)
        if previous is None:
            self.nodes[node.source] = node
            if node.kind not in (DependencyKind.DIRECTORY, DependencyKind.SYMLINK):
                self.pending.append(node.source)
        elif previous != node:
            # One ELF file may be both PT_INTERP and DT_NEEDED.
            priority = {DependencyKind.SHARED_LIBRARY: 0, DependencyKind.INTERPRETER: 1,
                        DependencyKind.EXECUTABLE: 2}
            if (previous.target != node.target or previous.kind not in priority
                    or node.kind not in priority):
                raise ElfError(f"Conflicting ELF path identity: {node.source}")
            if priority[node.kind] > priority[previous.kind]:
                self.nodes[node.source] = node

    def _edge(self, requester: str, relation: str, request: str,
              node: Dependency | None) -> None:
        self.edges.add(Edge(requester, Evidence("elf", relation, request),
                            Resolution.RESOLVED if node is not None else Resolution.UNRESOLVED,
                            node.source if node is not None else None))

    def _record(self, result: PathLookup) -> None:
        self._add(result.terminal)
        for alias, destination in result.links:
            self._add(alias)
            self._add(destination)
            self._edge(alias.source, "symlink", destination.target, destination)

    def _lookup(self, path: str, kind: DependencyKind) -> PathLookup:
        return lookup(self.profile.source_root, self.profile.policy, path, kind)

    def _request(self, requester: str, relation: str, request: str,
                 candidates: Iterable[str], kind: DependencyKind) -> None:
        for path in candidates:
            try:
                result = self._lookup(path, kind)
            except FileNotFoundError:
                continue
            self._record(result)
            self._edge(requester, relation, request, result.terminal)
            for alias in result.aliases:
                self._edge(requester, "path-alias", path, alias)
            return
        self._edge(requester, relation, request, None)

    def run(self, targets: Iterable[str]) -> ElfDiscovery:
        roots: set[str] = set()
        for target in targets:
            result = self._lookup(canonical_path(target), DependencyKind.EXECUTABLE)
            self._record(result)
            # A directory alias needs its own root to keep it materialized.
            roots.add(result.terminal.source)
            roots.update(alias.source for alias in result.aliases)
        if not roots:
            raise ElfError("Expected at least one executable root.")
        while self.pending:
            source = self.pending.pop()
            if source in self.visited:
                continue
            self.visited.add(source)
            node = self.nodes[source]
            metadata = read_elf(source)
            self._edge(source, "elf-sha256", metadata.sha256, node)
            dirs = _directories(self.profile, node.target, metadata)
            if metadata.interpreter is not None:
                path = canonical_path(metadata.interpreter)
                self._request(source, "interpreter", path, (path,), DependencyKind.INTERPRETER)
            for name in metadata.needed:
                candidates: tuple[str, ...]
                if "/" in name:
                    candidates = (canonical_path(name),)
                elif "$" in name:
                    raise ElfError(f"Unsupported dynamic token: {name}")
                else:
                    candidates = tuple(posixpath.join(path, name) for path in dirs)
                self._request(source, "needed", name, candidates, DependencyKind.SHARED_LIBRARY)
        graph = DependencyGraph(self.profile.source_root)
        for item in self.nodes.values():
            graph.add_node(item)
        for edge in self.edges:
            graph.add_edge(edge)
        return ElfDiscovery(graph, tuple(sorted(roots)))


def discover_elf(profile: LoaderProfile, roots: Iterable[str]) -> ElfDiscovery:
    """Static closure for explicit search directories, not general ld.so emulation."""
    if isinstance(roots, str):
        raise ElfError("Expected an iterable of executable paths.")
    # Validate root even if no candidate exists.
    source_path(profile.source_root, "/")
    return _Discovery(profile).run(roots)
