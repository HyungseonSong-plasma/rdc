"""Deterministic dependency graph, with no filesystem side effects."""

from collections.abc import Iterable
from pathlib import PurePosixPath

from rdc.models import Closure, Dependency, Edge, canonical_path, edge_key


class GraphError(ValueError):
    """Invalid graph identity, reference or requested root."""


class DependencyGraph:
    """One declared source root; node identity is its absolute lexical path."""

    def __init__(self, source_root: str) -> None:
        self._source_root = canonical_path(source_root)
        self._nodes: dict[str, Dependency] = {}
        self._edges: dict[str, set[Edge]] = {}

    @property
    def source_root(self) -> str:
        return self._source_root

    def add_node(self, node: Dependency) -> None:
        if not PurePosixPath(node.source).is_relative_to(self._source_root):
            raise GraphError(f"Source outside declared root: {node.source}")
        existing = self._nodes.get(node.source)
        if existing is not None and existing != node:
            raise GraphError(f"Conflicting source identity: {node.source}")
        if existing is None:
            self._nodes[node.source] = node
            self._edges[node.source] = set()

    def add_edge(self, edge: Edge) -> None:
        if edge.requester not in self._nodes:
            raise GraphError(f"Unknown requester: {edge.requester}")
        if edge.dependency is not None and edge.dependency not in self._nodes:
            raise GraphError(f"Unknown dependency: {edge.dependency}")
        self._edges[edge.requester].add(edge)

    def closure(self, roots: Iterable[str]) -> Closure:
        """Visit each reachable node once; retain failed and optional evidence."""
        if isinstance(roots, str):
            raise GraphError("Expected an iterable of root paths, not a string.")
        selected = tuple(sorted({canonical_path(root) for root in roots}))
        if not selected:
            raise GraphError("At least one root is required.")
        for root in selected:
            if root not in self._nodes:
                raise GraphError(f"Unknown root: {root}")

        pending = list(selected)
        visited: set[str] = set()
        observations: set[Edge] = set()
        while pending:
            source = pending.pop()
            if source in visited:
                continue
            visited.add(source)
            for edge in self._edges[source]:
                observations.add(edge)
                if edge.dependency is not None and edge.dependency not in visited:
                    pending.append(edge.dependency)

        return Closure(
            selected,
            tuple(self._nodes[source] for source in sorted(visited)),
            tuple(sorted(observations, key=edge_key)),
        )
