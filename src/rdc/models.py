"""Immutable, filesystem-independent dependency records."""

from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath


class DependencyKind(StrEnum):
    EXECUTABLE = "executable"
    SHARED_LIBRARY = "shared_library"
    INTERPRETER = "interpreter"
    HEADER = "header"
    DATA = "data"
    CONFIG = "config"
    SYMLINK = "symlink"
    DIRECTORY = "directory"


class Resolution(StrEnum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"
    DENIED = "denied"


def canonical_path(value: str) -> str:
    """Accept only already-normalized absolute POSIX paths, without I/O."""
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("Expected a POSIX path string.")
    path = PurePosixPath(value)
    if not path.is_absolute() or value.startswith("//") or ".." in path.parts:
        raise ValueError(f"Invalid absolute path: {value!r}")
    if str(path) != value:
        raise ValueError(f"Noncanonical path: {value!r}")
    return value


def nonempty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"Invalid {name}.")


@dataclass(frozen=True, slots=True)
class Dependency:
    """Source identity is lexical; symlink aliases remain distinct nodes."""

    source: str
    target: str
    kind: DependencyKind

    def __post_init__(self) -> None:
        canonical_path(self.source)
        canonical_path(self.target)
        if self.target == "/":
            raise ValueError("A dependency cannot replace the target root.")
        if not isinstance(self.kind, DependencyKind):
            raise ValueError("Invalid dependency kind.")


@dataclass(frozen=True, slots=True)
class Evidence:
    analyzer: str
    relation: str
    request: str

    def __post_init__(self) -> None:
        nonempty(self.analyzer, "analyzer")
        nonempty(self.relation, "relation")
        nonempty(self.request, "request")


@dataclass(frozen=True, slots=True)
class Edge:
    """A resolved edge names a node; failed observations retain their request."""

    requester: str
    evidence: Evidence
    status: Resolution
    dependency: str | None = None
    required: bool = True

    def __post_init__(self) -> None:
        canonical_path(self.requester)
        if not isinstance(self.evidence, Evidence):
            raise ValueError("Invalid evidence.")
        if not isinstance(self.status, Resolution) or type(self.required) is not bool:
            raise ValueError("Invalid resolution or requirement.")
        if self.status is Resolution.RESOLVED:
            if self.dependency is None:
                raise ValueError("Resolved edge requires a dependency.")
            canonical_path(self.dependency)
        elif self.dependency is not None:
            raise ValueError("Unresolved or denied edge cannot name a resolved node.")


def edge_key(edge: Edge) -> tuple[str, str, str, str, str, str, bool]:
    """Canonical order independent of discovery/insertion order."""
    return (
        edge.requester, edge.evidence.analyzer, edge.evidence.relation,
        edge.evidence.request, edge.status.value, edge.dependency or "",
        edge.required,
    )


@dataclass(frozen=True, slots=True)
class Closure:
    roots: tuple[str, ...]
    nodes: tuple[Dependency, ...]
    edges: tuple[Edge, ...]

    @property
    def blockers(self) -> tuple[Edge, ...]:
        return tuple(
            edge for edge in self.edges
            if edge.required and edge.status is not Resolution.RESOLVED
        )

    @property
    def complete(self) -> bool:
        """No known required blocker; not proof of workload coverage."""
        return not self.blockers


@dataclass(frozen=True, slots=True)
class FileSnapshot:
    """Content and local identity; only content enters the canonical manifest."""

    mode: int
    size: int
    sha256: str | None
    link: str | None
    identity: tuple[int, int, int, int, int, int]


@dataclass(frozen=True, slots=True)
class CollectionPolicy:
    allowed_roots: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BuildIdentity:
    build: str
    profile_sha256: str
    abi: str
    tools: tuple[tuple[str, str], ...]
    coverage: tuple[str, ...]

    def __post_init__(self) -> None:
        nonempty(self.build, "build identity")
        nonempty(self.abi, "ABI")
        if (len(self.profile_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.profile_sha256)):
            raise ValueError("Expected lowercase SHA256 profile digest.")
        for name, version in self.tools:
            nonempty(name, "tool name")
            nonempty(version, "tool version")
        if len({name for name, _ in self.tools}) != len(self.tools):
            raise ValueError("Duplicate tool name.")
        if not self.coverage:
            raise ValueError("Expected explicit validation coverage.")
        for item in self.coverage:
            nonempty(item, "coverage")


@dataclass(frozen=True, slots=True)
class PlannedEntry:
    node: Dependency
    snapshot: FileSnapshot


@dataclass(frozen=True, slots=True)
class CollectionPlan:
    source_root: str
    policy: CollectionPolicy
    build: BuildIdentity
    closure: Closure
    entries: tuple[PlannedEntry, ...]

    @property
    def directories(self) -> tuple[tuple[str, int], ...]:
        """Explicit directories keep their modes; synthetic parents use 0755."""
        modes: dict[str, int] = {"/": 0o755}
        for entry in self.entries:
            target = PurePosixPath(entry.node.target)
            for parent in target.parents:
                modes.setdefault(str(parent), 0o755)
            if entry.node.kind is DependencyKind.DIRECTORY:
                modes[str(target)] = entry.snapshot.mode
        return tuple(sorted(modes.items()))
