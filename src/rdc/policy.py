"""Explicit path and mode policy; no discovery or implicit resource expansion."""

import stat
from pathlib import PurePosixPath

from rdc.models import CollectionPolicy, Dependency, DependencyKind, canonical_path


class PolicyError(ValueError):
    """A selected path or file violates the collection policy."""


_DENIED = (
    "/proc", "/sys", "/dev", "/run", "/root", "/home",
    "/etc/shadow", "/etc/gshadow", "/etc/ssh", "/etc/ssl/private",
    "/var/lib/private",
)


def check_path(source_root: str, policy: CollectionPolicy, node: Dependency) -> None:
    root = PurePosixPath(canonical_path(source_root))
    source = PurePosixPath(node.source)
    allowed = tuple(PurePosixPath(canonical_path(p)) for p in policy.allowed_roots)
    if not allowed or any(not p.is_relative_to(root) for p in allowed):
        raise PolicyError("Allowed roots must be explicit and inside source root.")
    if source == root or not source.is_relative_to(root):
        raise PolicyError(f"Invalid source root boundary: {node.source}")
    if not any(source.is_relative_to(p) for p in allowed):
        raise PolicyError(f"Source not selected: {node.source}")
    logical = PurePosixPath("/") / source.relative_to(root)
    for candidate in (logical, PurePosixPath(node.target)):
        if any(candidate.is_relative_to(p) for p in _DENIED):
            raise PolicyError(f"Sensitive or virtual path: {candidate}")


def check_mode(node: Dependency, mode: int) -> None:
    if mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX):
        raise PolicyError(f"Privilege or special mode: {node.source}")
    if node.kind is DependencyKind.SYMLINK:
        valid = stat.S_ISLNK(mode)
    elif node.kind is DependencyKind.DIRECTORY:
        valid = stat.S_ISDIR(mode) and (mode & 0o555) == 0o555
    else:
        valid = stat.S_ISREG(mode) and (mode & 0o444) == 0o444
        if node.kind in (DependencyKind.EXECUTABLE, DependencyKind.INTERPRETER):
            valid = valid and (mode & 0o111) == 0o111
    if not valid:
        raise PolicyError(f"Type or portable read/execute mode mismatch: {node.source}")
