"""Resolve explicit runtime paths within a trusted source root; retain aliases."""

import os
import posixpath
import stat
from dataclasses import dataclass
from pathlib import PurePosixPath

from rdc.filesystem import parent_fd
from rdc.models import CollectionPolicy, Dependency, DependencyKind, canonical_path
from rdc.policy import check_mode, check_path


class LookupError(ValueError):
    """Unsafe or unsupported path lookup."""


@dataclass(frozen=True, slots=True)
class PathLookup:
    terminal: Dependency
    aliases: tuple[Dependency, ...]
    links: tuple[tuple[Dependency, Dependency], ...]


def source_path(root: str, target: str) -> str:
    return str(PurePosixPath(canonical_path(root)) / canonical_path(target).lstrip("/"))


def _node(root: str, target: str, kind: DependencyKind) -> Dependency:
    return Dependency(source_path(root, target), target, kind)


def _stat(root: str, policy: CollectionPolicy, target: str) -> os.stat_result:
    node = _node(root, target, DependencyKind.DATA)
    check_path(root, policy, node)
    with parent_fd(node.source) as (parent, name):
        return os.stat(name, dir_fd=parent, follow_symlinks=False)


def link_target(path: str, link: str) -> str:
    """Preserve only link forms supported by the P3 planner."""
    if not link or "\x00" in link or link.startswith("//"):
        raise LookupError(f"Invalid link: {path}")
    parts = link.split("/")
    if link.startswith("/"):
        if any(part in ("", ".", "..") for part in parts[1:]):
            raise LookupError(f"Noncanonical absolute link: {path}")
        return canonical_path(link)
    depth = len(PurePosixPath(path).parent.parts) - 1
    while parts and parts[0] == "..":
        if depth == 0:
            raise LookupError(f"Link escapes root: {path}")
        depth -= 1
        parts.pop(0)
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise LookupError(f"Ambiguous relative link: {path}")
    return canonical_path(posixpath.normpath(posixpath.join(posixpath.dirname(path), link)))


def _link(root: str, policy: CollectionPolicy, path: str) -> tuple[Dependency, Dependency]:
    alias = _node(root, path, DependencyKind.SYMLINK)
    with parent_fd(alias.source) as (parent, name):
        target = link_target(path, os.readlink(name, dir_fd=parent))
    info = _stat(root, policy, target)
    if stat.S_ISLNK(info.st_mode):
        kind = DependencyKind.SYMLINK
    elif stat.S_ISDIR(info.st_mode):
        kind = DependencyKind.DIRECTORY
    elif stat.S_ISREG(info.st_mode):
        kind = DependencyKind.SHARED_LIBRARY
    else:
        raise LookupError(f"Unsupported link target: {path}")
    check_mode(alias, _stat(root, policy, path).st_mode)
    return alias, _node(root, target, kind)


def lookup(root: str, policy: CollectionPolicy, target: str,
           kind: DependencyKind) -> PathLookup:
    """Resolve leaf and parent aliases; reject cycles and ambiguous link targets."""
    current = canonical_path(target)
    seen: set[str] = set()
    links: list[tuple[Dependency, Dependency]] = []
    while True:
        if current in seen or len(links) >= 40:
            raise LookupError(f"Symlink cycle or depth limit: {target}")
        seen.add(current)
        parts = PurePosixPath(current).parts
        for index in range(2, len(parts) + 1):
            prefix = str(PurePosixPath(*parts[:index]))
            info = _stat(root, policy, prefix)
            if stat.S_ISLNK(info.st_mode):
                alias, destination = _link(root, policy, prefix)
                links.append((alias, destination))
                current = str(PurePosixPath(destination.target).joinpath(*parts[index:]))
                break
            if index < len(parts) and not stat.S_ISDIR(info.st_mode):
                raise LookupError(f"Non-directory path ancestor: {prefix}")
        else:
            terminal = _node(root, current, kind)
            check_mode(terminal, _stat(root, policy, current).st_mode)
            return PathLookup(terminal, tuple(pair[0] for pair in links), tuple(links))
