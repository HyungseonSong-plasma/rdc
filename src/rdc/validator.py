"""Independently verify a published root against a trusted manifest digest."""

import hashlib
import json
import os
import posixpath
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import cast

from rdc.filesystem import snapshot
from rdc.models import CollectionPolicy, Dependency, DependencyKind, canonical_path
from rdc.policy import check_mode, check_path


class ValidationError(ValueError):
    """Invalid manifest, rootfs, or runtime evidence."""


@dataclass(frozen=True, slots=True)
class VerifiedRoot:
    root: Path
    manifest_sha256: str
    paths: tuple[str, ...]
    collected_bytes: int


def _object(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValidationError("Expected manifest object.")
    return cast(dict[str, object], value)


def _list(value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValidationError("Expected manifest array.")
    return cast(list[object], value)


def _string(value: object) -> str:
    if not isinstance(value, str):
        raise ValidationError("Expected manifest string.")
    return value


def _integer(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValidationError("Expected nonnegative manifest integer.")
    return value


def _digest(value: str) -> str:
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValidationError("Expected lowercase SHA256.")
    return value


def _target(value: object) -> str:
    return canonical_path(_string(value))


def _link_destination(path: str, link: str) -> str:
    """Independent lexical check of preserved, root-relative link semantics."""
    if not link or "\x00" in link or link.startswith("//"):
        raise ValidationError(f"Invalid link: {path}")
    parts = link.split("/")
    if link.startswith("/"):
        parts = parts[1:]
    else:
        depth = len(PurePosixPath(path).parent.parts) - 1
        while parts and parts[0] == "..":
            depth -= 1
            if depth < 0:
                raise ValidationError(f"Escaping link: {path}")
            parts.pop(0)
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValidationError(f"Ambiguous link: {path}")
    return canonical_path(posixpath.normpath(posixpath.join(posixpath.dirname(path), link)))


def _inventory(root: Path) -> set[str]:
    result = {"/"}
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as stream:
            for entry in stream:
                path = Path(entry.path)
                result.add("/" + path.relative_to(root).as_posix())
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
    return result


def verify_rootfs(root: Path, manifest: bytes, expected_sha256: str) -> VerifiedRoot:
    """Check exact inventory, types, modes, digests and preserved link layout.

    The manifest digest must come from a trusted collection receipt. Root and
    its parent must remain under caller control, not hostile concurrent writers.
    No access to the original source tree is required.
    """
    canonical_path(str(root))
    if root == Path("/") or root.resolve(strict=True) != root or not root.is_dir():
        raise ValidationError("Expected a real, dedicated runtime directory.")
    if hashlib.sha256(manifest).hexdigest() != _digest(expected_sha256):
        raise ValidationError("Manifest digest mismatch.")
    try:
        data = _object(json.loads(manifest))
        canonical = (json.dumps(data, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValidationError("Invalid canonical manifest.") from error
    if (canonical != manifest or data.get("schema") != "rdc.collection.v1"
            or data.get("validation") != "structural-and-content-only"):
        raise ValidationError("Unsupported or noncanonical collection manifest.")

    directories: dict[str, int] = {}
    for raw in _list(data.get("directories")):
        item = _object(raw)
        target, mode = _target(item.get("target")), _integer(item.get("mode"))
        if target in directories or mode > 0o777 or mode & 0o555 != 0o555:
            raise ValidationError(f"Duplicate or unsafe directory: {target}")
        directories[target] = mode
    if "/" not in directories:
        raise ValidationError("Missing root directory.")

    files: dict[str, tuple[DependencyKind, int, int, str | None, str | None]] = {}
    sources: set[str] = set()
    for raw in _list(data.get("files")):
        item = _object(raw)
        source, target = _target(item.get("source")), _target(item.get("target"))
        if source == "/" or target == "/" or source in sources or target in files:
            raise ValidationError(f"Duplicate or invalid file identity: {target}")
        sources.add(source)
        kind = DependencyKind(_string(item.get("kind")))
        mode, size = _integer(item.get("mode")), _integer(item.get("size"))
        raw_digest = item.get("sha256")
        raw_link = item.get("link")
        digest = None if raw_digest is None else _digest(_string(raw_digest))
        link = None if raw_link is None else _string(raw_link)
        if kind is DependencyKind.DIRECTORY:
            if directories.get(target) != mode or size != 0 or digest is not None or link is not None:
                raise ValidationError(f"Invalid directory entry: {target}")
        elif (target in directories or digest is None
              or (kind is DependencyKind.SYMLINK) != (link is not None)):
            raise ValidationError(f"Invalid file entry: {target}")
        files[target] = (kind, mode, size, digest, link)
    if not files:
        raise ValidationError("Empty runtime file inventory.")
    all_paths = set(directories) | set(files)
    for target in all_paths:
        if any(str(parent) not in directories for parent in PurePosixPath(target).parents):
            raise ValidationError(f"Missing directory ancestor: {target}")
    if _inventory(root) != all_paths:
        raise ValidationError("Unexpected or missing runtime paths.")

    # Independently enforce type and policy before reading each file.
    policy = CollectionPolicy((str(root),))
    for target, mode in directories.items():
        path = root / target.lstrip("/")
        if target != "/":
            check_path(str(root), policy, Dependency(str(path), target, DependencyKind.DIRECTORY))
        if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o7777 != mode:
            raise ValidationError(f"Directory mode or type mismatch: {target}")

    links: dict[str, str] = {}
    for target, (kind, mode, size, digest, link) in files.items():
        filename = str(root / target.lstrip("/"))
        node = Dependency(filename, target, kind)
        check_path(str(root), policy, node)
        actual = snapshot(filename, guard=lambda value: check_mode(node, value))
        if (actual.mode, actual.size, actual.sha256, actual.link) != (mode, size, digest, link):
            raise ValidationError(f"Runtime content mismatch: {target}")
        if link is not None:
            destination = _link_destination(target, link)
            if destination not in files:
                raise ValidationError(f"Uncollected symlink destination: {target}")
            links[target] = destination
    for start in links:
        seen: set[str] = set()
        path_name = start
        while path_name in links:
            if path_name in seen:
                raise ValidationError(f"Runtime symlink cycle: {start}")
            seen.add(path_name)
            path_name = links[path_name]
    collected = sum(value[2] for value in files.values())
    if collected != _integer(data.get("collected_bytes")):
        raise ValidationError("Collected byte count mismatch.")
    return VerifiedRoot(root, expected_sha256, tuple(sorted(all_paths)), collected)
