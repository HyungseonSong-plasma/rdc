"""Materialize a reviewed plan in a new root, then publish without replacement."""

import ctypes
import os
import shutil
import tempfile
from pathlib import Path

from rdc.filesystem import parent_fd, same_content, snapshot
from rdc.manifest import manifest_bytes
from rdc.models import CollectionPlan, DependencyKind, PlannedEntry, canonical_path
from rdc.planner import plan_closure


class CollectionError(ValueError):
    """Collection cannot be completed without violating the plan."""


def _target(stage: Path, entry: PlannedEntry) -> Path:
    return stage / entry.node.target.lstrip("/")


def _copy(stage: Path, entry: PlannedEntry) -> None:
    destination = _target(stage, entry)
    expected = entry.snapshot
    if entry.node.kind is DependencyKind.DIRECTORY:
        actual = snapshot(entry.node.source, expected=expected)
    elif entry.node.kind is DependencyKind.SYMLINK:
        actual = snapshot(entry.node.source, expected=expected)
        if actual != expected or actual.link is None:
            raise CollectionError(f"Source changed: {entry.node.source}")
        destination.symlink_to(actual.link)
    else:
        with destination.open("xb") as stream:
            actual = snapshot(entry.node.source, stream, expected=expected)
        destination.chmod(expected.mode)
    if actual != expected:
        raise CollectionError(f"Source changed: {entry.node.source}")


def _publish(stage: Path, output: Path) -> None:
    """Linux renameat2(RENAME_NOREPLACE); no clobber or unsafe fallback."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    with parent_fd(str(output)) as (parent, name):
        if rename(parent, os.fsencode(stage.name), parent, os.fsencode(name), 1) != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error), str(output))


def _inventory(stage: Path) -> set[str]:
    """Walk only actual directories, never dereference runtime links."""
    found = {"/"}
    pending = [stage]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                path = Path(entry.path)
                found.add("/" + path.relative_to(stage).as_posix())
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
    return found


def collect(plan: CollectionPlan, output: Path) -> bytes:
    """Return canonical manifest after a successful atomic root publication."""
    canonical_path(str(output))
    if output.exists() or output.is_symlink():
        raise CollectionError(f"Output already exists: {output}")
    with parent_fd(str(output)):
        pass
    for entry in plan.entries:
        if entry.node.kind is DependencyKind.DIRECTORY:
            if output.is_relative_to(entry.node.source):
                raise CollectionError("Output would modify a selected source directory.")
    if plan_closure(plan.source_root, plan.closure, plan.policy, plan.build) != plan:
        raise CollectionError("Plan changed since discovery.")
    manifest = manifest_bytes(plan)
    stage = Path(tempfile.mkdtemp(prefix=".rdc-", dir=output.parent))
    try:
        # Create all parents explicitly; do not inherit process umask in final modes.
        stage.chmod(0o700)
        for path, _ in plan.directories:
            if path != "/":
                directory = stage / path.lstrip("/")
                directory.mkdir(mode=0o700)
                directory.chmod(0o700)
        for entry in plan.entries:
            _copy(stage, entry)
        for path, mode in reversed(plan.directories):
            (stage / path.lstrip("/")).chmod(mode)
        for entry in plan.entries:
            if snapshot(entry.node.source, expected=entry.snapshot) != entry.snapshot:
                raise CollectionError(f"Source changed: {entry.node.source}")
            actual = snapshot(str(_target(stage, entry)))
            if not same_content(actual, entry.snapshot):
                raise CollectionError(f"Readback mismatch: {entry.node.target}")
        expected_paths = {entry.node.target for entry in plan.entries}
        expected_paths.update(path for path, _ in plan.directories)
        if _inventory(stage) != expected_paths:
            raise CollectionError("Unexpected or missing staged paths.")
        for path, mode in plan.directories:
            directory = stage / path.lstrip("/")
            if not directory.is_dir() or directory.is_symlink():
                raise CollectionError(f"Directory readback mismatch: {path}")
            if directory.stat().st_mode & 0o7777 != mode:
                raise CollectionError(f"Directory mode mismatch: {path}")
        _publish(stage, output)
    finally:
        if stage.exists():
            # Restore only owned staging directory modes for rollback.
            for directory, _, _ in os.walk(stage, topdown=True, followlinks=False):
                Path(directory).chmod(0o700)
            shutil.rmtree(stage)
    return manifest
