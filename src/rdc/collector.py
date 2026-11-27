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
    destination.parent.mkdir(parents=True, exist_ok=True)
    expected = entry.snapshot
    if entry.node.kind is DependencyKind.DIRECTORY:
        destination.mkdir(exist_ok=True)
        actual = snapshot(entry.node.source)
    elif entry.node.kind is DependencyKind.SYMLINK:
        actual = snapshot(entry.node.source)
        if actual != expected or actual.link is None:
            raise CollectionError(f"Source changed: {entry.node.source}")
        destination.symlink_to(actual.link)
    else:
        with destination.open("xb") as stream:
            actual = snapshot(entry.node.source, stream)
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
        # Directory creation precedes mode application so read-only directories
        # remain materializable. Links cannot be ancestors of planned targets.
        for entry in plan.entries:
            _copy(stage, entry)
        for entry in reversed(plan.entries):
            if entry.node.kind is DependencyKind.DIRECTORY:
                _target(stage, entry).chmod(entry.snapshot.mode)
        for entry in plan.entries:
            if snapshot(entry.node.source) != entry.snapshot:
                raise CollectionError(f"Source changed: {entry.node.source}")
            actual = snapshot(str(_target(stage, entry)))
            if not same_content(actual, entry.snapshot):
                raise CollectionError(f"Readback mismatch: {entry.node.target}")
        stage.chmod(0o755)
        _publish(stage, output)
    finally:
        if stage.exists():
            # Restore only owned staging directory modes for rollback.
            for directory, _, _ in os.walk(stage, topdown=True, followlinks=False):
                Path(directory).chmod(0o700)
            shutil.rmtree(stage)
    return manifest
