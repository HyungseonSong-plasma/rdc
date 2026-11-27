"""No-follow filesystem reads and stable content snapshots (Linux)."""

import hashlib
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import PurePosixPath
from typing import BinaryIO

from rdc.models import FileSnapshot, canonical_path


class FilesystemError(ValueError):
    """Path, file type or source stability failure."""


@contextmanager
def parent_fd(path: str) -> Iterator[tuple[int, str]]:
    """Walk from / using directory descriptors; never follow parent symlinks."""
    parts = PurePosixPath(canonical_path(path)).parts
    if len(parts) == 1:
        raise FilesystemError("Cannot inspect filesystem root as a file.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open("/", flags)
    try:
        for part in parts[1:-1]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, parts[-1]
    finally:
        os.close(fd)


def identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size,
            info.st_mtime_ns, info.st_ctime_ns)


def _read_regular(parent: int, name: str, before: os.stat_result,
                  output: BinaryIO | None) -> str:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(name, flags, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise FilesystemError("Source changed before reading.")
        digest = hashlib.sha256()
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            if output is not None:
                output.write(chunk)
        if identity(os.fstat(stream.fileno())) != identity(before):
            raise FilesystemError("Source changed during reading.")
    return digest.hexdigest()


def snapshot(path: str, output: BinaryIO | None = None) -> FileSnapshot:
    """Read a file or link without dereferencing it; detect replacement/drift."""
    try:
        with parent_fd(path) as (parent, name):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            mode = stat.S_IMODE(before.st_mode)
            digest, link, size = None, None, 0
            if stat.S_ISREG(before.st_mode):
                size = before.st_size
                digest = _read_regular(parent, name, before, output)
            elif stat.S_ISLNK(before.st_mode) and output is None:
                link = os.readlink(name, dir_fd=parent)
                raw = os.fsencode(link)
                size, digest = len(raw), hashlib.sha256(raw).hexdigest()
            elif not (stat.S_ISDIR(before.st_mode) and output is None):
                raise FilesystemError("Unsupported file type or copy operation.")
            after = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if identity(before) != identity(after):
                raise FilesystemError("Source changed during inspection.")
            return FileSnapshot(mode, size, digest, link, identity(before))
    except (OSError, FilesystemError) as error:
        raise FilesystemError(f"Cannot inspect {path}: {error}") from error


def same_content(left: FileSnapshot, right: FileSnapshot) -> bool:
    return (left.mode, left.size, left.sha256, left.link) == (
        right.mode, right.size, right.sha256, right.link)
