"""Bounded, non-executing ELF64 little-endian x86-64 metadata reader."""

import hashlib
import os
import stat
import struct
from dataclasses import dataclass
from typing import BinaryIO

from rdc.filesystem import identity, parent_fd


class ElfError(ValueError):
    """Invalid or unsupported ELF metadata."""


@dataclass(frozen=True, slots=True)
class ElfMetadata:
    interpreter: str | None
    needed: tuple[str, ...]
    runpath: str | None
    rpath: str | None
    soname: str | None
    nodeflib: bool
    sha256: str


@dataclass(frozen=True, slots=True)
class _Segment:
    kind: int
    offset: int
    address: int
    size: int


def _read(stream: BinaryIO, offset: int, count: int, size: int) -> bytes:
    if offset < 0 or count < 0 or offset + count > size:
        raise ElfError("ELF range outside file.")
    stream.seek(offset)
    data = stream.read(count)
    if len(data) != count:
        raise ElfError("Truncated ELF data.")
    return data


def _segments(stream: BinaryIO, size: int) -> tuple[_Segment, ...]:
    header = struct.unpack("<16sHHIQQQIHHHHHH", _read(stream, 0, 64, size))
    ident, kind, machine, version = header[:4]
    if (ident[:7] != b"\x7fELF\x02\x01\x01" or machine != 62
            or version != 1 or kind not in (2, 3)):
        raise ElfError("Expected ELF64 little-endian x86-64 executable/shared object.")
    offset, header_size, stride, count = header[5], header[8], header[9], header[10]
    if header_size != 64 or stride != 56 or not 0 < count < 65535:
        raise ElfError("Unsupported program header table.")
    if offset < 64 or offset + stride * count > size:
        raise ElfError("Invalid program header table.")
    result = []
    for index in range(count):
        fields = struct.unpack("<IIQQQQQQ", _read(stream, offset + index * stride, stride, size))
        segment = _Segment(fields[0], fields[2], fields[3], fields[5])
        if segment.offset + segment.size > size:
            raise ElfError("Segment outside file.")
        result.append(segment)
    return tuple(result)


def _one(segments: tuple[_Segment, ...], kind: int) -> _Segment | None:
    matches = tuple(item for item in segments if item.kind == kind)
    if len(matches) > 1:
        raise ElfError("Duplicate ELF segment.")
    return matches[0] if matches else None


def _string(data: bytes, offset: int) -> str:
    if not 0 <= offset < len(data):
        raise ElfError("Invalid ELF string offset.")
    end = data.find(b"\x00", offset)
    if end == -1 or end == offset:
        raise ElfError("Missing or empty ELF string.")
    try:
        return data[offset:end].decode("utf-8")
    except UnicodeError as error:
        raise ElfError("Unsupported ELF string encoding.") from error


def _dynamic(stream: BinaryIO, size: int, segment: _Segment) -> dict[int, list[int]]:
    if not segment.size or segment.size % 16 or segment.size > 1024 * 1024:
        raise ElfError("Invalid or oversized dynamic table.")
    values: dict[int, list[int]] = {}
    for tag, value in struct.iter_unpack(
            "<qQ", _read(stream, segment.offset, segment.size, size)):
        if tag == 0:
            break
        values.setdefault(tag, []).append(value)
    else:
        raise ElfError("Unterminated dynamic table.")
    if any(tag in values for tag in (0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff)):
        raise ElfError("ELF audit/filter/auxiliary dependencies are unsupported.")
    for tag in (5, 10, 14, 15, 29, 0x6ffffffb):
        if len(values.get(tag, ())) > 1:
            raise ElfError("Duplicate singleton dynamic tag.")
    return values


def _strings(stream: BinaryIO, size: int, segments: tuple[_Segment, ...],
             values: dict[int, list[int]]) -> bytes:
    if 5 not in values or 10 not in values:
        raise ElfError("Missing dynamic string table.")
    address, length = values[5][0], values[10][0]
    if not 0 < length <= 16 * 1024 * 1024:
        raise ElfError("Invalid or oversized dynamic string table.")
    offsets = {
        seg.offset + address - seg.address for seg in segments
        if seg.kind == 1 and seg.address <= address
        and address + length <= seg.address + seg.size
    }
    if len(offsets) != 1:
        raise ElfError("Unmapped or ambiguous dynamic string table.")
    return _read(stream, offsets.pop(), length, size)


def _parse(stream: BinaryIO, size: int) -> ElfMetadata:
    segments = _segments(stream, size)
    interp = _one(segments, 3)
    interpreter = None
    if interp is not None:
        if not 2 <= interp.size <= 4096:
            raise ElfError("Invalid interpreter length.")
        data = _read(stream, interp.offset, interp.size, size)
        interpreter = _string(data, 0)
        if data != interpreter.encode("utf-8") + b"\x00":
            raise ElfError("Invalid interpreter terminator.")
    dynamic = _one(segments, 2)
    needed: tuple[str, ...] = ()
    runpath = rpath = soname = None
    nodeflib = False
    if dynamic is not None:
        values = _dynamic(stream, size, dynamic)
        if any(tag in values for tag in (1, 14, 15, 29)):
            strings = _strings(stream, size, segments, values)
            needed = tuple(_string(strings, value) for value in values.get(1, ()))
            runpath = _string(strings, values[29][0]) if 29 in values else None
            rpath = _string(strings, values[15][0]) if 15 in values else None
            soname = _string(strings, values[14][0]) if 14 in values else None
        nodeflib = bool(values.get(0x6ffffffb, [0])[0] & 0x800)
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return ElfMetadata(interpreter, needed, runpath, rpath, soname, nodeflib,
                       digest.hexdigest())


def read_elf(path: str) -> ElfMetadata:
    """Inspect a regular file without executing it or following symlinks."""
    try:
        with parent_fd(path) as (parent, name):
            before = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (not stat.S_ISREG(before.st_mode) or before.st_mode & 0o7000
                    or before.st_mode & 0o444 != 0o444):
                raise ElfError("Expected non-privileged readable regular ELF.")
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                         dir_fd=parent)
            with os.fdopen(fd, "rb") as stream:
                if identity(os.fstat(stream.fileno())) != identity(before):
                    raise ElfError("ELF changed before inspection.")
                result = _parse(stream, before.st_size)
                if identity(os.fstat(stream.fileno())) != identity(before):
                    raise ElfError("ELF changed during inspection.")
            if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(before):
                raise ElfError("ELF replaced during inspection.")
            return result
    except (OSError, ElfError) as error:
        raise ElfError(f"{path}: {error}") from error
