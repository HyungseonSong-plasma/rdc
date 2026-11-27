"""Parse a deliberately bounded strace file/exec observation contract."""

import hashlib
import re
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath

from rdc.discovery.process import run_tool
from rdc.models import canonical_path


class TraceError(ValueError):
    """Malformed, truncated or unsupported trace input."""


class Access(StrEnum):
    READ = "read"
    EXEC = "exec"
    WRITE = "write"
    DIRECTORY = "directory"


class Scope(StrEnum):
    CANDIDATE = "candidate"
    WORKSPACE = "workspace"
    EXTERNAL = "external"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class TraceEvent:
    operation: str
    path: str
    access: Access
    scope: Scope
    success: bool
    errno: str | None


@dataclass(frozen=True, slots=True)
class TraceReport:
    events: tuple[TraceEvent, ...]
    stdout: str
    stream_sha256: tuple[str, ...]

    @property
    def candidates(self) -> tuple[str, ...]:
        """Observed inputs only; no statement that they are necessary."""
        return tuple(sorted({event.path for event in self.events
                             if event.success and event.scope is Scope.CANDIDATE
                             and event.access in (Access.READ, Access.EXEC)}))


# -xx gives unambiguous byte encoding. Per-process logs (-ff) avoid interleaving.
_SYSCALL = re.compile(r"^(open|openat|openat2|creat|execve|execveat)\((.*)\)\s+=\s+(-?\d+)(?:\s+([A-Z][A-Z0-9_]*))?(?:\s+.*)?$")
_QUOTED = re.compile(r'^"((?:\\x[0-9a-fA-F]{2})*)"')
_AT = frozenset({"openat", "openat2", "execveat"})
_EXEC = frozenset({"execve", "execveat"})
_WRITE = frozenset({"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_TMPFILE"})


def _scope(path: str, workspace: str, external: tuple[str, ...]) -> Scope:
    try:
        canonical_path(path)
    except ValueError:
        # Relative paths and lexical traversal require cwd/dirfd/alias evidence.
        return Scope.UNKNOWN
    item = PurePosixPath(path)
    if item.is_relative_to(workspace):
        return Scope.WORKSPACE
    if any(item.is_relative_to(root) for root in external):
        return Scope.EXTERNAL
    return Scope.CANDIDATE


def _decode_argument(arguments: str, operation: str) -> tuple[str, str]:
    if operation in _AT:
        prefix, separator, arguments = arguments.partition(", ")
        if not separator or not re.fullmatch(r"AT_FDCWD|-?\d+", prefix):
            raise TraceError("Unsupported dirfd argument.")
    match = _QUOTED.match(arguments)
    if match is None:
        raise TraceError("Expected complete hex-encoded pathname.")
    suffix = arguments[match.end():]
    if suffix and not suffix.startswith(", "):
        raise TraceError("Truncated pathname.")
    raw = bytes.fromhex(match[1].replace("\\x", ""))
    try:
        path = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise TraceError("Unsupported pathname encoding.") from error
    if "\x00" in path:
        raise TraceError("NUL in pathname.")
    return path, suffix.removeprefix(", ")


def parse_trace(lines: Iterable[str], workspace: str,
                external_roots: tuple[str, ...] = ("/proc", "/sys", "/dev", "/run")
                ) -> tuple[TraceEvent, ...]:
    """Fail closed on unparsed events; failed probes and writes remain evidence."""
    canonical_path(workspace)
    for path in external_roots:
        canonical_path(path)
    events = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("--- ") or line.startswith("+++ "):
            continue
        match = _SYSCALL.fullmatch(line)
        if match is None:
            raise TraceError("Unsupported or incomplete syscall record.")
        operation, arguments, result, errno = match.groups()
        path, suffix = _decode_argument(arguments, operation)
        if operation in _EXEC:
            access = Access.EXEC
        elif operation == "creat":
            access = Access.WRITE
        else:
            if operation == "openat2":
                flag_match = re.match(r"\{flags=([^,}]+)", suffix)
                if flag_match is None:
                    raise TraceError("Unsupported openat2 flags.")
                flag_text = flag_match[1]
            else:
                flag_text = suffix.split(",", 1)[0]
            flags = frozenset(flag_text.split("|"))
            if not flags or not flags <= (_WRITE | {
                "O_RDONLY", "O_CLOEXEC", "O_DIRECTORY", "O_PATH", "O_NOFOLLOW",
                "O_NONBLOCK", "O_NDELAY", "O_NOCTTY", "O_APPEND", "O_SYNC",
                "O_DSYNC", "O_DIRECT", "O_LARGEFILE", "O_EXCL", "O_ASYNC",
                "O_NOATIME", "O_RSYNC", "O_FSYNC", "O_TMPFILE", "O_SEARCH",
            }):
                raise TraceError("Unsupported open flags.")
            if flags & _WRITE:
                access = Access.WRITE
            elif flags & {"O_DIRECTORY", "O_PATH"}:
                access = Access.DIRECTORY
            else:
                access = Access.READ
        success = int(result) >= 0
        if not success and errno is None:
            raise TraceError("Failed syscall without errno.")
        events.append(TraceEvent(operation, path, access,
                                 _scope(path, workspace, external_roots),
                                 success, None if success else errno))
    return tuple(events)


def capture_trace(tracer: str, argv: tuple[str, ...], workspace: Path,
                  environment: Mapping[str, str], *, timeout: float = 120,
                  external_roots: tuple[str, ...] = ("/proc", "/sys", "/dev", "/run")
                  ) -> TraceReport:
    """Observe a trusted workload; caller owns its isolation and input snapshot."""
    canonical_path(tracer)
    if not argv:
        raise TraceError("Expected workload argv.")
    canonical_path(argv[0])
    if workspace.resolve(strict=True) != workspace or not workspace.is_dir():
        raise TraceError("Expected real workspace directory.")
    with tempfile.TemporaryDirectory(prefix="rdc-trace-", dir=workspace) as directory:
        prefix = Path(directory) / "events"
        result = run_tool(
            (tracer, "-ff", "-qq", "-s", "65535", "-xx",
             "-e", "trace=open,openat,openat2,creat,execve,execveat",
             "-o", str(prefix), "--", *argv),
            workspace, environment, timeout,
        )
        streams = sorted(prefix.parent.glob("events.*"))
        if not streams or len(streams) > 4096:
            raise TraceError("Missing or excessive trace streams.")
        events: list[TraceEvent] = []
        digests = []
        size = 0
        for stream in streams:
            size += stream.stat().st_size
            if size > 64 * 1024 * 1024:
                raise TraceError("Trace exceeds configured parse budget.")
            data = stream.read_bytes()
            digests.append(hashlib.sha256(data).hexdigest())
            events.extend(parse_trace(data.decode("utf-8"), str(workspace), external_roots))
        if not any(event.success and event.access is Access.EXEC for event in events):
            raise TraceError("Trace contains no successful exec.")
        return TraceReport(tuple(events), result.stdout, tuple(sorted(digests)))
