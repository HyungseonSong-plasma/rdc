"""Execute explicitly trusted tools with no inherited environment or shell."""

import os
import signal
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from rdc.models import canonical_path


class ToolError(ValueError):
    """Tool launch, timeout or nonzero exit."""


@dataclass(frozen=True, slots=True)
class ToolResult:
    stdout: str
    stderr: str


def run_tool(argv: tuple[str, ...], workspace: Path, environment: Mapping[str, str],
             timeout: float = 60) -> ToolResult:
    """Caller supplies an isolated disposable workspace and trusted executable."""
    if not argv or timeout <= 0:
        raise ToolError("Expected explicit argv and positive timeout.")
    canonical_path(argv[0])
    canonical_path(str(workspace))
    if workspace.resolve(strict=True) != workspace or not workspace.is_dir():
        raise ToolError("Expected a real absolute workspace directory.")
    if any("\x00" in arg for arg in argv):
        raise ToolError("NUL in tool argument.")
    if any(not key or "=" in key or "\x00" in key or "\x00" in value
           for key, value in environment.items()):
        raise ToolError("Invalid environment.")
    try:
        with subprocess.Popen(
            argv, cwd=workspace, env=dict(environment), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            encoding="utf-8", errors="replace", start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired as error:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise ToolError(f"Tool timed out: {argv[0]}") from error
            if process.returncode:
                raise ToolError(f"Tool failed ({process.returncode}): {argv[0]}")
            return ToolResult(stdout, stderr)
    except OSError as error:
        raise ToolError(f"Cannot launch tool: {argv[0]}") from error
