"""Local Docker adapter for manifest-bound, isolated runtime validation."""

import hashlib
import math
import re
import subprocess
import tarfile
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path

from rdc.models import canonical_path
from rdc.validator import ValidationError, verify_rootfs


@dataclass(frozen=True, slots=True)
class RuntimeCase:
    argv: tuple[str, ...]
    expected_stdout: bytes
    expected_stderr: bytes = b""
    environment: tuple[tuple[str, str], ...] = ()
    executable_tmpfs: bool = False
    timeout: float = 120

    def __post_init__(self) -> None:
        if not self.argv or any("\x00" in arg for arg in self.argv):
            raise ValidationError("Expected explicit workload argv.")
        canonical_path(self.argv[0])
        if not math.isfinite(self.timeout) or self.timeout <= 0:
            raise ValidationError("Expected finite positive timeout.")
        keys = set()
        for key, value in self.environment:
            if (not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
                    or key in keys or "\x00" in value):
                raise ValidationError("Invalid or duplicate runtime environment.")
            keys.add(key)


@dataclass(frozen=True, slots=True)
class RuntimeReceipt:
    manifest_sha256: str
    archive_sha256: str
    image_id: str
    image_bytes: int
    collected_bytes: int
    argv: tuple[str, ...]
    stdout_sha256: str
    stderr_sha256: str


def _normalized(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = info.gid = info.mtime = 0
    info.uname = info.gname = ""
    return info


def _invoke(prefix: tuple[str, ...], args: tuple[str, ...], timeout: float,
            *, archive: Path | None = None) -> bytes:
    try:
        if archive is None:
            result = subprocess.run((*prefix, *args), stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=timeout, check=False,
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        else:
            with archive.open("rb") as stream:
                result = subprocess.run((*prefix, *args), stdin=stream,
                                        capture_output=True, timeout=timeout, check=False,
                                        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValidationError(f"Docker {args[0]} launch or timeout failure.") from error
    if result.returncode:
        detail = result.stderr[-2000:].decode("utf-8", errors="replace").strip()
        raise ValidationError(f"Docker {args[0]} failed ({result.returncode}): {detail}")
    return result.stdout


def _run(prefix: tuple[str, ...], args: tuple[str, ...], case: RuntimeCase) -> tuple[bytes, bytes]:
    try:
        result = subprocess.run((*prefix, *args), stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=case.timeout, check=False,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValidationError("Isolated workload launch or timeout failure.") from error
    if result.returncode:
        raise ValidationError(f"Isolated workload exited {result.returncode}: "
                              + result.stderr[-2000:].decode("utf-8", errors="replace"))
    if result.stdout != case.expected_stdout or result.stderr != case.expected_stderr:
        raise ValidationError("Isolated workload output mismatch.")
    return result.stdout, result.stderr


def _options(case: RuntimeCase) -> tuple[str, ...]:
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                   "HOME": "/tmp", "TMPDIR": "/tmp"}
    environment.update(case.environment)
    flags = "exec" if case.executable_tmpfs else "noexec"
    options = (
        "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--pids-limit", "256", "--tmpfs", f"/tmp:rw,{flags},nosuid,nodev,mode=1777,size=128m",
    )
    return options + tuple(value for key, value_str in sorted(environment.items())
                           for value in ("--env", f"{key}={value_str}"))


def validate_docker(root: Path, manifest: bytes, expected_sha256: str,
                    case: RuntimeCase, *, docker: str = "/usr/bin/docker",
                    socket: str = "/var/run/docker.sock") -> RuntimeReceipt:
    """Import only a verified rootfs; compare exact outputs; never pull or push.

    Requires a trusted local Docker daemon. Docker itself is not a sandbox
    guarantee against malicious workloads. No host bind mounts are supported.
    """
    canonical_path(docker)
    canonical_path(socket)
    verified = verify_rootfs(root, manifest, expected_sha256)
    if case.argv[0] not in verified.paths:
        raise ValidationError("Workload executable not present in verified inventory.")
    with tempfile.TemporaryDirectory(prefix="rdc-docker-") as directory:
        workspace = Path(directory)
        if workspace.is_relative_to(root):
            raise ValidationError("Docker workspace overlaps runtime root.")
        archive = workspace / "rootfs.tar"
        config = workspace / "config"
        config.mkdir()
        with tarfile.open(archive, "w", dereference=False, format=tarfile.PAX_FORMAT) as tar:
            for target in verified.paths:
                tar.add(root / target.lstrip("/"), arcname="." + target if target != "/" else ".",
                        recursive=False, filter=_normalized)
        if verify_rootfs(root, manifest, expected_sha256) != verified:
            raise ValidationError("Runtime changed during archive construction.")
        with archive.open("rb") as stream:
            archive_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        prefix = (docker, "--config", str(config), "--host", "unix://" + socket)
        token = uuid.uuid4().hex
        tag, name = "rdc-validation:" + token, "rdc-validation-" + token
        imported = created = False
        try:
            image_id = _invoke(prefix, ("image", "import", "-", tag), 180,
                               archive=archive).decode("ascii").strip()
            imported = True
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                raise ValidationError("Invalid imported image identity.")
            size = int(_invoke(prefix, ("image", "inspect", "--format", "{{.Size}}",
                                       image_id), 30).strip())
            if size <= 0:
                raise ValidationError("Invalid imported image size.")
            container_id = _invoke(
                prefix, ("container", "create", "--pull", "never", "--name", name,
                         *_options(case), image_id, *case.argv), 60,
            ).decode("ascii").strip()
            created = True
            if not re.fullmatch(r"[0-9a-f]{64}", container_id):
                raise ValidationError("Invalid created container identity.")
            stdout, stderr = _run(prefix, ("container", "start", "--attach", container_id), case)
            exit_code = _invoke(prefix, ("container", "inspect", "--format",
                                         "{{.State.ExitCode}}", container_id), 30).strip()
            if exit_code != b"0":
                raise ValidationError("Container did not exit successfully.")
            return RuntimeReceipt(verified.manifest_sha256, archive_digest, image_id, size,
                                  verified.collected_bytes, case.argv,
                                  hashlib.sha256(stdout).hexdigest(),
                                  hashlib.sha256(stderr).hexdigest())
        finally:
            try:
                if created:
                    _invoke(prefix, ("container", "rm", "--force", name), 30)
            finally:
                if imported:
                    _invoke(prefix, ("image", "rm", tag), 30)
