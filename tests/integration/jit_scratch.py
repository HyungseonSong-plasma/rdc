"""Validate a trace-selected native C++ toolchain in an isolated scratch image."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from rdc.collector import collect
from rdc.docker import RuntimeCase, validate_docker
from rdc.discovery.elf import read_elf
from rdc.discovery.jit import add_jit_inputs, query_compiler
from rdc.discovery.loader import LoaderProfile, discover_elf
from rdc.discovery.trace import Access, capture_trace
from rdc.models import BuildIdentity, CollectionPolicy, Dependency, DependencyKind
from rdc.planner import plan_collection
from tests.wiring import register_integration
from work.libs.testing import TestSuite


_DRIVER = r"""
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4 || chdir(argv[3]) != 0) return 10;
    if (access("expression.cc", F_OK) == 0 ||
        access("expression.so", F_OK) == 0) return 11;
    FILE *source = fopen("expression.cc", "wx");
    if (!source) return 12;
    fprintf(source, "#include \"%s\"\n"
                    "extern \"C\" int evaluate(int x) { return transform(x); }\n", argv[2]);
    if (fclose(source) != 0) return 13;
    pid_t child = fork();
    if (child == 0) {
        execl(argv[1], argv[1], "-shared", "-fPIC", "-O2", "-o",
              "expression.so", "expression.cc", (char *)NULL);
        _exit(127);
    }
    int status;
    if (child < 0 || waitpid(child, &status, 0) != child ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) return 14;
    void *library = dlopen("./expression.so", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "%s\n", dlerror()); return 15; }
    int (*evaluate)(int) = (int (*)(int))dlsym(library, "evaluate");
    if (!evaluate) return 16;
    printf("%d\n", evaluate(14));
    dlclose(library);
    return 0;
}
"""

_DIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
         "/lib64", "/usr/lib64", "/lib", "/usr/lib")
_SYSTEM = ("/usr", "/lib", "/lib64", "/bin")
_DRIVER_TARGET = "/opt/rdc-fixture/jit-driver"
_HEADER_TARGET = "/opt/rdc-fixture/expression.h"


def command(*args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=180, **kwargs)
    if result.returncode != 0:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stderr[-4000:]}")
    return result.stdout


def environment(work):
    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
            "HOME": str(work), "TMPDIR": str(work)}


def stage_file(root, target, source):
    """Fixture-only staging: retain the observed path as a regular-file alias.

    The host is a trusted CI input; the production collector independently
    validates and copies the resulting explicit source inventory.
    """
    destination = root / target.lstrip("/")
    if destination.exists():
        if not destination.is_file():
            raise ValueError(f"Fixture destination is not a file: {target}")
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination, follow_symlinks=True)
    return destination


def is_system(path):
    return any(Path(path).is_relative_to(prefix) for prefix in _SYSTEM)


def select_observations(root, trace, work, fixture_paths):
    """Explicitly select regular files under reviewed toolchain prefixes.

    Do not collect host loader cache, special files, generated outputs,
    failed probes or relative names with unknown cwd/dirfd.
    """
    files = {}
    executables = set()
    unknown = set()
    for event in trace.events:
        if not event.success or event.access not in (Access.READ, Access.EXEC):
            continue
        if not event.path.startswith("/"):
            unknown.add(event.path)
            continue
        original = Path(event.path)
        normalized = Path(os.path.normpath(event.path))
        if normalized.is_relative_to(work) or normalized in fixture_paths:
            continue
        if normalized == Path("/etc/ld.so.cache") or any(
            normalized.is_relative_to(prefix) for prefix in ("/dev", "/proc", "/sys", "/run")
        ):
            continue
        if not is_system(normalized):
            raise ValueError(f"Unclassified successful host input: {event.path}")
        # Do not equate lexical traversal with actual symlink resolution.
        actual = original.resolve(strict=True)
        if actual != normalized.resolve(strict=True) or not is_system(actual):
            raise ValueError(f"Ambiguous toolchain pathname: {event.path}")
        if actual.is_dir():
            continue
        if not actual.is_file():
            raise ValueError(f"Non-regular toolchain input: {event.path}")
        target = str(normalized)
        files[target] = stage_file(root, target, actual)
        if event.access is Access.EXEC:
            executables.add(target)
    print("JIT_TRACE_SELECTION", len(files), "executables", sorted(executables),
          "unresolved-relative", len(unknown), flush=True)
    return files, executables


def elf_magic(path):
    with path.open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def stage_interpreters(root, files):
    """PT_INTERP is kernel-loaded and may not appear in the open trace."""
    for path in tuple(files.values()):
        if not elf_magic(path):
            continue
        # Relocatable ELF .o files are linker inputs, not runtime executables.
        with path.open("rb") as stream:
            stream.seek(16)
            kind = int.from_bytes(stream.read(2), "little")
        if kind not in (2, 3):
            continue
        interpreter = read_elf(str(path)).interpreter
        if interpreter is not None:
            actual = Path(interpreter).resolve(strict=True)
            if not is_system(actual) or not is_system(interpreter):
                raise ValueError(f"Unapproved interpreter: {interpreter}")
            files[interpreter] = stage_file(root, interpreter, actual)


@register_integration("jit_scratch")
class JitScratchContract(TestSuite):
    def test_isolated_cold_jit(self):
        def check(ctx):
            compiler = shutil.which("g++", path="/usr/bin:/bin")
            tracer = shutil.which("strace", path="/usr/bin:/bin")
            self.assertIsNotNone(compiler)
            self.assertIsNotNone(tracer)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                work = root / "native"
                work.mkdir()
                source = root / "source"
                source.mkdir()
                driver_source = root / "driver.c"
                driver = root / "jit-driver"
                header = root / "expression.h"
                driver_source.write_text(_DRIVER)
                header.write_text(
                    "#include <cstdint>\n"
                    "inline int transform(int x) { std::int64_t y = x; return int(y * 3); }\n"
                )
                command("/usr/bin/gcc", "-O2", "-o", str(driver), str(driver_source), "-ldl")
                profile = LoaderProfile(str(source), CollectionPolicy((str(source),)), _DIRS)
                queries = query_compiler(compiler, work, environment(work))
                trace = capture_trace(tracer, (str(driver), compiler, str(header), str(work)),
                                      work, environment(work))
                self.assertEqual(trace.stdout, "42\n")
                self.assertTrue((work / "expression.so").is_file())
                files, executables = select_observations(
                    source, trace, work, {driver, header},
                )
                self.assertIn(compiler, executables)
                self.assertTrue(any("cc1plus" in path for path in executables))
                self.assertTrue(any(path.endswith("/as") or path.endswith("-as")
                                    for path in executables))
                self.assertTrue(any(path.endswith("/ld") or path.endswith("-ld")
                                    or path.endswith("ld.bfd") for path in executables))
                self.assertTrue(any(path.endswith("/cstdint") for path in files))
                files[_DRIVER_TARGET] = stage_file(source, _DRIVER_TARGET, driver)
                files[_HEADER_TARGET] = stage_file(source, _HEADER_TARGET, header)
                executables.add(_DRIVER_TARGET)
                stage_interpreters(source, files)
                discovered = discover_elf(profile, sorted(executables))
                closure = discovered.graph.closure(discovered.roots)
                self.assertEqual(closure.blockers, (),
                                 [(e.requester, e.evidence.request) for e in closure.blockers])
                by_target = {node.target: node for node in closure.nodes}
                requester = by_target[_DRIVER_TARGET]
                resources = []
                for target, path in sorted(files.items()):
                    if target in by_target:
                        resources.append(by_target[target])
                        continue
                    kind = DependencyKind.DATA
                    if target == _HEADER_TARGET or target.endswith((".h", ".hpp", "/cstdint")):
                        kind = DependencyKind.HEADER
                    resources.append(Dependency(str(path), target, kind))
                add_jit_inputs(discovered.graph, requester, resources, trace, queries)
                build = BuildIdentity("native-cxx-toolchain-fixture", "0" * 64,
                                      queries.machine, (("g++", queries.version),),
                                      ("observed-toolchain", "elf", "scratch-cold-jit"))
                plan = plan_collection(discovered.graph, discovered.roots, profile.policy, build)
                runtime = root / "runtime"
                manifest_bytes = collect(plan, runtime)
                manifest = json.loads(manifest_bytes)
                self.assertEqual({item["target"] for item in manifest["files"]},
                                 set(files) | set(by_target))
                self.assertFalse((runtime / "etc/ld.so.cache").exists())
                self.assertFalse((runtime / "tmp/expression.so").exists())
                print("JIT_SCRATCH_COLLECTION", len(manifest["files"]),
                      manifest["collected_bytes"], flush=True)
                receipt = validate_docker(
                    runtime, manifest_bytes, hashlib.sha256(manifest_bytes).hexdigest(),
                    RuntimeCase((_DRIVER_TARGET, compiler, _HEADER_TARGET, "/tmp"),
                                trace.stdout.encode(), executable_tmpfs=True),
                )
                self.assertEqual(receipt.stdout_sha256,
                                 hashlib.sha256(trace.stdout.encode()).hexdigest())
                self.assertEqual(receipt.collected_bytes, manifest["collected_bytes"])
                print("JIT_SCRATCH_COLD_EQUIVALENCE_PASS", len(manifest["files"]),
                      receipt.collected_bytes, repr(trace.stdout), flush=True)
                print("JIT_RUNTIME_VALIDATOR_PASS", receipt.image_id, receipt.image_bytes,
                      receipt.archive_sha256, flush=True)

        self.run_contract(check=check)
