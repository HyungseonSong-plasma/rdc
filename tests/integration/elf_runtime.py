"""Compile a real transitive ELF fixture and execute its collected scratch root."""

import json
import shutil
import subprocess
import tarfile
import tempfile
import uuid
from pathlib import Path

from rdc.collector import collect
from rdc.discovery.elf import read_elf
from rdc.discovery.loader import LoaderProfile, discover_elf
from rdc.models import BuildIdentity, CollectionPolicy
from rdc.planner import plan_collection
from tests.architecture import registration_violations
from tests.wiring import INTEGRATION, register_integration
from work.libs.testing import TestSuite


def command(*args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          timeout=120, **kwargs).stdout


def install(root, target, source):
    destination = root / target.lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return destination


def compile_fixture(work, source):
    (work / "leaf.c").write_text("int leaf(void) { return 42; }\n")
    (work / "middle.c").write_text(
        "extern int leaf(void); int middle(void) { return leaf(); }\n")
    (work / "main.c").write_text(
        '#include <stdio.h>\nextern int middle(void);\n'
        'int main(void) { printf("%d\\n", middle()); return 0; }\n')
    lib = work / "lib"
    lib.mkdir()
    command("gcc", "-shared", "-fPIC", "-nostdlib", "-Wl,-soname,librdc_leaf.so.1",
            "-o", str(lib / "librdc_leaf.so.1"), str(work / "leaf.c"))
    (lib / "librdc_leaf.so").symlink_to("librdc_leaf.so.1")
    command("gcc", "-shared", "-fPIC", "-nostdlib", "-Wl,-soname,librdc_mid.so.1",
            "-Wl,-rpath,$ORIGIN", "-L" + str(lib), "-o", str(lib / "librdc_mid.so.1"),
            str(work / "middle.c"), "-lrdc_leaf")
    (lib / "librdc_mid.so").symlink_to("librdc_mid.so.1")
    # The executable's RUNPATH is not inherited; the middle library has its own.
    command("gcc", str(work / "main.c"), "-L" + str(lib), "-lrdc_mid",
            "-Wl,-rpath,$ORIGIN/lib", "-Wl,-rpath-link," + str(lib), "-o", str(work / "app"))
    install(source, "/opt/fixture/app", work / "app")
    for name in ("librdc_leaf.so.1", "librdc_mid.so.1"):
        install(source, "/opt/fixture/lib/" + name, lib / name)
    meta = read_elf(str(work / "app"))
    if meta.interpreter is None:
        raise ValueError("Fixture must have a dynamic interpreter.")
    install(source, meta.interpreter, Path(meta.interpreter).resolve(strict=True))
    libc = Path(command("gcc", "-print-file-name=libc.so.6").strip()).resolve(strict=True)
    install(source, "/lib/x86_64-linux-gnu/libc.so.6", libc)
    return meta.interpreter


@register_integration("elf_runtime")
class ElfRuntimeContract(TestSuite):
    def test_registry(self):
        def check(ctx):
            self.assertEqual(registration_violations(INTEGRATION, "integration"), ())

        self.run_contract(check=check)

    def test_scratch_equivalence(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                work = Path(directory)
                source = work / "source"
                source.mkdir()
                interpreter = compile_fixture(work, source)
                profile = LoaderProfile(str(source), CollectionPolicy((str(source),)),
                                        ("/lib/x86_64-linux-gnu",
                                         str(Path(interpreter).parent)))
                result = discover_elf(profile, ("/opt/fixture/app",))
                closure = result.graph.closure(result.roots)
                self.assertEqual(closure.blockers, ())
                self.assertEqual({node.target for node in closure.nodes}, {
                    "/opt/fixture/app", "/opt/fixture/lib/librdc_leaf.so.1",
                    "/opt/fixture/lib/librdc_mid.so.1", interpreter,
                    "/lib/x86_64-linux-gnu/libc.so.6",
                })
                build = BuildIdentity("compiled-elf-fixture", "0" * 64, "linux-x86_64",
                                      (("gcc", command("gcc", "--version").splitlines()[0]),),
                                      ("static-elf", "scratch-fixture"))
                plan = plan_collection(result.graph, result.roots, profile.policy, build)
                root = work / "runtime"
                manifest = json.loads(collect(plan, root))
                self.assertGreater(manifest["collected_bytes"], 0)
                # glibc's default ABI path matches the explicit fixture profile.
                baseline = command(str(work / "app"))
                self.assertEqual(baseline, "42\n")
                archive = work / "rootfs.tar"
                with tarfile.open(archive, "w", dereference=False) as tar:
                    tar.add(root, arcname=".")
                image = "rdc-elf-fixture:" + uuid.uuid4().hex
                try:
                    with archive.open("rb") as stream:
                        subprocess.run(("docker", "import", "-", image), stdin=stream,
                                       check=True, timeout=120, capture_output=True)
                    actual = command("docker", "run", "--rm", "--network", "none",
                                     "--read-only", "--cap-drop", "ALL",
                                     "--user", "65534:65534", image, "/opt/fixture/app")
                    self.assertEqual(actual, baseline)
                    print("ELF_SCRATCH_EQUIVALENCE_PASS", len(closure.nodes),
                          manifest["collected_bytes"], repr(actual), flush=True)
                finally:
                    subprocess.run(("docker", "image", "rm", image), check=False,
                                   timeout=60, capture_output=True)

        self.run_contract(check=check)
