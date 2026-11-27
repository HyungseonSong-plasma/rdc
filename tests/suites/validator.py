"""Independent manifest/root verification contracts."""

import hashlib
import json
import tempfile
from pathlib import Path

from rdc.collector import collect
from rdc.docker import RuntimeCase
from rdc.graph import DependencyGraph
from rdc.models import BuildIdentity, CollectionPolicy, Dependency, DependencyKind
from rdc.planner import plan_collection
from rdc.validator import ValidationError, verify_rootfs
from tests.wiring import register
from work.libs.testing import TestSuite


def fixture(root):
    source = root / "source"
    source.mkdir()
    app = source / "app"
    app.write_bytes(b"fixture bytes")
    app.chmod(0o755)
    graph = DependencyGraph(str(source))
    graph.add_node(Dependency(str(app), "/bin/app", DependencyKind.EXECUTABLE))
    build = BuildIdentity("validation-fixture", "0" * 64, "linux-x86_64", (), ("fixture",))
    plan = plan_collection(graph, (str(app),), CollectionPolicy((str(source),)), build)
    runtime = root / "runtime"
    manifest = collect(plan, runtime)
    return source, runtime, manifest


def digest(data):
    return hashlib.sha256(data).hexdigest()


@register("validator")
class ValidatorContract(TestSuite):
    def test_independent_manifest_verification(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                source, root, manifest = fixture(Path(directory))
                (source / "app").unlink()
                source.rmdir()
                verified = verify_rootfs(root, manifest, digest(manifest))
                self.assertEqual(verified.paths, ("/", "/bin", "/bin/app"))
                self.assertEqual(verified.collected_bytes, len(b"fixture bytes"))
                self.assertEqual(verified.manifest_sha256, digest(manifest))

        self.run_contract(check=check)

    def test_rootfs_drift(self):
        cases = (("content", "content"), ("extra", "extra"), ("missing", "missing"),
                 ("mode", "mode"), ("link", "link"), ("directory", "directory"))

        def check(ctx, case):
            with tempfile.TemporaryDirectory() as directory:
                _, root, manifest = fixture(Path(directory))
                target = root / "bin/app"
                if case == "content":
                    target.write_bytes(b"changed")
                elif case == "extra":
                    (root / "extra").write_text("unexpected")
                elif case == "missing":
                    target.unlink()
                elif case == "mode":
                    target.chmod(0o555)
                elif case == "link":
                    target.unlink()
                    target.symlink_to("/etc/passwd")
                else:
                    (root / "bin").chmod(0o777)
                with self.assertRaises(ValueError):
                    verify_rootfs(root, manifest, digest(manifest))

        self.run_cases(cases, check)

    def test_manifest_drift(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                _, root, manifest = fixture(Path(directory))
                with self.assertRaisesRegex(ValidationError, "digest mismatch"):
                    verify_rootfs(root, manifest + b" ", digest(manifest))
                with self.assertRaisesRegex(ValidationError, "noncanonical"):
                    verify_rootfs(root, manifest + b" ", digest(manifest + b" "))
                data = json.loads(manifest)
                data["files"][0]["target"] = "/../etc/passwd"
                invalid = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
                with self.assertRaises(ValueError):
                    verify_rootfs(root, invalid, digest(invalid))

        self.run_contract(check=check)

    def test_runtime_case(self):
        cases = (("relative", ("app",), (), 1), ("empty", (), (), 1),
                 ("duplicate", ("/app",), (("X", "1"), ("X", "2")), 1),
                 ("timeout", ("/app",), (), 0), ("invalid env", ("/app",), (("A=B", "1"),), 1))

        def check(ctx, argv, env, timeout):
            with self.assertRaises(ValueError):
                RuntimeCase(argv, b"", environment=env, timeout=timeout)

        self.run_cases(cases, check)
