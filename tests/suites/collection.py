from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
from unittest.mock import patch

from rdc.collector import CollectionError, collect
from rdc.graph import DependencyGraph
from rdc.manifest import manifest_bytes
from rdc.models import (
    BuildIdentity, CollectionPolicy, Dependency, DependencyKind, Edge, Evidence, Resolution,
)
from rdc.planner import PlanError, plan_collection
from rdc.policy import PolicyError
from rdc.filesystem import FilesystemError
from tests.wiring import register
from work.libs.testing import TestSuite


BUILD = BuildIdentity("fixture-v1", "0" * 64, "linux-x86_64",
                      (("fixture", "1"),), ("synthetic",))


@contextmanager
def fixture(ctx):
    with tempfile.TemporaryDirectory() as directory:
        ctx.root = Path(directory)
        ctx.source = ctx.root / "source"
        ctx.source.mkdir()
        ctx.output = ctx.root / "runtime"
        ctx.graph = DependencyGraph(str(ctx.source))
        ctx.policy = CollectionPolicy((str(ctx.source),))
        yield


def add(ctx, name, target, kind=DependencyKind.DATA, content=b"data", mode=0o644):
    source = ctx.source / name
    source.parent.mkdir(parents=True, exist_ok=True)
    if kind is DependencyKind.SYMLINK:
        source.symlink_to(content.decode())
    elif kind is DependencyKind.DIRECTORY:
        source.mkdir(exist_ok=True)
        source.chmod(mode)
    else:
        source.write_bytes(content)
        source.chmod(mode)
    ctx.graph.add_node(Dependency(str(source), target, kind))
    return str(source)


def link(ctx, requester, dependency):
    ctx.graph.add_edge(Edge(requester, Evidence("fixture", "symlink", dependency),
                            Resolution.RESOLVED, dependency))


def plan(ctx, *roots):
    return plan_collection(ctx.graph, roots, ctx.policy, BUILD)


@register("collection")
class CollectionContract(TestSuite):
    def test_collect_and_manifest(self):
        @contextmanager
        def arrange(ctx):
            with fixture(ctx):
                ctx.lib = add(ctx, "lib/a.so", "/lib/a.so", content=b"abc")
                ctx.alias = add(ctx, "lib/b.so", "/lib/b.so", DependencyKind.SYMLINK,
                                b"a.so")
                ctx.exe = add(ctx, "bin/app", "/bin/app", DependencyKind.EXECUTABLE,
                              b"binary", 0o755)
                link(ctx, ctx.alias, ctx.lib)
                yield

        def act(ctx):
            ctx.plan = plan(ctx, ctx.alias, ctx.exe)
            self.assertFalse(ctx.output.exists())
            return collect(ctx.plan, ctx.output)

        def check(ctx, result):
            self.assertEqual(result, manifest_bytes(ctx.plan))
            self.assertEqual((ctx.output / "lib/a.so").read_bytes(), b"abc")
            self.assertEqual((ctx.output / "lib/b.so").readlink(), Path("a.so"))
            self.assertEqual((ctx.output / "bin/app").stat().st_mode & 0o777, 0o755)
            manifest = json.loads(result)
            self.assertEqual(manifest["schema"], "rdc.collection.v1")
            self.assertEqual(manifest["collected_bytes"], 13)
            self.assertEqual(manifest["files"][1]["sha256"],
                             "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            self.assertNotIn(str(ctx.root).encode(), result)
            self.assertEqual((ctx.source / "lib/a.so").read_bytes(), b"abc")

        self.run_contract(act, check, arrange=arrange)

    def test_absolute_link_and_directory(self):
        @contextmanager
        def arrange(ctx):
            with fixture(ctx):
                yield

        def check(ctx):
            directory = add(ctx, "usr/lib", "/usr/lib", DependencyKind.DIRECTORY,
                            mode=0o755)
            library = add(ctx, "usr/lib/a", "/usr/lib/a")
            alias = add(ctx, "lib", "/lib", DependencyKind.SYMLINK, b"/usr/lib")
            link(ctx, alias, directory)
            collect(plan(ctx, alias, library), ctx.output)
            self.assertEqual((ctx.output / "lib").readlink(), Path("/usr/lib"))
            self.assertEqual((ctx.output / "usr/lib/a").read_bytes(), b"data")

        self.run_contract(check=check, arrange=arrange)

    def test_bad_modes_and_special_files(self):
        cases = (("unreadable", 0o600), ("setuid", 0o4755), ("setgid", 0o2755))

        def check(ctx, mode):
            with fixture(ctx):
                source = add(ctx, "bad", "/bad", mode=mode)
                with patch("rdc.filesystem._read_regular") as reader:
                    with self.assertRaises(PolicyError):
                        plan(ctx, source)
                    reader.assert_not_called()
                self.assertFalse(ctx.output.exists())
                self.assertEqual(Path(source).stat().st_mode & 0o7777, mode)

        self.run_cases(cases, check)

    def test_scope_and_parent_symlink(self):
        def check(ctx):
            with fixture(ctx):
                source = add(ctx, "a", "/a")
                ctx.policy = CollectionPolicy((str(ctx.source / "selected"),))
                with self.assertRaises(PolicyError):
                    plan(ctx, source)
                ctx.policy = CollectionPolicy((str(ctx.source),))
                secret = add(ctx, "etc/shadow", "/etc/shadow")
                with self.assertRaises(PolicyError):
                    plan(ctx, secret)
                outside = ctx.root / "outside"
                outside.mkdir()
                (outside / "file").write_text("outside")
                (ctx.source / "alias").symlink_to(outside)
                through = str(ctx.source / "alias/file")
                ctx.graph.add_node(Dependency(through, "/file", DependencyKind.DATA))
                with self.assertRaises(FilesystemError):
                    plan(ctx, through)

        self.run_contract(check=check)

    def test_target_conflicts(self):
        cases = (("same", "/a"), ("ancestor", "/a/b"))

        def check(ctx, target):
            with fixture(ctx):
                a = add(ctx, "a", "/a")
                b = add(ctx, "b", target)
                with self.assertRaises(PlanError):
                    plan(ctx, a, b)
                self.assertFalse(ctx.output.exists())

        self.run_cases(cases, check)

    def test_invalid_links(self):
        cases = (("missing", "missing"), ("escape", "../../outside"),
                 ("ambiguous", "x/../a"), ("no_edge", "a"))

        def check(ctx, target):
            with fixture(ctx):
                a = add(ctx, "a", "/a")
                b = add(ctx, "b", "/b", DependencyKind.SYMLINK, target.encode())
                with self.assertRaises(PlanError):
                    plan(ctx, a, b)
                self.assertFalse(ctx.output.exists())

        self.run_cases(cases, check)

    def test_link_cycle_and_mismapping(self):
        def check(ctx):
            with fixture(ctx):
                a = add(ctx, "a", "/a", DependencyKind.SYMLINK, b"b")
                b = add(ctx, "b", "/b", DependencyKind.SYMLINK, b"a")
                link(ctx, a, b)
                link(ctx, b, a)
                with self.assertRaisesRegex(PlanError, "cycle"):
                    plan(ctx, a)
            with fixture(ctx):
                a = add(ctx, "a", "/different")
                b = add(ctx, "b", "/b", DependencyKind.SYMLINK, b"a")
                link(ctx, b, a)
                with self.assertRaisesRegex(PlanError, "mismapped"):
                    plan(ctx, b)

        self.run_contract(check=check)

    def test_source_drift_and_existing_output(self):
        def check(ctx):
            with fixture(ctx):
                a = add(ctx, "a", "/a")
                original = plan(ctx, a)
                Path(a).write_bytes(b"changed")
                with self.assertRaises(CollectionError):
                    collect(original, ctx.output)
                self.assertFalse(ctx.output.exists())
                ctx.output.mkdir()
                sentinel = ctx.output / "keep"
                sentinel.write_text("untouched")
                with self.assertRaises(CollectionError):
                    collect(plan(ctx, a), ctx.output)
                self.assertEqual(sentinel.read_text(), "untouched")

        self.run_contract(check=check)

    def test_rollback_after_partial_copy(self):
        def check(ctx):
            with fixture(ctx):
                a = add(ctx, "a", "/a")
                b = add(ctx, "b", "/b")
                original = plan(ctx, a, b)
                from rdc.collector import _copy

                def fail(stage, entry):
                    if entry.node.target == "/b":
                        raise OSError("injected")
                    _copy(stage, entry)

                with patch("rdc.collector._copy", side_effect=fail):
                    with self.assertRaisesRegex(OSError, "injected"):
                        collect(original, ctx.output)
                self.assertFalse(ctx.output.exists())
                self.assertEqual(tuple(ctx.root.glob(".rdc-*")), ())
                self.assertEqual(Path(a).read_bytes(), b"data")

        self.run_contract(check=check)

    def test_manifest_reproducible(self):
        def check(ctx):
            with fixture(ctx):
                a = add(ctx, "a", "/a")
                b = add(ctx, "b", "/b")
                first = manifest_bytes(plan(ctx, a, b))
            with fixture(ctx):
                b = add(ctx, "b", "/b")
                a = add(ctx, "a", "/a")
                second = manifest_bytes(plan(ctx, b, a))
            self.assertEqual(first, second)

        self.run_contract(check=check)

    def test_implicit_directory_modes_and_inventory(self):
        def check(ctx):
            with fixture(ctx):
                source = add(ctx, "file", "/usr/lib/file")
                original = plan(ctx, source)
                previous = os.umask(0o077)
                try:
                    manifest = json.loads(collect(original, ctx.output))
                finally:
                    os.umask(previous)
                self.assertEqual(manifest["directories"], [
                    {"target": "/", "mode": 0o755},
                    {"target": "/usr", "mode": 0o755},
                    {"target": "/usr/lib", "mode": 0o755},
                ])
                for relative in (".", "usr", "usr/lib"):
                    self.assertEqual((ctx.output / relative).stat().st_mode & 0o777, 0o755)

        self.run_contract(check=check)

    def test_unplanned_file_rejected(self):
        def check(ctx):
            with fixture(ctx):
                source = add(ctx, "file", "/file")
                original = plan(ctx, source)
                from rdc.collector import _copy

                def inject(stage, entry):
                    _copy(stage, entry)
                    (stage / "unplanned").write_text("unexpected")

                with patch("rdc.collector._copy", side_effect=inject):
                    with self.assertRaisesRegex(CollectionError, "staged paths"):
                        collect(original, ctx.output)
                self.assertFalse(ctx.output.exists())
                self.assertEqual(tuple(ctx.root.glob(".rdc-*")), ())

        self.run_contract(check=check)

    def test_fifo_rejected(self):
        def check(ctx):
            with fixture(ctx):
                source = ctx.source / "pipe"
                os.mkfifo(source)
                ctx.graph.add_node(Dependency(str(source), "/pipe", DependencyKind.DATA))
                with self.assertRaises(PolicyError):
                    plan(ctx, str(source))

        self.run_contract(check=check)
