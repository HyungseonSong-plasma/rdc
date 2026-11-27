import struct
import tempfile
from pathlib import Path

from rdc.discovery.elf import ElfError, read_elf
from rdc.discovery.loader import LoaderProfile, discover_elf
from rdc.models import BuildIdentity, CollectionPolicy
from rdc.planner import PlanError, plan_collection
from tests.wiring import register
from work.libs.testing import TestSuite


def image(needed=(), runpath=None, interp=None, rpath=None):
    """Minimal independent ELF fixture with LOAD, DYNAMIC and optional INTERP."""
    strings = bytearray(b"\0")
    tags = []

    def add(tag, text):
        tags.append((tag, len(strings)))
        strings.extend(text.encode() + b"\0")

    for name in needed:
        add(1, name)
    if runpath is not None:
        add(29, runpath)
    if rpath is not None:
        add(15, rpath)
    tags.extend(((5, 0x400400), (10, len(strings)), (0, 0)))
    data = bytearray(4096)
    count = 3 if interp else 2
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    struct.pack_into("<16sHHIQQQIHHHHHH", data, 0, ident, 3, 62, 1,
                     0, 64, 0, 0, 64, 56, count, 0, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0,
                     len(data), len(data), 4096)
    struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 0x200, 0x400200, 0,
                     len(tags) * 16, len(tags) * 16, 8)
    for index, (tag, value) in enumerate(tags):
        struct.pack_into("<qQ", data, 0x200 + index * 16, tag, value)
    data[0x400:0x400 + len(strings)] = strings
    if interp:
        encoded = interp.encode() + b"\0"
        struct.pack_into("<IIQQQQQQ", data, 176, 3, 4, 0x800, 0x400800, 0,
                         len(encoded), len(encoded), 1)
        data[0x800:0x800 + len(encoded)] = encoded
    return bytes(data)


def put(root, target, content):
    path = root / target.lstrip("/")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    path.chmod(0o755)
    return path


def profile(root):
    return LoaderProfile(str(root), CollectionPolicy((str(root),)),
                         ("/lib64", "/usr/lib"))


@register("elf")
class ElfContract(TestSuite):
    def test_metadata(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                path = put(Path(directory), "/app", image(
                    ("liba.so", "libb.so"), "$ORIGIN/lib", "/lib64/ld.so"))
                meta = read_elf(str(path))
                self.assertEqual(meta.needed, ("liba.so", "libb.so"))
                self.assertEqual(meta.interpreter, "/lib64/ld.so")
                self.assertEqual(meta.runpath, "$ORIGIN/lib")
                self.assertEqual(len(meta.sha256), 64)

        self.run_contract(check=check)

    def test_malformed_elf(self):
        cases = (("short", "short"), ("machine", "machine"), ("offset", "offset"),
                 ("string", "string"), ("unterminated", "unterminated"))

        def check(ctx, case):
            data = bytearray(image(("liba.so",)))
            if case == "short":
                data = data[:30]
            elif case == "machine":
                struct.pack_into("<H", data, 18, 183)
            elif case == "offset":
                struct.pack_into("<Q", data, 32, 999999)
            elif case == "string":
                struct.pack_into("<Q", data, 0x208, 99999)
            else:
                struct.pack_into("<qQ", data, 0x230, 1, 1)
            with tempfile.TemporaryDirectory() as directory:
                path = put(Path(directory), "/bad", data)
                with self.assertRaises(ElfError):
                    read_elf(str(path))

        self.run_cases(cases, check)

    def test_transitive_alias_and_missing(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                put(root, "/app/bin/main", image(
                    ("liba.so",), "$ORIGIN/../lib", "/lib64/ld.so"))
                put(root, "/app/lib/liba.so.1", image(("libb.so", "missing.so")))
                put(root, "/usr/lib/libb.so", image())
                put(root, "/usr/lib/ld.so", image())
                (root / "lib64").symlink_to("usr/lib")
                (root / "app/lib/liba.so").symlink_to("liba.so.1")
                found = discover_elf(profile(root), ("/app/bin/main",))
                closure = found.graph.closure(found.roots)
                self.assertEqual(tuple(e.evidence.request for e in closure.blockers),
                                 ("missing.so",))
                self.assertEqual({node.target for node in closure.nodes}, {
                    "/app/bin/main", "/app/lib/liba.so", "/app/lib/liba.so.1",
                    "/lib64", "/usr/lib", "/usr/lib/libb.so", "/usr/lib/ld.so",
                })

        self.run_contract(check=check)

    def test_runpath_not_inherited(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                put(root, "/main", image(("liba.so",), "/private/lib"))
                put(root, "/private/lib/liba.so", image(("libb.so",)))
                put(root, "/private/lib/libb.so", image())
                result = discover_elf(profile(root), ("/main",))
                self.assertEqual(tuple(e.evidence.request for e in
                                       result.graph.closure(result.roots).blockers), ("libb.so",))

        self.run_contract(check=check)

    def test_rpath_and_unsafe_tokens(self):
        cases = (("legacy", None, "/lib"), ("cwd", ":/lib", None),
                 ("token", "$LIB", None), ("escape", "/../../lib", None))

        def check(ctx, runpath, rpath):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                put(root, "/main", image(("liba.so",), runpath, rpath=rpath))
                with self.assertRaises(ElfError):
                    discover_elf(profile(root), ("/main",))

        self.run_cases(cases, check)

    def test_discovery_content_drift(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = put(root, "/main", image())
                found = discover_elf(profile(root), ("/main",))
                path.write_bytes(image(("changed.so",)))
                build = BuildIdentity("fixture", "0" * 64, "linux-x86_64", (), ("elf",))
                with self.assertRaisesRegex(PlanError, "ELF changed"):
                    plan_collection(found.graph, found.roots, profile(root).policy, build)

        self.run_contract(check=check)
