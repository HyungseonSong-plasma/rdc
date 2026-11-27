"""Actual cold-cache C++ compile/load and explicit header collection."""

import json
import shutil
import sys
import tempfile
from pathlib import Path

from rdc.collector import collect
from rdc.discovery.jit import add_jit_inputs, query_compiler
from rdc.discovery.trace import Access, Scope, capture_trace
from rdc.graph import DependencyGraph
from rdc.models import BuildIdentity, CollectionPolicy, Dependency, DependencyKind
from rdc.planner import plan_collection
from tests.wiring import register_integration
from work.libs.testing import TestSuite


# The trusted fixture compiles a fresh shared object and calls it via dlopen.
_DRIVER = """import ctypes, pathlib, subprocess, sys
compiler, header, work = sys.argv[1:]
work = pathlib.Path(work)
source = work / "expression.cc"
output = work / "expression.so"
assert not source.exists() and not output.exists()
source.write_text('#include "' + header + '"\\nextern "C" int evaluate(int x) { return transform(x); }\\n')
subprocess.run([compiler, "-shared", "-fPIC", "-O2", "-o", str(output), str(source)], check=True)
function = ctypes.CDLL(str(output)).evaluate
function.argtypes = [ctypes.c_int]
function.restype = ctypes.c_int
print(function(14))
"""


@register_integration("jit_runtime")
class JitRuntimeContract(TestSuite):
    def test_cold_compile_trace_and_collected_header(self):
        def check(ctx):
            compiler = shutil.which("g++")
            tracer = shutil.which("strace")
            self.assertIsNotNone(compiler)
            self.assertIsNotNone(tracer)
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "source"
                source.mkdir()
                header = source / "expression.h"
                header.write_text("inline int transform(int x) { return x * 3; }\n")
                app = source / "driver.py"
                app.write_text(_DRIVER)
                first, second = root / "first", root / "second"
                first.mkdir()
                second.mkdir()

                def environment(work):
                    return {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                            "HOME": str(work), "TMPDIR": str(work)}

                queries = query_compiler(compiler, first, environment(first))
                self.assertTrue(queries.version)
                self.assertIn("x86_64", queries.machine)
                self.assertTrue(all(item.path for item in queries.items
                                    if item.category == "program"))
                command = (sys.executable, str(app), compiler, str(header), str(first))
                observed = capture_trace(tracer, command, first, environment(first))
                self.assertEqual(observed.stdout, "42\n")
                self.assertIn(str(header), observed.candidates)
                self.assertTrue(any(event.success and event.access is Access.EXEC
                                    and "cc1plus" in event.path for event in observed.events))
                self.assertTrue(any(event.success and event.access is Access.WRITE
                                    and event.scope is Scope.WORKSPACE
                                    and event.path.endswith("expression.so")
                                    for event in observed.events))
                self.assertTrue(any(not event.success for event in observed.events))
                graph = DependencyGraph(str(source))
                requester = Dependency(str(app), "/driver.py", DependencyKind.DATA)
                resource = Dependency(str(header), "/expression.h", DependencyKind.HEADER)
                add_jit_inputs(graph, requester, (resource,), observed, queries)
                build = BuildIdentity("cold-cxx-fixture", "0" * 64, queries.machine,
                                      (("g++", queries.version),),
                                      ("cold-cxx-trace", "explicit-header-replay"))
                plan = plan_collection(graph, (requester.source,),
                                       CollectionPolicy((str(source),)), build)
                runtime = root / "runtime"
                manifest = json.loads(collect(plan, runtime))
                self.assertEqual(len(manifest["files"]), 2)
                replay = capture_trace(
                    tracer, (sys.executable, str(runtime / "driver.py"), compiler,
                             str(runtime / "expression.h"), str(second)),
                    second, environment(second),
                )
                self.assertEqual(replay.stdout, observed.stdout)
                self.assertIn(str(runtime / "expression.h"), replay.candidates)
                print("JIT_COLD_HEADER_REPLAY_PASS", len(observed.events),
                      len(observed.candidates), len(replay.events), repr(replay.stdout),
                      flush=True)

        self.run_contract(check=check)
