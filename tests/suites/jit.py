from pathlib import Path
import tempfile
from unittest.mock import patch

from rdc.discovery.jit import add_jit_inputs, query_compiler
from rdc.discovery.process import ToolError, ToolResult, run_tool
from rdc.discovery.trace import Access, Scope, TraceError, TraceReport, parse_trace
from rdc.graph import DependencyGraph
from rdc.models import Dependency, DependencyKind
from tests.wiring import register
from work.libs.testing import TestSuite


def encoded(path):
    return '"' + "".join(f"\\x{byte:02x}" for byte in path.encode()) + '"'


def opening(path, flags="O_RDONLY", result="3"):
    return f"openat(AT_FDCWD, {encoded(path)}, {flags}) = {result}"


@register("jit")
class JitContract(TestSuite):
    def test_trace_classes(self):
        def check(ctx):
            lines = (
                opening("/usr/include/header.h"),
                opening("/usr/lib/missing.so", result="-1 ENOENT (No such file)"),
                opening("/work/out.so", "O_WRONLY|O_CREAT"),
                opening("/proc/self/maps"),
                opening("relative.h"),
                opening("/usr/lib/../include/x"),
                opening("/usr/include", "O_RDONLY|O_DIRECTORY"),
                f"execve({encoded('/usr/bin/g++')}, [], 0x0) = 0",
            )
            events = parse_trace(lines, "/work")
            self.assertEqual(tuple((e.access, e.scope, e.success) for e in events), (
                (Access.READ, Scope.CANDIDATE, True),
                (Access.READ, Scope.CANDIDATE, False),
                (Access.WRITE, Scope.WORKSPACE, True),
                (Access.READ, Scope.EXTERNAL, True),
                (Access.READ, Scope.UNKNOWN, True),
                (Access.READ, Scope.UNKNOWN, True),
                (Access.DIRECTORY, Scope.CANDIDATE, True),
                (Access.EXEC, Scope.CANDIDATE, True),
            ))
            self.assertEqual(events[1].errno, "ENOENT")
            report = TraceReport(events, "", ())
            self.assertEqual(report.candidates, ("/usr/bin/g++", "/usr/include/header.h"))

        self.run_contract(check=check)

    def test_invalid_trace_records(self):
        cases = (
            ("truncated", 'openat(AT_FDCWD, "\\x2f"..., O_RDONLY) = 3'),
            ("plain", 'openat(AT_FDCWD, "/file", O_RDONLY) = 3'),
            ("flags", opening("/file", "UNKNOWN")),
            ("unfinished", 'openat(AT_FDCWD, <unfinished ...>'),
            ("unknown", 'stat("/file", {}) = 0'),
            ("failure", opening("/file", result="-1")),
        )

        def check(ctx, line):
            with self.assertRaises(TraceError):
                parse_trace((line,), "/work")

        self.run_cases(cases, check)

    def test_explicit_inputs_only(self):
        def check(ctx):
            root = "/source"
            graph = DependencyGraph(root)
            app = Dependency(root + "/app", "/app", DependencyKind.EXECUTABLE)
            selected = Dependency(root + "/usr/include/a.h", "/usr/include/a.h",
                                  DependencyKind.HEADER)
            unobserved = Dependency(root + "/usr/include/b.h", "/usr/include/b.h",
                                    DependencyKind.HEADER)
            report = TraceReport(parse_trace((
                opening("/usr/include/a.h"), opening("/usr/include/not-selected.h"),
                opening("/usr/include/b.h", result="-1 ENOENT (missing)"),
            ), "/work"), "", ())
            add_jit_inputs(graph, app, (selected, unobserved), report)
            closure = graph.closure((app.source,))
            self.assertEqual(set(closure.nodes), {app, selected, unobserved})
            self.assertEqual(len(closure.edges), 3)
            self.assertEqual(sum(edge.required for edge in closure.edges), 2)
            self.assertEqual(tuple(edge.evidence.request for edge in closure.edges
                                   if edge.evidence.analyzer == "trace"), (selected.target,))

        self.run_contract(check=check)

    def test_compiler_queries(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory)
                resource = workspace / "include"
                resource.mkdir()
                responses = (
                    ToolResult("13.2.0\n", ""), ToolResult("x86_64-linux-gnu\n", ""),
                    ToolResult("cc1plus\n", ""), ToolResult(str(resource) + "\n", ""),
                )
                with patch("rdc.discovery.jit.run_tool", side_effect=responses) as tool:
                    result = query_compiler("/usr/bin/g++", workspace, {},
                                            programs=("cc1plus",), resources=("include",))
                self.assertEqual(result.version, "13.2.0")
                self.assertEqual(result.machine, "x86_64-linux-gnu")
                self.assertIsNone(result.items[0].path)
                self.assertEqual(result.items[1].path, str(resource))
                self.assertEqual(tuple(call.args[0][1] for call in tool.call_args_list), (
                    "-dumpfullversion", "-dumpmachine", "-print-prog-name=cc1plus",
                    "-print-file-name=include",
                ))

        self.run_contract(check=check)

    def test_tool_contract(self):
        def check(ctx):
            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    run_tool(("relative",), Path(directory), {})
                with self.assertRaises(ToolError):
                    run_tool(("/nonexistent-rdc-tool",), Path(directory), {})

        self.run_contract(check=check)
