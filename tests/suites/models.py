from rdc.models import Dependency, DependencyKind, Edge, Evidence, Resolution
from tests.wiring import register
from work.libs.testing import TestSuite


@register("models")
class ModelContract(TestSuite):
    def test_invalid_paths(self):
        cases = (
            ("relative", "bin/app"),
            ("dot", "/bin/./app"),
            ("parent", "/bin/../app"),
            ("double_slash", "//bin/app"),
            ("empty_component", "/bin//app"),
            ("trailing_slash", "/bin/app/"),
            ("null", "/bin/\x00app"),
        )

        def check(ctx, path):
            with self.assertRaises(ValueError):
                Dependency(path, "/bin/app", DependencyKind.EXECUTABLE)
            with self.assertRaises(ValueError):
                Dependency("/build/app", path, DependencyKind.EXECUTABLE)

        self.run_cases(cases, check)

    def test_immutable_node(self):
        def check(ctx):
            from dataclasses import FrozenInstanceError

            node = Dependency("/build/app", "/bin/app", DependencyKind.EXECUTABLE)
            self.assertEqual(node.source, "/build/app")
            with self.assertRaises(FrozenInstanceError):
                node.source = "/build/changed"
            with self.assertRaises(ValueError):
                Dependency("/build/app", "/", DependencyKind.EXECUTABLE)
            with self.assertRaises(ValueError):
                Dependency("/build/app", "/bin/app", "executable")

        self.run_contract(check=check)

    def test_resolution_contract(self):
        cases = (
            ("resolved", Resolution.RESOLVED, "/build/lib.so", True),
            ("missing_target", Resolution.RESOLVED, None, False),
            ("unresolved", Resolution.UNRESOLVED, None, True),
            ("denied", Resolution.DENIED, None, True),
            ("invalid_unresolved", Resolution.UNRESOLVED, "/build/lib.so", False),
            ("invalid_denied", Resolution.DENIED, "/build/lib.so", False),
        )

        def check(ctx, status, target, valid):
            evidence = Evidence("elf", "needed", "lib.so")
            if valid:
                edge = Edge("/build/app", evidence, status, target)
                self.assertEqual(edge.dependency, target)
                self.assertTrue(edge.required)
            else:
                with self.assertRaises(ValueError):
                    Edge("/build/app", evidence, status, target)

        self.run_cases(cases, check)

    def test_empty_evidence(self):
        cases = (
            ("analyzer", "", "needed", "lib.so"),
            ("relation", "elf", " ", "lib.so"),
            ("request", "elf", "needed", ""),
        )

        def check(ctx, analyzer, relation, request):
            with self.assertRaises(ValueError):
                Evidence(analyzer, relation, request)

        self.run_cases(cases, check)
