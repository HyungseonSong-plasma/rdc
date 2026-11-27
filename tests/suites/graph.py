from rdc.graph import DependencyGraph, GraphError
from rdc.models import Dependency, DependencyKind, Edge, Evidence, Resolution
from tests.wiring import register
from work.libs.testing import TestSuite


def node(name, kind=DependencyKind.SHARED_LIBRARY):
    return Dependency("/build/" + name, "/runtime/" + name, kind)


def link(source, target, analyzer="elf", relation="needed", required=True):
    return Edge(
        "/build/" + source, Evidence(analyzer, relation, target),
        Resolution.RESOLVED, "/build/" + target, required,
    )


@register("graph")
class GraphContract(TestSuite):
    def test_cycles_and_evidence(self):
        def check(ctx):
            graph = DependencyGraph("/build")
            for name in ("a", "b", "c", "unreachable"):
                graph.add_node(node(name))
            edges = (
                link("a", "b"), link("b", "c"), link("c", "a"),
                link("a", "b", "trace", "open"),
                link("a", "b"),
            )
            for edge in edges:
                graph.add_edge(edge)
            graph.add_node(node("a"))
            closure = graph.closure(("/build/a", "/build/a"))
            self.assertEqual(closure.roots, ("/build/a",))
            self.assertEqual(tuple(n.source for n in closure.nodes),
                             ("/build/a", "/build/b", "/build/c"))
            self.assertEqual(len(closure.edges), 4)
            self.assertEqual(tuple(e.evidence.analyzer for e in closure.edges
                                   if e.requester == "/build/a"), ("elf", "trace"))
            self.assertTrue(closure.complete)

        self.run_contract(check=check)

    def test_optional_and_required_failures(self):
        def check(ctx):
            graph = DependencyGraph("/build")
            graph.add_node(node("a"))
            graph.add_node(node("b"))
            optional = Edge("/build/a", Evidence("trace", "probe", "optional"),
                            Resolution.UNRESOLVED, required=False)
            denied = Edge("/build/b", Evidence("policy", "deny", "secret"),
                          Resolution.DENIED)
            missing = Edge("/build/a", Evidence("elf", "needed", "missing.so"),
                           Resolution.UNRESOLVED)
            for edge in (optional, denied, missing):
                graph.add_edge(edge)
            partial = graph.closure(("/build/a",))
            self.assertEqual(partial.blockers, (missing,))
            self.assertEqual(len(partial.edges), 2)
            self.assertFalse(partial.complete)
            both = graph.closure(("/build/b", "/build/a"))
            self.assertEqual(both.blockers, (missing, denied))

        self.run_contract(check=check)

    def test_optional_resolved_is_reachable(self):
        def check(ctx):
            graph = DependencyGraph("/build")
            for name in ("a", "b"):
                graph.add_node(node(name))
            graph.add_edge(link("a", "b", required=False))
            self.assertEqual(tuple(n.source for n in graph.closure(("/build/a",)).nodes),
                             ("/build/a", "/build/b"))

        self.run_contract(check=check)

    def test_insertion_order(self):
        def check(ctx):
            left, right = DependencyGraph("/build"), DependencyGraph("/build")
            nodes = (node("a"), node("b"), node("c", DependencyKind.SYMLINK))
            edges = (link("a", "c"), link("c", "b", "fs", "symlink"))
            for graph, ns, es in ((left, nodes, edges),
                                  (right, reversed(nodes), reversed(edges))):
                for item in ns:
                    graph.add_node(item)
                for edge in es:
                    graph.add_edge(edge)
            self.assertEqual(left.closure(("/build/a", "/build/b")),
                             right.closure(("/build/b", "/build/a")))

        self.run_contract(check=check)

    def test_invalid_graph_operations(self):
        cases = (
            ("outside_root", "outside"),
            ("source_conflict", "conflict"),
            ("unknown_requester", "requester"),
            ("unknown_dependency", "dependency"),
            ("empty_roots", "empty"),
            ("unknown_root", "root"),
            ("string_roots", "string"),
        )

        def check(ctx, operation):
            graph = DependencyGraph("/build")
            graph.add_node(node("a"))
            actions = {
                "outside": lambda: graph.add_node(
                    Dependency("/build-other/a", "/runtime/a", DependencyKind.DATA)),
                "conflict": lambda: graph.add_node(node("a", DependencyKind.HEADER)),
                "requester": lambda: graph.add_edge(link("b", "a")),
                "dependency": lambda: graph.add_edge(link("a", "b")),
                "empty": lambda: graph.closure(()),
                "root": lambda: graph.closure(("/build/b",)),
                "string": lambda: graph.closure("/build/a"),
            }
            with self.assertRaises(GraphError):
                actions[operation]()
            self.assertEqual(graph.closure(("/build/a",)).nodes, (node("a"),))
            self.assertEqual(graph.closure(("/build/a",)).edges, ())

        self.run_cases(cases, check)

    def test_deep_chain(self):
        def check(ctx):
            graph = DependencyGraph("/build")
            for index in range(1500):
                graph.add_node(node(str(index)))
            for index in range(1499):
                graph.add_edge(link(str(index), str(index + 1)))
            result = graph.closure(("/build/0",))
            self.assertEqual(len(result.nodes), 1500)
            self.assertEqual(len(result.edges), 1499)
            self.assertTrue(result.complete)

        self.run_contract(check=check)
