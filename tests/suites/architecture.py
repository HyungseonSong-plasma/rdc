from tests.architecture import import_violations, registration_violations, repository_violations
from tests.wiring import SUITES, register
from work.libs.testing import TestSuite


@register("architecture")
class ArchitectureContract(TestSuite):
    def test_repository(self):
        def check(ctx):
            self.assertEqual(repository_violations(), ())
            self.assertEqual(registration_violations(SUITES), ())

        self.run_contract(check=check)

    def test_import_policy(self):
        cases = (
            ("stdlib", "models.py", "from pathlib import Path", True),
            ("graph_models", "graph.py", "from rdc.models import Dependency", True),
            ("models_graph", "models.py", "import rdc.graph", False),
            ("work", "graph.py", "from work.libs.testing import TestSuite", False),
            ("tests", "models.py", "import tests", False),
            ("dynamic", "models.py", "__import__('work')", False),
            ("unknown", "unknown.py", "import sys", False),
        )

        def check(ctx, filename, source, allowed):
            self.assertEqual(not import_violations(filename, source), allowed)

        self.run_cases(cases, check)
