"""Standalone provider compatibility probe, executed outside the RDC checkout."""

import unittest
from contextlib import contextmanager
from pathlib import Path
import sys

import work
from work.libs.testing import SuiteRegistry, TestSuite


class InvalidSuite(TestSuite):
    def test_invalid(self):
        self.assertTrue(True)


class ProviderContract(TestSuite):
    def test_cases(self):
        cases = (("one", 1), ("two", 2))

        def check(ctx, value):
            self.assertFalse(hasattr(ctx, "value"))
            ctx.value = value
            self.assertIn(ctx.value, (1, 2))

        self.run_cases(cases, check)

    def test_contract(self):
        def act(ctx):
            raise ValueError("expected")

        def check(ctx, error):
            self.assertEqual(str(error), "expected")

        self.run_contract(act, check, raises=ValueError)

    def test_scenario(self):
        @contextmanager
        def arrange(ctx):
            ctx.values = []
            try:
                yield
            finally:
                ctx.values.clear()

        def first(ctx):
            ctx.values.append(1)

        def second(ctx):
            ctx.values.append(2)

        def check(ctx):
            self.assertEqual(ctx.values, [1, 2])

        steps = (("first", first), ("second", second))
        self.run_scenario(steps, check, arrange=arrange)

    def test_registry_rejects_invalid_grammar(self):
        def check(ctx):
            registry = SuiteRegistry()
            registry.register("invalid")(InvalidSuite)
            with self.assertRaisesRegex(ValueError, "framework runner"):
                registry.build(("invalid",))

        self.run_contract(check=check)


if __name__ == "__main__":
    if not Path(work.__file__).resolve().is_relative_to(Path(sys.prefix).resolve()):
        raise SystemExit("Provider must be installed.")
    registry = SuiteRegistry()
    registry.register("provider")(ProviderContract)
    result = unittest.TextTestRunner(verbosity=2).run(registry.build(("provider",)))
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 4 else 1)
