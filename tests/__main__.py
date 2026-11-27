"""Run the complete registered offline suite."""

import unittest

from tests import suites  # noqa: F401 -- explicit registration
from tests.wiring import build_suite


def main():
    suite = build_suite()
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != expected or not expected or result.skipped:
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
