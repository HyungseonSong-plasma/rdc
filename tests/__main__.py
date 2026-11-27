"""Run the complete registered offline suite."""

import argparse
import unittest

from tests import suites  # noqa: F401 -- explicit registration
from tests.wiring import build_suite


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--group", choices=("offline", "integration"), default="offline")
    group = parser.parse_args().group
    if group == "integration":
        from tests import integration  # noqa: F401
    suite = build_suite(group)
    expected = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if result.testsRun != expected or not expected or result.skipped:
        return 1
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
