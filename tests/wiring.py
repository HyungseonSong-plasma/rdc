"""Explicit RDC suite registration; no implicit discovery or exemptions."""

import tomllib
from pathlib import Path

from work.libs.testing import SuiteRegistry

SUITES = SuiteRegistry()
register = SUITES.register
INTEGRATION = SuiteRegistry()
register_integration = INTEGRATION.register


def build_suite(group="offline"):
    with Path(__file__).with_name("tests.toml").open("rb") as stream:
        config = tomllib.load(stream)
    if set(config) != {"offline", "integration"} or group not in config:
        raise ValueError("Expected explicit suite group.")
    names = config[group]
    if not isinstance(names, list):
        raise ValueError("Expected suite manifest.")
    if any(type(name) is not str or not name for name in names):
        raise ValueError("Invalid suite name.")
    return (SUITES if group == "offline" else INTEGRATION).build(tuple(names))
