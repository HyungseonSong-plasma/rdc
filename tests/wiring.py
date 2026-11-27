"""Explicit RDC suite registration; no implicit discovery or exemptions."""

import tomllib
from pathlib import Path

from work.libs.testing import SuiteRegistry

SUITES = SuiteRegistry()
register = SUITES.register


def build_suite():
    with Path(__file__).with_name("tests.toml").open("rb") as stream:
        config = tomllib.load(stream)
    if set(config) != {"offline"} or not isinstance(config["offline"], list):
        raise ValueError("Expected offline suite manifest.")
    names = config["offline"]
    if any(type(name) is not str or not name for name in names):
        raise ValueError("Invalid suite name.")
    return SUITES.build(tuple(names))
