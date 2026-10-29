"""Smoke test: the package and all declared subpackages import cleanly."""

from __future__ import annotations

import importlib

import netmon

SUBPACKAGES = [
    "ingest",
    "discovery",
    "enrich",
    "timeseries",
    "detect",
    "learn",
    "correlate",
    "notify",
    "report",
    "api",
    "storage",
]


def test_version_present() -> None:
    assert netmon.__version__
    assert netmon.__version__.count(".") == 2


def test_subpackages_import() -> None:
    for name in SUBPACKAGES:
        module = importlib.import_module(f"netmon.{name}")
        assert module is not None
