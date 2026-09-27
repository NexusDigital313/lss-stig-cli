"""Supported STIG benchmarks and host → benchmark resolution."""

from __future__ import annotations

import importlib

from lss_stig.lib import distro
from lss_stig.lib.registry import Benchmark, load_benchmark

# benchmark key → (distro id, VERSION_ID, control package)
SUPPORTED = {
    "ubuntu2404_v1r6": ("ubuntu", "24.04", "lss_stig.controls.ubuntu2404"),
}


def for_host() -> str | None:
    host = distro.detect()
    for key, (did, ver, _) in SUPPORTED.items():
        if host.id == did and host.version == ver:
            return key
    return None


def activate(key: str) -> Benchmark:
    """Load a benchmark's catalog and register its controls."""
    if key not in SUPPORTED:
        raise ValueError(f"unknown benchmark {key!r} (supported: {', '.join(SUPPORTED)})")
    importlib.import_module(SUPPORTED[key][2])
    return load_benchmark(key)
