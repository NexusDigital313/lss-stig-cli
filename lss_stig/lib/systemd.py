"""Thin systemctl wrappers. All read calls are side-effect free."""

from __future__ import annotations

import subprocess


def _ctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=30)


def is_enabled(unit: str) -> str:
    """Raw `systemctl is-enabled` word: enabled, disabled, masked, static,
    not-found, ... ('' if systemctl is unavailable)."""
    try:
        return _ctl("is-enabled", unit).stdout.strip()
    except FileNotFoundError:
        return ""


def is_active(unit: str) -> str:
    try:
        return _ctl("is-active", unit).stdout.strip()
    except FileNotFoundError:
        return ""


def run(*args: str) -> None:
    r = _ctl(*args)
    if r.returncode != 0:
        raise RuntimeError(f"systemctl {' '.join(args)} failed: {r.stderr.strip()}")
