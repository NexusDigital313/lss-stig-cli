"""Kernel parameters: runtime value, the value that will apply at boot, and a
journaled setter.

"Persisted" follows systemd-sysctl: files from all sysctl.d directories are
merged by basename (/etc wins over /run over /usr/lib), applied in basename
order, last assignment wins. On Ubuntu /etc/sysctl.d/99-sysctl.conf links to
/etc/sysctl.conf, so our file sorts after it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss_stig.lib import keyval
from lss_stig.lib.registry import RollbackEntry

DIRS = ["/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d"]
OUR_FILE = Path("/etc/sysctl.d/99-zz-lss-stig.conf")


def runtime(key: str) -> str | None:
    p = Path("/proc/sys") / key.replace(".", "/")
    try:
        return " ".join(p.read_text().split())
    except OSError:
        return None


def config_files() -> list[Path]:
    chosen: dict[str, Path] = {}
    for d in DIRS:
        dp = Path(d)
        if not dp.is_dir():
            continue
        for f in dp.glob("*.conf"):
            chosen.setdefault(f.name, f)   # earlier dir in DIRS wins
    return [chosen[n] for n in sorted(chosen)]


def assignments(key: str) -> list[tuple[str, str]]:
    """Every (file, value) assigning `key`, in application order."""
    out = []
    for f in config_files():
        try:
            for line in f.read_text(errors="replace").splitlines():
                s = line.strip()
                if not s or s[0] in "#;":
                    continue
                k, sep, v = s.lstrip("-").partition("=")
                if sep and k.strip() == key:
                    out.append((str(f), v.strip()))
        except OSError:
            continue
    return out


def persisted(key: str) -> str | None:
    a = assignments(key)
    return a[-1][1] if a else None


def evidence(key: str) -> str:
    lines = [f"runtime {key} = {runtime(key)}"]
    lines += [f"{f}: {key} = {v}" for f, v in assignments(key)] or [f"no persisted {key}"]
    return "\n".join(lines)


def set_value(key: str, value: str) -> list[RollbackEntry]:
    old = runtime(key)
    out = keyval.set_value(OUR_FILE, key, value, fmt=f"{key} = {value}")
    r = subprocess.run(["sysctl", "-w", f"{key}={value}"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"sysctl -w {key}={value}: {r.stderr.strip()}")
    if old is not None and old != value:
        out.append(RollbackEntry(action=f"sysctl {key}={value} (runtime)",
                                 undo=[["sysctl", "-w", f"{key}={old}"]]))
    return out
