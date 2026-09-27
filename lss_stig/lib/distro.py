"""Detect the host Linux distribution and version."""

from __future__ import annotations

import platform
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DistroInfo:
    """Parsed distribution identity."""
    id: str            # e.g. "debian", "ubuntu", "kali", "rhel", "rocky", "alma"
    family: str        # "debian" or "rhel"
    name: str          # human-readable, e.g. "Ubuntu 24.04"
    version: str       # e.g. "24.04", "12", "rolling"
    kernel: str        # uname release string

    @property
    def is_debian_family(self) -> bool:
        return self.family == "debian"

    @property
    def is_rhel_family(self) -> bool:
        return self.family == "rhel"


def _parse_os_release() -> dict[str, str]:
    """Parse /etc/os-release into a dict."""
    data: dict[str, str] = {}
    p = Path("/etc/os-release")
    if not p.exists():
        return data
    for line in p.read_text().splitlines():
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        data[key.strip()] = val.strip().strip('"')
    return data


_CACHED: DistroInfo | None = None


def detect() -> DistroInfo:
    """Detect the running distribution. Returns DistroInfo (cached)."""
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    osr = _parse_os_release()
    distro_id = osr.get("ID", "unknown").lower()
    version = osr.get("VERSION_ID", "rolling")
    pretty = osr.get("PRETTY_NAME", "Unknown Linux")
    id_like = osr.get("ID_LIKE", "").lower()

    # Determine family
    if distro_id in ("debian", "ubuntu", "kali"):
        family = "debian"
    elif distro_id in ("rhel", "centos", "rocky", "alma", "fedora"):
        family = "rhel"
    elif "debian" in id_like or "ubuntu" in id_like:
        family = "debian"
    elif "rhel" in id_like or "fedora" in id_like:
        family = "rhel"
    else:
        family = "unknown"

    _CACHED = DistroInfo(
        id=distro_id,
        family=family,
        name=pretty,
        version=version,
        kernel=platform.release(),
    )
    return _CACHED


def is_debian_family() -> bool:
    return detect().is_debian_family


def is_rhel_family() -> bool:
    return detect().is_rhel_family
