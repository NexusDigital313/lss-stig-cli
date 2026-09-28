"""Site-specific values the STIG requires but no tool can guess.

A handful of rules only pass against *your* infrastructure — the DOD time
source, the remote audit collector, who gets audit-capacity alerts. Those
values live in /etc/lss-stig/site.conf (`key = value`), set with
`lss-stig site key=value`. Until a value is set, its rules report open with
the exact command to run instead of inventing a default.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path

from lss_stig.lib import keyval

SITE_CONF = Path("/etc/lss-stig/site.conf")

KEYS = {
    "time_server": "authoritative (DOD) NTP server chrony must use — V-270751",
    "audit_remote_server": "host that receives audit records via audisp-remote — V-270658",
    "admin_email": "SA/ISSO address for audit alerts — V-270818, V-270819",
    "ssh_allow_from": "optional management IP/CIDR exempt from the SSH rate limit — V-270655, V-270754",
}

_HOST = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+$")


def get(key: str) -> str | None:
    v = keyval.get(SITE_CONF, key)
    return v or None


_BLOCKED = "site value"


def missing(key: str) -> str:
    """Detail line for a rule blocked on an unset site value."""
    return f"{_BLOCKED} '{key}' not set — run: sudo lss-stig site {key}=<value>"


def is_blocked(detail: str) -> bool:
    """True for a detail line produced by missing()."""
    return f"{_BLOCKED} '" in (detail or "")


def validate(key: str, value: str) -> str:
    """'' if OK, else why not."""
    if key not in KEYS:
        return f"unknown key (known: {', '.join(KEYS)})"
    if key == "admin_email":
        return "" if _EMAIL.match(value) else "not an email address"
    if key == "ssh_allow_from":
        try:
            ipaddress.ip_network(value, strict=False)
            return ""
        except ValueError:
            return "not an IP address or CIDR (e.g. 10.20.0.0/24)"
    if not _HOST.match(value):
        return "not a hostname or IP address"
    if key == "audit_remote_server" and is_local(value):
        return "points at this host — audit records must leave the system"
    return ""


def is_local(host: str) -> bool:
    if host.lower() in ("localhost", "localhost.localdomain", socket.gethostname().lower()):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def write(values: dict[str, str]) -> None:
    """Persist values (outside any harden run — no journal backup)."""
    SITE_CONF.parent.mkdir(parents=True, exist_ok=True)
    text = SITE_CONF.read_text() if SITE_CONF.exists() else "# lss-stig site values — see `lss-stig site`\n"
    lines = text.splitlines()
    for key, val in values.items():
        new = f"{key} = {val}"
        for i, l in enumerate(lines):
            if re.match(rf"^\s*{key}\s*=", l):
                lines[i] = new
                break
        else:
            lines.append(new)
    SITE_CONF.write_text("\n".join(lines) + "\n")
    SITE_CONF.chmod(0o644)
