"""Shared package-manager helpers for install/remove fixes.

Picks the right tool for the distro family. Package removal uses `remove`
rather than `purge` so the original configuration files are preserved on
Debian-family systems and a subsequent reinstall restores prior state.

For lss-stig-installed packages on rollback, we use `purge` (not `remove`)
because lss-stig owns the package's lifecycle on that path — the configuration
files were created by the package install, not by the customer, so leaving
them behind on rollback would be litter rather than preservation.
"""

from __future__ import annotations

import os
import subprocess

from lss_stig.lib import distro
from lss_stig.lib.registry import RollbackEntry


# Inherit the parent environment so apt's perl/locale-sensitive postinst
# scripts have LANG, HOME, etc., then layer our non-interactive flags on top.
# Explicit overrides:
#   DEBIAN_FRONTEND=noninteractive — suppress debconf prompts (apt baseline)
#   APT_LISTCHANGES_FRONTEND=none  — suppress apt-listchanges pager invocation
#   NEEDRESTART_MODE=a             — needrestart (Ubuntu 22.04+) auto-restarts
#                                    services without prompting; without this
#                                    `apt install` hangs indefinitely on a
#                                    needrestart prompt even with DEBIAN_FRONTEND
#   PATH                           — pinned to admin paths so no $HOME/bin shim
#   LC_ALL=C.UTF-8                 — perl postinst scripts complain on missing
#                                    locale; C.UTF-8 is universally available
def _build_env() -> dict[str, str]:
    return {
        **os.environ,
        "DEBIAN_FRONTEND": "noninteractive",
        "APT_LISTCHANGES_FRONTEND": "none",
        "NEEDRESTART_MODE": "a",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C.UTF-8",
    }


# Package operations are never timed out: killing apt mid-dpkg leaves the
# package database "interrupted" and every later install fails until someone
# runs `dpkg --configure -a` (found on a real 24.04 VM, where aide-common's
# postinst outran a 300 s timeout). Instead apt waits up to 10 min for the
# dpkg lock — a freshly booted cloud host is usually mid unattended-upgrade.
_APT_OPTS = ["-o", "DPkg::Lock::Timeout=600"]


def dpkg_interrupted() -> str:
    """Non-empty (dpkg --audit output) if the package database needs repair."""
    if not distro.is_debian_family():
        return ""
    r = subprocess.run(["dpkg", "--audit"], capture_output=True, text=True)
    return r.stdout.strip()


def _run(cmd: list[str]) -> None:
    if distro.is_debian_family() and (bad := dpkg_interrupted()):
        raise RuntimeError("dpkg is in an interrupted state — run `sudo dpkg --configure -a` first "
                           f"({bad.splitlines()[0]})")
    r = subprocess.run(cmd, capture_output=True, text=True, env=_build_env())
    if r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed: {(r.stderr or r.stdout).strip()[-400:]}")


def is_installed(pkg: str) -> bool:
    """Return True if `pkg` is installed on the running distro family.

    Dispatches on distro family first so we never spawn `rpm` on a host
    that doesn't have it (FileNotFoundError would crash the caller).
    """
    if distro.is_debian_family():
        r = subprocess.run(
            ["dpkg-query", "-W", "-f=${Status}", pkg],
            capture_output=True, text=True,
        )
        return r.returncode == 0 and "install ok installed" in r.stdout
    if distro.is_rhel_family():
        try:
            r = subprocess.run(["rpm", "-q", pkg], capture_output=True, text=True)
        except FileNotFoundError:
            return False
        return r.returncode == 0
    return False


def install(pkg: str) -> list[RollbackEntry]:
    """Install `pkg`. Returns a RollbackEntry whose undo purges the package.

    Uses `purge` (not `remove`) on the undo path because lss-stig just installed
    the package — its config files were created by the package install,
    not by the customer, so rollback should clean them up rather than
    leave litter under /etc/<pkg>/.

    No-op if already installed, or if the distro family is neither Debian
    nor RHEL (returns an empty list so the caller can surface a no-op).

    NOTE: rollback removes only the named package, not the dependencies
    that were pulled in transitively. On Debian, those dependencies remain
    marked as manually-installed (because the install was non-interactive)
    and won't be `apt autoremove`d unless the operator runs that explicitly.
    A snapshot-and-diff dpkg approach is planned for a future release.
    """
    if is_installed(pkg):
        return []
    if distro.is_debian_family():
        # No recommends: a STIG box should get exactly what the rule asks for
        # (aide recommends an MTA, which would drag postfix onto the host).
        cmd = ["apt-get", *_APT_OPTS, "install", "-y", "--no-install-recommends", pkg]
        undo = [["apt-get", "purge", "-y", pkg]]
    elif distro.is_rhel_family():
        cmd = ["dnf", "install", "-y", pkg]
        undo = [["dnf", "remove", "-y", pkg]]
    else:
        return []
    _run(cmd)
    return [RollbackEntry(action=f"installed package {pkg}", undo=undo)]


def remove(pkg: str) -> list[RollbackEntry]:
    """Remove `pkg` (not purge — preserves customer's existing config files
    so rollback via `install` restores the package without wiping their
    settings). Rollback reinstalls.
    """
    if not is_installed(pkg):
        return []
    if distro.is_debian_family():
        cmd = ["apt-get", *_APT_OPTS, "remove", "-y", pkg]
        undo = [["apt-get", "install", "-y", pkg]]
    elif distro.is_rhel_family():
        cmd = ["dnf", "remove", "-y", pkg]
        undo = [["dnf", "install", "-y", pkg]]
    else:
        return []
    _run(cmd)
    return [RollbackEntry(action=f"removed package {pkg}", undo=undo)]
