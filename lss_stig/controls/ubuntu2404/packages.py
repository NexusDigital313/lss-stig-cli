"""Ubuntu 24.04 STIG — package presence rules."""

from __future__ import annotations

from lss_stig.lib import pkg
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"


def _dpkg_evidence(names: list[str]) -> str:
    return "\n".join(f"dpkg-query {n}: {'installed' if pkg.is_installed(n) else 'not installed'}"
                     for n in names)


def _must_not_have(vuln_id: str, names: list[str], impact: str | None = None) -> None:
    def check() -> CheckResult:
        present = [n for n in names if pkg.is_installed(n)]
        ev = _dpkg_evidence(names)
        if present:
            return CheckResult("fail", "installed: " + ", ".join(present), ev)
        return CheckResult("pass", "", ev)

    def fix() -> list[RollbackEntry]:
        out: list[RollbackEntry] = []
        for n in names:
            out += pkg.remove(n)
        return out

    register(B, Control(vuln_id, check, fix, impact=impact))


# V-270647 CAT I — telnet server. Cleartext credentials on the wire.
_must_not_have("V-270647", ["telnetd"])

# V-270648 CAT I — rsh-server. Host-trust auth, cleartext, no real authentication.
_must_not_have("V-270648", ["rsh-server"])

# V-279938 CAT I — NFS. Removing nfs-common also breaks NFS *client* mounts.
_must_not_have(
    "V-279938", ["nfs-kernel-server", "nfs-common"],
    impact="removes NFS server AND client (nfs-common) — any NFS mounts in /etc/fstab stop working",
)


# V-270665 CAT I — openssh-server must be installed (SSH is the mandated
# protected remote-access path).
def _check_ssh_installed() -> CheckResult:
    ev = _dpkg_evidence(["openssh-server"])
    if pkg.is_installed("openssh-server"):
        return CheckResult("pass", "", ev)
    return CheckResult("fail", "openssh-server not installed", ev)


register(B, Control("V-270665", _check_ssh_installed, lambda: pkg.install("openssh-server")))
