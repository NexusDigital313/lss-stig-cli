"""Ubuntu 24.04 STIG — SSH daemon rules."""

from __future__ import annotations

from lss_stig.lib import pkg, sshd, systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"


def _no_sshd() -> CheckResult | None:
    if not pkg.is_installed("openssh-server"):
        return CheckResult("na", "openssh-server not installed (see V-270665)")
    return None


def _setting_rule(vuln_id: str, settings: dict[str, str]) -> None:
    def check() -> CheckResult:
        if (r := _no_sshd()) is not None:
            return r
        results = [sshd.check_setting(k, v) for k, v in settings.items()]
        evidence = "\n".join(r.evidence for r in results)
        failed = [r.detail for r in results if r.status != "pass"]
        if failed:
            return CheckResult("fail", "; ".join(failed), evidence)
        return CheckResult("pass", "", evidence)

    register(B, Control(vuln_id, check, lambda: sshd.set_settings(settings)))


# V-270708 CAT I — X11 forwarding exposes the client's X display to the server side.
_setting_rule("V-270708", {"X11Forwarding": "no"})

# V-270717 CAT I — no empty-password logins, no user-supplied environment
# (PermitUserEnvironment lets users set LD_PRELOAD etc. for their session).
_setting_rule("V-270717", {"PermitEmptyPasswords": "no", "PermitUserEnvironment": "no"})


# V-270666 CAT I — ssh.service enabled and active.
#
# Ubuntu 24.04 ships SSH socket-activated: ssh.socket listens, ssh.service is
# "disabled" and only runs per connection. The STIG check literally runs
# `systemctl is-enabled ssh` and `is-active ssh`, so a stock 24.04 box fails
# even though SSH works fine. Switching a live remote box off socket
# activation risks dropping the listener, so that case is left to the
# operator with the exact commands.
def _check_ssh_service() -> CheckResult:
    if (r := _no_sshd()) is not None:
        return CheckResult("fail", "openssh-server not installed (see V-270665)")
    en, act = systemd.is_enabled("ssh.service"), systemd.is_active("ssh.service")
    sock = systemd.is_enabled("ssh.socket")
    ev = f"is-enabled ssh.service: {en}\nis-active ssh.service: {act}\nis-enabled ssh.socket: {sock}"
    if en == "enabled" and act == "active":
        return CheckResult("pass", "", ev)
    if sock == "enabled":
        return CheckResult(
            "manual",
            "socket-activated (Ubuntu default) — from a console: systemctl disable --now ssh.socket "
            "&& systemctl enable --now ssh.service",
            ev,
        )
    return CheckResult("fail", f"ssh.service {en}/{act}", ev)


def _fix_ssh_service() -> list[RollbackEntry]:
    if systemd.is_enabled("ssh.socket") == "enabled":
        return []  # manual path, see check
    undo = []
    if systemd.is_enabled("ssh.service") != "enabled":
        undo.append(["systemctl", "disable", "ssh.service"])
    if systemd.is_active("ssh.service") != "active":
        undo.append(["systemctl", "stop", "ssh.service"])
    systemd.run("enable", "--now", "ssh.service")
    return [RollbackEntry(action="enabled and started ssh.service", undo=undo)] if undo else []


register(B, Control("V-270666", _check_ssh_service, _fix_ssh_service))
