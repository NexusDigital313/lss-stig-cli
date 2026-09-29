"""Ubuntu 24.04 STIG — SSH daemon rules."""

from __future__ import annotations

from pathlib import Path

from lss_stig.controls.ubuntu2404 import dod
from lss_stig.lib import keyval, pkg, sshd, systemd
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


# ---- CAT II ----

FIPS_CIPHERS = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr"
FIPS_MACS = "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
FIPS_KEX = ("ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256,"
            "diffie-hellman-group16-sha512,diffie-hellman-group14-sha256")


def _subset_of(allowed: str):
    """Algorithm list may only contain approved entries (and at least one)."""
    ok = set(allowed.lower().split(","))
    return lambda v: bool(v) and set(v.lower().replace(" ", "").split(",")) <= ok


def _algo_rule(vuln_id: str, key: str, allowed: str, client: bool = False) -> None:
    pred = _subset_of(allowed)

    def check() -> CheckResult:
        if not client and (r := _no_sshd()) is not None:
            return r
        return sshd.check_setting(key, allowed, ok=pred, client=client)

    register(B, Control(vuln_id, check,
                        lambda: sshd.set_settings({key: allowed}, ok=lambda k, v: pred(v), client=client)))


_algo_rule("V-270667", "Ciphers", FIPS_CIPHERS)
_algo_rule("V-270668", "MACs", FIPS_MACS)
_algo_rule("V-270669", "KexAlgorithms", FIPS_KEX)
_algo_rule("V-270670", "Ciphers", FIPS_CIPHERS, client=True)
_algo_rule("V-270671", "MACs", FIPS_MACS, client=True)

# V-270709 — X11 proxy display bound to loopback only.
_setting_rule("V-270709", {"X11UseLocalhost": "yes"})
# V-270722 — public key (smart card/PIV-derived) authentication allowed.
_setting_rule("V-270722", {"PubkeyAuthentication": "yes"})
# V-270741 — PAM in the SSH login path (lockout, pwquality, MFA modules apply).
_setting_rule("V-270741", {"UsePAM": "yes"})
# V-270742 — one missed keepalive ends the session.
_setting_rule("V-270742", {"ClientAliveCountMax": "1"})


# V-270743 — keepalive interval ≤ 600s (with CountMax 1: idle sessions end in ≤10 min).
def _le_600(v: str) -> bool:
    return v.isdigit() and 0 < int(v) <= 600


def _check_alive_interval() -> CheckResult:
    if (r := _no_sshd()) is not None:
        return r
    return sshd.check_setting("ClientAliveInterval", "600", ok=_le_600)


register(B, Control("V-270743", _check_alive_interval,
                    lambda: sshd.set_settings({"ClientAliveInterval": "600"}, ok=lambda k, v: _le_600(v))))


# ---- V-270691 — DOD banner before SSH logon ----

ISSUE_NET = "/etc/issue.net"


def _check_ssh_banner() -> CheckResult:
    if (r := _no_sshd()) is not None:
        return r
    res = sshd.check_setting("Banner", ISSUE_NET, ok=lambda v: v.lower() != "none")
    if res.status != "pass":
        return res
    path = Path(sshd.effective("Banner") or ISSUE_NET)
    text = path.read_text(errors="replace") if path.exists() else ""
    if dod.normalize(text) != dod.normalize(dod.banner()):
        return CheckResult("fail", f"{path} is not the DOD Notice and Consent Banner", res.evidence)
    return CheckResult("pass", "", res.evidence + f"\n{path}: matches DOD banner")


def _fix_ssh_banner() -> list[RollbackEntry]:
    out = keyval.write_file(ISSUE_NET, dod.banner(), 0o644)
    return out + sshd.set_settings({"Banner": ISSUE_NET})


register(B, Control("V-270691", _check_ssh_banner, _fix_ssh_banner))


# ---- V-270694 — SSH users must acknowledge the banner ----

SSH_CONFIRM = "/etc/profile.d/ssh_confirm.sh"


def _check_ssh_confirm() -> CheckResult:
    p = Path(SSH_CONFIRM)
    if not p.exists():
        return CheckResult("fail", f"{SSH_CONFIRM} missing", f"{SSH_CONFIRM}: not present")
    if dod.normalize(p.read_text()) != dod.normalize(dod.ssh_confirm_script()):
        return CheckResult("fail", f"{SSH_CONFIRM} differs from the DISA script", f"{SSH_CONFIRM}: content differs")
    return CheckResult("pass", "", f"{SSH_CONFIRM}: matches DISA script")


def _fix_ssh_confirm() -> list[RollbackEntry]:
    return keyval.write_file(SSH_CONFIRM, dod.ssh_confirm_script(), 0o644)


register(B, Control("V-270694", _check_ssh_confirm, _fix_ssh_confirm,
                    impact="interactive SSH logins must answer y to the consent prompt (answering n disconnects)"))
