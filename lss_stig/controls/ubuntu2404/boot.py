"""Ubuntu 24.04 STIG — boot loader and console rules."""

from __future__ import annotations

from pathlib import Path

from lss_stig.lib import systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"

GRUB_CFG = Path("/boot/grub/grub.cfg")


# ---- V-270675 CAT I — GRUB password for single-user/maintenance boot ----
# Choosing the password is the operator's job, so this stays manual. The
# detail carries the part DISA's fix text leaves out.

def _check_grub_password() -> CheckResult:
    if not GRUB_CFG.exists():
        return CheckResult("manual", f"{GRUB_CFG} not found — verify boot loader password by hand")
    lines = [l.strip() for l in GRUB_CFG.read_text(errors="replace").splitlines()]
    pw = [l for l in lines if l.startswith("password")]
    ev = f"{GRUB_CFG}: " + ("; ".join(p.split()[0] + " " + p.split()[1] + " <hash>" for p in pw if len(p.split()) > 1) or "no password entries")
    if any(l.startswith("password_pbkdf2") for l in pw):
        return CheckResult("pass", "", ev)
    return CheckResult(
        "manual",
        "no password_pbkdf2 — set one with grub-mkpasswd-pbkdf2 (see fix text); then test a "
        "reboot: without --unrestricted on normal menu entries GRUB prompts on every boot",
        ev,
    )


register(B, Control("V-270675", _check_grub_password))


# ---- V-270712 CAT I — Ctrl-Alt-Del must not reboot the box ----

def _check_cad_target() -> CheckResult:
    state = systemd.is_enabled("ctrl-alt-del.target")
    ev = f"systemctl is-enabled ctrl-alt-del.target: {state or '(unavailable)'}"
    if state == "masked":
        return CheckResult("pass", "", ev)
    return CheckResult("fail", f"ctrl-alt-del.target not masked (is-enabled: {state or 'unknown'})", ev)


def _fix_cad_target() -> list[RollbackEntry]:
    systemd.run("mask", "ctrl-alt-del.target")
    systemd.run("daemon-reload")
    return [RollbackEntry(action="masked ctrl-alt-del.target",
                          undo=[["systemctl", "unmask", "ctrl-alt-del.target"],
                                ["systemctl", "daemon-reload"]])]


register(B, Control("V-270712", _check_cad_target, _fix_cad_target))
