"""Ubuntu 24.04 STIG — boot loader and console rules."""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss_stig.lib import journal, pkg, systemd
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


# ---- V-270711 CAT I — Ctrl-Alt-Del logout disabled in GNOME ----
#
# The classic silent failure here: the keyfile is written but `dconf update`
# never ran (or the user profile doesn't read system-db:local), so the setting
# never reaches a session. We check the compiled database is newer than the
# keyfiles and that the profile references it.

DCONF_DIR = Path("/etc/dconf/db/local.d")
DCONF_DB = Path("/etc/dconf/db/local")
DCONF_PROFILE = Path("/etc/dconf/profile/user")
DCONF_FILE = DCONF_DIR / "00-mediakeys"
SECTION = "[org/gnome/settings-daemon/plugins/media-keys]"


def _gui_installed() -> bool:
    return any(pkg.is_installed(p) for p in ("gnome-shell", "gdm3", "ubuntu-desktop"))


def logout_value(text: str) -> str | None:
    in_sec = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            in_sec = line == SECTION
        elif in_sec and line.split("=", 1)[0].strip() == "logout":
            return line.split("=", 1)[1].strip()
    return None


def _check_gnome_cad() -> CheckResult:
    if not _gui_installed():
        return CheckResult("na", "no GNOME desktop installed")
    ev, value, newest = [], None, 0.0
    if DCONF_DIR.is_dir():
        for f in sorted(DCONF_DIR.iterdir()):
            if f.is_file():
                newest = max(newest, f.stat().st_mtime)
                v = logout_value(f.read_text(errors="replace"))
                if v is not None:
                    value = v
                    ev.append(f"{f}: logout={v}")
    profile = DCONF_PROFILE.read_text() if DCONF_PROFILE.exists() else ""
    ev.append(f"{DCONF_PROFILE}: {'references system-db:local' if 'system-db:local' in profile else 'missing system-db:local'}")
    ev.append(f"{DCONF_DB}: {'present' if DCONF_DB.exists() else 'not compiled'}")
    evidence = "\n".join(ev)
    if value is None or value.replace(" ", "") not in ("@as[]", "['']", "[]"):
        return CheckResult("fail", f"logout key {'not set' if value is None else 'bound: ' + value}", evidence)
    if "system-db:local" not in profile:
        return CheckResult("fail", "dconf user profile does not read system-db:local", evidence)
    if not DCONF_DB.exists() or DCONF_DB.stat().st_mtime < newest:
        return CheckResult("fail", "keyfile set but `dconf update` not run — setting not in effect", evidence)
    return CheckResult("pass", "", evidence)


def _fix_gnome_cad() -> list[RollbackEntry]:
    out = []
    DCONF_DIR.mkdir(parents=True, exist_ok=True)
    bkp = journal.backup_file(str(DCONF_FILE))
    DCONF_FILE.write_text(f"{SECTION}\nlogout=@as []\n")
    out.append(RollbackEntry(action=f"wrote {DCONF_FILE}", path=str(DCONF_FILE), backup=bkp,
                             undo=([] if bkp else [["rm", "-f", str(DCONF_FILE)]]) + [["dconf", "update"]]))
    profile = DCONF_PROFILE.read_text() if DCONF_PROFILE.exists() else ""
    if "system-db:local" not in profile:
        pbkp = journal.backup_file(str(DCONF_PROFILE))
        DCONF_PROFILE.parent.mkdir(parents=True, exist_ok=True)
        base = profile if profile.strip() else "user-db:user\n"
        DCONF_PROFILE.write_text(base.rstrip("\n") + "\nsystem-db:local\n")
        out.append(RollbackEntry(action=f"added system-db:local to {DCONF_PROFILE}",
                                 path=str(DCONF_PROFILE), backup=pbkp,
                                 undo=[] if pbkp else [["rm", "-f", str(DCONF_PROFILE)]]))
    r = subprocess.run(["dconf", "update"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"dconf update failed: {r.stderr.strip()}")
    return out


register(B, Control("V-270711", _check_gnome_cad, _fix_gnome_cad))
