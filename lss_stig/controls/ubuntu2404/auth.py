"""Ubuntu 24.04 STIG — accounts, PAM and privilege rules."""

from __future__ import annotations

import grp
import re
import subprocess
from pathlib import Path

from lss_stig.lib import journal, sshd
from lss_stig.lib.output import warn
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"

SHADOW = Path("/etc/shadow")
PAM_FILES = [Path("/etc/pam.d/common-password"), Path("/etc/pam.d/common-auth")]
SSSD_CONF = Path("/etc/sssd/sssd.conf")


# ---- V-270713 CAT I — no accounts with blank passwords ----

def blank_password_accounts(shadow_text: str) -> list[str]:
    out = []
    for line in shadow_text.splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0] and parts[1] == "":
            out.append(parts[0])
    return out


def _check_blank() -> CheckResult:
    users = blank_password_accounts(SHADOW.read_text())
    if users:
        return CheckResult("fail", "blank password: " + ", ".join(users),
                           "accounts with empty /etc/shadow password field:\n" + "\n".join(users))
    return CheckResult("pass", "", "awk -F: '!$2 {print $1}' /etc/shadow → (no output)")


def _fix_blank() -> list[RollbackEntry]:
    out = []
    for user in blank_password_accounts(SHADOW.read_text()):
        if user == "root" and not sshd.has_non_root_admin():
            warn("V-270713: not locking root — no other sudo admin exists; set a root "
                 "password instead: sudo passwd root")
            continue
        r = subprocess.run(["passwd", "-l", user], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"passwd -l {user}: {r.stderr.strip()}")
        # Exact inverse: put the empty hash back (usermod -U refuses to
        # unlock into a passwordless account, which is the point).
        out.append(RollbackEntry(action=f"locked passwordless account {user}",
                                 undo=[["usermod", "-p", "", user]]))
    return out


register(B, Control("V-270713", _check_blank, _fix_blank,
                    impact="locks every account whose password is blank"))


# ---- V-270714 CAT I — no nullok in PAM ----
#
# Note: Ubuntu generates common-auth/common-password with pam-auth-update.
# Once edited by hand, pam-auth-update stops rewriting them (it prints
# "Local modifications ... not updating") — so nullok stays gone, but future
# PAM profile changes from packages won't be merged automatically.

_NULLOK = re.compile(r"[ \t]+nullok(?:_secure)?\b")


def strip_nullok(text: str) -> str:
    return "".join(
        _NULLOK.sub("", line) if not line.lstrip().startswith("#") else line
        for line in text.splitlines(keepends=True)
    )


def _nullok_lines() -> list[str]:
    hits = []
    for f in PAM_FILES:
        if not f.exists():
            continue
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if not line.lstrip().startswith("#") and _NULLOK.search(line):
                hits.append(f"{f}:{n}: {line.strip()}")
    return hits


def _check_nullok() -> CheckResult:
    hits = _nullok_lines()
    if hits:
        return CheckResult("fail", f"nullok in {len(hits)} PAM line(s)", "\n".join(hits))
    return CheckResult("pass", "", "grep nullok " + " ".join(map(str, PAM_FILES)) + " → (no output)")


def _fix_nullok() -> list[RollbackEntry]:
    out = []
    for f in PAM_FILES:
        if not f.exists():
            continue
        text = f.read_text()
        new = strip_nullok(text)
        if new != text:
            bkp = journal.backup_file(str(f))
            f.write_text(new)
            out.append(RollbackEntry(action=f"removed nullok from {f}", path=str(f), backup=bkp))
    return out


register(B, Control("V-270714", _check_nullok, _fix_nullok))


# ---- V-270748 CAT I — sudo group only has users who need it ----
# Whether someone "needs" sudo is an ISSO decision. We collect the evidence.

def _check_sudo_members() -> CheckResult:
    try:
        members = grp.getgrnam("sudo").gr_mem
    except KeyError:
        return CheckResult("pass", "no sudo group", "getent group sudo → (none)")
    ev = "sudo group members: " + (", ".join(members) if members else "(none)")
    if not members:
        return CheckResult("pass", "", ev)
    return CheckResult("review", f"{len(members)} member(s): {', '.join(members)} — confirm each is authorized", ev)


register(B, Control("V-270748", _check_sudo_members))


# ---- V-270736 CAT I — PKI identities mapped to accounts (sssd) ----

def _check_pki_mapping() -> CheckResult:
    if not SSSD_CONF.exists():
        return CheckResult("manual", "sssd not configured — PKI/CAC authentication not set up",
                           f"{SSSD_CONF}: not present")
    hits = [l.strip() for l in SSSD_CONF.read_text().splitlines()
            if l.strip().lower().startswith("ldap_user_certificate")]
    if hits:
        return CheckResult("pass", "", f"{SSSD_CONF}: " + "; ".join(hits))
    return CheckResult("manual", "ldap_user_certificate not set in sssd.conf",
                       f"{SSSD_CONF}: no ldap_user_certificate entry")


register(B, Control("V-270736", _check_pki_mapping))
