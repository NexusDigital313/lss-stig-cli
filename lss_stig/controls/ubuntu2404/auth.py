"""Ubuntu 24.04 STIG — accounts, PAM and privilege rules."""

from __future__ import annotations

import grp
import os
import pwd
import re
import subprocess
from datetime import date, timedelta
from pathlib import Path

from lss_stig.lib import ini, journal, keyval, pamstack, pkg, sshd, systemd
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


# ======================================================================
# CAT II
# ======================================================================

PWQUALITY = Path("/etc/security/pwquality.conf")
LOGIN_DEFS = Path("/etc/login.defs")
USERADD = Path("/etc/default/useradd")
COMMON_PASSWORD = Path("/etc/pam.d/common-password")
COMMON_AUTH = Path("/etc/pam.d/common-auth")


def _int(v: str | None, base: int = 10) -> int | None:
    try:
        return int(v, base) if v is not None else None
    except ValueError:
        return None


def _conf_rule(vuln_id: str, path: Path, key: str, target: str, ok, *, sep: str = "=",
               fmt: str | None = None, needs: str | None = None, needs_rule: str = "") -> None:
    """One `key` in one config file; `ok(value_or_None) -> bool`."""
    def check() -> CheckResult:
        if needs and not pkg.is_installed(needs):
            return CheckResult("fail", f"{needs} not installed (see {needs_rule})")
        v = keyval.get(path, key, sep)
        ev = keyval.evidence(path, key, sep)
        if not ok(v):
            return CheckResult("fail", f"{key} = {v}" if v is not None else f"{key} not set", ev)
        return CheckResult("pass", "", ev)

    def fix() -> list[RollbackEntry]:
        if needs and not pkg.is_installed(needs):
            raise RuntimeError(f"{needs} not installed — fix {needs_rule} first")
        return keyval.set_value(path, key, target, sep, fmt)

    register(B, Control(vuln_id, check, fix))


def _pwq(vuln_id: str, key: str, target: str, ok) -> None:
    _conf_rule(vuln_id, PWQUALITY, key, target, ok, fmt=f"{key} = {target}",
               needs="libpam-pwquality", needs_rule="V-270661")


# pwquality — values per the V1R6 check text.
_pwq("V-270704", "dictcheck", "1", lambda v: v == "1")
_pwq("V-270726", "ucredit", "-1", lambda v: (_int(v) is not None and _int(v) <= -1))
_pwq("V-270727", "lcredit", "-1", lambda v: (_int(v) is not None and _int(v) <= -1))
_pwq("V-270728", "dcredit", "-1", lambda v: (_int(v) is not None and _int(v) <= -1))
_pwq("V-270733", "ocredit", "-1", lambda v: (_int(v) is not None and _int(v) <= -1))
_pwq("V-270729", "difok", "8", lambda v: (_int(v) is not None and _int(v) >= 8))
_pwq("V-270732", "minlen", "15", lambda v: (_int(v) is not None and _int(v) >= 15))

# login.defs. UMASK 000 would be CAT I per the check text; 077 is required.
_conf_rule("V-270716", LOGIN_DEFS, "UMASK", "077", lambda v: _int(v, 8) == 0o77, sep=" ")
_conf_rule("V-270730", LOGIN_DEFS, "PASS_MIN_DAYS", "1", lambda v: (_int(v) or 0) >= 1, sep=" ")
# The V1R6 check text says "less than 60 is a finding" — a DISA typo; the
# requirement is a 60-day MAXIMUM. We enforce 1..60 and set exactly 60, which
# passes either reading.
_conf_rule("V-270731", LOGIN_DEFS, "PASS_MAX_DAYS", "60", lambda v: 0 < (_int(v) or 0) <= 60, sep=" ")
_conf_rule("V-270739", LOGIN_DEFS, "ENCRYPT_METHOD", "SHA512", lambda v: (v or "").upper() == "SHA512", sep=" ")
_conf_rule("V-270683", USERADD, "INACTIVE", "35", lambda v: 0 < (_int(v) or 0) <= 35)


# ---- V-270705 — pwquality enforced, and in the PAM password stack ----

_PWQ_LINE = re.compile(r"^\s*password\s+(\[[^\]]*\]|\S+)\s+pam_pwquality\.so\b(.*)$")


def _pwq_pam_line() -> tuple[str, str] | None:
    if not COMMON_PASSWORD.exists():
        return None
    for line in COMMON_PASSWORD.read_text().splitlines():
        m = _PWQ_LINE.match(line)
        if m:
            return m.group(1), m.group(2)
    return None


def _check_pwq_enforced() -> CheckResult:
    if not pkg.is_installed("libpam-pwquality"):
        return CheckResult("fail", "libpam-pwquality not installed (see V-270661)")
    enf = keyval.get(PWQUALITY, "enforcing")
    line = _pwq_pam_line()
    ev = keyval.evidence(PWQUALITY, "enforcing") + "\n" + (
        f"{COMMON_PASSWORD}: password {line[0]} pam_pwquality.so{line[1]}" if line else f"{COMMON_PASSWORD}: no pam_pwquality line")
    problems = []
    if enf != "1":
        problems.append(f"enforcing = {enf}")
    if not line:
        problems.append("pam_pwquality not in common-password")
    else:
        retry = re.search(r"\bretry=(\d+)", line[1])
        if line[0] != "requisite":
            problems.append(f"pam_pwquality control is {line[0]}, not requisite")
        if not retry or not 1 <= int(retry.group(1)) <= 3:
            problems.append("retry not 1-3")
    if problems:
        return CheckResult("fail", "; ".join(problems), ev)
    return CheckResult("pass", "", ev)


def _set_pwq_line(text: str) -> str:
    lines = text.splitlines()
    want = "password\trequisite\t\t\tpam_pwquality.so retry=3"
    for i, line in enumerate(lines):
        m = _PWQ_LINE.match(line)
        if m:
            args = re.sub(r"\s*\bretry=\d+", "", m.group(2)).strip()
            lines[i] = want + (f" {args}" if args else "")
            return "\n".join(lines) + "\n"
    for i, line in enumerate(lines):
        if re.match(r"^\s*password\s+.*pam_unix\.so", line):
            lines.insert(i, want)
            return "\n".join(lines) + "\n"
    raise RuntimeError(f"no pam_unix password line in {COMMON_PASSWORD} to anchor pam_pwquality")


def _fix_pwq_enforced() -> list[RollbackEntry]:
    if not pkg.is_installed("libpam-pwquality"):
        raise RuntimeError("libpam-pwquality not installed — fix V-270661 first")
    out = keyval.set_value(PWQUALITY, "enforcing", "1", fmt="enforcing = 1")
    return out + keyval.edit_file(COMMON_PASSWORD, _set_pwq_line, f"pam_pwquality requisite retry=3 in {COMMON_PASSWORD}")


register(B, Control("V-270705", _check_pwq_enforced, _fix_pwq_enforced))


# ---- V-270725 — pam_unix stores sha512 hashes with rounds ≥ 100000 ----
# Ubuntu 24.04 ships yescrypt, so a stock box fails. Switching only affects
# passwords set from now on: existing yescrypt hashes stay until each user
# changes their password — the evidence counts them.

_UNIX_PW = re.compile(r"^(\s*password\s+(?:\[[^\]]*\]|\S+)\s+pam_unix\.so)(.*)$")
_OTHER_HASHES = {"md5", "bigcrypt", "sha256", "blowfish", "gost_yescrypt", "yescrypt"}


def _hash_census() -> str:
    counts: dict[str, int] = {}
    names = {"$y$": "yescrypt", "$6$": "sha512", "$5$": "sha256", "$1$": "md5", "$2": "bcrypt"}
    try:
        for line in SHADOW.read_text().splitlines():
            h = line.split(":")[1] if ":" in line else ""
            h = h.lstrip("!")
            for pfx, n in names.items():
                if h.startswith(pfx):
                    counts[n] = counts.get(n, 0) + 1
    except OSError:
        return ""
    return "existing password hashes: " + (", ".join(f"{n}={c}" for n, c in counts.items()) or "none")


def _check_unix_hash() -> CheckResult:
    if not COMMON_PASSWORD.exists():
        return CheckResult("fail", f"{COMMON_PASSWORD} missing")
    line = next((l for l in COMMON_PASSWORD.read_text().splitlines() if _UNIX_PW.match(l)), None)
    ev = f"{COMMON_PASSWORD}: {line.strip() if line else 'no pam_unix password line'}\n{_hash_census()}"
    if not line:
        return CheckResult("fail", "no pam_unix password line", ev)
    toks = _UNIX_PW.match(line).group(2).split()
    rounds = next((_int(t.split("=", 1)[1]) for t in toks if t.startswith("rounds=")), None)
    problems = []
    if "sha512" not in toks:
        problems.append("hash is " + (next((t for t in toks if t in _OTHER_HASHES), None) or "default") + ", not sha512")
    if rounds is None or rounds < 100000:
        problems.append(f"rounds={rounds}")
    if problems:
        return CheckResult("fail", "; ".join(problems), ev)
    return CheckResult("pass", "", ev)


def _set_unix_hash(text: str) -> str:
    out = []
    for line in text.splitlines():
        m = _UNIX_PW.match(line)
        if m:
            toks = [t for t in m.group(2).split() if t not in _OTHER_HASHES and not t.startswith("rounds=")]
            if "sha512" not in toks:
                toks.append("sha512")
            toks.append("rounds=100000")
            line = m.group(1) + " " + " ".join(toks)
        out.append(line)
    return "\n".join(out) + "\n"


register(B, Control("V-270725", _check_unix_hash,
                    lambda: keyval.edit_file(COMMON_PASSWORD, _set_unix_hash, f"pam_unix sha512 rounds=100000 in {COMMON_PASSWORD}")))


# ---- V-270724 — no direct root login ----

def _root_status() -> str:
    r = subprocess.run(["passwd", "-S", "root"], capture_output=True, text=True)
    return r.stdout.strip()


def _check_root_locked() -> CheckResult:
    st = _root_status()
    f = st.split()
    ev = f"passwd -S root: {st}"
    if len(f) > 1 and f[1] == "L":
        return CheckResult("pass", "", ev)
    return CheckResult("fail", f"root password status {f[1] if len(f) > 1 else '?'}", ev)


def _fix_root_locked() -> list[RollbackEntry]:
    if not sshd.has_non_root_admin():
        raise RuntimeError("refusing to lock root: no other sudo admin with a login shell exists")
    r = subprocess.run(["passwd", "-l", "root"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"passwd -l root: {r.stderr.strip()}")
    return [RollbackEntry(action="locked root password", undo=[["passwd", "-u", "root"]])]


register(B, Control("V-270724", _check_root_locked, _fix_root_locked,
                    impact="root can no longer log in with a password (console included) — admins use sudo"))


# ---- sudoers: V-270707 !authenticate, V-274868 NOPASSWD, V-274869 ALL ALL ----
# Check-only on purpose. Cloud images give the default user
# `NOPASSWD:ALL` and no password at all — stripping NOPASSWD there removes
# the only admin path. These are the operator's (and ISSO's) call.

def _sudoers_lines() -> list[tuple[str, int, str]]:
    files = [Path("/etc/sudoers")]
    d = Path("/etc/sudoers.d")
    if d.is_dir():
        files += sorted(f for f in d.iterdir() if f.is_file() and "." not in f.name and not f.name.endswith("~"))
    out = []
    for f in files:
        try:
            for n, line in enumerate(f.read_text().splitlines(), 1):
                s = line.strip()
                if s and not s.startswith("#") and not s.startswith("@"):
                    out.append((str(f), n, s))
        except OSError:
            continue
    return out


def _sudo_rule(vuln_id: str, pattern: re.Pattern, what: str, advice: str) -> None:
    def check() -> CheckResult:
        hits = [f"{f}:{n}: {s}" for f, n, s in _sudoers_lines() if pattern.search(s)]
        if hits:
            return CheckResult("manual", f"{len(hits)} {what} — {advice}", "\n".join(hits))
        return CheckResult("pass", "", f"no {what} in /etc/sudoers or /etc/sudoers.d")

    register(B, Control(vuln_id, check))


_sudo_rule("V-270707", re.compile(r"!authenticate", re.I), "!authenticate entr(ies)",
           "remove them (users must re-authenticate)")
_sudo_rule("V-274868", re.compile(r"NOPASSWD", re.I), "NOPASSWD entr(ies)",
           "remove, or document with the ISSO as an MFA admin group; give the user a password first")
_sudo_rule("V-274869", re.compile(r"^ALL\s+ALL\s*=\s*\(ALL(?::ALL)?\)\s+ALL$"), "'ALL ALL=(ALL) ALL' rule(s)",
           "restrict to named users/groups")


# ---- V-270720 — no duplicate UIDs among interactive users ----

_NOLOGIN = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}


def _check_dup_uids() -> CheckResult:
    by_uid: dict[int, list[str]] = {}
    for p in pwd.getpwall():
        if p.pw_shell not in _NOLOGIN:
            by_uid.setdefault(p.pw_uid, []).append(p.pw_name)
    dups = {u: n for u, n in by_uid.items() if len(n) > 1}
    if dups:
        ev = "\n".join(f"uid {u}: {', '.join(n)}" for u, n in dups.items())
        return CheckResult("manual", f"{len(dups)} UID(s) shared by interactive accounts", ev)
    return CheckResult("pass", "", f"{sum(len(n) for n in by_uid.values())} interactive accounts, all UIDs unique")


register(B, Control("V-270720", _check_dup_uids))


# ---- V-270682 — temporary/emergency accounts expire within 72 hours ----

def _check_emergency() -> CheckResult:
    exp = {}
    for line in SHADOW.read_text().splitlines():
        f = line.split(":")
        if len(f) > 7:
            exp[f[0]] = f[7]
    rows = []
    for p in pwd.getpwall():
        if p.pw_uid >= 1000 and p.pw_shell not in _NOLOGIN and p.pw_name != "nobody":
            e = exp.get(p.pw_name, "")
            when = (date(1970, 1, 1) + timedelta(days=int(e))).isoformat() if e.isdigit() else "never"
            rows.append(f"{p.pw_name} (uid {p.pw_uid}): account expires {when}")
    return CheckResult("review", "confirm any temporary/emergency accounts expire within 72h",
                       "\n".join(rows) or "no interactive user accounts")


register(B, Control("V-270682", _check_emergency))


# ---- PKI / smart card (check-only: needs the site's CA, card middleware, directory) ----

PAM_PKCS11 = Path("/etc/pam_pkcs11/pam_pkcs11.conf")


def _pkcs11_in_auth() -> str:
    if not COMMON_AUTH.exists():
        return ""
    for line in COMMON_AUTH.read_text().splitlines():
        if not line.lstrip().startswith("#") and "pam_pkcs11.so" in line:
            return line.strip()
    return ""


def _check_pkcs11_auth() -> CheckResult:
    line = _pkcs11_in_auth()
    if line:
        return CheckResult("pass", "", f"{COMMON_AUTH}: {line}")
    return CheckResult("manual", "pam_pkcs11.so not in common-auth — smart card login not configured",
                       f"{COMMON_AUTH}: no pam_pkcs11.so line")


register(B, Control("V-270721", _check_pkcs11_auth))


def cert_policies(text: str) -> list[str]:
    """cert_policy values inside the pkcs11_module block named by use_pkcs11_module."""
    text = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    m = re.search(r"use_pkcs11_module\s*=\s*(\S+?)\s*;", text)
    name = m.group(1) if m else "opensc"
    block = re.search(rf"pkcs11_module\s+{re.escape(name)}\s*\{{(.*?)\n\s*\}}", text, re.S)
    if not block:
        return []
    return [p.replace(" ", "") for p in re.findall(r"cert_policy\s*=\s*([^;]*);", block.group(1))]


def _cert_policy_rule(vuln_id: str, needs: tuple[str, ...], label: str, na_without_pkcs11: bool = False) -> None:
    def check() -> CheckResult:
        if na_without_pkcs11 and not _pkcs11_in_auth():
            return CheckResult("na", "smart card authentication not in use (no pam_pkcs11 in common-auth)")
        if not PAM_PKCS11.exists():
            return CheckResult("manual", f"{PAM_PKCS11} missing — pam_pkcs11 not configured", f"{PAM_PKCS11}: not present")
        pols = cert_policies(PAM_PKCS11.read_text())
        ev = f"{PAM_PKCS11}: " + ("; ".join(f"cert_policy = {p}" for p in pols) or "no cert_policy in active module")
        if pols and all(any(n in p.split(",") for n in needs) for p in pols):
            return CheckResult("pass", "", ev)
        return CheckResult("manual", f"cert_policy lacks {label}", ev)

    register(B, Control(vuln_id, check))


_cert_policy_rule("V-270723", ("ocsp_on",), "ocsp_on")
_cert_policy_rule("V-270737", ("ca",), "ca")
_cert_policy_rule("V-270738", ("crl_auto", "crl_offline"), "crl_auto/crl_offline", na_without_pkcs11=True)


def _ini_sections(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    cur = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            cur = out.setdefault(s[1:-1].strip().lower(), {})
        elif cur is not None and "=" in s:
            k, v = s.split("=", 1)
            cur[k.strip().lower()] = v.strip()
    return out


def _check_sssd_pki() -> CheckResult:
    if not SSSD_CONF.exists():
        return CheckResult("manual", "sssd not configured — PKI certificate path validation not set up",
                           f"{SSSD_CONF}: not present")
    sec = _ini_sections(SSSD_CONF.read_text())
    services = [s.strip() for s in sec.get("sssd", {}).get("services", "").split(",")]
    cert_auth = sec.get("pam", {}).get("pam_cert_auth", "")
    verify = next((v.get("certificate_verification", "") for v in sec.values() if "certificate_verification" in v), "")
    ev = f"[sssd] services = {','.join(services)}\n[pam] pam_cert_auth = {cert_auth}\ncertificate_verification = {verify}"
    problems = []
    if "pam" not in services:
        problems.append("pam not in [sssd] services")
    if cert_auth.lower() != "true":
        problems.append("pam_cert_auth not True")
    if "ca" not in verify and "ca_cert" not in verify:
        problems.append("certificate_verification lacks ca")
    if problems:
        return CheckResult("manual", "; ".join(problems), ev)
    return CheckResult("pass", "", ev)


register(B, Control("V-270735", _check_sssd_pki))


def _check_dod_ca() -> CheckResult:
    certs = Path("/etc/ssl/certs")
    hits = []
    if certs.is_dir():
        for f in sorted(certs.iterdir()):
            if "dod" in f.name.lower():
                hits.append(f.name)
                continue
            if f.is_file() and f.suffix in (".pem", ".crt") and f.name != "ca-certificates.crt":
                try:
                    if "DOD ROOT CA" in f.read_text(errors="ignore").upper():
                        hits.append(f.name)
                except OSError:
                    pass
    if hits:
        return CheckResult("pass", "", "DOD CA files in /etc/ssl/certs: " + ", ".join(hits[:20]))
    return CheckResult("manual", "no DOD root CA in /etc/ssl/certs — install the DOD PKI chain",
                       "no file in /etc/ssl/certs mentions DOD ROOT CA")


register(B, Control("V-270745", _check_dod_ca))


# ======================================================================
# CAT III
# ======================================================================


LIMITS = Path("/etc/security/limits.conf")
LIMITS_D = Path("/etc/security/limits.d")
MAXLOGINS_CONF = LIMITS_D / "lss-stig-maxlogins.conf"
FAILLOCK_CONF = Path("/etc/security/faillock.conf")
FAILLOCK_DIR = "/var/lib/faillock"


# ---- V-270677 — at most 10 concurrent sessions ----

def _maxlogins() -> list[tuple[str, str, str, int]]:
    out = []
    files = ([LIMITS] if LIMITS.exists() else []) + (sorted(LIMITS_D.glob("*.conf")) if LIMITS_D.is_dir() else [])
    for f in files:
        for line in f.read_text(errors="replace").splitlines():
            t = line.split("#", 1)[0].split()
            if len(t) == 4 and t[2] == "maxlogins" and t[3].isdigit():
                out.append((str(f), t[0], t[1], int(t[3])))
    return out


def _check_maxlogins() -> CheckResult:
    found = _maxlogins()
    ev = "\n".join(f"{f}: {d} {t} maxlogins {v}" for f, d, t, v in found) or "no maxlogins limit"
    if any(v > 10 for *_, v in found):
        return CheckResult("fail", "a maxlogins limit above 10 is set", ev)
    if not any(d == "*" and t in ("hard", "-") for _, d, t, _ in found):
        return CheckResult("fail", "no `* hard maxlogins 10` for all accounts", ev)
    return CheckResult("pass", "", ev)


def _fix_maxlogins() -> list[RollbackEntry]:
    out = keyval.write_file(MAXLOGINS_CONF, "# lss-stig: V-270677\n* hard maxlogins 10\n")
    for f in {f for f, _, _, v in _maxlogins() if v > 10}:
        out += keyval.edit_file(f, lambda t: "\n".join(
            f"# {l}  # lss-stig: V-270677" if len(l.split("#", 1)[0].split()) == 4 and l.split()[2] == "maxlogins"
            and l.split()[3].isdigit() and int(l.split()[3]) > 10 else l for l in t.splitlines()) + "\n",
            f"commented maxlogins > 10 in {f}")
    return out


register(B, Control("V-270677", _check_maxlogins, _fix_maxlogins,
                    impact="each account can hold at most 10 simultaneous login sessions"))


# ---- V-270690 — lock after 3 failures until an admin releases it ----
# Two things the fix text doesn't say: (1) inserting lines under pam_unix
# breaks Ubuntu's success=N jumps — pamstack recomputes them; (2) the
# default tally dir /var/run/faillock is tmpfs, so a reboot silently
# unlocks everyone, which defeats unlock_time = 0. The tally is kept in
# /var/lib/faillock instead.

FAILLOCK_OPTS = {"deny": "3", "fail_interval": "900", "unlock_time": "0", "dir": FAILLOCK_DIR}
FAILLOCK_FLAGS = ("audit", "silent")


def _faillock_flag(text: str, flag: str) -> bool:
    return any(l.strip() == flag for l in text.splitlines())


def _check_faillock() -> CheckResult:
    auth_mods = pamstack.modules(COMMON_AUTH.read_text(), "auth") if COMMON_AUTH.exists() else []
    fl = [f"{m.control} {m.module} {m.args}".strip() for m in auth_mods if m.module == "pam_faillock.so"]
    conf = FAILLOCK_CONF.read_text() if FAILLOCK_CONF.exists() else ""
    vals = {k: keyval.get(FAILLOCK_CONF, k) for k in FAILLOCK_OPTS}
    ev = [f"{COMMON_AUTH}: " + ("; ".join(fl) or "no pam_faillock.so")]
    ev += [f"{FAILLOCK_CONF}: {f} {'set' if _faillock_flag(conf, f) else 'missing'}" for f in FAILLOCK_FLAGS]
    ev += [f"{FAILLOCK_CONF}: {k} = {v}" for k, v in vals.items()]
    problems = []
    if not any("authfail" in x for x in fl):
        problems.append("pam_faillock authfail not in common-auth")
    problems += [f"{f} missing" for f in FAILLOCK_FLAGS if not _faillock_flag(conf, f)]
    deny, interval = _int(vals["deny"]), _int(vals["fail_interval"])
    if deny is None or not 0 < deny <= 3:
        problems.append(f"deny = {vals['deny']}")
    if interval is None or not 0 < interval <= 900:
        problems.append(f"fail_interval = {vals['fail_interval']}")
    if vals["unlock_time"] != "0":
        problems.append(f"unlock_time = {vals['unlock_time']}")
    if problems:
        return CheckResult("fail", "; ".join(problems), "\n".join(ev))
    note = "" if vals["dir"] and not vals["dir"].startswith(("/run", "/var/run")) else \
        "\nnote: tally dir is on tmpfs — a reboot unlocks every account"
    return CheckResult("pass", "", "\n".join(ev) + note)


def add_faillock(text: str) -> str:
    """Insert preauth / authfail / authsucc into a Debian-style common-auth."""
    mods = pamstack.modules(text, "auth")
    if any(m.module == "pam_faillock.so" for m in mods):
        return text
    deny = next((i for i, m in enumerate(mods) if m.module == "pam_deny.so"), None)
    if deny is None or not mods:
        raise RuntimeError(f"{COMMON_AUTH} has no pam_deny.so — not a pam-auth-update layout; configure faillock by hand")
    return pamstack.insert(text, "auth", [
        (0, "auth\trequisite\t\t\tpam_faillock.so preauth"),
        (deny, "auth\t[default=die]\t\t\tpam_faillock.so authfail"),
        (deny, "auth\t[success=1 default=die]\tpam_faillock.so authsucc"),
    ], retarget_success={deny + 1: 2})


def _set_faillock_conf(text: str) -> str:
    lines = text.splitlines()
    for flag in FAILLOCK_FLAGS:
        if not _faillock_flag(text, flag):
            idx = next((i for i, l in enumerate(lines) if re.match(rf"^\s*#\s*{flag}\s*$", l)), None)
            if idx is None:
                lines.append(flag)
            else:
                lines[idx] = flag
    return "\n".join(lines) + "\n"


def _fix_faillock() -> list[RollbackEntry]:
    os.makedirs(FAILLOCK_DIR, mode=0o755, exist_ok=True)
    out = keyval.edit_file(FAILLOCK_CONF, _set_faillock_conf, f"enabled audit/silent in {FAILLOCK_CONF}") \
        if FAILLOCK_CONF.exists() else keyval.write_file(FAILLOCK_CONF, "audit\nsilent\n")
    for k, v in FAILLOCK_OPTS.items():
        out += keyval.set_value(FAILLOCK_CONF, k, v, fmt=f"{k} = {v}")
    return out + keyval.edit_file(COMMON_AUTH, add_faillock, f"added pam_faillock to {COMMON_AUTH}")


register(B, Control("V-270690", _check_faillock, _fix_faillock,
                    impact="3 failed password logins in 15 min lock an account until an admin runs "
                           "`faillock --user NAME --reset` (root is exempt; SSH keys are unaffected)"))


# ---- V-270706 — 4 s delay after a failed logon ----

def _faildelay() -> tuple[str, int | None]:
    for m in (pamstack.modules(COMMON_AUTH.read_text(), "auth") if COMMON_AUTH.exists() else []):
        if m.module == "pam_faildelay.so":
            d = re.search(r"\bdelay=(\d+)", m.args)
            return f"auth {m.control} pam_faildelay.so {m.args}", int(d.group(1)) if d else None
    return "", None


def _check_faildelay() -> CheckResult:
    line, delay = _faildelay()
    ev = f"{COMMON_AUTH}: {line or 'no pam_faildelay.so'}"
    if delay is None or delay < 4000000:
        return CheckResult("fail", f"delay={delay}" if line else "pam_faildelay not in common-auth", ev)
    return CheckResult("pass", "", ev)


def _set_faildelay(text: str) -> str:
    if any(m.module == "pam_faildelay.so" for m in pamstack.modules(text, "auth")):
        return re.sub(r"(pam_faildelay\.so.*?)\bdelay=\d+", r"\g<1>delay=4000000", text)
    return pamstack.insert(text, "auth", [(0, "auth\trequired\t\t\tpam_faildelay.so delay=4000000")])


register(B, Control("V-270706", _check_faildelay,
                    lambda: keyval.edit_file(COMMON_AUTH, _set_faildelay, f"pam_faildelay delay=4000000 in {COMMON_AUTH}")))


# ---- V-270734 — cached (offline) credentials expire after 1 day ----

SSSD_CONFD = Path("/etc/sssd/conf.d")


def _smartcard_in_use() -> bool:
    if _pkcs11_in_auth():
        return True
    if SSSD_CONF.exists():
        return (ini.get(SSSD_CONF.read_text(), "pam", "pam_cert_auth") or "").lower() == "true"
    return False


def _check_offline_creds() -> CheckResult:
    if not _smartcard_in_use():
        return CheckResult("na", "smart card authentication not in use")
    files = [SSSD_CONF] + (sorted(f for f in SSSD_CONFD.glob("*.conf") if not f.name.startswith(".")) if SSSD_CONFD.is_dir() else [])
    vals = [(str(f), ini.get(f.read_text(), "pam", "offline_credentials_expiration")) for f in files if f.exists()]
    set_ = [(f, v) for f, v in vals if v is not None]
    ev = "\n".join(f"{f}: [pam] offline_credentials_expiration = {v}" for f, v in set_) or "offline_credentials_expiration not set"
    if not set_:
        return CheckResult("fail", "offline_credentials_expiration not set", ev)
    if any(v != "1" for _, v in set_):
        return CheckResult("fail", "offline_credentials_expiration is not 1 (or conflicting)", ev)
    return CheckResult("pass", "", ev)


def _fix_offline_creds() -> list[RollbackEntry]:
    out = keyval.edit_file(SSSD_CONF, lambda t: ini.set_ini(t, "pam", "offline_credentials_expiration", "1"),
                           f"[pam] offline_credentials_expiration = 1 in {SSSD_CONF}")
    systemd.run("restart", "sssd.service")
    return out + [RollbackEntry(action="restarted sssd", undo=[["systemctl", "restart", "sssd.service"]])]


register(B, Control("V-270734", _check_offline_creds, _fix_offline_creds))
