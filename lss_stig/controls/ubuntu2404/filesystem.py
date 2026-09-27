"""Ubuntu 24.04 STIG — file permissions, logs, kernel parameters, devices.

Fix note: several DISA fix texts are destructive as written —
`find ... -perm /022 -exec chmod 755` strips setuid/setgid, and V-270824's
`chmod -R 755` on /usr/bin would strip setuid from sudo, su and passwd.
Every fix here removes only the offending bits from only the offending
entries, and journals the exact prior mode/owner for rollback.
"""

from __future__ import annotations

import fnmatch
import os
import re
import stat
import subprocess
from pathlib import Path

from lss_stig.lib import keyval, perms, pkg, sysctl, systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"

LIB_ROOTS = ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
CMD_ROOTS = ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"]


def _libs():
    return [(p, st) for p, st in perms.walk(LIB_ROOTS)
            if stat.S_ISREG(st.st_mode) and fnmatch.fnmatch(os.path.basename(p), "*.so*")]


def _lib_dirs():
    return [(p, st) for p, st in perms.walk(LIB_ROOTS) if stat.S_ISDIR(st.st_mode)]


def _cmds():
    return [(p, st) for p, st in perms.walk(CMD_ROOTS) if stat.S_ISREG(st.st_mode)]


def _cmd_dirs():
    return [(p, st) for p, st in perms.walk(CMD_ROOTS) if stat.S_ISDIR(st.st_mode)]


def _scan_rule(vuln_id: str, items_fn, bad_fn, fix_fn, what: str, impact: str | None = None,
               na: str = "nothing to check") -> None:
    def check() -> CheckResult:
        items = items_fn()
        if not items:
            return CheckResult("na", na)
        bad = [i for i in items if bad_fn(i[1])]
        if bad:
            return CheckResult("fail", f"{len(bad)} {what}", perms.evidence(bad))
        return CheckResult("pass", "", f"{len(items)} checked, none {what}")

    def fix() -> list[RollbackEntry]:
        return fix_fn([i for i in items_fn() if bad_fn(i[1])])

    register(B, Control(vuln_id, check, fix, impact=impact))


# ---- Shared libraries ----
_scan_rule("V-270696", _libs, lambda st: perms.mode(st) & 0o022,
           lambda b: perms.chmod_remove(b, 0o022, "library go-w"), "library file(s) group/world-writable")
_scan_rule("V-270697", _libs, lambda st: st.st_uid != 0,
           lambda b: perms.chown_to(b, uid=0, label="library owner"), "library file(s) not owned by root")
_scan_rule("V-270699", _libs, lambda st: st.st_gid != 0,
           lambda b: perms.chown_to(b, gid=0, label="library group"), "library file(s) not group-owned by root")
_scan_rule("V-270698", _lib_dirs, lambda st: st.st_uid != 0,
           lambda b: perms.chown_to(b, uid=0, label="library dir owner"), "library dir(s) not owned by root")
_scan_rule("V-270700", _lib_dirs, lambda st: st.st_gid != 0,
           lambda b: perms.chown_to(b, gid=0, label="library dir group"), "library dir(s) not group-owned by root")

# ---- System commands ----
_scan_rule("V-270701", _cmds, lambda st: perms.mode(st) & 0o022,
           lambda b: perms.chmod_remove(b, 0o022, "command go-w"), "command(s) group/world-writable")
_scan_rule("V-270824", _cmd_dirs, lambda st: perms.mode(st) & 0o022,
           lambda b: perms.chmod_remove(b, 0o022, "command dir go-w"), "command dir(s) group/world-writable")
_scan_rule("V-270825", _cmd_dirs, lambda st: st.st_uid != 0,
           lambda b: perms.chown_to(b, uid=0, label="command dir owner"), "command dir(s) not owned by root")
_scan_rule("V-270826", _cmd_dirs, lambda st: st.st_gid != 0,
           lambda b: perms.chown_to(b, gid=0, label="command dir group"), "command dir(s) not group-owned by root")


# V-270702 / V-270703 — commands owned / group-owned by root or a system account.
# A system account (id < 1000) is legitimate by the rule text — e.g. `wall` is
# setgid tty — but DISA's example filter would still list it, so those come
# back as "review" with the list; ids ≥ 1000 are real findings.
_DISA_GROUPS = {"root", "daemon", "adm", "shadow", "mail", "crontab", "_ssh"}


def _ownership_rule(vuln_id: str, attr: str) -> None:
    is_uid = attr == "st_uid"

    def name(st):
        return perms.user(st.st_uid) if is_uid else perms.group(st.st_gid)

    def items():
        c = _cmds()
        return c if is_uid else [(p, st) for p, st in c if st.st_mode & stat.S_IXUSR]

    def check() -> CheckResult:
        it = items()
        human = [(p, st) for p, st in it if getattr(st, attr) >= 1000]
        system = [(p, st) for p, st in it if 0 < getattr(st, attr) < 1000 and (is_uid or name(st) not in _DISA_GROUPS)]
        if human:
            return CheckResult("fail", f"{len(human)} command(s) {'owned' if is_uid else 'group-owned'} by a non-system account",
                               perms.evidence(human))
        if system:
            return CheckResult("review", f"{len(system)} command(s) use a system {'account' if is_uid else 'group'} "
                               "(e.g. setgid helpers) — confirm each is required", perms.evidence(system))
        return CheckResult("pass", "", f"{len(it)} commands checked")

    def fix() -> list[RollbackEntry]:
        bad = [(p, st) for p, st in items() if getattr(st, attr) >= 1000]
        return perms.chown_to(bad, uid=0 if is_uid else None, gid=None if is_uid else 0, label="command")

    register(B, Control(vuln_id, check, fix))


_ownership_rule("V-270702", "st_uid")
_ownership_rule("V-270703", "st_gid")


# ---- systemd journal (V-270757, V-270761..764) ----
# DISA's tmpfiles drop-in is named zzz-...; systemd-tmpfiles applies the entry
# from the lexically EARLIEST file when paths collide, so systemd's own
# systemd.conf (2755) wins and the setting silently reverts at boot. Ours is
# named 00-... so it actually takes precedence.

JOURNAL_ROOTS = ["/run/log/journal", "/var/log/journal"]
TMPFILES = Path("/etc/tmpfiles.d/00-lss-stig-journal.conf")
TMPFILES_TEXT = """# lss-stig: systemd journal ownership/permissions (UBTU-24-7000xx)
z /run/log/journal 0640 root systemd-journal - -
Z /run/log/journal/%m ~0640 root systemd-journal - -
z /var/log/journal 0640 root systemd-journal - -
z /var/log/journal/%m 0640 root systemd-journal - -
z /var/log/journal/%m/system.journal 0640 root systemd-journal - -
"""


def _journal(kind: str):
    want = stat.S_ISDIR if kind == "d" else stat.S_ISREG
    return [(p, st) for p, st in perms.walk(JOURNAL_ROOTS) if want(st.st_mode)]


def _journal_gid() -> int | None:
    import grp
    try:
        return grp.getgrnam("systemd-journal").gr_gid
    except KeyError:
        return None


def _journal_rule(vuln_id: str, kind: str, bad_fn, fix_fn, what: str, impact: str | None = None) -> None:
    def fix(bad) -> list[RollbackEntry]:
        return keyval.write_file(TMPFILES, TMPFILES_TEXT) + fix_fn(bad)

    _scan_rule(vuln_id, lambda: _journal(kind), bad_fn, fix, what, impact=impact, na="no journal directory")


_journal_rule("V-270757", "d", lambda st: perms.mode(st) & ~0o640,
              lambda b: perms.chmod_remove(b, 0o7137, "journal ≤0640"), "journal dir(s) more permissive than 0640",
              impact="only root can read the persistent journal (systemd-journal/adm group members lose journalctl access)")
_journal_rule("V-270761", "d", lambda st: st.st_gid != _journal_gid(),
              lambda b: perms.chown_to(b, gid=_journal_gid(), label="journal group"), "journal dir(s) not group systemd-journal")
_journal_rule("V-270762", "f", lambda st: st.st_gid != _journal_gid(),
              lambda b: perms.chown_to(b, gid=_journal_gid(), label="journal group"), "journal file(s) not group systemd-journal")
_journal_rule("V-270763", "d", lambda st: st.st_uid != 0,
              lambda b: perms.chown_to(b, uid=0, label="journal owner"), "journal dir(s) not owned by root")
_journal_rule("V-270764", "f", lambda st: st.st_uid != 0,
              lambda b: perms.chown_to(b, uid=0, label="journal owner"), "journal file(s) not owned by root")


# ---- journalctl binary (V-270758/759/760) ----
# A plain chmod is undone by the next systemd package update. dpkg-statoverride
# makes dpkg itself apply 0740 root:root on every upgrade.

JOURNALCTL = "/usr/bin/journalctl"


def _statoverride(owner: str, grp_: str, mode: int) -> list[RollbackEntry]:
    st = os.lstat(JOURNALCTL)
    prev = subprocess.run(["dpkg-statoverride", "--list", JOURNALCTL], capture_output=True, text=True).stdout.split()
    if prev:
        subprocess.run(["dpkg-statoverride", "--remove", JOURNALCTL], capture_output=True)
    r = subprocess.run(["dpkg-statoverride", "--update", "--add", owner, grp_, f"{mode:o}", JOURNALCTL],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"dpkg-statoverride: {r.stderr.strip()}")
    undo = [["dpkg-statoverride", "--remove", JOURNALCTL]]
    if prev:
        undo.append(["dpkg-statoverride", "--add", prev[0], prev[1], prev[2], JOURNALCTL])
    undo += [["chown", f"{st.st_uid}:{st.st_gid}", JOURNALCTL], ["chmod", f"{perms.mode(st):o}", JOURNALCTL]]
    perms.invalidate()
    return [RollbackEntry(action=f"dpkg-statoverride {owner}:{grp_} {mode:o} {JOURNALCTL}", undo=undo)]


def _jctl_rule(vuln_id: str, ok, what: str, target, impact: str | None = None) -> None:
    def check() -> CheckResult:
        if not os.path.exists(JOURNALCTL):
            return CheckResult("na", "journalctl not present")
        st = os.lstat(JOURNALCTL)
        ev = perms.describe(JOURNALCTL, st)
        return CheckResult("pass", "", ev) if ok(st) else CheckResult("fail", what, ev)

    def fix() -> list[RollbackEntry]:
        st = os.lstat(JOURNALCTL)
        owner, grp_, mode = target(st)
        return _statoverride(owner, grp_, mode)

    register(B, Control(vuln_id, check, fix, impact=impact))


_jctl_rule("V-270758", lambda st: perms.mode(st) == 0o740, "journalctl mode is not 0740",
           lambda st: (perms.user(st.st_uid), perms.group(st.st_gid), 0o740),
           impact="non-root users can no longer run journalctl")
_jctl_rule("V-270759", lambda st: st.st_uid == 0, "journalctl not owned by root",
           lambda st: ("root", perms.group(st.st_gid), perms.mode(st)))
_jctl_rule("V-270760", lambda st: st.st_gid == 0, "journalctl not group-owned by root",
           lambda st: (perms.user(st.st_uid), "root", perms.mode(st)))


# ---- /var/log and /var/log/syslog ----

def _single(path: str):
    return lambda: [(path, os.lstat(path))] if os.path.exists(path) else []


def _gid(name: str) -> int | None:
    import grp
    try:
        return grp.getgrnam(name).gr_gid
    except KeyError:
        return None


def _uid(name: str) -> int | None:
    import pwd
    try:
        return pwd.getpwnam(name).pw_uid
    except KeyError:
        return None


_scan_rule("V-270765", _single("/var/log"), lambda st: st.st_gid != _gid("syslog"),
           lambda b: perms.chown_to(b, gid=_gid("syslog"), label="/var/log group"), "/var/log not group syslog")
_scan_rule("V-270766", _single("/var/log"), lambda st: st.st_uid != 0,
           lambda b: perms.chown_to(b, uid=0, label="/var/log owner"), "/var/log not owned by root")


def _check_varlog_mode() -> CheckResult:
    if systemd.is_active("rsyslog.service") == "active" and systemd.is_enabled("rsyslog.service") == "enabled":
        return CheckResult("na", "rsyslog is active and enabled")
    st = os.lstat("/var/log")
    ev = perms.describe("/var/log", st)
    return CheckResult("fail", "/var/log more permissive than 0755", ev) if perms.mode(st) & 0o022 else CheckResult("pass", "", ev)


register(B, Control("V-270767", _check_varlog_mode,
                    lambda: perms.chmod_remove(_single("/var/log")(), 0o022, "/var/log ≤0755")))

_SYSLOG_NA = "/var/log/syslog does not exist (rsyslog not installed — see V-270653)"
_scan_rule("V-270768", _single("/var/log/syslog"), lambda st: st.st_gid != _gid("adm"),
           lambda b: perms.chown_to(b, gid=_gid("adm"), label="syslog group"), "/var/log/syslog not group adm", na=_SYSLOG_NA)
_scan_rule("V-270769", _single("/var/log/syslog"), lambda st: st.st_uid != _uid("syslog"),
           lambda b: perms.chown_to(b, uid=_uid("syslog"), label="syslog owner"), "/var/log/syslog not owned by syslog", na=_SYSLOG_NA)
_scan_rule("V-270770", _single("/var/log/syslog"), lambda st: perms.mode(st) & 0o137,
           lambda b: perms.chmod_remove(b, 0o137, "syslog ≤0640"), "/var/log/syslog more permissive than 0640", na=_SYSLOG_NA)


# V-270756 — log files ≤ 0640 (DISA excludes btmp/wtmp/lastlog/history/eipp.log.xz).
_LOG_EXCLUDE = ("*btmp", "*wtmp", "*lastlog", "history", "eipp.log.xz")


def _log_files():
    return [(p, st) for p, st in perms.walk(["/var/log"]) if stat.S_ISREG(st.st_mode)
            and not any(fnmatch.fnmatch(os.path.basename(p), g) for g in _LOG_EXCLUDE)]


_scan_rule("V-270756", _log_files, lambda st: perms.mode(st) & 0o137,
           lambda b: perms.chmod_remove(b, 0o137, "log ≤0640"), "log file(s) more permissive than 0640")


# ---- V-270750 — sticky bit on world-writable directories ----

_PSEUDO = {"proc", "sysfs", "devpts", "cgroup", "cgroup2", "securityfs", "debugfs", "tracefs", "pstore",
           "bpf", "configfs", "fusectl", "mqueue", "hugetlbfs", "binfmt_misc", "autofs", "efivarfs",
           "rpc_pipefs", "nsfs", "nfs", "nfs4", "cifs", "smb3", "devtmpfs"}


def _public_dirs_without_sticky():
    skip = {m for m, t in perms.mounts().items() if t in _PSEUDO or t.startswith("fuse.")}
    out, stack = [], ["/"]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    if not e.is_dir(follow_symlinks=False) or e.path in skip:
                        continue
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if st.st_mode & 0o002 and not st.st_mode & 0o1000:
                        out.append((e.path, st))
                    stack.append(e.path)
        except OSError:
            continue
    return out


def _check_sticky() -> CheckResult:
    bad = _public_dirs_without_sticky()
    if bad:
        return CheckResult("fail", f"{len(bad)} world-writable dir(s) without sticky bit", perms.evidence(bad))
    return CheckResult("pass", "", "find / -type d -perm -002 ! -perm -1000 → (no output)")


register(B, Control("V-270750", _check_sticky,
                    lambda: perms.chmod_add(_public_dirs_without_sticky(), 0o1000, "sticky bit")))


# ---- V-270718 — USB mass storage disabled ----

MODPROBE_D = Path("/etc/modprobe.d")
USB_CONF = MODPROBE_D / "lss-stig-usb-storage.conf"


def _modprobe_lines() -> list[str]:
    out = []
    if MODPROBE_D.is_dir():
        for f in sorted(MODPROBE_D.glob("*.conf")):
            out += [f"{f}: {l.strip()}" for l in f.read_text(errors="replace").splitlines()
                    if l.strip() and not l.lstrip().startswith("#") and "usb-storage" in l]
    return out


def _check_usb() -> CheckResult:
    lines = _modprobe_lines()
    ev = "\n".join(lines) or "no usb-storage entries in /etc/modprobe.d"
    install = any(re.search(r"install\s+usb-storage\s+/bin/false", l) for l in lines)
    blacklist = any(re.search(r"blacklist\s+usb-storage\b", l) for l in lines)
    missing = [n for n, ok in (("install /bin/false", install), ("blacklist", blacklist)) if not ok]
    if missing:
        return CheckResult("fail", "usb-storage missing: " + ", ".join(missing), ev)
    loaded = "usb_storage" in Path("/proc/modules").read_text() if Path("/proc/modules").exists() else False
    return CheckResult("pass", "", ev + ("\nnote: usb_storage currently loaded — unloads at reboot" if loaded else ""))


register(B, Control("V-270718", _check_usb,
                    lambda: keyval.write_file(USB_CONF, "install usb-storage /bin/false\nblacklist usb-storage\n"),
                    impact="USB mass-storage devices stop working (from next reboot, or once the module unloads)"))


# ---- V-270755 — wireless adapters ----

def _check_wireless() -> CheckResult:
    ifaces = sorted(p.parent.name for p in Path("/sys/class/net").glob("*/wireless"))
    if not ifaces:
        return CheckResult("na", "no wireless interfaces")
    return CheckResult("review", f"wireless interface(s): {', '.join(ifaces)} — disable unless ISSO-approved",
                       "\n".join(ifaces))


register(B, Control("V-270755", _check_wireless))


# ---- V-270747 — data at rest encrypted ----

def _check_crypt() -> CheckResult:
    import json
    try:
        r = subprocess.run(["lsblk", "-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"], capture_output=True, text=True, timeout=30)
        tree = json.loads(r.stdout)["blockdevices"]
    except (FileNotFoundError, ValueError, KeyError, subprocess.TimeoutExpired):
        return CheckResult("manual", "could not read block devices — verify disk encryption by hand")
    plain, enc = [], []

    def walk(nodes, under_crypt=False):
        for n in nodes:
            crypt = under_crypt or n.get("type") == "crypt"
            for mp in [m for m in (n.get("mountpoints") or []) if m]:
                if mp in ("/boot", "/boot/efi") or n.get("fstype") == "swap":
                    continue
                (enc if crypt else plain).append(f"{mp} on /dev/{n['name']}")
            walk(n.get("children") or [], crypt)

    walk(tree)
    ev = "encrypted: " + (", ".join(enc) or "none") + "\nnot encrypted: " + (", ".join(plain) or "none")
    if not plain and enc:
        return CheckResult("pass", "", ev)
    if not plain and not enc:
        return CheckResult("manual", "no persistent block-device filesystems found — verify by hand", ev)
    return CheckResult("manual", f"unencrypted filesystem(s): {', '.join(p.split(' on ')[0] for p in plain)} "
                       "— encrypt or document the mission exception", ev)


register(B, Control("V-270747", _check_crypt))


# ---- V-270771 — NX ----

def _check_nx() -> CheckResult:
    try:
        flags = next((l for l in Path("/proc/cpuinfo").read_text().splitlines() if l.startswith("flags")), "")
    except OSError:
        flags = ""
    if "nx" in flags.split(":", 1)[-1].split():
        return CheckResult("pass", "", "cpu flags include nx")
    return CheckResult("manual", "nx flag missing — enable No-Execute in firmware", "cpu flags lack nx")


register(B, Control("V-270771", _check_nx))


# ---- V-270772 — ASLR = 2, and not overridden in sysctl config ----

def _check_aslr() -> CheckResult:
    key = "kernel.randomize_va_space"
    rt = sysctl.runtime(key)
    bad = [(f, v) for f, v in sysctl.assignments(key) if v != "2"]
    ev = sysctl.evidence(key)
    if rt != "2":
        return CheckResult("fail", f"{key} = {rt}", ev)
    if bad:
        return CheckResult("fail", "overridden in " + ", ".join(f for f, _ in bad), ev)
    return CheckResult("pass", "", ev)


def _fix_aslr() -> list[RollbackEntry]:
    key = "kernel.randomize_va_space"
    out: list[RollbackEntry] = []
    for f in {f for f, v in sysctl.assignments(key) if v != "2"}:
        if f.startswith("/etc/"):
            out += keyval.edit_file(f, lambda t: "\n".join(
                ("# " + l + "  # lss-stig: V-270772") if re.match(rf"^\s*-?{re.escape(key)}\s*=", l) else l
                for l in t.splitlines()) + "\n", f"commented {key} in {f}")
    if sysctl.runtime(key) != "2" or any(v != "2" for _, v in sysctl.assignments(key)):
        out += sysctl.set_value(key, "2")
    return out


register(B, Control("V-270772", _check_aslr, _fix_aslr))


# ---- V-270753 — TCP syncookies ----

def _check_syncookies() -> CheckResult:
    key = "net.ipv4.tcp_syncookies"
    ev = sysctl.evidence(key)
    if sysctl.runtime(key) != "1":
        return CheckResult("fail", f"{key} = {sysctl.runtime(key)}", ev)
    if sysctl.persisted(key) != "1":
        return CheckResult("fail", f"{key} not persisted as 1 (boot value {sysctl.persisted(key)})", ev)
    return CheckResult("pass", "", ev)


register(B, Control("V-270753", _check_syncookies, lambda: sysctl.set_value("net.ipv4.tcp_syncookies", "1")))


# ---- V-270680 — shell sessions time out ----

TMOUT_FILE = Path("/etc/profile.d/99-terminal_tmout.sh")


def _tmout_values() -> list[tuple[str, int]]:
    files = [Path("/etc/bash.bashrc")] + sorted(Path("/etc/profile.d").glob("*"))
    out = []
    for f in files:
        if not f.is_file():
            continue
        for line in f.read_text(errors="replace").splitlines():
            if line.lstrip().startswith("#"):
                continue
            m = re.search(r"\bTMOUT=(\d+)", line)
            if m:
                out.append((str(f), int(m.group(1))))
    return out


def _check_tmout() -> CheckResult:
    vals = _tmout_values()
    ev = "\n".join(f"{f}: TMOUT={v}" for f, v in vals) or "TMOUT not set"
    if not vals:
        return CheckResult("fail", "TMOUT not set", ev)
    if any(v == 0 or v > 600 for _, v in vals):
        return CheckResult("fail", "TMOUT is 0 or above 600", ev)
    return CheckResult("pass", "", ev)


register(B, Control("V-270680", _check_tmout,
                    lambda: keyval.write_file(TMOUT_FILE, "TMOUT=600\nreadonly TMOUT\nexport TMOUT\n"),
                    impact="idle shells (including SSH sessions) exit after 10 minutes"))


# ---- V-270681 — remote access (auth/authpriv/daemon) logged by rsyslog ----

RSYSLOG_DROPIN = Path("/etc/rsyslog.d/40-lss-stig-remote-access.conf")


def _rsyslog_selectors() -> list[str]:
    files = [Path("/etc/rsyslog.conf")] + (sorted(Path("/etc/rsyslog.d").glob("*.conf")) if Path("/etc/rsyslog.d").is_dir() else [])
    out = []
    for f in files:
        if f.is_file():
            out += [f"{f}: {l.strip()}" for l in f.read_text(errors="replace").splitlines()
                    if re.match(r"^(auth|authpriv|daemon)[.,]", l.strip())]
    return out


def _check_remote_logging() -> CheckResult:
    if not pkg.is_installed("rsyslog"):
        return CheckResult("fail", "rsyslog not installed (see V-270653)")
    sels = _rsyslog_selectors()
    ev = "\n".join(sels) or "no auth/authpriv/daemon selectors"
    sel_text = " ".join(s.split(": ", 1)[1].split()[0] for s in sels)
    have_auth = bool(re.search(r"(^|[,;\s])auth(,authpriv)?\.\*", sel_text)) and "authpriv" in sel_text
    have_daemon = "daemon.*" in sel_text
    missing = [n for n, ok in (("auth,authpriv.*", have_auth), ("daemon.*", have_daemon)) if not ok]
    if missing:
        return CheckResult("fail", "not logged: " + ", ".join(missing), ev)
    return CheckResult("pass", "", ev)


def _fix_remote_logging() -> list[RollbackEntry]:
    out = keyval.write_file(RSYSLOG_DROPIN, "auth.*,authpriv.* /var/log/secure\ndaemon.* /var/log/messages\n")
    r = subprocess.run(["systemctl", "restart", "rsyslog.service"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"restart rsyslog: {r.stderr.strip()}")
    for e in out:
        e.undo.append(["systemctl", "restart", "rsyslog.service"])
    return out


register(B, Control("V-270681", _check_remote_logging, _fix_remote_logging))
