"""Ubuntu 24.04 STIG — audit subsystem (auditd, rules, audit file protection)."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path

from lss_stig.lib import auditrules, journal, keyval, perms, pkg, site, systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"


# ---- V-270656 — auditd installed ----

def _check_auditd_pkg() -> CheckResult:
    ok = pkg.is_installed("auditd")
    return CheckResult("pass" if ok else "fail", "" if ok else "auditd not installed",
                       f"dpkg-query auditd: {'installed' if ok else 'not installed'}")


register(B, Control("V-270656", _check_auditd_pkg, lambda: pkg.install("auditd")))


# ---- V-270657 — auditd enabled and running ----

def _check_auditd_svc() -> CheckResult:
    if not pkg.is_installed("auditd"):
        return CheckResult("fail", "auditd not installed (see V-270656)")
    en, act = systemd.is_enabled("auditd.service"), systemd.is_active("auditd.service")
    ev = f"is-enabled auditd: {en}\nis-active auditd: {act}"
    if en == "enabled" and act == "active":
        return CheckResult("pass", "", ev)
    return CheckResult("fail", f"auditd {en}/{act}", ev)


def _fix_auditd_svc() -> list[RollbackEntry]:
    undo = []
    if systemd.is_enabled("auditd.service") != "enabled":
        undo.append(["systemctl", "disable", "auditd.service"])
    if systemd.is_active("auditd.service") != "active":
        undo.append(["systemctl", "stop", "auditd.service"])
    systemd.run("enable", "--now", "auditd.service")
    return [RollbackEntry(action="enabled and started auditd", undo=undo)] if undo else []


register(B, Control("V-270657", _check_auditd_svc, _fix_auditd_svc))


# ---- Audit rules. Rule text is DISA's, verbatim. ----

_PRIV = "-F perm=x -F auid>=1000 -F auid!=-1 -k"
RULES: dict[str, list[str]] = {
    "V-270684": ["-w /etc/passwd -p wa -k usergroup_modification"],
    "V-270685": ["-w /etc/group -p wa -k usergroup_modification"],
    "V-270686": ["-w /etc/shadow -p wa -k usergroup_modification"],
    "V-270687": ["-w /etc/gshadow -p wa -k usergroup_modification"],
    "V-270688": ["-w /etc/security/opasswd -p wa -k usergroup_modification"],
    "V-270689": [
        "-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
        "-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
        "-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -F key=execpriv",
        "-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -F key=execpriv",
    ],
    "V-270715": ["-w /var/log/journal -p wa -k systemd_journal"],
    "V-270740": ["-w /var/log/sudo.log -p wa -k maintenance"],
    "V-270778": [f"-a always,exit -F path=/bin/su {_PRIV} privileged-priv_change"],
    "V-270779": [f"-a always,exit -F path=/usr/bin/chfn {_PRIV} privileged-chfn"],
    "V-270780": [f"-a always,exit -F path=/usr/bin/mount {_PRIV} privileged-mount"],
    "V-270781": [f"-a always,exit -F path=/usr/bin/umount {_PRIV} privileged-umount"],
    "V-270782": [f"-a always,exit -F path=/usr/bin/ssh-agent {_PRIV} privileged-ssh"],
    "V-270783": [f"-a always,exit -F path=/usr/lib/openssh/ssh-keysign {_PRIV} privileged-ssh"],
    "V-270784": [
        f"-a always,exit -F arch={a} -S setxattr,fsetxattr,lsetxattr,removexattr,fremovexattr,lremovexattr {f} -k perm_mod"
        for a in ("b32", "b64") for f in ("-F auid>=1000 -F auid!=-1", "-F auid=0")
    ],
    "V-270785": [f"-a always,exit -F arch={a} -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_chng"
                 for a in ("b32", "b64")],
    "V-270786": [f"-a always,exit -F arch={a} -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -k perm_chng"
                 for a in ("b32", "b64")],
    "V-270787": [
        f"-a always,exit -F arch={a} -S creat,open,openat,open_by_handle_at,truncate,ftruncate -F exit={e} -F auid>=1000 -F auid!=-1 -k perm_access"
        for a in ("b32", "b64") for e in ("-EPERM", "-EACCES")
    ],
    "V-270788": [f"-a always,exit -F path=/usr/bin/sudo {_PRIV} priv_cmd"],
    "V-270789": [f"-a always,exit -F path=/usr/bin/sudoedit {_PRIV} priv_cmd"],
    "V-270790": [f"-a always,exit -F path=/usr/bin/chsh {_PRIV} priv_cmd"],
    "V-270791": [f"-a always,exit -F path=/usr/bin/newgrp {_PRIV} priv_cmd"],
    "V-270792": [f"-a always,exit -F path=/usr/bin/chcon {_PRIV} perm_chng"],
    "V-270793": [f"-a always,exit -F path=/sbin/apparmor_parser {_PRIV} perm_chng"],
    "V-270794": [f"-a always,exit -F path=/usr/bin/setfacl {_PRIV} perm_chng"],
    "V-270795": [f"-a always,exit -F path=/usr/bin/chacl {_PRIV} perm_chng"],
    "V-270796": ["-w /var/log/faillog -p wa -k logins"],
    "V-270797": ["-w /var/log/lastlog -p wa -k logins"],
    "V-270798": [f"-a always,exit -F path=/usr/bin/passwd {_PRIV} privileged-passwd"],
    "V-270799": [f"-a always,exit -F path=/sbin/unix_update {_PRIV} privileged-unix-update"],
    "V-270800": [f"-a always,exit -F path=/usr/bin/gpasswd {_PRIV} privileged-gpasswd"],
    "V-270801": [f"-a always,exit -F path=/usr/bin/chage {_PRIV} privileged-chage"],
    "V-270802": [f"-a always,exit -F path=/usr/sbin/usermod {_PRIV} privileged-usermod"],
    "V-270803": [f"-a always,exit -F path=/usr/bin/crontab {_PRIV} privileged-crontab"],
    "V-270804": [f"-a always,exit -F path=/usr/sbin/pam_timestamp_check {_PRIV} privileged-pam_timestamp_check"],
    "V-270805": [f"-a always,exit -F arch={a} -S init_module,finit_module -F auid>=1000 -F auid!=-1 -k module_chng"
                 for a in ("b32", "b64")],
    "V-270806": [f"-a always,exit -F arch={a} -S delete_module -F auid>=1000 -F auid!=-1 -k module_chng"
                 for a in ("b32", "b64")],
    "V-270807": ["-w /etc/sudoers -p wa -k privilege_modification"],
    "V-270808": ["-w /etc/sudoers.d -p wa -k privilege_modification"],
    "V-270809": [f"-a always,exit -F arch={a} -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k delete"
                 for a in ("b64", "b32")],
    "V-270810": ["-w /var/log/wtmp -p wa -k logins"],
    "V-270811": ["-w /var/run/utmp -p wa -k logins"],
    "V-270812": ["-w /var/log/btmp -p wa -k logins"],
    "V-270813": ["-w /sbin/modprobe -p x -k modules"],
    "V-270814": ["-w /bin/kmod -p x -k modules"],
    "V-270815": ["-w /usr/sbin/fdisk -p x -k fdisk"],
    "V-274870": ["-w /etc/cron.d/ -p wa -k cronjobs", "-w /var/spool/cron/ -p wa -k cronjobs"],
}


def _rule_control(vuln_id: str, rules: list[str]) -> None:
    register(B, Control(vuln_id, lambda: auditrules.check(rules), lambda: auditrules.ensure(rules)))


for _vid, _rules in RULES.items():
    _rule_control(_vid, _rules)


# ---- V-270832 — audit rules immutable (-e 2) ----
# Written and compiled into audit.rules but NOT loaded: loading -e 2 mid-run
# would lock out every audit rule harden adds after it. It takes effect at
# the next boot, which is when an immutable rule set is meant to start.

FINALIZE = auditrules.RULES_D / "99-lss-stig-finalize.rules"


def _check_immutable() -> CheckResult:
    if not pkg.is_installed("auditd"):
        return CheckResult("fail", "auditd not installed (see V-270656)")
    lines = auditrules.AUDIT_RULES.read_text().splitlines() if auditrules.AUDIT_RULES.exists() else []
    real = [l.strip() for l in lines if l.strip() and not l.strip().startswith("#")]
    ev = f"{auditrules.AUDIT_RULES} last rule: {real[-1] if real else '(empty)'}\nlive: {'immutable' if auditrules.immutable() else 'mutable'}"
    if real and real[-1] == "-e 2":
        return CheckResult("pass", "", ev)
    if any(l == "-e 2" for l in real):
        return CheckResult("fail", "-e 2 present but not the final rule", ev)
    return CheckResult("fail", "-e 2 not set", ev)


def _fix_immutable() -> list[RollbackEntry]:
    if not pkg.is_installed("auditd"):
        raise RuntimeError("auditd not installed — fix V-270656 first")
    bkp_rules = journal.backup_file(str(auditrules.AUDIT_RULES))
    out = keyval.write_file(FINALIZE, "-e 2\n", 0o640)
    r = subprocess.run(["augenrules"], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"augenrules: {(r.stderr or r.stdout).strip()}")
    out.append(RollbackEntry(action=f"regenerated {auditrules.AUDIT_RULES}",
                             path=str(auditrules.AUDIT_RULES), backup=bkp_rules))
    return out


register(B, Control("V-270832", _check_immutable, _fix_immutable,
                    impact="audit rules become immutable from next boot — changing them afterwards needs a reboot"))


# ---- V-270676 — audit=1 on the kernel command line ----

DEFAULT_GRUB = Path("/etc/default/grub")
GRUB_CFG = Path("/boot/grub/grub.cfg")


def _grub_var(text: str, var: str) -> str | None:
    val = None
    for line in text.splitlines():
        m = re.match(rf'^\s*{var}=(["\']?)(.*)\1\s*$', line)
        if m:
            val = m.group(2)
    return val


def _check_audit_boot() -> CheckResult:
    if not DEFAULT_GRUB.exists():
        return CheckResult("manual", f"{DEFAULT_GRUB} not found — verify audit=1 in the boot loader by hand")
    text = DEFAULT_GRUB.read_text()
    lin, dflt = _grub_var(text, "GRUB_CMDLINE_LINUX"), _grub_var(text, "GRUB_CMDLINE_LINUX_DEFAULT")
    cfg_lines = ([l.strip() for l in GRUB_CFG.read_text(errors="replace").splitlines() if l.strip().startswith("linux")]
                 if GRUB_CFG.exists() else [])
    cmdline = Path("/proc/cmdline").read_text().strip() if Path("/proc/cmdline").exists() else ""
    ev = "\n".join([f'GRUB_CMDLINE_LINUX="{lin}"', f'GRUB_CMDLINE_LINUX_DEFAULT="{dflt}"',
                    f"grub.cfg linux lines without audit=1: {sum('audit=1' not in l.split() for l in cfg_lines)}/{len(cfg_lines)}",
                    f"running kernel: {'audit=1' if 'audit=1' in cmdline.split() else 'no audit=1'}"])
    missing = [n for n, v in (("GRUB_CMDLINE_LINUX", lin), ("GRUB_CMDLINE_LINUX_DEFAULT", dflt))
               if "audit=1" not in (v or "").split()]
    if missing:
        return CheckResult("fail", "audit=1 missing from " + ", ".join(missing), ev)
    if not cfg_lines or any("audit=1" not in l.split() for l in cfg_lines):
        return CheckResult("fail", "grub.cfg not regenerated (update-grub)", ev)
    return CheckResult("pass", "", ev)


def _add_audit(text: str) -> str:
    out = []
    for line in text.splitlines():
        m = re.match(r'^(\s*GRUB_CMDLINE_LINUX(?:_DEFAULT)?=)(["\']?)(.*)\2\s*$', line)
        if m and "audit=1" not in m.group(3).split():
            q = m.group(2) or '"'
            line = f"{m.group(1)}{q}{(m.group(3) + ' audit=1').strip()}{q}"
        out.append(line)
    for var in ("GRUB_CMDLINE_LINUX", "GRUB_CMDLINE_LINUX_DEFAULT"):
        if _grub_var("\n".join(out), var) is None:
            out.append(f'{var}="audit=1"')
    return "\n".join(out) + "\n"


def _fix_audit_boot() -> list[RollbackEntry]:
    out = keyval.edit_file(DEFAULT_GRUB, _add_audit, f"added audit=1 to {DEFAULT_GRUB}")
    bkp = journal.backup_file(str(GRUB_CFG))
    r = subprocess.run(["update-grub"], capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise RuntimeError(f"update-grub: {r.stderr.strip()}")
    out.append(RollbackEntry(action="update-grub", path=str(GRUB_CFG), backup=bkp))
    return out


register(B, Control("V-270676", _check_audit_boot, _fix_audit_boot))


# ---- Audit configuration files: 0640, root:root (V-270775/776/777) ----

def _audit_conf_files():
    items = []
    for p in [Path("/etc/audit/audit.rules"), Path("/etc/audit/auditd.conf")] + \
            (sorted(Path("/etc/audit/rules.d").glob("*")) if Path("/etc/audit/rules.d").is_dir() else []):
        if p.is_file():
            items.append((str(p), p.lstat()))
    return items


def _file_rule(vuln_id, items_fn, bad_fn, fix_fn, what: str, na_when_empty: str) -> None:
    def check() -> CheckResult:
        items = items_fn()
        if not items:
            return CheckResult("na", na_when_empty)
        bad = [i for i in items if bad_fn(i[1])]
        if bad:
            return CheckResult("fail", f"{len(bad)} {what}", perms.evidence(bad))
        return CheckResult("pass", "", perms.evidence(items))

    def fix() -> list[RollbackEntry]:
        return fix_fn([i for i in items_fn() if bad_fn(i[1])])

    register(B, Control(vuln_id, check, fix))


_file_rule("V-270775", _audit_conf_files, lambda st: perms.mode(st) & 0o137,
           lambda b: perms.chmod_remove(b, 0o137, "audit config ≤0640"), "file(s) more permissive than 0640",
           "no audit configuration files (auditd not installed)")
_file_rule("V-270776", _audit_conf_files, lambda st: st.st_uid != 0,
           lambda b: perms.chown_to(b, uid=0, label="audit config"), "file(s) not owned by root",
           "no audit configuration files (auditd not installed)")
_file_rule("V-270777", _audit_conf_files, lambda st: st.st_gid != 0,
           lambda b: perms.chown_to(b, gid=0, label="audit config"), "file(s) not group-owned by root",
           "no audit configuration files (auditd not installed)")


# ---- Audit logs (V-270827/828/829/830) ----

AUDITD_CONF = Path("/etc/audit/auditd.conf")


def _log_dir() -> Path:
    f = keyval.get(AUDITD_CONF, "log_file") or "/var/log/audit/audit.log"
    return Path(f).parent


def _audit_logs():
    d = _log_dir()
    return [(str(p), p.lstat()) for p in sorted(d.glob("*")) if p.is_file()] if d.is_dir() else []


_file_rule("V-270827", _audit_logs, lambda st: perms.mode(st) & 0o177,
           lambda b: perms.chmod_remove(b, 0o177, "audit log ≤0600"), "audit log(s) more permissive than 0600",
           "no audit log files")
_file_rule("V-270828", _audit_logs, lambda st: st.st_uid != 0,
           lambda b: perms.chown_to(b, uid=0, label="audit log"), "audit log(s) not owned by root", "no audit log files")


def _check_log_group() -> CheckResult:
    items = _audit_logs()
    lg = keyval.get(AUDITD_CONF, "log_group")
    bad = [i for i in items if i[1].st_gid != 0]
    ev = f"{AUDITD_CONF}: log_group = {lg}\n" + perms.evidence(items)
    if not AUDITD_CONF.exists():
        return CheckResult("fail", "auditd not installed (see V-270656)")
    if lg != "root":
        return CheckResult("fail", f"log_group = {lg}", ev)
    if bad:
        return CheckResult("fail", f"{len(bad)} audit log(s) not group-owned by root", ev)
    return CheckResult("pass", "", ev)


def _fix_log_group() -> list[RollbackEntry]:
    out = keyval.set_value(AUDITD_CONF, "log_group", "root", fmt="log_group = root")
    out += perms.chown_to([i for i in _audit_logs() if i[1].st_gid != 0], gid=0, label="audit log")
    subprocess.run(["systemctl", "kill", "-s", "SIGHUP", "auditd"], capture_output=True)
    return out


register(B, Control("V-270829", _check_log_group, _fix_log_group))


def _audit_log_dir():
    d = _log_dir()
    return [(str(d), d.lstat())] if d.is_dir() else []


_file_rule("V-270830", _audit_log_dir, lambda st: perms.mode(st) & 0o027,
           lambda b: perms.chmod_remove(b, 0o027, "audit log dir ≤0750"), "audit log directory more permissive than 0750",
           "no audit log directory")


# ---- Audit tools (V-270821/822/823) ----

AUDIT_TOOLS = ["auditctl", "aureport", "ausearch", "autrace", "auditd", "augenrules"]


def _audit_tools():
    out = []
    for t in AUDIT_TOOLS:
        p = Path("/usr/sbin") / t
        if p.exists():
            out.append((f"/sbin/{t}", p.lstat()))
    return out


def _fix_tools(b, fn):
    # report as /sbin/x (as DISA does) but operate on the real file
    return fn([(p.replace("/sbin/", "/usr/sbin/"), st) for p, st in b])


_file_rule("V-270821", _audit_tools, lambda st: perms.mode(st) & 0o022,
           lambda b: _fix_tools(b, lambda x: perms.chmod_remove(x, 0o022, "audit tool ≤0755")),
           "audit tool(s) more permissive than 0755", "audit tools not installed")
_file_rule("V-270822", _audit_tools, lambda st: st.st_uid != 0,
           lambda b: _fix_tools(b, lambda x: perms.chown_to(x, uid=0, label="audit tool")),
           "audit tool(s) not owned by root", "audit tools not installed")
_file_rule("V-270823", _audit_tools, lambda st: st.st_gid != 0,
           lambda b: _fix_tools(b, lambda x: perms.chown_to(x, gid=0, label="audit tool")),
           "audit tool(s) not group-owned by root", "audit tools not installed")


# ======================================================================
# CAT III — audit storage, offload, alerting
# ======================================================================

AU_REMOTE = Path("/etc/audit/plugins.d/au-remote.conf")
AUDISP_REMOTE = Path("/etc/audit/audisp-remote.conf")
ALERT_SCRIPT = Path("/usr/local/sbin/lss-stig-audit-alert")
SENDMAIL = Path("/usr/sbin/sendmail")


def _hup_auditd() -> list[RollbackEntry]:
    # Ubuntu's auditd.service refuses a manual stop/restart (DISA's fix text
    # says `systemctl restart auditd`); SIGHUP makes auditd re-read its config
    # and plugins without dropping events.
    subprocess.run(["systemctl", "kill", "-s", "SIGHUP", "auditd.service"], capture_output=True)
    return [RollbackEntry(action="reloaded auditd (SIGHUP)",
                          undo=[["systemctl", "kill", "-s", "SIGHUP", "auditd.service"]])]


def _remote_configured() -> tuple[bool, str]:
    active = keyval.get(AU_REMOTE, "active")
    server = keyval.get(AUDISP_REMOTE, "remote_server")
    ev = f"audispd-plugins: {'installed' if pkg.is_installed('audispd-plugins') else 'not installed'}\n" \
         f"{AU_REMOTE}: active = {active}\n{AUDISP_REMOTE}: remote_server = {server}"
    ok = pkg.is_installed("audispd-plugins") and (active or "").lower() == "yes" and bool(server) \
        and not site.is_local(server or "")
    return ok, ev


# ---- V-270658 — audit records offloaded to another system ----

def _check_offload() -> CheckResult:
    if not pkg.is_installed("auditd"):
        return CheckResult("fail", "auditd not installed (see V-270656)")
    ok, ev = _remote_configured()
    want = site.get("audit_remote_server")
    if ok and (not want or keyval.get(AUDISP_REMOTE, "remote_server") == want):
        return CheckResult("pass", "", ev)
    if not want:
        return CheckResult("manual", site.missing("audit_remote_server"), ev)
    return CheckResult("fail", f"audit records not sent to {want}", ev)


def _fix_offload() -> list[RollbackEntry]:
    want = site.get("audit_remote_server")
    if not want:
        raise RuntimeError(site.missing("audit_remote_server"))
    if not pkg.is_installed("auditd"):
        raise RuntimeError("auditd not installed — fix V-270656 first")
    out = pkg.install("audispd-plugins")
    out += keyval.set_value(AU_REMOTE, "active", "yes", fmt="active = yes")
    out += keyval.set_value(AUDISP_REMOTE, "remote_server", want, fmt=f"remote_server = {want}")
    return out + _hup_auditd()


register(B, Control("V-270658", _check_offload, _fix_offload,
                    impact="audit records are also sent to the site audit_remote_server (TCP 60 by default)"))


# ---- V-270816 — a week of audit records fits ----
# A judgement call in the STIG. We measure: the audit log's growth rate over
# the span the current logs cover, projected to 7 days, against free space.

def _audit_growth() -> tuple[int, float]:
    """(bytes in audit logs, seconds of history they cover)."""
    files = [p for p, _ in _audit_logs()]
    total = sum(Path(p).stat().st_size for p in files)
    oldest = None
    for p in files:
        try:
            with open(p, errors="replace") as fh:
                m = re.search(r"msg=audit\((\d+)\.", fh.readline())
            if m:
                oldest = min(oldest or float(m.group(1)), float(m.group(1)))
        except OSError:
            continue
    return total, (time.time() - oldest) if oldest else 0.0


def _check_capacity() -> CheckResult:
    if not pkg.is_installed("auditd"):
        return CheckResult("fail", "auditd not installed (see V-270656)")
    if _remote_configured()[0]:
        return CheckResult("pass", "", "audit records are sent to a remote collector (V-270658)")
    d = _log_dir()
    if not d.exists():
        return CheckResult("fail", f"audit log directory {d} missing")
    st = os.statvfs(d)
    free, size = st.f_bavail * st.f_frsize, st.f_blocks * st.f_frsize
    dedicated = os.path.ismount(d)
    used, span = _audit_growth()
    week = used / span * 7 * 86400 if span > 3600 else None
    gb = lambda b: f"{b / 2**30:.1f} GiB"
    ev = (f"{d}: {'dedicated partition' if dedicated else 'shares its filesystem'}; size {gb(size)}, free {gb(free)}\n"
          f"audit logs: {gb(used)} covering {span / 3600:.1f} h" +
          (f" → ~{gb(week)} per week" if week is not None else " (too little history to project)"))
    if week is not None and week > free:
        return CheckResult("manual", f"a week of audit records (~{gb(week)}) exceeds free space ({gb(free)})", ev)
    if not dedicated:
        return CheckResult("review", f"{d} is not a dedicated partition — confirm capacity is reserved for audit records", ev)
    if week is None:
        return CheckResult("review", "not enough audit history yet to project a week — re-run later", ev)
    return CheckResult("pass", "", ev)


register(B, Control("V-270816", _check_capacity))


# ---- V-270817 — weekly offload script (standalone systems only) ----

def _check_weekly_offload() -> CheckResult:
    try:
        networked = any(l.split()[1] == "00000000" for l in Path("/proc/net/route").read_text().splitlines()[1:])
    except (OSError, IndexError):
        networked = True
    if networked:
        return CheckResult("na", "interconnected system (has a default route)")
    weekly = Path("/etc/cron.weekly")
    hits = [f.name for f in sorted(weekly.iterdir()) if f.is_file() and "audit" in f.read_text(errors="ignore")] \
        if weekly.is_dir() else []
    if hits:
        return CheckResult("review", f"confirm {', '.join(hits)} offloads audit logs to external media",
                           "/etc/cron.weekly: " + ", ".join(hits))
    return CheckResult("manual", "no weekly audit offload script in /etc/cron.weekly", "/etc/cron.weekly: none mention audit")


register(B, Control("V-270817", _check_weekly_offload))


# ---- V-270818 — alert at 75% of audit storage; V-270819 — alert on failure ----

def _alert_script(email: str) -> str:
    return f"""#!/bin/sh
# lss-stig: auditd space_left notifier (V-270818). auditd runs this when audit
# storage crosses space_left; it must reach the SA/ISSO even without an MTA.
msg="auditd on $(hostname): audit record storage has reached the space_left threshold"
logger -p authpriv.alert -t auditd-alert "$msg"
wall "$msg" 2>/dev/null
if [ -x /usr/sbin/sendmail ]; then
    printf 'To: %s\\nSubject: %s\\n\\n%s\\n' '{email}' "$msg" "$msg" | /usr/sbin/sendmail -t
fi
exit 0
"""


def _space_left_ok(v: str | None, d: Path) -> bool:
    if not v:
        return False
    if v.endswith("%"):
        return v[:-1].isdigit() and int(v[:-1]) >= 25
    if not v.isdigit():
        return False
    st = os.statvfs(d) if d.exists() else None
    return st is not None and int(v) >= 0.25 * st.f_blocks * st.f_frsize / 2**20


def _check_space_left() -> CheckResult:
    if not AUDITD_CONF.exists():
        return CheckResult("fail", "auditd not installed (see V-270656)")
    g = lambda k: keyval.get(AUDITD_CONF, k)
    action, space, acct = (g("space_left_action") or ""), g("space_left"), g("action_mail_acct")
    ev = f"{AUDITD_CONF}: space_left = {space}; space_left_action = {action}; action_mail_acct = {acct}\n" \
         f"MTA (/usr/sbin/sendmail): {'present' if SENDMAIL.exists() else 'absent'}"
    problems = []
    kind = action.split()[0].lower() if action else ""
    if kind not in ("email", "exec"):
        problems.append(f"space_left_action = {action or 'unset'}")
    elif kind == "email" and not SENDMAIL.exists():
        problems.append("space_left_action = email but no mail transfer agent is installed — alerts go nowhere")
    elif kind == "exec" and not Path(action.split(None, 1)[1] if " " in action else "").exists():
        problems.append("space_left_action exec script missing")
    if not _space_left_ok(space, _log_dir()):
        problems.append(f"space_left = {space} (needs ≥ 25%)")
    want = site.get("admin_email")
    if kind == "email" and (not acct or acct.split("@")[0] == "root") and not want:
        problems.append("action_mail_acct is root")
    if problems:
        if not want:
            return CheckResult("manual", "; ".join(problems) + " — " + site.missing("admin_email"), ev)
        return CheckResult("fail", "; ".join(problems), ev)
    return CheckResult("pass", "", ev)


def _fix_space_left() -> list[RollbackEntry]:
    want = site.get("admin_email")
    if not want:
        raise RuntimeError(site.missing("admin_email"))
    out = keyval.set_value(AUDITD_CONF, "space_left", "25%", fmt="space_left = 25%")
    if SENDMAIL.exists():
        out += keyval.set_value(AUDITD_CONF, "space_left_action", "email", fmt="space_left_action = email")
    else:
        out += keyval.write_file(ALERT_SCRIPT, _alert_script(want), 0o750)
        out += keyval.set_value(AUDITD_CONF, "space_left_action", f"exec {ALERT_SCRIPT}",
                                fmt=f"space_left_action = exec {ALERT_SCRIPT}")
    out += keyval.set_value(AUDITD_CONF, "action_mail_acct", want, fmt=f"action_mail_acct = {want}")
    return out + _hup_auditd()


register(B, Control("V-270818", _check_space_left, _fix_space_left))


def _check_mail_acct() -> CheckResult:
    if not AUDITD_CONF.exists():
        return CheckResult("fail", "auditd not installed (see V-270656)")
    acct = keyval.get(AUDITD_CONF, "action_mail_acct")
    want = site.get("admin_email")
    ev = keyval.evidence(AUDITD_CONF, "action_mail_acct") + f"\nsite admin_email: {want or '(not set)'}"
    if want and acct == want:
        return CheckResult("pass", "", ev)
    if not want:
        if acct and acct.split("@")[0] != "root":
            return CheckResult("review", f"action_mail_acct = {acct} — confirm it reaches security personnel", ev)
        return CheckResult("manual", site.missing("admin_email"), ev)
    return CheckResult("fail", f"action_mail_acct = {acct or 'unset (root)'}", ev)


def _fix_mail_acct() -> list[RollbackEntry]:
    want = site.get("admin_email")
    if not want:
        raise RuntimeError(site.missing("admin_email"))
    return keyval.set_value(AUDITD_CONF, "action_mail_acct", want, fmt=f"action_mail_acct = {want}") + _hup_auditd()


register(B, Control("V-270819", _check_mail_acct, _fix_mail_acct))
