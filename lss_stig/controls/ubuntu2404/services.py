"""Ubuntu 24.04 STIG — services: logging, firewall, AppArmor, SSSD, kdump, APT."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss_stig.lib import keyval, pkg, site, sshd, systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"


def _service_rule(vuln_id: str, unit: str, package: str, prereq: str, *,
                  install: bool = False, impact: str | None = None, precheck=None) -> None:
    def check() -> CheckResult:
        if not pkg.is_installed(package):
            return CheckResult("fail", f"{package} not installed" + (f" (see {prereq})" if prereq else ""))
        if precheck and (r := precheck()) is not None:
            return r
        en, act = systemd.is_enabled(unit), systemd.is_active(unit)
        ev = f"is-enabled {unit}: {en}\nis-active {unit}: {act}"
        if en == "enabled" and act == "active":
            return CheckResult("pass", "", ev)
        return CheckResult("fail", f"{unit} {en}/{act}", ev)

    def fix() -> list[RollbackEntry]:
        out = pkg.install(package) if install else []
        if not pkg.is_installed(package):
            raise RuntimeError(f"{package} not installed — fix {prereq} first")
        undo = []
        if systemd.is_enabled(unit) != "enabled":
            undo.append(["systemctl", "disable", unit])
        if systemd.is_active(unit) != "active":
            undo.append(["systemctl", "stop", unit])
        systemd.run("enable", "--now", unit)
        if undo:
            out.append(RollbackEntry(action=f"enabled and started {unit}", undo=undo))
        return out

    register(B, Control(vuln_id, check, fix, impact=impact))


# V-270653 — rsyslog installed, enabled, running.
_service_rule("V-270653", "rsyslog.service", "rsyslog", "", install=True)

# V-270660 — AppArmor enabled and running.
_service_rule("V-270660", "apparmor.service", "apparmor", "V-270659")


# V-270663 — sssd enabled and running. sssd refuses to start without a
# configured domain, so an unconfigured host is the operator's call.
def _sssd_configured() -> CheckResult | None:
    if not Path("/etc/sssd/sssd.conf").exists():
        return CheckResult("manual", "sssd has no /etc/sssd/sssd.conf — configure the PKI/directory domain first")
    return None


_service_rule("V-270663", "sssd.service", "sssd", "V-270662", precheck=_sssd_configured)


# ---- ufw (V-270655 enabled, V-270754 rate limits) ----
#
# `ufw enable` on a remote box with no allow rule for SSH is the textbook
# self-lockout (DISA's own note: "will potentially disrupt ssh sessions").
# We add `limit` rules for every port sshd listens on BEFORE enabling — which
# also satisfies the rate-limit rule for SSH.

def _ufw(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["ufw", *args], capture_output=True, text=True, timeout=60)


def _ufw_active() -> tuple[bool, str]:
    try:
        r = _ufw("status")
    except FileNotFoundError:
        return False, "ufw not installed"
    return r.stdout.splitlines()[0].strip() == "Status: active" if r.stdout else False, r.stdout.strip() or r.stderr.strip()


def _other_firewall() -> str:
    for unit in ("firewalld.service", "nftables.service"):
        if systemd.is_active(unit) == "active":
            return unit
    return ""


def _check_ufw() -> CheckResult:
    other = _other_firewall()
    if not pkg.is_installed("ufw"):
        if other:
            return CheckResult("pass", "", f"ufw not installed; {other} active")
        return CheckResult("fail", "ufw not installed (see V-270654)")
    active, out = _ufw_active()
    if active:
        return CheckResult("pass", "", out)
    if other:
        return CheckResult("pass", "", f"ufw inactive; {other} active\n{out}")
    return CheckResult("fail", "ufw inactive", out)


def _limit_ssh() -> list[RollbackEntry]:
    out = []
    added = _ufw("show", "added").stdout
    mgmt = site.get("ssh_allow_from")
    for port in sshd.ports():
        # `limit` refuses a source after 6 new connections in 30 s — and a
        # retrying client's SYN retransmits keep refreshing that window, so
        # automation (Ansible, monitoring) or admins behind one NAT lock
        # themselves out. A management network is allowed ahead of the limit.
        allow = f"allow proto tcp from {mgmt} to any port {port}"
        if mgmt and f"ufw {allow}" not in added:
            r = _ufw("insert", "1", *allow.split())
            if r.returncode != 0:
                raise RuntimeError(f"ufw {allow}: {r.stderr.strip()}")
            out.append(RollbackEntry(action=f"ufw {allow}", undo=[["ufw", "delete", *allow.split()]]))
        rule = f"limit {port}/tcp"
        if f"ufw {rule}" in added:
            continue
        r = _ufw("limit", f"{port}/tcp")
        if r.returncode != 0:
            raise RuntimeError(f"ufw {rule}: {r.stderr.strip()}")
        out.append(RollbackEntry(action=f"ufw {rule}", undo=[["ufw", "delete", "limit", f"{port}/tcp"]]))
    return out


def _fix_ufw() -> list[RollbackEntry]:
    if not pkg.is_installed("ufw"):
        raise RuntimeError("ufw not installed — fix V-270654 first")
    out = _limit_ssh()
    r = _ufw("--force", "enable")
    if r.returncode != 0:
        raise RuntimeError(f"ufw enable: {r.stderr.strip()}")
    out.append(RollbackEntry(action="ufw enable", undo=[["ufw", "--force", "disable"]]))
    return out


register(B, Control("V-270655", _check_ufw, _fix_ufw,
                    impact="turns the firewall on: only SSH is allowed in, and a source opening more than 5 new SSH "
                           "connections in 30 s is refused — exempt automation with `lss-stig site ssh_allow_from=<cidr>`"))


_LOOPBACK = re.compile(r"^(127\.|\[?::1\]?|\[?::ffff:127\.)")


def listening() -> list[tuple[str, int, str]]:
    """(proto, port, local address) for non-loopback listeners."""
    try:
        r = subprocess.run(["ss", "-Hlnut46"], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return []
    out = set()
    for line in r.stdout.splitlines():
        f = line.split()
        if len(f) < 5:
            continue
        proto, local = f[0], f[4]
        addr, _, port = local.rpartition(":")
        addr = addr.split("%")[0]
        if not port.isdigit() or _LOOPBACK.match(addr):
            continue
        out.add((proto, int(port), addr))
    return sorted(out)


def _ufw_covered() -> dict[tuple[str, int], str]:
    """(proto, port) → LIMIT/DENY/REJECT from `ufw status` (app profiles resolved)."""
    covered: dict[tuple[str, int], str] = {}
    out = _ufw("status").stdout
    for line in out.splitlines():
        m = re.match(r"^(\S+)(?: \(v6\))?\s+(LIMIT|DENY|REJECT)(?: IN)?(?!\s*OUT)\s", line)
        if not m:
            continue
        to, action = m.group(1), m.group(2)
        specs = [to]
        if not re.match(r"^\d", to):  # application profile, e.g. OpenSSH
            info = _ufw("app", "info", to).stdout
            specs = re.findall(r"^\s*(\d+(?::\d+)?(?:,\d+)*(?:/\w+)?)\s*$", info, re.M)
        for spec in specs:
            ports_part, _, proto = spec.partition("/")
            for chunk in ports_part.split(","):
                lo, _, hi = chunk.partition(":")
                for p in range(int(lo), int(hi or lo) + 1):
                    for pr in ([proto] if proto else ["tcp", "udp"]):
                        covered[(pr, p)] = action
    return covered


def _check_rate_limit() -> CheckResult:
    if not pkg.is_installed("ufw"):
        return CheckResult("fail", "ufw not installed (see V-270654)")
    active, status = _ufw_active()
    if not active:
        return CheckResult("fail", "ufw inactive (see V-270655)", status)
    covered = _ufw_covered()
    listen = listening()
    open_ = sorted({(pr, p) for pr, p, _ in listen if (pr, p) not in covered})
    ev = "listening (non-loopback):\n" + "\n".join(f"  {pr} {a}:{p} → {covered.get((pr, p), 'NOT LIMITED')}"
                                                   for pr, p, a in listen) + f"\n{status}"
    if not open_:
        return CheckResult("pass", "", ev)
    ssh_ports = set(sshd.ports())
    names = ", ".join(f"{p}/{pr}" for pr, p in open_)
    if any(pr == "tcp" and p in ssh_ports for pr, p in open_):
        return CheckResult("fail", f"not rate-limited: {names}", ev)
    return CheckResult("manual", f"not rate-limited or denied: {names} — `ufw limit` or `ufw deny` each", ev)


register(B, Control("V-270754", _check_rate_limit, _limit_ssh))


# ---- V-270719 — ports/protocols match the site PPSM CLSA ----

def _check_ppsm() -> CheckResult:
    try:
        st = _ufw("status", "verbose").stdout.strip()
    except FileNotFoundError:
        st = "ufw not installed"
    ev = st + "\n\nlistening (non-loopback):\n" + "\n".join(f"  {pr} {a}:{p}" for pr, p, a in listening())
    return CheckResult("review", "compare firewall rules and listeners with the PPSM CLSA", ev)


register(B, Control("V-270719", _check_ppsm))


# ---- V-270746 — kernel crash dumps off unless documented ----

def _check_kdump() -> CheckResult:
    if not pkg.is_installed("kdump-tools"):
        return CheckResult("pass", "", "kdump-tools not installed")
    en, act = systemd.is_enabled("kdump-tools.service"), systemd.is_active("kdump-tools.service")
    ev = f"kdump-tools.service: {en}/{act}"
    if act != "active" and en in ("masked", "disabled"):
        return CheckResult("pass", "", ev)
    return CheckResult("fail", f"kdump-tools {en}/{act} — disable unless documented with the ISSO", ev)


def _fix_kdump() -> list[RollbackEntry]:
    en, act = systemd.is_enabled("kdump-tools.service"), systemd.is_active("kdump-tools.service")
    systemd.run("disable", "--now", "kdump-tools.service")
    undo = [["systemctl", "enable", "kdump-tools.service"]] if en == "enabled" else []
    if act == "active":
        undo.append(["systemctl", "start", "kdump-tools.service"])
    return [RollbackEntry(action="disabled kdump-tools", undo=undo)]


register(B, Control("V-270746", _check_kdump, _fix_kdump,
                    impact="kernel crash dumps are no longer captured"))


# ---- V-270773 — unattended-upgrades removes superseded packages ----

UU = Path("/etc/apt/apt.conf.d/50unattended-upgrades")
UU_KEYS = ["Unattended-Upgrade::Remove-Unused-Dependencies", "Unattended-Upgrade::Remove-Unused-Kernel-Packages"]


def _uu_value(text: str, key: str) -> str | None:
    val = None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("//"):
            continue
        m = re.match(rf'^{re.escape(key)}\s+"([^"]*)"\s*;', s)
        if m:
            val = m.group(1)
    return val


def _check_uu() -> CheckResult:
    if not UU.exists():
        return CheckResult("fail", f"{UU} not found (unattended-upgrades not installed)")
    text = UU.read_text()
    vals = {k: _uu_value(text, k) for k in UU_KEYS}
    ev = "\n".join(f'{UU}: {k} "{v}"' if v is not None else f"{UU}: {k} not set" for k, v in vals.items())
    bad = [k.split("::")[1] for k, v in vals.items() if (v or "").lower() != "true"]
    if bad:
        return CheckResult("fail", "not true: " + ", ".join(bad), ev)
    return CheckResult("pass", "", ev)


def _set_uu(text: str) -> str:
    lines = text.splitlines()
    for key in UU_KEYS:
        want = f'{key} "true";'
        done = False
        for i, line in enumerate(lines):
            s = line.strip()
            if re.match(rf'^(//\s*)?{re.escape(key)}\s+"', s):
                if not done:
                    lines[i] = want
                    done = True
                elif not s.startswith("//"):
                    lines[i] = "// " + line
        if not done:
            lines.append(want)
    return "\n".join(lines) + "\n"


def _fix_uu() -> list[RollbackEntry]:
    if not UU.exists():
        raise RuntimeError("unattended-upgrades not installed")
    return keyval.edit_file(UU, _set_uu, f"set Remove-Unused-* true in {UU}")


register(B, Control("V-270773", _check_uu, _fix_uu))


# ---- V-270695 (CAT III) — APT never installs unsigned packages ----

APT_CONF_D = Path("/etc/apt/apt.conf.d")
_UNAUTH = re.compile(r'AllowUnauthenticated\s+"?(true|yes|1)"?', re.I)


def _unauth_lines() -> list[tuple[str, int, str]]:
    files = ([Path("/etc/apt/apt.conf")] if Path("/etc/apt/apt.conf").exists() else []) + \
        (sorted(f for f in APT_CONF_D.iterdir() if f.is_file()) if APT_CONF_D.is_dir() else [])
    out = []
    for f in files:
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            if not line.lstrip().startswith(("//", "#")) and _UNAUTH.search(line):
                out.append((str(f), n, line.strip()))
    return out


def _check_apt_signed() -> CheckResult:
    hits = _unauth_lines()
    if hits:
        return CheckResult("fail", f"AllowUnauthenticated enabled in {len(hits)} place(s)",
                           "\n".join(f"{f}:{n}: {l}" for f, n, l in hits))
    return CheckResult("pass", "", "no APT configuration allows unauthenticated packages")


def _fix_apt_signed() -> list[RollbackEntry]:
    out: list[RollbackEntry] = []
    for f in {f for f, _, _ in _unauth_lines()}:
        out += keyval.edit_file(f, lambda t: _UNAUTH.sub(lambda m: m.group(0).replace(m.group(1), "false"), t),
                                f"AllowUnauthenticated false in {f}")
    return out


register(B, Control("V-270695", _check_apt_signed, _fix_apt_signed))
