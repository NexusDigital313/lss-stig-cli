"""Ubuntu 24.04 STIG — time synchronization (chrony) and UTC timestamps.

CAT III, but load-bearing: audit records are only evidence if their
timestamps can be trusted and correlated across hosts.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss_stig.lib import keyval, pkg, site, systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"

CHRONY_CONF = Path("/etc/chrony/chrony.conf")
CHRONY_CONFD = Path("/etc/chrony/conf.d")
CHRONY_SOURCES = Path("/etc/chrony/sources.d")
OUR_SOURCE = CHRONY_CONFD / "lss-stig-time-source.conf"


def _dpkg_state(name: str) -> str:
    r = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Abbrev}", name], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


# ---- Packages: chrony in, the others out -----------------------------------
# `dpkg -l | grep systemd-timesyncd` — DISA's check — still lists a package
# that was removed but whose config files remain ("rc"). Installing chrony
# removes timesyncd exactly that way, which is why DISA's fix says "purge".
# So config-file remnants count as present here too.

def _absent_rule(vuln_id: str, names: list[str]) -> None:
    def check() -> CheckResult:
        states = {n: _dpkg_state(n) for n in names}
        ev = "\n".join(f"dpkg -l {n}: {s or 'not known to dpkg'}" for n, s in states.items())
        present = [n for n, s in states.items() if s.startswith("ii") or s.startswith("rc") or s.startswith("i")]
        if present:
            kinds = ", ".join(f"{n} ({'config files remain' if states[n].startswith('rc') else 'installed'})"
                              for n in present)
            return CheckResult("fail", kinds, ev)
        return CheckResult("pass", "", ev)

    def fix() -> list[RollbackEntry]:
        out: list[RollbackEntry] = []
        was_installed = [n for n in names if pkg.is_installed(n)]
        # Replace, never just remove: a host with no time daemon drifts.
        out += pkg.install("chrony")
        remnants = [n for n in names if _dpkg_state(n)[:2] in ("ii", "rc")]
        if remnants:
            r = subprocess.run(["apt-get", "-o", "DPkg::Lock::Timeout=600", "purge", "-y", *remnants],
                               capture_output=True, text=True, env=pkg._build_env())
            if r.returncode != 0:
                raise RuntimeError(f"apt-get purge {' '.join(remnants)}: {(r.stderr or r.stdout).strip()[-300:]}")
        if was_installed:
            out.append(RollbackEntry(action=f"purged {' '.join(was_installed)}",
                                     undo=[["apt-get", "install", "-y", *was_installed]]))
        return out

    register(B, Control(vuln_id, check, fix,
                        impact="replaces the time daemon with chrony (the rules below point it at your time source)"))


_absent_rule("V-270645", ["systemd-timesyncd"])
_absent_rule("V-270646", ["ntp", "ntpsec"])


def _check_chrony() -> CheckResult:
    ok = pkg.is_installed("chrony")
    return CheckResult("pass" if ok else "fail", "" if ok else "chrony not installed",
                       f"dpkg-query chrony: {'installed' if ok else 'not installed'}")


register(B, Control("V-270664", _check_chrony, lambda: pkg.install("chrony")))


# ---- chrony sources (V-270751) ---------------------------------------------

def _chrony_files() -> list[Path]:
    files = [CHRONY_CONF] if CHRONY_CONF.exists() else []
    for d, pat in ((CHRONY_CONFD, "*.conf"), (CHRONY_SOURCES, "*.sources")):
        if d.is_dir():
            files += sorted(d.glob(pat))
    return files


_SOURCE = re.compile(r"^\s*(server|pool|peer)\s+(\S+)(.*)$")


def sources() -> list[tuple[str, int, str, str, str]]:
    """(file, lineno, kind, host, options) for active source lines."""
    out = []
    for f in _chrony_files():
        for n, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
            m = _SOURCE.match(line)
            if m and not line.lstrip().startswith("#"):
                out.append((str(f), n, m.group(1), m.group(2), m.group(3).strip()))
    return out


def _maxpoll(opts: str) -> int | None:
    m = re.search(r"\bmaxpoll\s+(-?\d+)", opts)
    return int(m.group(1)) if m else None


def _networked() -> bool:
    try:
        return any(l.split()[1] == "00000000" for l in Path("/proc/net/route").read_text().splitlines()[1:])
    except (OSError, IndexError):
        return True


def _check_sources() -> CheckResult:
    if not _networked():
        return CheckResult("na", "system is not networked (no default route)")
    if not pkg.is_installed("chrony"):
        return CheckResult("fail", "chrony not installed (see V-270664)")
    src = sources()
    want = site.get("time_server")
    ev = "\n".join(f"{f}:{n}: {k} {h} {o}".rstrip() for f, n, k, h, o in src) or "no active chrony sources"
    ev += f"\nsite time_server: {want or '(not set)'}"
    if not want:
        return CheckResult("manual", site.missing("time_server"), ev)
    ours = [s for s in src if s[2] == "server" and s[3] == want]
    others = [s for s in src if s[3] != want]
    if not ours:
        return CheckResult("fail", f"no `server {want}` line", ev)
    if any(_maxpoll(s[4]) is None or _maxpoll(s[4]) > 16 for s in ours):
        return CheckResult("fail", f"server {want} lacks maxpoll ≤ 16", ev)
    if others:
        return CheckResult("fail", "non-authoritative sources still active: " + ", ".join(sorted({s[3] for s in others})), ev)
    return CheckResult("pass", "", ev)


def _fix_sources() -> list[RollbackEntry]:
    want = site.get("time_server")
    if not want:
        raise RuntimeError(site.missing("time_server"))
    out: list[RollbackEntry] = []
    for f in {s[0] for s in sources() if s[3] != want or s[2] != "server"}:
        out += keyval.edit_file(f, lambda t: "\n".join(
            f"# {l}  # lss-stig: replaced by {OUR_SOURCE.name}" if _SOURCE.match(l) and not l.lstrip().startswith("#")
            and _SOURCE.match(l).group(2) != want else l for l in t.splitlines()) + "\n",
            f"commented non-authoritative sources in {f}")
    out += keyval.write_file(OUR_SOURCE, f"# lss-stig: authoritative time source (V-270751)\nserver {want} iburst maxpoll 16\n")
    return out + _restart_chrony()


def _restart_chrony() -> list[RollbackEntry]:
    systemd.run("restart", "chrony.service")
    return [RollbackEntry(action="restarted chrony", undo=[["systemctl", "restart", "chrony.service"]])]


register(B, Control("V-270751", _check_sources, _fix_sources,
                    impact="chrony uses only the site time_server; public NTP pools are commented out"))


# ---- makestep 1 -1 (V-270752) ----------------------------------------------
# Ubuntu ships `makestep 1 3` (step only in the first 3 updates); the STIG
# wants any >1 s offset stepped at any time.

def _check_makestep() -> CheckResult:
    if not pkg.is_installed("chrony"):
        return CheckResult("fail", "chrony not installed (see V-270664)")
    v = keyval.get(CHRONY_CONF, "makestep", " ")
    ev = keyval.evidence(CHRONY_CONF, "makestep", " ")
    if v is None or v.split() != ["1", "-1"]:
        return CheckResult("fail", f"makestep {v}" if v else "makestep not set", ev)
    return CheckResult("pass", "", ev)


def _fix_makestep() -> list[RollbackEntry]:
    if not pkg.is_installed("chrony"):
        raise RuntimeError("chrony not installed — fix V-270664 first")
    return keyval.set_value(CHRONY_CONF, "makestep", "1 -1", " ") + _restart_chrony()


register(B, Control("V-270752", _check_makestep, _fix_makestep))


# ---- UTC (V-270820) ----------------------------------------------------------

def _timezone() -> str:
    try:
        r = subprocess.run(["timedatectl", "show", "-p", "Timezone", "--value"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    lt = Path("/etc/localtime")
    if lt.is_symlink():
        return str(lt.readlink()).split("zoneinfo/", 1)[-1]
    return Path("/etc/timezone").read_text().strip() if Path("/etc/timezone").exists() else "unknown"


def _check_utc() -> CheckResult:
    tz = _timezone()
    ev = f"Time zone: {tz}"
    if tz in ("UTC", "Etc/UTC", "GMT", "Etc/GMT", "Etc/Universal", "Universal", "Zulu", "Etc/Zulu"):
        return CheckResult("pass", "", ev)
    return CheckResult("fail", f"time zone is {tz}", ev)


def _fix_utc() -> list[RollbackEntry]:
    old = _timezone()
    systemd_ok = subprocess.run(["timedatectl", "set-timezone", "UTC"], capture_output=True).returncode == 0
    if not systemd_ok:
        subprocess.run(["ln", "-sf", "/usr/share/zoneinfo/Etc/UTC", "/etc/localtime"], check=True)
    return [RollbackEntry(action=f"time zone {old} → UTC", undo=[["timedatectl", "set-timezone", old]])]


register(B, Control("V-270820", _check_utc, _fix_utc,
                    impact="clock shows UTC — cron jobs keep their wall-clock times, so they now run at UTC hours"))
