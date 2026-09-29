"""Ubuntu 24.04 STIG — file integrity (AIDE)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from lss_stig.lib import keyval, pkg, systemd
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"

AIDE_CONF = Path("/etc/aide/aide.conf")
PKG_CONF = Path("/usr/share/aide/config/aide/aide.conf")
AIDE_DB = Path("/var/lib/aide/aide.db")
AIDE_DEFAULT = Path("/etc/default/aide")
AUDIT_TOOL_LINES = [f"/sbin/{t} p+i+n+u+g+s+b+acl+xattrs+sha512"
                    for t in ("auditctl", "auditd", "ausearch", "aureport", "autrace", "augenrules")]


# aide-common (aide.conf, the cron job, /etc/default/aide) is only a
# Recommends of aide, so --no-install-recommends must name it explicitly;
# without it aide has no configuration and V-270650/V-270831 can't be fixed.
AIDE_PKGS = ("aide", "aide-common")


def _need_aide() -> CheckResult | None:
    if not all(pkg.is_installed(p) for p in AIDE_PKGS):
        return CheckResult("fail", "aide not installed (see V-270649)")
    return None


# ---- V-270649 — AIDE installed ----

def _check_installed() -> CheckResult:
    state = {p: pkg.is_installed(p) for p in AIDE_PKGS}
    missing = [p for p, ok in state.items() if not ok]
    ev = "\n".join(f"dpkg-query {p}: {'installed' if ok else 'not installed'}" for p, ok in state.items())
    if not state["aide"]:
        return CheckResult("fail", "aide not installed", ev)
    if missing:
        return CheckResult("fail", "aide-common not installed — aide has no configuration", ev)
    return CheckResult("pass", "", ev)


register(B, Control("V-270649", _check_installed, lambda: pkg.install(*AIDE_PKGS)))


# ---- V-270650 — AIDE baseline initialized ----
# Running a full `aide --check` would make every audit take minutes; the
# baseline database existing + the config parsing cleanly is what makes that
# check succeed.

def _check_initialized() -> CheckResult:
    if (r := _need_aide()) is not None:
        return r
    cfg = subprocess.run(["aide", "--config-check", "-c", str(AIDE_CONF)], capture_output=True, text=True)
    ev = f"aide --config-check: exit {cfg.returncode}\n{AIDE_DB}: {'present' if AIDE_DB.exists() else 'missing'}"
    if cfg.returncode != 0:
        return CheckResult("fail", "aide.conf does not parse", ev + "\n" + (cfg.stderr or cfg.stdout).strip()[-500:])
    if not AIDE_DB.exists():
        return CheckResult("fail", "no AIDE baseline database (aideinit never run)", ev)
    return CheckResult("pass", "", ev)


def _fix_initialized() -> list[RollbackEntry]:
    existed = AIDE_DB.exists()
    r = subprocess.run(["aideinit", "-y", "-f"], capture_output=True, text=True, timeout=7200)
    if r.returncode not in (0, 1):  # aide exits 1 when the new db differs, which is expected
        raise RuntimeError(f"aideinit: {(r.stderr or r.stdout).strip()[-300:]}")
    return [] if existed else [RollbackEntry(action="initialized AIDE database",
                                             undo=[["rm", "-f", str(AIDE_DB), str(AIDE_DB) + ".new"]])]


register(B, Control("V-270650", _check_initialized, _fix_initialized,
                    impact="builds the AIDE baseline — scans the whole filesystem, can take many minutes"))


# ---- V-270651 — default AIDE config + scheduled check present ----
# Conflict inside the STIG: V-270831 requires adding audit-tool lines to
# aide.conf, which makes it differ from the packaged default this rule
# compares against. When that is the only difference, this is "review".

def _check_default() -> CheckResult:
    if not pkg.is_installed("aide"):
        return CheckResult("na", "AIDE not installed")
    timer = systemd.is_enabled("dailyaidecheck.timer")
    cron = any(Path(p).exists() for p in ("/etc/cron.daily/dailyaidecheck", "/etc/cron.daily/aide"))
    ev = [f"dailyaidecheck.timer: {timer or 'n/a'}", f"cron.daily script: {'present' if cron else 'absent'}"]
    if timer != "enabled" and not cron:
        return CheckResult("fail", "no scheduled AIDE check (timer or cron.daily)", "\n".join(ev))
    if not PKG_CONF.exists():
        return CheckResult("manual", f"packaged default {PKG_CONF} not found — compare aide.conf by hand", "\n".join(ev))
    live = AIDE_CONF.read_text().splitlines()
    default = set(PKG_CONF.read_text().splitlines())
    extra = [l for l in live if l not in default and l.strip() and not l.startswith("#")]
    missing = [l for l in default if l not in set(live) and l.strip() and not l.startswith("#")]
    ev.append(f"aide.conf vs packaged default: {len(extra)} added, {len(missing)} removed line(s)")
    if not extra and not missing:
        return CheckResult("pass", "", "\n".join(ev))
    if not missing and set(extra) <= set(AUDIT_TOOL_LINES):
        return CheckResult("review", "aide.conf differs only by the audit-tool lines V-270831 requires (STIG conflict)",
                           "\n".join(ev))
    return CheckResult("manual", "aide.conf modified from the packaged default", "\n".join(ev + extra[:20]))


register(B, Control("V-270651", _check_default))


# ---- V-270652 — AIDE reports are not silenced ----

def _check_silent() -> CheckResult:
    if (r := _need_aide()) is not None:
        return r
    v = keyval.get(AIDE_DEFAULT, "SILENTREPORTS")
    ev = keyval.evidence(AIDE_DEFAULT, "SILENTREPORTS")
    return CheckResult("pass", "", ev) if v == "no" else CheckResult("fail", f"SILENTREPORTS={v}", ev)


register(B, Control("V-270652", _check_silent, lambda: keyval.set_value(AIDE_DEFAULT, "SILENTREPORTS", "no")))


# ---- V-270831 — AIDE covers the audit tools with sha512 ----

def _check_audit_tools() -> CheckResult:
    if (r := _need_aide()) is not None:
        return r
    lines = {" ".join(l.split()) for l in AIDE_CONF.read_text().splitlines()} if AIDE_CONF.exists() else set()
    missing = [l for l in AUDIT_TOOL_LINES if l not in lines]
    if missing:
        return CheckResult("fail", f"{len(missing)} audit tool selection line(s) missing", "missing:\n" + "\n".join(missing))
    return CheckResult("pass", "", "\n".join(AUDIT_TOOL_LINES))


def _fix_audit_tools() -> list[RollbackEntry]:
    if not AIDE_CONF.exists():
        raise RuntimeError(f"{AIDE_CONF} missing — fix V-270649 first")

    def add(text: str) -> str:
        have = {" ".join(l.split()) for l in text.splitlines()}
        todo = [l for l in AUDIT_TOOL_LINES if l not in have]
        return text.rstrip("\n") + "\n\n# Audit Tools (lss-stig: V-270831)\n" + "\n".join(todo) + "\n" if todo else text

    return keyval.edit_file(AIDE_CONF, add, f"added audit tool selection lines to {AIDE_CONF}")


register(B, Control("V-270831", _check_audit_tools, _fix_audit_tools))
