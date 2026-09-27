"""GNOME system-wide settings via the dconf `local` database.

A setting only reaches user sessions when all three hold:
  1. a keyfile under /etc/dconf/db/local.d/ sets it (and locks/ locks it),
  2. /etc/dconf/profile/user reads `system-db:local`,
  3. `dconf update` has compiled /etc/dconf/db/local AFTER the last edit.
Missing 2 or 3 is the classic silent failure — the file looks right to a
grep but nothing changed for users. state_problem() checks exactly that.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from lss_stig.lib import journal, pkg
from lss_stig.lib.registry import CheckResult, RollbackEntry

DB_DIR = Path("/etc/dconf/db/local.d")
LOCK_DIR = DB_DIR / "locks"
DB = Path("/etc/dconf/db/local")
PROFILE = Path("/etc/dconf/profile/user")
OUR_KEYFILE = DB_DIR / "00-lss-stig"
OUR_LOCKS = LOCK_DIR / "00-lss-stig-locks"


def gui_installed() -> bool:
    return any(pkg.is_installed(p) for p in ("gnome-shell", "gdm3", "ubuntu-desktop"))


def not_applicable() -> CheckResult | None:
    return None if gui_installed() else CheckResult("na", "no GNOME desktop installed")


def parse_value(text: str, section: str, key: str) -> str | None:
    """Value of `key` inside `[section]` of one keyfile's text."""
    hdr = f"[{section}]"
    cur = None
    val = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            cur = line
        elif cur == hdr and "=" in line and line.split("=", 1)[0].strip() == key:
            val = line.split("=", 1)[1].strip()
    return val


def _files(d: Path) -> list[Path]:
    return sorted(f for f in d.iterdir() if f.is_file()) if d.is_dir() else []


def value(section: str, key: str) -> tuple[str | None, str]:
    """(value, where) across local.d keyfiles; later files win."""
    found, where = None, ""
    for f in _files(DB_DIR):
        v = parse_value(f.read_text(errors="replace"), section, key)
        if v is not None:
            found, where = v, str(f)
    return found, where


def locked(path: str) -> str:
    """File that locks `path` (e.g. /org/gnome/desktop/...), or ''."""
    for f in _files(LOCK_DIR):
        for line in f.read_text(errors="replace").splitlines():
            if line.strip() == path:
                return str(f)
    return ""


def state_problem() -> str:
    profile = PROFILE.read_text() if PROFILE.exists() else ""
    if "system-db:local" not in profile:
        return f"{PROFILE} does not read system-db:local"
    newest = max((f.stat().st_mtime for f in _files(DB_DIR) + _files(LOCK_DIR)), default=0.0)
    if not DB.exists() or DB.stat().st_mtime < newest:
        return "keyfiles changed but `dconf update` not run — not in effect"
    return ""


def check(settings: dict[tuple[str, str], object] | None = None, locks: list[str] | None = None) -> CheckResult:
    """settings: {(section, key): expected_str or predicate(value)->bool}."""
    if (na := not_applicable()) is not None:
        return na
    ev, problems = [], []
    for (section, key), want in (settings or {}).items():
        v, where = value(section, key)
        ev.append(f"{where or DB_DIR}: [{section}] {key}={v}")
        ok = want(v) if callable(want) else (v is not None and v.replace(" ", "") == str(want).replace(" ", ""))
        if not ok:
            problems.append(f"{key}={v}")
    for path in locks or []:
        where = locked(path)
        ev.append(f"lock {path}: {where or 'not locked'}")
        if not where:
            problems.append(f"{path.rsplit('/', 1)[-1]} not locked")
    sp = state_problem()
    ev.append(f"dconf state: {sp or 'compiled and referenced'}")
    evidence = "\n".join(ev)
    if problems:
        return CheckResult("fail", "; ".join(problems), evidence)
    if sp:
        return CheckResult("fail", sp, evidence)
    return CheckResult("pass", "", evidence)


def _merge_keyfile(text: str, section: str, key: str, val: str) -> str:
    lines = text.splitlines()
    hdr = f"[{section}]"
    if hdr not in [l.strip() for l in lines]:
        if lines and lines[-1].strip():
            lines.append("")
        lines += [hdr, f"{key}={val}"]
        return "\n".join(lines) + "\n"
    out, cur, done = [], None, False
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("["):
            if cur == hdr and not done:
                out.append(f"{key}={val}")
                done = True
            cur = s
        elif cur == hdr and "=" in s and s.split("=", 1)[0].strip() == key:
            if not done:
                out.append(f"{key}={val}")
                done = True
            continue
        out.append(raw)
    if not done:
        out.append(f"{key}={val}")
    return "\n".join(out) + "\n"


def apply(settings: dict[tuple[str, str], str] | None = None, locks: list[str] | None = None) -> list[RollbackEntry]:
    out: list[RollbackEntry] = []
    if settings:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        text = OUR_KEYFILE.read_text() if OUR_KEYFILE.exists() else ""
        new = text
        for (section, key), val in settings.items():
            new = _merge_keyfile(new, section, key, val)
        if new != text:
            bkp = journal.backup_file(str(OUR_KEYFILE))
            OUR_KEYFILE.write_text(new)
            out.append(RollbackEntry(action=f"dconf keys in {OUR_KEYFILE}", path=str(OUR_KEYFILE), backup=bkp,
                                     undo=([] if bkp else [["rm", "-f", str(OUR_KEYFILE)]]) + [["dconf", "update"]]))
    if locks:
        LOCK_DIR.mkdir(parents=True, exist_ok=True)
        text = OUR_LOCKS.read_text() if OUR_LOCKS.exists() else ""
        missing = [l for l in locks if l not in text.splitlines()]
        if missing:
            bkp = journal.backup_file(str(OUR_LOCKS))
            OUR_LOCKS.write_text(text + "".join(f"{l}\n" for l in missing))
            out.append(RollbackEntry(action=f"dconf locks in {OUR_LOCKS}", path=str(OUR_LOCKS), backup=bkp,
                                     undo=([] if bkp else [["rm", "-f", str(OUR_LOCKS)]]) + [["dconf", "update"]]))
    profile = PROFILE.read_text() if PROFILE.exists() else ""
    if "system-db:local" not in profile:
        bkp = journal.backup_file(str(PROFILE))
        PROFILE.parent.mkdir(parents=True, exist_ok=True)
        base = profile if profile.strip() else "user-db:user\n"
        PROFILE.write_text(base.rstrip("\n") + "\nsystem-db:local\n")
        out.append(RollbackEntry(action=f"added system-db:local to {PROFILE}", path=str(PROFILE), backup=bkp,
                                 undo=[] if bkp else [["rm", "-f", str(PROFILE)]]))
    r = subprocess.run(["dconf", "update"], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"dconf update failed: {r.stderr.strip()}")
    return out
