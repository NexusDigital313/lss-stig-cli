"""Linux audit rules: compare what the STIG requires against what the kernel
has LOADED (`auditctl -l`), not just what sits in /etc/audit/rules.d.

Rules are compared semantically, because auditctl rewrites them on output:
`-k x` comes back as `-F key=x`, path rules gain `-S all`, syscall lists are
reordered, `auid!=-1` may print as `unset`, and on Ubuntu /bin, /sbin and
/var/run are symlinks to /usr/bin, /usr/sbin and /run. The key is ignored —
the STIG says it's arbitrary.

A rule written to disk but not loaded is the silent failure here, and with
`-e 2` (immutable) nothing new loads until reboot — reported as such rather
than "fixed".
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from lss_stig.lib import journal, pkg
from lss_stig.lib.registry import CheckResult, RollbackEntry

RULES_D = Path("/etc/audit/rules.d")
AUDIT_RULES = Path("/etc/audit/audit.rules")
STIG_RULES = RULES_D / "stig.rules"

_ALIASES = [("/bin/", "/usr/bin/"), ("/sbin/", "/usr/sbin/"), ("/lib/", "/usr/lib/"), ("/var/run/", "/run/")]
_UNSET = {"-1", "unset", "4294967295"}


def _norm_path(p: str) -> str:
    p = p.rstrip("/") or "/"
    for a, b in _ALIASES:
        if p.startswith(a):
            return b + p[len(a):]
    return p


def _field(tok: str) -> tuple[str, str, str]:
    for op in ("!=", ">=", "<=", "&=", "=", ">", "<", "&"):
        if op in tok:
            k, v = tok.split(op, 1)
            return k, op, v
    return tok, "", ""


def canon(rule: str):
    """Canonical, order-independent form of one rule line (None if not a rule)."""
    toks = rule.split()
    if not toks or toks[0] not in ("-w", "-a", "-A"):
        return None
    if toks[0] == "-w":
        path, perms = _norm_path(toks[1]), ""
        for i, t in enumerate(toks):
            if t == "-p" and i + 1 < len(toks):
                perms = "".join(sorted(toks[i + 1]))
        return ("w", path, perms)
    action = frozenset(toks[1].split(","))
    syscalls, fields = set(), set()
    i = 2
    while i < len(toks):
        t = toks[i]
        arg = toks[i + 1] if i + 1 < len(toks) else ""
        if t == "-S":
            syscalls |= {s for s in arg.split(",") if s != "all"}
        elif t == "-F":
            k, op, v = _field(arg)
            if k == "key":
                pass
            elif k in ("path", "dir"):
                fields.add((k, op, _norm_path(v)))
            elif k == "perm":
                fields.add((k, op, "".join(sorted(v))))
            elif k in ("auid", "uid", "euid", "loginuid") and v in _UNSET:
                fields.add((k, op, "unset"))
            else:
                fields.add((k, op, v))
        elif t == "-C":
            fields.add(("C", "", arg))
        elif t == "-k":
            pass
        else:
            i += 1
            continue
        i += 2
    return ("a", action, frozenset(syscalls), frozenset(fields))


def loaded() -> tuple[list[str] | None, str]:
    """(loaded rule lines, error)."""
    try:
        r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True, timeout=30)
    except FileNotFoundError:
        return None, "auditctl not found"
    if r.returncode != 0:
        return None, (r.stderr or r.stdout).strip() or f"auditctl -l exit {r.returncode}"
    return [l for l in r.stdout.splitlines() if l.startswith("-")], ""


def on_disk() -> list[str]:
    out = []
    files = sorted(RULES_D.glob("*.rules")) if RULES_D.is_dir() else []
    for f in files:
        try:
            out += [l.strip() for l in f.read_text().splitlines() if l.strip().startswith("-")]
        except OSError:
            pass
    return out


def immutable() -> bool:
    try:
        r = subprocess.run(["auditctl", "-s"], capture_output=True, text=True, timeout=30)
        return any(l.split() == ["enabled", "2"] for l in r.stdout.splitlines())
    except FileNotFoundError:
        return False


def _missing_binary(rule: str) -> str:
    c = canon(rule)
    if c and c[0] == "a":
        for k, _, v in c[3]:
            if k == "path" and not any(os.path.exists(p) for p in (v, v.replace("/usr/", "/", 1))):
                return v
    return ""


def check(rules: list[str]) -> CheckResult:
    if not pkg.is_installed("auditd"):
        return CheckResult("fail", "auditd not installed (see V-270656)")
    absent = [m for r in rules if (m := _missing_binary(r))]
    if absent and len(absent) == len(rules):
        return CheckResult("na", f"{', '.join(sorted(set(absent)))} not installed")
    rules = [r for r in rules if not _missing_binary(r)]

    live, err = loaded()
    disk = {canon(l) for l in on_disk()}
    if live is None:
        pending = [r for r in rules if canon(r) not in disk]
        ev = f"auditctl -l failed: {err}\non disk: {len(rules) - len(pending)}/{len(rules)} required rules"
        return CheckResult("manual", f"cannot read loaded audit rules ({err})", ev)
    live_c = {canon(l): l for l in live}
    found = [live_c[canon(r)] for r in rules if canon(r) in live_c]
    missing = [r for r in rules if canon(r) not in live_c]
    ev = "\n".join(["auditctl -l (matching):"] + (found or ["(none)"]))
    if not missing:
        return CheckResult("pass", "", ev)
    ev += "\nmissing:\n" + "\n".join(missing)
    if all(canon(r) in disk for r in missing):
        if immutable():
            return CheckResult("manual", "rules are in rules.d but audit is locked (-e 2) — they load at next reboot", ev)
        return CheckResult("fail", "rules on disk but not loaded (augenrules --load)", ev)
    return CheckResult("fail", f"{len(missing)} of {len(rules)} required rule(s) not loaded", ev)


def ensure(rules: list[str], load: bool = True, path: Path = STIG_RULES) -> list[RollbackEntry]:
    """Append whichever `rules` aren't already on disk, then (re)load."""
    if not pkg.is_installed("auditd"):
        raise RuntimeError("auditd not installed — fix V-270656 first")
    out: list[RollbackEntry] = []
    disk = {canon(l) for l in on_disk()}
    todo = [r for r in rules if canon(r) not in disk and not _missing_binary(r)]
    if todo:
        RULES_D.mkdir(parents=True, exist_ok=True)
        existing = path.read_text() if path.exists() else ""
        bkp = journal.backup_file(str(path))
        text = existing + ("" if not existing or existing.endswith("\n") else "\n") + "\n".join(todo) + "\n"
        path.write_text(text)
        os.chmod(path, 0o640)
        out.append(RollbackEntry(
            action=f"added {len(todo)} audit rule(s) to {path}", path=str(path), backup=bkp,
            undo=([] if bkp else [["rm", "-f", str(path)]]) + [["augenrules", "--load"]],
        ))
    if load and not immutable():
        r = subprocess.run(["augenrules", "--load"], capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"augenrules --load: {(r.stderr or r.stdout).strip()}")
    elif not load:
        subprocess.run(["augenrules"], capture_output=True, text=True, timeout=120)
    return out
