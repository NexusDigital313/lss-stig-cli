"""sshd_config helpers, shaped around how a STIG assessor checks SSH.

The STIG check text greps every sshd_config* file and calls it a finding if
the keyword is missing, set wrong, OR set more than once with conflicting
values — even when sshd's effective value happens to be right. So a drop-in
alone isn't enough: a stray `X11Forwarding yes` left in sshd_config fails the
assessor's grep while `sshd -T` says "no". We check (and fix) both:

  1. the effective value (`sshd -T`, falling back to first-match file parsing)
  2. every uncommented occurrence across sshd_config and sshd_config.d/*.conf

The fix writes our drop-in (00- so it wins sshd's first-match rule, ahead of
cloud-init's 50-cloud-init.conf) and comments out conflicting lines elsewhere,
backing up every file it touches. `sshd -t` validates before anything is
reloaded; on failure every file is reverted.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from lss_stig.lib import journal
from lss_stig.lib.registry import CheckResult, RollbackEntry

SSHD_CONFIG = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_D = Path("/etc/ssh/sshd_config.d")
DROPIN = SSHD_CONFIG_D / "00-lss-stig.conf"
SSH_CONFIG = Path("/etc/ssh/ssh_config")
SSH_CONFIG_D = Path("/etc/ssh/ssh_config.d")
CLIENT_DROPIN = SSH_CONFIG_D / "00-lss-stig.conf"
MARK = "# lss-stig:"


def _paths(client: bool) -> tuple[Path, Path, Path]:
    # Resolved at call time so tests can patch the module constants.
    if client:
        return SSH_CONFIG, SSH_CONFIG_D, CLIENT_DROPIN
    return SSHD_CONFIG, SSHD_CONFIG_D, DROPIN


@dataclass
class Occurrence:
    path: str
    lineno: int      # 1-based
    value: str
    in_match: bool


def config_files(client: bool = False) -> list[Path]:
    main, confd, _ = _paths(client)
    files = []
    if main.is_file():
        files.append(main)
    if confd.is_dir():
        files.extend(sorted(p for p in confd.glob("*.conf") if p.is_file()))
    return files


def parse_occurrences(text: str, key: str, path: str = "") -> list[Occurrence]:
    """Uncommented `key value` lines in one file (keyword is case-insensitive;
    `key=value` form is accepted, as sshd accepts it)."""
    out = []
    in_match = False
    key_l = key.lower()
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tok = re.split(r"[\s=]+", line, maxsplit=1)
        word = tok[0].lower()
        if word in ("match", "host"):
            in_match = True
            continue
        if word == key_l:
            val = tok[1].strip() if len(tok) > 1 else ""
            out.append(Occurrence(path, n, val, in_match))
    return out


def occurrences(key: str, client: bool = False) -> list[Occurrence]:
    found = []
    for f in config_files(client):
        try:
            found.extend(parse_occurrences(f.read_text(), key, str(f)))
        except OSError:
            continue
    return found


def effective(key: str) -> str | None:
    """Effective global value via `sshd -T`. Falls back to first global match
    in file order when sshd -T can't run — on socket-activated Ubuntu 24.04
    sshd -T fails with 'Missing privilege separation directory: /run/sshd'
    until the first connection, and an audit must not create it."""
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                parts = line.split(None, 1)
                if len(parts) == 2 and parts[0].lower() == key.lower():
                    return parts[1].strip()
            return None
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    for occ in occurrences(key):
        if not occ.in_match:
            return occ.value
    return None


def check_setting(key: str, expected: str, ok=None, client: bool = False) -> CheckResult:
    """STIG-style verdict for one keyword: must be explicitly set, every
    occurrence acceptable (`ok(value)`, default: equals `expected`), and the
    effective value acceptable too. Client config has no `sshd -T`; there
    the file view is authoritative."""
    main, confd, _ = _paths(client)
    if not main.exists() and not confd.exists():
        return CheckResult("fail", f"{main} not found")
    ok = ok or (lambda v: v.lower() == expected.lower())
    occs = occurrences(key, client)
    eff = None if client else effective(key)
    ev = [] if client else [f"sshd -T: {key.lower()} {eff if eff is not None else '(unavailable)'}"]
    ev += [f"{o.path}:{o.lineno}: {key} {o.value}{'  [inside Host/Match]' if o.in_match else ''}" for o in occs]
    evidence = "\n".join(ev) or f"{key}: no uncommented occurrence"

    bad = [o for o in occs if not ok(o.value)]
    if not occs:
        return CheckResult("fail", f"{key} not set (relying on default)", evidence)
    if bad:
        where = ", ".join(f"{Path(o.path).name}:{o.lineno}={o.value}" for o in bad)
        return CheckResult("fail", f"{key} conflicting/incorrect: {where}", evidence)
    if eff is not None and not ok(eff):
        return CheckResult("fail", f"effective {key}={eff}", evidence)
    return CheckResult("pass", "", evidence)


def ports() -> list[int]:
    """Ports sshd listens on (for firewall rules)."""
    out = set()
    try:
        r = subprocess.run(["sshd", "-T"], capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            out |= {int(l.split()[1]) for l in r.stdout.splitlines() if l.startswith("port ")}
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        pass
    if not out:
        out |= {int(o.value) for o in occurrences("Port") if o.value.isdigit()}
    return sorted(out) or [22]


def validate() -> tuple[bool, str]:
    try:
        r = subprocess.run(["sshd", "-t"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return True, "sshd not found — validation skipped"
    if r.returncode == 0:
        return True, "ok"
    msg = (r.stderr or r.stdout or "").strip()
    # Same socket-activation quirk as effective(): not a config error.
    if "privilege separation directory" in msg:
        os.makedirs("/run/sshd", mode=0o755, exist_ok=True)
        return validate()
    return False, msg.splitlines()[-1] if msg else "sshd -t failed"


def reload() -> bool:
    """Reload (not restart) keeps live sessions. On socket-activated hosts the
    service may be idle; new connections read the new config anyway."""
    for unit in ("ssh", "sshd"):
        try:
            if subprocess.run(["systemctl", "reload", unit], capture_output=True).returncode == 0:
                return True
        except FileNotFoundError:
            return False
    return False


def _include_present(client: bool = False) -> bool:
    main, confd, _ = _paths(client)
    try:
        for raw in main.read_text().splitlines():
            s = raw.strip().lower()
            if s.startswith("include") and confd.name in s:
                return True
    except OSError:
        return True
    return False


def validate_client() -> tuple[bool, str]:
    try:
        r = subprocess.run(["ssh", "-G", "localhost"], capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        return True, "ssh not found — validation skipped"
    if r.returncode == 0:
        return True, "ok"
    msg = (r.stderr or "").strip()
    return False, msg.splitlines()[-1] if msg else "ssh -G failed"


def set_settings(settings: dict[str, str], ok=None, client: bool = False) -> list[RollbackEntry]:
    """Enforce `settings` STIG-style. Returns rollback entries; raises (after
    reverting every touched file) if the result doesn't validate.
    `ok(key, value)` decides which existing lines are acceptable (default:
    equal to the target value); unacceptable ones are commented out."""
    main, confd, dropin = _paths(client)
    if not _include_present(client):
        raise RuntimeError(f"{main} does not Include {confd.name}/*.conf — "
                           "refusing to write a drop-in that would be ignored")
    ok = ok or (lambda k, v: v.lower() == settings[k].lower())

    entries: list[RollbackEntry] = []
    touched: list[tuple[Path, str]] = []   # (path, backup or "" if created)

    # 1. Comment out every conflicting occurrence outside our drop-in.
    for f in config_files(client):
        if f == dropin:
            continue
        lines = f.read_text().splitlines(keepends=True)
        changed = False
        for key, val in settings.items():
            for occ in parse_occurrences("".join(lines), key, str(f)):
                if not ok(key, occ.value):
                    i = occ.lineno - 1
                    lines[i] = f"{MARK} {lines[i].rstrip()}  (superseded by {dropin.name})\n"
                    changed = True
        if changed:
            bkp = journal.backup_file(str(f))
            touched.append((f, bkp))
            f.write_text("".join(lines))
            entries.append(RollbackEntry(action=f"commented conflicting lines in {f}",
                                         path=str(f), backup=bkp))

    # 2. Write/update the drop-in.
    dropin.parent.mkdir(parents=True, exist_ok=True)
    existing = dropin.read_text() if dropin.exists() else ""
    bkp = journal.backup_file(str(dropin))
    touched.append((dropin, bkp))
    lines = existing.splitlines(keepends=True)
    if not lines:
        lines = [f"{MARK} managed by lss-stig; undo with `lss-stig rollback`\n"]
    for key, val in settings.items():
        new = f"{key} {val}\n"
        for i, line in enumerate(lines):
            tok = re.split(r"[\s=]+", line.strip(), maxsplit=1)
            if tok and tok[0].lower() == key.lower():
                lines[i] = new
                break
        else:
            lines.append(new)
    dropin.write_text("".join(lines))
    dropin.chmod(0o644 if client else 0o600)  # users' ssh must read the client file
    entries.append(RollbackEntry(
        action="set " + ", ".join(f"{k} {v}" for k, v in settings.items()) + f" in {dropin}",
        path=str(dropin), backup=bkp,
        undo=[] if bkp else [["rm", "-f", str(dropin)]],
    ))

    valid, msg = validate_client() if client else validate()
    if not valid:
        for path, b in reversed(touched):
            if b:
                shutil.copy2(b, path)
            else:
                path.unlink(missing_ok=True)
        raise RuntimeError(f"{'ssh -G' if client else 'sshd -t'} rejected the change — reverted ({msg})")
    if not client:
        reload()
    return entries


def has_non_root_admin() -> bool:
    """True if some non-root account in sudo/wheel has a real login shell."""
    import grp
    import pwd
    members: set[str] = set()
    for g in ("sudo", "wheel", "admin"):
        try:
            members |= set(grp.getgrnam(g).gr_mem)
        except KeyError:
            pass
    nologin = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
    for name in members - {"root"}:
        try:
            if pwd.getpwnam(name).pw_shell not in nologin:
                return True
        except KeyError:
            pass
    return False
