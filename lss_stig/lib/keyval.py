"""Read/modify simple `KEY value` / `key = value` config files.

Covers pwquality.conf, login.defs, /etc/default/*, auditd.conf and the like.
Edits keep the file's layout: an existing (last) uncommented occurrence is
rewritten in place, otherwise a commented-out default is replaced, otherwise
the line is appended. Every edit is backed up to the run journal.
"""

from __future__ import annotations

import re
from pathlib import Path

from lss_stig.lib import journal
from lss_stig.lib.registry import RollbackEntry


def _pattern(key: str, sep: str) -> re.Pattern:
    k = re.escape(key)
    if sep == "=":
        return re.compile(rf"^\s*{k}\s*=\s*(.*?)\s*$", re.I)
    return re.compile(rf"^\s*{k}\s+(.*?)\s*$", re.I)


def get(path: Path | str, key: str, sep: str = "=") -> str | None:
    """Last uncommented value for `key`, or None."""
    p = Path(path)
    if not p.is_file():
        return None
    pat = _pattern(key, sep)
    val = None
    for line in p.read_text(errors="replace").splitlines():
        if line.lstrip().startswith("#"):
            continue
        m = pat.match(line)
        if m:
            val = m.group(1).strip().strip('"')
    return val


def evidence(path: Path | str, key: str, sep: str = "=") -> str:
    v = get(path, key, sep)
    return f"{path}: {key}{'=' if sep == '=' else ' '}{v}" if v is not None else f"{path}: {key} not set"


def set_value(path: Path | str, key: str, value: str, sep: str = "=",
              fmt: str | None = None) -> list[RollbackEntry]:
    """Set `key` to `value`. `fmt` overrides the written line (e.g. 'enforcing = 1')."""
    p = Path(path)
    new_line = fmt or (f"{key}={value}" if sep == "=" else f"{key} {value}")
    text = p.read_text() if p.exists() else ""
    lines = text.splitlines()
    pat = _pattern(key, sep)
    commented = re.compile(rf"^\s*#\s*{re.escape(key)}(\s|=|$)", re.I)

    idx = [i for i, l in enumerate(lines) if not l.lstrip().startswith("#") and pat.match(l)]
    if idx:
        if all(pat.match(lines[i]).group(1).strip().strip('"') == value for i in idx):
            return []
        for i in idx[:-1]:  # earlier duplicates would mislead a grep-based assessor
            lines[i] = f"# {lines[i]}  # lss-stig: superseded below"
        lines[idx[-1]] = new_line
    else:
        cidx = [i for i, l in enumerate(lines) if commented.match(l)]
        if cidx:
            lines.insert(cidx[-1] + 1, new_line)
        else:
            lines.append(new_line)

    bkp = journal.backup_file(str(p))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + "\n")
    return [RollbackEntry(action=f"set {key} {value} in {p}", path=str(p), backup=bkp,
                          undo=[] if bkp else [["rm", "-f", str(p)]])]


def write_file(path: Path | str, content: str, mode: int = 0o644) -> list[RollbackEntry]:
    """Replace a whole file (backed up), e.g. a drop-in we own."""
    p = Path(path)
    if p.exists() and p.read_text() == content:
        return []
    bkp = journal.backup_file(str(p))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    p.chmod(mode)
    return [RollbackEntry(action=f"wrote {p}", path=str(p), backup=bkp,
                          undo=[] if bkp else [["rm", "-f", str(p)]])]


def edit_file(path: Path | str, transform, action: str) -> list[RollbackEntry]:
    """Apply `transform(text) -> text` to a file, backed up. No-op if unchanged."""
    p = Path(path)
    text = p.read_text()
    new = transform(text)
    if new == text:
        return []
    bkp = journal.backup_file(str(p))
    p.write_text(new)
    return [RollbackEntry(action=action, path=str(p), backup=bkp)]
