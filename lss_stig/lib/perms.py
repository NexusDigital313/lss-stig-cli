"""File ownership/mode scanning and journaled fixes.

Scans never follow symlinks (on Ubuntu /lib, /bin, /sbin are symlinks into
/usr — walking them would double-count and chase links into other trees).
Tree walks are memoized per run and invalidated by every fix, because a dozen
rules walk the same /usr/lib and /usr/bin trees.
"""

from __future__ import annotations

import grp
import os
import pwd
import stat
from pathlib import Path

from lss_stig.lib.registry import RollbackEntry

_walk_cache: dict[tuple, list[tuple[str, os.stat_result]]] = {}


def invalidate() -> None:
    _walk_cache.clear()


def _real_roots(roots) -> list[str]:
    seen, out = set(), []
    for r in roots:
        if not os.path.exists(r):
            continue
        real = os.path.realpath(r)
        if real not in seen:
            seen.add(real)
            out.append(real)
    return out


def walk(roots, skip_fstypes: frozenset[str] = frozenset()) -> list[tuple[str, os.stat_result]]:
    """Every entry (dirs included) under `roots`, via lstat, no symlink follow."""
    key = (tuple(roots), skip_fstypes)
    if key in _walk_cache:
        return _walk_cache[key]
    skip_mounts = {m for m, t in mounts().items() if t in skip_fstypes} if skip_fstypes else set()
    out: list[tuple[str, os.stat_result]] = []
    stack = _real_roots(roots)
    for r in stack:
        try:
            out.append((r, os.lstat(r)))
        except OSError:
            pass
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        st = e.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    out.append((e.path, st))
                    if stat.S_ISDIR(st.st_mode) and e.path not in skip_mounts:
                        stack.append(e.path)
        except OSError:
            continue
    _walk_cache[key] = out
    return out


def mounts() -> dict[str, str]:
    out = {}
    try:
        for line in Path("/proc/self/mounts").read_text().splitlines():
            f = line.split()
            if len(f) >= 3:
                out[f[1].replace("\\040", " ")] = f[2]
    except OSError:
        pass
    return out


def user(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def mode(st: os.stat_result) -> int:
    return stat.S_IMODE(st.st_mode)


def describe(path: str, st: os.stat_result) -> str:
    return f"{path} {mode(st):o} {user(st.st_uid)}:{group(st.st_gid)}"


def evidence(items: list[tuple[str, os.stat_result]], limit: int = 50) -> str:
    lines = [describe(p, st) for p, st in items[:limit]]
    if len(items) > limit:
        lines.append(f"... and {len(items) - limit} more")
    return "\n".join(lines)


# ---- fixes (each returns its own exact inverse) ----

def chmod_remove(items, bits: int, label: str) -> list[RollbackEntry]:
    out = []
    for path, st in items:
        old = mode(st)
        new = old & ~bits
        if new == old:
            continue
        os.chmod(path, new, follow_symlinks=False)
        out.append(RollbackEntry(action=f"chmod {new:o} {path} ({label})",
                                 undo=[["chmod", f"{old:o}", path]]))
    invalidate()
    return out


def chmod_to(items, new: int, label: str) -> list[RollbackEntry]:
    out = []
    for path, st in items:
        old = mode(st)
        if old == new:
            continue
        os.chmod(path, new, follow_symlinks=False)
        out.append(RollbackEntry(action=f"chmod {new:o} {path} ({label})",
                                 undo=[["chmod", f"{old:o}", path]]))
    invalidate()
    return out


def chmod_add(items, bits: int, label: str) -> list[RollbackEntry]:
    out = []
    for path, st in items:
        old = mode(st)
        os.chmod(path, old | bits, follow_symlinks=False)
        out.append(RollbackEntry(action=f"chmod {old | bits:o} {path} ({label})",
                                 undo=[["chmod", f"{old:o}", path]]))
    invalidate()
    return out


def chown_to(items, uid: int | None = None, gid: int | None = None, label: str = "") -> list[RollbackEntry]:
    out = []
    for path, st in items:
        u = st.st_uid if uid is None else uid
        g = st.st_gid if gid is None else gid
        if (u, g) == (st.st_uid, st.st_gid):
            continue
        os.chown(path, u, g, follow_symlinks=False)
        # chown clears setuid/setgid bits on regular files — restore the mode too.
        undo = [["chown", "-h", f"{st.st_uid}:{st.st_gid}", path]]
        if not stat.S_ISLNK(st.st_mode):
            undo.append(["chmod", f"{mode(st):o}", path])
            if mode(st) & 0o6000:
                os.chmod(path, mode(st))
        out.append(RollbackEntry(action=f"chown {user(u)}:{group(g)} {path} ({label})", undo=undo))
    invalidate()
    return out
