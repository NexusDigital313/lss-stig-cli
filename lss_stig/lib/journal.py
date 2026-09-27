"""Rollback journal — records every change made during hardening so it can be undone.

Writes are atomic: temp file + fsync + rename. Backups of modified files are
stored under JOURNAL_DIR/backups/<run_id>/<sanitized-path>.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from lss_stig.lib.registry import RollbackEntry  # noqa: F401

JOURNAL_DIR = Path("/var/log/lss-stig/journal")
BACKUPS_DIR = JOURNAL_DIR / "backups"

# Module-level "current run" context. harden.py calls set_current_run_id()
# before invoking any control fix; fixes then call backup_file(path) without
# threading the run_id through every function signature.
_current_run_id: str | None = None


def set_current_run_id(run_id: str | None) -> None:
    global _current_run_id
    _current_run_id = run_id


def new_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]


def _atomic_write(path: Path, content: str) -> None:
    """Write content to path atomically: temp file in same dir, fsync, rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def _sanitize_path(p: str) -> str:
    """Turn an absolute filesystem path into a safe relative backup path."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", p.lstrip("/"))


def backup_file(path: str, run_id: str | None = None) -> str:
    """Snapshot `path` into the journal backups dir for the current run.

    Returns the backup path as a string, or "" if `path` does not exist as a
    regular file (nothing to back up). When called from a control fix,
    `run_id` defaults to the current run set by harden.py.
    """
    rid = run_id if run_id is not None else _current_run_id
    if rid is None:
        raise RuntimeError("backup_file called outside a harden run (no run_id set)")
    src = Path(path)
    if not src.exists() or not src.is_file():
        return ""
    dest_dir = BACKUPS_DIR / rid
    dest_dir.mkdir(parents=True, exist_ok=True)
    base = _sanitize_path(path)
    # Each call must produce a UNIQUE backup. When several controls modify
    # the same file in one run, a single deterministic dest would let later
    # backups overwrite earlier ones — leaving every entry's "backup"
    # pointing to the same final state, so reverse-order restore can't
    # rebuild the original. Append a counter to keep them distinct.
    dest = dest_dir / base
    counter = 0
    while dest.exists():
        counter += 1
        dest = dest_dir / f"{base}.{counter:04d}"
    # copy2 preserves mode/mtime so rollback restores them too
    shutil.copy2(src, dest)
    return str(dest)


def write_run(run_id: str, entries: dict[str, list[dict]]) -> Path:
    """Write a complete harden run to the journal atomically.

    entries: {control_id: [{"action": ..., "undo": [[...], ...], "path": ..., "backup": ...}, ...]}
    """
    JOURNAL_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "controls": entries,
    }
    path = JOURNAL_DIR / f"{run_id}.json"
    _atomic_write(path, json.dumps(data, indent=2))

    # Atomically swap the "latest" symlink: write to a temp link, then rename.
    latest = JOURNAL_DIR / "latest.json"
    tmp_link = JOURNAL_DIR / "latest.json.new"
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(path.name)
    os.replace(tmp_link, latest)

    return path


def read_run(run_id: str | None = None) -> dict | None:
    """Read a journal run. If run_id is None, reads the latest."""
    if run_id:
        path = JOURNAL_DIR / f"{run_id}.json"
    else:
        path = JOURNAL_DIR / "latest.json"

    if not path.exists():
        return None

    return json.loads(path.read_text())


def list_runs() -> list[str]:
    """List all run IDs, newest first."""
    if not JOURNAL_DIR.exists():
        return []
    runs = []
    for f in sorted(JOURNAL_DIR.glob("*.json"), reverse=True):
        if f.name == "latest.json":
            continue
        runs.append(f.stem)
    return runs
