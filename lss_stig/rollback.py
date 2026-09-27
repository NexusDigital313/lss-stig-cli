"""Rollback engine — reverses hardening changes using the journal.

For each entry: if a backup exists, restore it (with mtime safety check);
then run any argv-list undo commands with shell=False. Never uses shell=True.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from lss_stig.lib import journal, sshd, syslog
from lss_stig.lib.output import info, header, err, warn, GREEN, DIM, RESET


def _restore_backup(control_id: str, backup: str, path: str) -> tuple[bool, str]:
    """Restore `path` from `backup`. Returns (ok, message).

    Warns (but still restores) if the live file has been modified since the
    backup was taken — the operator should know they may be losing edits.
    """
    src = Path(backup)
    dst = Path(path)
    if not src.exists():
        return False, f"backup file missing: {backup}"

    if dst.exists():
        try:
            backup_mtime = src.stat().st_mtime
            live_mtime = dst.stat().st_mtime
            if live_mtime > backup_mtime + 1:  # 1s grace for FS resolution
                warn(f"  {control_id}   {path} was modified after backup — restoring anyway will overwrite those changes")
        except OSError:
            pass

    shutil.copy2(src, dst)
    return True, f"restored {path} from backup"


def _run_undo(control_id: str, argv: list[str]) -> tuple[bool, str]:
    """Run a single argv list with shell=False. Returns (ok, message)."""
    if not argv or not isinstance(argv, list):
        return False, f"malformed undo (expected argv list, got {type(argv).__name__})"
    try:
        subprocess.run(
            argv,
            shell=False,
            check=True,
            capture_output=True,
            text=True,
        )
        return True, " ".join(argv)
    except FileNotFoundError:
        return False, f"command not found: {argv[0]}"
    except subprocess.CalledProcessError as exc:
        msg = (exc.stderr or "").strip().splitlines()[-1] if exc.stderr else f"exit {exc.returncode}"
        return False, f"{' '.join(argv)} → {msg}"


def run_rollback(args) -> int:
    """Undo a previous harden run."""
    run_id = None
    if args.last:
        runs = journal.list_runs()
        if not runs:
            err("no harden runs found in journal")
            return 1
        run_id = runs[0]
    elif args.run_id:
        if not re.fullmatch(r"[0-9TZ]+-[0-9a-f]{8}", args.run_id):
            err(f"malformed run id: {args.run_id}")
            return 1
        run_id = args.run_id
    else:  # --rule: undo one rule from the most recent run
        runs = journal.list_runs()
        if not runs:
            err("no harden runs found in journal")
            return 1
        run_id = runs[0]

    run_data = journal.read_run(run_id)
    if not run_data:
        err(f"journal not found for run: {run_id}")
        return 1

    info(f"Rolling back run: {run_data['run_id']}  ({run_data['timestamp']})")
    syslog.info(
        f"rollback start run_id={run_data['run_id']} "
        f"target={'rule:' + args.rule if args.rule else 'all'}"
    )

    controls = run_data.get("controls", {})

    if args.rule:
        args.rule = args.rule.upper()
        if args.rule not in controls:
            err(f"rule {args.rule} not found in run {run_data['run_id']}")
            return 1
        controls = {args.rule: controls[args.rule]}

    header("Rollback")

    errors = 0
    sshd_touched = False
    # Iterate controls in reverse application order so that when multiple
    # controls modified the same file, the LAST control's undo runs first.
    # If the OUTER loop runs forward, an early control's `rm -f` deletes
    # the file before later controls' "restore from backup" recreate it
    # with their stale post-edit state — leaving the file partially
    # hardened. See tests/test_journal.py for the multi-control case.
    for control_id, entries in reversed(list(controls.items())):
        for entry in reversed(entries):  # reverse order for safe undo
            action = entry.get("action", "")
            backup = entry.get("backup", "") or ""
            path = entry.get("path", "") or ""
            undo = entry.get("undo", []) or []

            # Never execute a string as a shell command, whatever the journal says.
            if isinstance(undo, str):
                err(f"  {control_id}   refusing non-argv undo: {undo!r}")
                errors += 1
                undo = []

            did_something = False

            # 1. Restore from backup if available
            if backup and path:
                ok, msg = _restore_backup(control_id, backup, path)
                if ok:
                    print(f"{GREEN}  ✓{RESET} {control_id}   {msg}")
                    did_something = True
                else:
                    err(f"  {control_id}   {msg}")
                    errors += 1

            # 2. Run undo argv lists in order
            for argv in undo:
                ok, msg = _run_undo(control_id, argv)
                if ok:
                    print(f"{GREEN}  ✓{RESET} {control_id}   {action} {DIM}({msg}){RESET}")
                    did_something = True
                else:
                    err(f"  {control_id}   undo failed: {msg}")
                    errors += 1

            if not did_something and action:
                warn(f"  {control_id}   no backup or undo for: {action}")

            # An SSH config file was reverted on disk, but the RUNNING sshd
            # still holds the hardened settings until it is reloaded. Harden
            # reloads on apply; rollback must too, or the revert looks done
            # while the live daemon keeps enforcing the old rules.
            if path.startswith("/etc/ssh"):
                sshd_touched = True

    if sshd_touched:
        if sshd.reload():
            info("reloaded sshd so the reverted SSH config is live on the running daemon")
        else:
            warn("reverted SSH config on disk but could not reload sshd — "
                 "run from the console: sudo systemctl reload ssh")

    print()
    if errors:
        err(f"rollback completed with {errors} error(s)")
        syslog.err(f"rollback complete run_id={run_data['run_id']} errors={errors}")
    else:
        info("rollback complete — all changes reversed")
        syslog.info(f"rollback complete run_id={run_data['run_id']} errors=0")

    return errors
