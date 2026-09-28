"""Rollback engine — reverses hardening changes using the journal.

For each entry: if a backup exists, restore it (with mtime safety check);
then run any argv-list undo commands with shell=False. Never uses shell=True.
"""

from __future__ import annotations

import re
import shutil
from datetime import datetime
import subprocess
from pathlib import Path

from lss_stig.lib import auditrules, journal, sshd, syslog
from lss_stig.lib.output import info, header, err, warn, GREEN, DIM, RESET


def _restore_backup(control_id: str, backup: str, path: str, run_ts: float | None = None) -> tuple[bool, str]:
    """Restore `path` from `backup`. Returns (ok, message).

    Warns (but still restores) if the live file changed after the harden run
    finished — the operator should know they may be losing edits. The backup's
    own mtime can't be the reference: it predates harden's edit by design.
    """
    src = Path(backup)
    dst = Path(path)
    if not src.exists():
        return False, f"backup file missing: {backup}"

    if run_ts is not None and dst.exists():
        try:
            if dst.stat().st_mtime > run_ts + 2:  # grace for FS resolution
                warn(f"  {control_id}   {path} was modified after the harden run — restoring anyway will overwrite those changes")
        except OSError:
            pass

    # The directory can be gone when a package this run installed was already
    # purged (e.g. a retried rollback after auditd's own undo removed
    # /etc/audit) — there is nothing left to restore into.
    if not dst.parent.is_dir():
        return True, f"skipped {path}: {dst.parent} no longer exists"
    try:
        shutil.copy2(src, dst)
    except OSError as exc:
        return False, f"restore {path} failed: {exc}"
    return True, f"restored {path} from backup"


def _run_undo(control_id: str, argv: list[str]) -> tuple[bool, str]:
    """Run a single argv list with shell=False. Returns (ok, message)."""
    if not argv or not isinstance(argv, list):
        return False, f"malformed undo (expected argv list, got {type(argv).__name__})"
    # With `-e 2` loaded the kernel refuses any rule change until reboot, so a
    # load can't succeed. Regenerate audit.rules from the restored rules.d
    # instead; the reverted rules take effect at the next boot.
    if argv == ["augenrules", "--load"]:
        if shutil.which("augenrules") is None:
            return True, "auditd no longer installed — no audit rules to reload"
        if auditrules.immutable():
            argv = ["augenrules"]
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
        # Undo must be safe to retry: an override already removed is the goal.
        if argv[:2] == ["dpkg-statoverride", "--remove"] and exc.returncode == 2 \
                and "no override present" in (exc.stderr or ""):
            return True, " ".join(argv) + " (already removed)"
        msg = (exc.stderr or "").strip().splitlines()[-1] if exc.stderr else f"exit {exc.returncode}"
        return False, f"{' '.join(argv)} → {msg}"


def run_rollback(args) -> int:
    """Undo a previous harden run."""
    run_id = None
    if args.run_id:
        if not re.fullmatch(r"[0-9TZ]+-[0-9a-f]{8}", args.run_id):
            err(f"malformed run id: {args.run_id}")
            return 1
        run_id = args.run_id
    else:  # --last, or --rule: the most recent run not yet fully rolled back
        runs = journal.list_runs()
        if not runs:
            err("no harden runs found in journal")
            return 1
        run_id = next((r for r in runs if (d := journal.read_run(r)) and journal.pending_controls(d)), None)
        if run_id is None:
            info("every harden run in the journal is already rolled back")
            return 0

    run_data = journal.read_run(run_id)
    if not run_data:
        err(f"journal not found for run: {run_id}")
        return 1

    info(f"Rolling back run: {run_data['run_id']}  ({run_data['timestamp']})")
    syslog.info(
        f"rollback start run_id={run_data['run_id']} "
        f"target={'rule:' + args.rule if args.rule else 'all'}"
    )

    controls = journal.pending_controls(run_data)
    if not controls:
        info(f"run {run_data['run_id']} is already rolled back")
        return 0

    if args.rule:
        args.rule = args.rule.upper()
        if args.rule not in controls:
            done = args.rule in run_data.get("controls", {})
            err(f"rule {args.rule} {'already rolled back in' if done else 'not found in'} run {run_data['run_id']}")
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
    try:
        run_ts = datetime.fromisoformat(run_data["timestamp"]).timestamp()
    except (KeyError, TypeError, ValueError):
        run_ts = None
    restored: set[str] = set()
    for control_id, entries in reversed(list(controls.items())):
        errors_before = errors
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
                # A path several rules edited is restored once per rule, newest
                # first; only the first restore can find post-run edits.
                ok, msg = _restore_backup(control_id, backup, path, None if path in restored else run_ts)
                restored.add(path)
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
        # Marked per rule, not at the end: a rollback killed halfway (a dropped
        # session, a reboot) must not replay the rules it already undid.
        # Rules whose undo failed stay pending, so a retry redoes only those.
        if errors == errors_before:
            journal.mark_rolled_back(run_data["run_id"], [control_id])

    if any(a == ["augenrules", "--load"] for es in controls.values()
           for e in es if isinstance(e.get("undo"), list) for a in e["undo"]) and auditrules.immutable():
        warn("audit rules are locked until reboot (-e 2) — the restored rules take effect at the next boot")

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
