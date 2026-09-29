"""Harden engine — fixes open findings that have a safe automatic fix, and
journals every change so `lss-stig rollback` can reverse it."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from lss_stig.lib import distro, journal, output, pkg, syslog
from lss_stig.lib.output import DIM, RESET, YELLOW, banner, err, header, info, warn
from lss_stig.lib.registry import Benchmark, get_control, select_rules
from lss_stig.audit import evaluate


def _save_partial(run_id: str, entries: dict) -> None:
    if not entries:
        return
    try:
        info(f"Partial run journaled at: {journal.write_run(run_id, entries)}")
    except Exception as exc:
        fallback = Path(f"/root/lss-stig-emergency-journal-{os.getpid()}-{run_id}.json")
        try:
            fallback.write_text(json.dumps(entries, indent=2, default=str))
            err(f"journal write failed ({exc}); emergency copy at {fallback}")
        except Exception as exc2:
            err(f"journal AND emergency copy failed ({exc2}) — applied changes have NO rollback record")


def run_harden(args, bench: Benchmark) -> int:
    dry_run, interactive = args.dry_run, args.interactive
    if interactive and not (sys.stdin.isatty() and sys.stdout.isatty()):
        err("--interactive needs a terminal on stdin and stdout")
        return 1

    host = distro.detect()
    banner(f"Host: {host.name} | {'dry run - no changes' if dry_run else 'hardening'}", bench)

    rules = [r for r in select_rules(bench, args.rule, args.cat, args.skip)
             if (c := get_control(bench.key, r.vuln_id)) is not None and c.fix is not None]

    impacts = [(r, get_control(bench.key, r.vuln_id).impact) for r in rules
               if get_control(bench.key, r.vuln_id).impact]
    if impacts and not dry_run:
        warn("These fixes can take away something in use on this host:")
        for r, text in impacts:
            warn(f"    {r.vuln_id}  {text}")
        warn("Leave any out with --skip <ID>, or preview with --dry-run.")

    if not dry_run and (bad := pkg.dpkg_interrupted()):
        warn("dpkg reports an interrupted install — package fixes will be refused until you run:")
        warn("    sudo dpkg --configure -a")
        warn(f"    ({bad.splitlines()[0]})")

    run_id = journal.new_run_id()
    if not dry_run:
        journal.set_current_run_id(run_id)
        syslog.info(f"harden start run_id={run_id} benchmark={bench.key}")
        info(f"Run ID: {run_id}")

    header("Plan" if dry_run else "Applying")
    entries: dict[str, list[dict]] = {}
    fixed = still_open = errors = would = declined = skipped = 0
    aborted = False

    for rule in rules:
        ctrl = get_control(bench.key, rule.vuln_id)
        before = evaluate(bench, rule)
        if before.status != "fail":
            skipped += 1
            continue

        if dry_run:
            output.step("→", "YELLOW", rule, before.detail)
            would += 1
            continue

        if interactive:
            print(f"\n  {YELLOW}?{RESET} {rule.vuln_id} {rule.stig_id} {rule.title}")
            print(f"    {DIM}now: {before.detail}{RESET}")
            if ctrl.impact:
                warn(f"    impact: {ctrl.impact}")
            try:
                if input("    Apply fix? [y/N] ").strip().lower() not in ("y", "yes"):
                    declined += 1
                    continue
            except (EOFError, KeyboardInterrupt):
                print()
                err("aborted at prompt — nothing further will be applied")
                _save_partial(run_id, entries)
                journal.set_current_run_id(None)
                return 130

        try:
            applied = ctrl.fix()
            entries[rule.vuln_id] = [
                {"action": e.action, "undo": e.undo, "path": e.path, "backup": e.backup}
                for e in applied
            ]
            # Flush after every fix so a hard kill still leaves a usable journal.
            try:
                journal.write_run(run_id, entries)
            except Exception:
                pass
            after = evaluate(bench, rule)
            if after.status == "pass":
                output.step("✓", "GREEN", rule, f"was: {before.detail}")
                syslog.info(f"harden run_id={run_id} rule={rule.vuln_id} status=fixed")
                fixed += 1
            else:
                output.step("◐", "YELLOW", rule, f"fix applied, still {after.status}: {after.detail}")
                syslog.warn(f"harden run_id={run_id} rule={rule.vuln_id} status=still-{after.status}")
                still_open += 1
        except KeyboardInterrupt:
            aborted = True
            break
        except Exception as exc:
            output.step("✗", "RED", rule, f"fix error: {exc}")
            syslog.err(f"harden run_id={run_id} rule={rule.vuln_id} error={exc!r}")
            errors += 1

    if dry_run:
        output.tally([("→", "YELLOW", would, "would be fixed"),
                      ("·", "GRAY", skipped, "already compliant or not auto-fixable")])
        output.next_steps([("sudo lss-stig harden --confirm", f"apply these {would} fixes")] if would else [])
        print()
        return 0

    jpath = journal.write_run(run_id, entries)
    journal.set_current_run_id(None)
    output.tally([("✓", "GREEN", fixed, "fixed"), ("◐", "YELLOW", still_open, "still Open"),
                  ("✗", "RED", errors, "errors"), ("·", "GRAY", skipped, "skipped")]
                 + ([("-", "GRAY", declined, "declined")] if interactive else []))
    syslog.info(f"harden done run_id={run_id} fixed={fixed} open={still_open} errors={errors}")
    if entries:
        info(f"Journal: {jpath}")
        output.next_steps([("sudo lss-stig audit", "verify and write a fresh checklist"),
                           ("sudo lss-stig rollback --last", "undo this run")])
    print()
    if aborted:
        err("interrupted — changes so far are journaled; undo with: sudo lss-stig rollback --last")
        return 130
    return 1 if errors or still_open else 0
