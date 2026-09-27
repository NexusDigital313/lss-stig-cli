"""lss-stig command line."""

from __future__ import annotations

import argparse
import os
import sys

from lss_stig import __version__, benchmarks


def _rule_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rule", metavar="ID", action="append",
                   help="limit to a rule (V-ID, UBTU-24-xxxxxx or SV rule ID); repeatable")
    p.add_argument("--cat", metavar="I|II|III", action="append", choices=["I", "II", "III"],
                   help="limit to a severity category; repeatable")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lss-stig",
        description="Audit, harden and roll back Linux hosts against DISA STIGs.",
    )
    p.add_argument("-V", "--version", action="version", version=f"lss-stig {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--benchmark", metavar="KEY", choices=sorted(benchmarks.SUPPORTED),
                   help="STIG benchmark (default: detected from the host)")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    a = sub.add_parser("audit", help="check the host (read-only) and write a CKLB checklist")
    _rule_args(a)
    a.add_argument("--json", action="store_true", help="print the full result record as JSON")
    a.add_argument("-o", "--output", metavar="PATH", help="checklist path (default: ~/.local/share/lss-stig/checklists/)")
    a.add_argument("--no-checklist", action="store_true", help="don't write a .cklb file")

    h = sub.add_parser("harden", help="fix open findings that have a safe automatic fix")
    mode = h.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="show what would change")
    mode.add_argument("--confirm", action="store_true", help="apply the changes")
    h.add_argument("-i", "--interactive", action="store_true", help="ask before each fix")
    _rule_args(h)

    r = sub.add_parser("rollback", help="undo a harden run")
    which = r.add_mutually_exclusive_group(required=True)
    which.add_argument("--last", action="store_true", help="undo the most recent run")
    which.add_argument("--run-id", metavar="ID", help="undo a specific run")
    which.add_argument("--rule", metavar="V-ID", help="undo one rule from the most recent run")

    c = sub.add_parser("checklist", help="rebuild a CKLB checklist from a saved audit")
    c.add_argument("--from", dest="source", metavar="AUDIT_JSON",
                   help="audit record (default: /var/log/lss-stig/audit-latest.json)")
    c.add_argument("-o", "--output", metavar="PATH", required=True, help="where to write the .cklb")

    ls = sub.add_parser("list", help="list the benchmark's rules and which are automated")
    ls.add_argument("--cat", metavar="I|II|III", action="append", choices=["I", "II", "III"])
    ls.add_argument("--automated", action="store_true", help="only rules with an automated check")
    return p


def _resolve_benchmark(args) -> str:
    from lss_stig.lib import distro
    from lss_stig.lib.output import err
    key = args.benchmark or benchmarks.for_host()
    if key is None:
        err(f"no STIG benchmark for this host ({distro.detect().name}). "
            f"Supported: {', '.join(benchmarks.SUPPORTED)} — force one with --benchmark.")
        sys.exit(2)
    return key


def _run_list(args, bench) -> int:
    from lss_stig.lib.output import BOLD, GRAY, GREEN, RESET
    from lss_stig.lib.registry import get_control, select_rules
    rules = select_rules(bench, None, args.cat)
    shown = 0
    for r in rules:
        c = get_control(bench.key, r.vuln_id)
        if args.automated and c is None:
            continue
        tag = f"{GREEN}check+fix{RESET}" if c and c.fix else f"{GREEN}check{RESET}    " if c else f"{GRAY}manual{RESET}   "
        print(f"  {r.category:<7} {BOLD}{r.vuln_id}{RESET} {GRAY}{r.stig_id}{RESET}  {tag}  {r.title}")
        shown += 1
    auto = sum(1 for r in bench.rules if get_control(bench.key, r.vuln_id))
    print(f"\n  {bench.label}: {len(bench.rules)} rules, {auto} automated · showing {shown}")
    return 0


def _run_checklist(args, bench) -> int:
    from pathlib import Path
    from lss_stig import checklist
    from lss_stig.audit import load_record
    from lss_stig.lib.output import err, info
    rec = load_record(args.source)
    if rec["benchmark"]["key"] != bench.key:
        err(f"audit was run against {rec['benchmark']['key']}, not {bench.key}")
        return 2
    results = {r["vuln_id"]: r for r in rec["results"]}
    out = checklist.write(checklist.build(bench, results), Path(args.output))
    info(f"Checklist written: {out}")
    return 0


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    from lss_stig.lib import output
    if args.no_color:
        output.disable_color()
    if not args.command:
        build_parser().print_help()
        sys.exit(0)

    key = _resolve_benchmark(args)
    bench = benchmarks.activate(key)

    if args.command == "list":
        sys.exit(_run_list(args, bench))

    if os.geteuid() != 0:
        output.err(f"lss-stig {args.command} must run as root (it reads /etc/shadow, sssd.conf, ...)")
        sys.exit(1)

    try:
        if args.command == "audit":
            from lss_stig.audit import run_audit
            sys.exit(run_audit(args, bench))
        if args.command == "harden":
            from lss_stig.harden import run_harden
            sys.exit(run_harden(args, bench))
        if args.command == "rollback":
            from lss_stig.rollback import run_rollback
            sys.exit(run_rollback(args))
        if args.command == "checklist":
            sys.exit(_run_checklist(args, bench))
    except ValueError as exc:   # unknown --rule etc.
        output.err(str(exc))
        sys.exit(2)
