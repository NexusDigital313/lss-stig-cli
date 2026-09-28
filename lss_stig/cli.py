"""lss-stig command line."""

from __future__ import annotations

import argparse
import os
import signal
import sys

from lss_stig import __version__, benchmarks


def _rule_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--rule", metavar="ID", action="append",
                   help="limit to a rule (V-ID, UBTU-24-xxxxxx or SV rule ID); repeatable")
    p.add_argument("--cat", metavar="I|II|III", action="append", choices=["I", "II", "III"],
                   help="limit to a severity category; repeatable")
    p.add_argument("--skip", metavar="ID", action="append",
                   help="leave out a rule (any ID form); repeatable")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lss-stig",
        description="Audit, harden and roll back Linux hosts against DISA STIGs.",
    )
    p.add_argument("-V", "--version", action="version", version=f"lss-stig {__version__}")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("--theme", choices=("default", "dod"),
                   help="output style; dod = DISA-tool conventions (also LSS_STIG_THEME=dod)")
    p.add_argument("--benchmark", metavar="KEY", choices=sorted(benchmarks.SUPPORTED),
                   help="STIG benchmark (default: detected from the host)")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    a = sub.add_parser("audit", help="check the host (read-only) and write a CKLB checklist")
    _rule_args(a)
    a.add_argument("--json", action="store_true", help="print the full result record as JSON")
    a.add_argument("-o", "--output", metavar="PATH", help="checklist path (default: ~/.local/share/lss-stig/checklists/)")
    a.add_argument("--no-checklist", action="store_true", help="don't write a .cklb file")
    a.add_argument("-v", "--verbose", action="store_true", help="list passing and not-applicable rules too")

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

    st = sub.add_parser("site", help="show or set site values (time source, audit collector, admin email)")
    st.add_argument("assign", nargs="*", metavar="KEY=VALUE", help="e.g. time_server=tick.usno.navy.mil")

    lic = sub.add_parser("license", help="install, inspect or remove this host's license")
    lsub = lic.add_subparsers(dest="license_cmd", metavar="ACTION")
    lsub.add_parser("status", help="show the license state (default)")
    li = lsub.add_parser("install", help="install a license file")
    li.add_argument("file")
    lsub.add_parser("id", help="print this host's ID, for a host-bound license")
    lsub.add_parser("remove", help="remove this host's license")
    return p


def _run_license(args) -> int:
    from lss_stig.lib import license
    from lss_stig.lib.output import BOLD, GRAY, GREEN, RED, RESET, err, info
    cmd = args.license_cmd or "status"
    if cmd == "id":
        print(license.host_id())
        return 0
    if os.geteuid() != 0:
        err(f"lss-stig license {cmd} needs root (the license lives in {license.CONF_DIR})")
        return 1
    if cmd == "install":
        try:
            with open(args.file, encoding="utf-8", errors="replace") as f:
                text = f.read(4 << 20)
        except OSError as exc:
            err(f"{args.file}: {exc.strerror}")
            return 1
        st = license.install_offline(text)
    elif cmd == "remove":
        st = license.remove()
        (info if st.valid else err)(st.detail)
        return 0 if st.valid else 1
    else:
        st = license.check()
    mark = f"{GREEN}●{RESET}" if st.valid else f"{RED}●{RESET}"
    print(f"\n  {mark} {BOLD}{st.detail}{RESET}")
    for label, val in (("Tier", st.tier), ("Licensee", st.licensee), ("Expires", st.expires),
                       ("Source", st.source), ("Host ID", license.host_id())):
        if val:
            print(f"    {GRAY}{label:<9}{RESET} {val}")
    if not st.valid:
        print(f"\n  {GRAY}Free without a license: audit, checklists, harden --dry-run, rollback.{RESET}")
        print(f"  {GRAY}Send `lss-stig license id` to get a license file, then:{RESET}")
        print(f"  {GRAY}  sudo lss-stig license install <file.lic>{RESET}")
    print()
    return 0 if st.valid else 1


def _require_license() -> None:
    from lss_stig.lib import license
    from lss_stig.lib.output import err
    st = license.check()
    if st.valid:
        return
    err(f"harden --confirm needs a license: {st.detail}")
    err("  preview for free:  sudo lss-stig harden --dry-run")
    err("  details:           sudo lss-stig license")
    sys.exit(3)


def _run_site(args) -> int:
    from lss_stig.lib import site
    from lss_stig.lib.output import BOLD, GRAY, RESET, err, info
    if args.assign:
        if os.geteuid() != 0:
            err("setting site values needs root")
            return 1
        values = {}
        for a in args.assign:
            key, sep, val = a.partition("=")
            key, val = key.strip(), val.strip()
            problem = "expected KEY=VALUE" if not sep or not val else site.validate(key, val)
            if problem:
                err(f"{a}: {problem}")
                return 2
            values[key] = val
        site.write(values)
        for k, v in values.items():
            info(f"{k} = {v}")
        info("Re-run `sudo lss-stig audit` to see the rules these unblock.")
        return 0
    print(f"  {GRAY}{site.SITE_CONF}{RESET}")
    for key, what in site.KEYS.items():
        print(f"  {BOLD}{key:<20}{RESET} {site.get(key) or GRAY + '(not set)' + RESET}\n  {GRAY}{'':<20} {what}{RESET}")
    return 0


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


class _Tolerant:
    """Stream wrapper that stops writing once the terminal is gone instead of
    raising EIO/EPIPE into the middle of a fix or an undo."""

    def __init__(self, stream):
        self._s, self._dead = stream, False

    def write(self, data):
        if not self._dead:
            try:
                return self._s.write(data)
            except OSError:
                self._dead = True
        return len(data)

    def flush(self):
        if not self._dead:
            try:
                self._s.flush()
            except OSError:
                self._dead = True

    def __getattr__(self, name):
        return getattr(self._s, name)


def _survive_disconnect() -> None:
    # Harden and rollback restart sshd, reload the firewall and run apt: a
    # dropped SSH session must not SIGHUP them halfway through a change (seen
    # on a 24.04 VM — the rollback finished, but only because it was lucky).
    # Line-buffer so output redirected to a file survives an abrupt end.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
        setattr(sys, name, _Tolerant(stream))


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    from lss_stig.lib import output
    if args.theme:
        output.set_theme(args.theme)
    if args.no_color:
        output.disable_color()
    if not args.command:
        build_parser().print_help()
        sys.exit(0)
    if args.command == "site":
        sys.exit(_run_site(args))
    if args.command == "license":
        sys.exit(_run_license(args))

    key = _resolve_benchmark(args)
    bench = benchmarks.activate(key)

    if args.command == "list":
        sys.exit(_run_list(args, bench))

    if os.geteuid() != 0:
        output.err(f"lss-stig {args.command} must run as root (it reads /etc/shadow, sssd.conf, ...)")
        sys.exit(1)

    if args.command == "harden" and args.confirm:
        _require_license()
    if args.command in ("harden", "rollback"):
        _survive_disconnect()

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
