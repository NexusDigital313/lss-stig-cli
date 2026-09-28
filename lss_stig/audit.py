"""Audit engine — evaluates every rule in the benchmark, read-only."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

from lss_stig import __version__, checklist
from lss_stig.lib import distro, output, paths, site
from lss_stig.lib.output import banner, info, summary, warn
from lss_stig.lib.registry import CATEGORY, Benchmark, CheckResult, get_control, select_rules

RESULTS_DIR = Path("/var/log/lss-stig")


def evaluate(bench: Benchmark, rule) -> CheckResult:
    ctrl = get_control(bench.key, rule.vuln_id)
    if ctrl is None:
        return CheckResult("unimpl")
    try:
        r = ctrl.check()
    except Exception as exc:  # a broken check must not hide as a pass
        return CheckResult("manual", f"check error: {exc}")
    # A failing rule we can't fix automatically is the operator's to resolve.
    if r.status == "fail" and ctrl.fix is None:
        r.status = "manual"
    return r


def run_audit(args, bench: Benchmark) -> int:
    rules = select_rules(bench, args.rule, args.cat, args.skip)
    json_mode = args.json

    if not json_mode:
        automated = sum(1 for r in rules if get_control(bench.key, r.vuln_id))
        banner(f"{bench.label} · {distro.detect().name} · {len(rules)} rules ({automated} automated) · read-only")

    results: dict[str, dict] = {}
    rows = []
    counts = {s: 0 for s in ("pass", "fail", "manual", "review", "na", "unimpl")}
    open_by_cat = {c: 0 for c in CATEGORY.values()}
    total_by_cat = {c: 0 for c in CATEGORY.values()}
    pass_by_cat = {c: 0 for c in CATEGORY.values()}

    order = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(rules, key=lambda r: (order.get(r.severity, 3), r.vuln_id))
    for i, rule in enumerate(ordered, 1):
        if not json_mode:
            output.progress(i, len(ordered), rule.vuln_id)
        r = evaluate(bench, rule)
        results[rule.vuln_id] = {
            "vuln_id": rule.vuln_id, "rule_id": rule.rule_id, "stig_id": rule.stig_id,
            "severity": rule.severity, "status": r.status, "detail": r.detail,
            "evidence": r.evidence,
        }
        counts[r.status] = counts.get(r.status, 0) + 1
        if r.status not in ("na", "unimpl"):
            total_by_cat[rule.category] += 1
        if r.status == "pass":
            pass_by_cat[rule.category] += 1
        if r.status in ("fail", "manual"):
            open_by_cat[rule.category] += 1
        rows.append((rule, output.area_of(get_control(bench.key, rule.vuln_id)), r.status, r.detail))
    if not json_mode:
        output.progress_done()

    record = _save(bench, results, counts)
    cklb_path = None
    if not args.no_checklist:
        cklb_path = _write_checklist(bench, results, args.output)

    if json_mode:
        print(json.dumps(record, indent=2))
        return 1 if counts["fail"] or counts["manual"] else 0

    output.cascade(rows, verbose=getattr(args, "verbose", False))
    summary(counts, open_by_cat, total_by_cat, pass_by_cat)
    print()
    if cklb_path:
        info(f"Checklist for STIG Viewer 3 / eMASS: {cklb_path}")
    steps = []
    if counts["fail"]:
        steps.append(("sudo lss-stig harden --dry-run", f"preview {counts['fail']} automatic fixes"))
        steps.append(("sudo lss-stig harden --confirm", "apply them · every change is journaled"))
    if any(site.is_blocked(r[3]) for r in rows):
        steps.append(("sudo lss-stig site", "set the site values some rules are waiting on"))
    if not getattr(args, "verbose", False):
        steps.append(("sudo lss-stig audit -v", "list passing rules too"))
    output.next_steps(steps)
    print()
    return 1 if counts["fail"] or counts["manual"] else 0


def _save(bench: Benchmark, results: dict, counts: dict) -> dict:
    host = distro.detect()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    record = {
        "tool": f"lss-stig {__version__}",
        "timestamp": ts,
        "benchmark": {"key": bench.key, "stig_id": bench.stig_id, "version": bench.version,
                      "release_info": bench.release_info},
        "host": {"name": host.name, "id": host.id, "version": host.version, "kernel": host.kernel},
        "summary": counts,
        "results": list(results.values()),
    }
    try:
        RESULTS_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        out = RESULTS_DIR / f"audit-{ts}.json"
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(record, f, indent=2)
        latest = RESULTS_DIR / "audit-latest.json"
        tmp = RESULTS_DIR / "audit-latest.json.new"
        tmp.unlink(missing_ok=True)
        tmp.symlink_to(out.name)
        os.replace(tmp, latest)
    except OSError as exc:
        warn(f"could not save audit record to {RESULTS_DIR}: {exc}")
    return record


def _write_checklist(bench: Benchmark, results: dict, output: str | None) -> Path | None:
    if output:
        path = Path(output)
    else:
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        path = paths.default_checklist_dir() / f"{bench.key}-{ts}.cklb"
        paths.ensure_user_dir(path.parent)
    try:
        checklist.write(checklist.build(bench, results), path)
        paths.chown_to_invoking_user(path)
        return path
    except OSError as exc:
        warn(f"could not write checklist {path}: {exc}")
        return None


def load_record(path: str | None) -> dict:
    p = Path(path) if path else RESULTS_DIR / "audit-latest.json"
    return json.loads(p.read_text())
