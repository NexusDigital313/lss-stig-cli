"""Rule catalog + control registry.

Two layers, kept separate on purpose:

  * The catalog (lss_stig/benchmarks/*.json) is DISA's content: every rule in
    the STIG release with its IDs, severity and check/fix text. It is imported
    verbatim from the XCCDF and never hand-edited.
  * Controls are our implementations: a read-only check() and an optional
    fix(), registered against a catalog rule by its Vuln ID (V-xxxxxx).

Every catalog rule is always reported. A rule with no registered control is
"not_reviewed" — the checklist stays complete and honest instead of silently
shrinking to what we happen to automate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

BENCHMARK_DIR = Path(__file__).resolve().parent.parent / "benchmarks"

# DISA severity → Category. CAT I = direct path to compromise.
CATEGORY = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}

# Result statuses (internal) and their CKLB equivalents.
#   pass    — requirement met                       → not_a_finding
#   fail    — not met; `harden` has a fix           → open
#   manual  — not met, or needs a human decision;   → open / not_reviewed
#             no safe automatic fix
#   review  — automated evidence gathered, but the  → not_reviewed
#             verdict is organizational (e.g. "only
#             users who need it are in sudo")
#   na      — not applicable on this host           → not_applicable
#   unimpl  — no automated check yet                → not_reviewed
STATUSES = ("pass", "fail", "manual", "review", "na", "unimpl")


@dataclass
class RollbackEntry:
    """One reversible action recorded during hardening.

    `undo` is a list of argv lists run with shell=False. If `backup` is set it
    is restored to `path` first, then each undo runs in order.
    """
    action: str
    undo: list[list[str]] = field(default_factory=list)
    path: str = ""
    backup: str = ""


@dataclass
class CheckResult:
    status: str
    detail: str = ""     # one line, shown in the terminal
    evidence: str = ""   # what we looked at — becomes CKLB finding_details


@dataclass(frozen=True)
class Rule:
    """One STIG rule from the catalog (read-only DISA metadata)."""
    vuln_id: str        # V-270647
    rule_id: str        # SV-270647r1066436_rule
    stig_id: str        # UBTU-24-100030
    severity: str       # high | medium | low
    title: str
    raw: dict           # full catalog entry, used for CKLB export

    @property
    def category(self) -> str:
        return CATEGORY.get(self.severity, self.severity)


@dataclass
class Benchmark:
    key: str
    stig_id: str
    stig_name: str
    version: str
    release_info: str
    rules: list[Rule]

    @property
    def label(self) -> str:
        """e.g. 'Ubuntu 24.04 V1R6'."""
        rel = self.release_info.split("Benchmark")[0].replace("Release:", "").strip()
        return f"{_SHORT_NAMES.get(self.key, self.stig_name)} V{self.version}R{rel}"


_SHORT_NAMES = {"ubuntu2404_v1r6": "Ubuntu 24.04"}


@lru_cache(maxsize=None)
def load_benchmark(key: str) -> Benchmark:
    data = json.loads((BENCHMARK_DIR / f"{key}.json").read_text())
    rules = [
        Rule(
            vuln_id=r["group_id"],
            rule_id=r["rule_id_src"],
            stig_id=r["rule_version"],
            severity=r["severity"],
            title=r["rule_title"],
            raw=r,
        )
        for r in data["rules"]
    ]
    return Benchmark(
        key=key,
        stig_id=data["stig_id"],
        stig_name=data["stig_name"],
        version=data["version"],
        release_info=data["release_info"],
        rules=rules,
    )


@dataclass
class Control:
    """Our implementation of one catalog rule."""
    vuln_id: str
    check: Callable[[], CheckResult]
    fix: Callable[[], list[RollbackEntry]] | None = None
    # Human-readable warning shown before harden applies this fix, for fixes
    # that can take away something the operator may be using (a service, a
    # package, an account). None for routine config changes.
    impact: str | None = None


_controls: dict[str, dict[str, Control]] = {}


def register(benchmark: str, control: Control) -> None:
    bench = load_benchmark(benchmark)
    if not any(r.vuln_id == control.vuln_id for r in bench.rules):
        raise ValueError(f"{control.vuln_id} is not a rule in {benchmark}")
    slot = _controls.setdefault(benchmark, {})
    if control.vuln_id in slot:
        raise ValueError(f"{control.vuln_id} registered twice for {benchmark}")
    slot[control.vuln_id] = control


def get_control(benchmark: str, vuln_id: str) -> Control | None:
    return _controls.get(benchmark, {}).get(vuln_id)


def select_rules(bench: Benchmark, ids: list[str] | None = None,
                 categories: list[str] | None = None, skip: list[str] | None = None) -> list[Rule]:
    """Filter rules by any ID form (V-ID, SV rule ID, or UBTU STIG ID) and/or
    category ("I", "II", "III"). Raises ValueError on an unknown ID so a typo
    never silently audits nothing."""
    rules = bench.rules
    if categories:
        wanted = {f"CAT {c.upper().replace('CAT', '').strip()}" for c in categories}
        rules = [r for r in rules if r.category in wanted]
    if ids:
        idx: dict[str, Rule] = {}
        for r in bench.rules:
            idx[r.vuln_id.upper()] = r
            idx[r.stig_id.upper()] = r
            idx[r.rule_id.upper()] = r
        picked = []
        for i in ids:
            r = idx.get(i.strip().upper())
            if r is None:
                raise ValueError(f"unknown rule: {i}")
            picked.append(r)
        keep = {r.vuln_id for r in picked}
        rules = [r for r in rules if r.vuln_id in keep]
    if skip:
        drop = {r.vuln_id for r in select_rules(bench, skip)}
        rules = [r for r in rules if r.vuln_id not in drop]
    return rules
