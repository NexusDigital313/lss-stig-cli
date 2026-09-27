"""Terminal output — standard library only.

STIG'd hosts are frequently air-gapped with no PyPI access, so lss-stig has
no third-party runtime dependencies. Color is plain ANSI, auto-disabled when
stdout is not a TTY, when NO_COLOR is set, or with --no-color.
"""

from __future__ import annotations

import os
import sys

from lss_stig import __version__

_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str) -> str:
    return f"\033[{code}m" if _color else ""


def _refresh():
    global RED, GREEN, YELLOW, BLUE, CYAN, GRAY, BOLD, DIM, RESET
    RED, GREEN, YELLOW = _c("31"), _c("32"), _c("33")
    BLUE, CYAN, GRAY = _c("38;5;75"), _c("36"), _c("38;5;245")
    BOLD, DIM, RESET = _c("1"), _c("2"), _c("0")


_refresh()


def disable_color() -> None:
    global _color
    _color = False
    _refresh()


def banner(subtitle: str = "") -> None:
    print(f"\n  {BOLD}LSS · STIG{RESET}  {GRAY}v{__version__}{RESET}")
    if subtitle:
        print(f"  {GRAY}{subtitle}{RESET}")
    print(f"  {GRAY}{'─' * 60}{RESET}")


def header(text: str) -> None:
    print(f"\n{BOLD}{BLUE}{text}{RESET}")


def info(msg: str) -> None:
    print(f"{CYAN}::{RESET} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}!!{RESET} {msg}", file=sys.stderr)


def err(msg: str) -> None:
    print(f"{RED}error:{RESET} {msg}", file=sys.stderr)


_SYMBOL = {
    "pass":   ("✓", "GREEN"),
    "fail":   ("✗", "RED"),
    "manual": ("◐", "YELLOW"),
    "review": ("?", "YELLOW"),
    "na":     ("-", "GRAY"),
    "unimpl": ("·", "GRAY"),
}

_CAT_COLOR = {"CAT I": "RED", "CAT II": "YELLOW", "CAT III": "GRAY"}


def result_line(rule, status: str, detail: str = "") -> None:
    sym, color = _SYMBOL.get(status, ("✗", "RED"))
    col = globals()[color]
    cat = rule.category
    catc = globals()[_CAT_COLOR.get(cat, "GRAY")]
    line = (f"  {col}{sym}{RESET} {catc}{cat:<7}{RESET} {BOLD}{rule.vuln_id}{RESET} "
            f"{GRAY}{rule.stig_id}{RESET}  {_short(rule.title)}")
    if detail:
        line += f"  {DIM}({detail}){RESET}"
    print(line)


def _short(title: str, width: int = 78) -> str:
    # DISA titles all open with "Ubuntu 24.04 LTS ..." — drop the subject,
    # the operator knows which host they're on.
    if title.startswith("Ubuntu 24.04 LTS"):
        title = title[len("Ubuntu 24.04 LTS"):].lstrip(" ,")
        title = title[:1].upper() + title[1:]
    return title if len(title) <= width else title[: width - 1] + "…"


def summary(counts: dict[str, int], by_cat_open: dict[str, int]) -> None:
    header("Summary")
    total = sum(counts.values())
    print(f"  {GREEN}Not a finding{RESET}  {counts.get('pass', 0):>4}")
    print(f"  {RED}Open{RESET}           {counts.get('fail', 0) + counts.get('manual', 0):>4}"
          f"   {GRAY}({counts.get('fail', 0)} auto-fixable, {counts.get('manual', 0)} need you){RESET}")
    print(f"  {YELLOW}Needs review{RESET}   {counts.get('review', 0):>4}"
          f"   {GRAY}(evidence collected, verdict is organizational){RESET}")
    print(f"  {GRAY}Not applicable{RESET} {counts.get('na', 0):>4}")
    print(f"  {GRAY}Not reviewed{RESET}   {counts.get('unimpl', 0):>4}"
          f"   {GRAY}(no automated check yet){RESET}")
    print(f"  {GRAY}{'─' * 20}{RESET}\n  Total          {total:>4}")
    if any(by_cat_open.values()):
        parts = [f"{globals()[_CAT_COLOR[c]]}{c}: {n}{RESET}" for c, n in by_cat_open.items() if n]
        print(f"\n  Open findings by category: " + "   ".join(parts))
