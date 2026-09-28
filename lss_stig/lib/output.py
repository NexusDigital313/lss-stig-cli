"""Terminal output — standard library only.

STIG'd hosts are frequently air-gapped with no PyPI access, so lss-stig has
no third-party runtime dependencies. Color is plain ANSI, auto-disabled when
stdout is not a TTY, when NO_COLOR is set, or with --no-color.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

from lss_stig import __version__

_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
# "default": the LSS look. "dod": DISA-tool conventions — 8 standard colors,
# no wordmark or plates, STIG Viewer status words, CAT I (High) severities.
_theme = "dod" if os.environ.get("LSS_STIG_THEME", "").lower() == "dod" else "default"


def _c(code: str) -> str:
    return f"\033[{code}m" if _color else ""


def _refresh():
    # Red, orange and white on black. The names are roles: GREEN = good/done
    # (bright white), YELLOW = needs attention (orange), BLUE/CYAN = accent.
    global RED, GREEN, YELLOW, BLUE, CYAN, GRAY, EMBER, BOLD, DIM, RESET, CHROME, PLATE
    RED, GREEN, YELLOW = _c("38;5;196"), _c("1;38;5;231"), _c("38;5;214")
    BLUE = CYAN = _c("38;5;208")
    GRAY, EMBER = _c("38;5;250"), _c("38;5;124")      # body text; rules and tree lines
    CHROME = [_c("38;5;231"), _c("38;5;214"), _c("38;5;196")]   # wordmark: white-hot to red
    PLATE = {"CAT I": _c("1;38;5;231;48;5;160"), "CAT II": _c("1;38;5;16;48;5;208"),
             "CAT III": _c("1;38;5;16;48;5;255"), "": _c("1;38;5;231;48;5;160")}
    BOLD, DIM, RESET = _c("1"), _c("2"), _c("0")
    if _theme == "dod":
        RED, GREEN, YELLOW = _c("31"), _c("32"), _c("33")
        BLUE = CYAN = _c("36")
        GRAY = EMBER = ""
        CHROME = ["", "", ""]


_refresh()


def set_theme(name: str) -> None:
    global _theme
    _theme = name
    _refresh()


def _dod() -> bool:
    return _theme == "dod"


_SEVERITY = {"CAT I": "High", "CAT II": "Medium", "CAT III": "Low"}


def cat_label(cat: str) -> str:
    return f"{cat} ({_SEVERITY[cat]})" if _dod() and cat in _SEVERITY else cat


def disable_color() -> None:
    global _color
    _color = False
    _refresh()


_WORDMARK = ("█   █▀▀ █▀▀   █▀▀ ▀█▀ █ █▀▀▀",
             "█   ▀▀█ ▀▀█   ▀▀█  █  █ █ ▀█",
             "▀▀▀ ▀▀▀ ▀▀▀   ▀▀▀  ▀  ▀ ▀▀▀▀")


def banner(subtitle: str = "") -> None:
    from lss_stig import _edition
    tag = f"{YELLOW}owner build · unlicensed{RESET}" if _edition.EDITION == "owner" else ""
    width = _width()
    if _color and not _dod():
        side = [f"{GREEN}v{__version__}{RESET}", f"{RED}▌{RESET}{BOLD}DISA STIG{RESET}",
                f"{BLUE}THE LINUX SECURITY SUITE{RESET}"]
        print()
        for row, shade, extra in zip(_WORDMARK, CHROME, side):
            print(f"  {shade}{BOLD}{row}{RESET}   {extra}")
        if tag:
            print(f"  {tag}")
    else:
        print(f"\n  LSS STIG  v{__version__}" + (f"  {tag}" if tag else ""))
    if subtitle:
        print(f"  {GRAY}{_clip(subtitle, width - 3)}{RESET}")
    if _dod():
        print(f"  {'─' * (width - 4)}")
    else:
        print(f"  {BLUE}▪{EMBER}{'━' * (width - 6)}{BLUE}▪{RESET}")


def header(text: str) -> None:
    print(f"\n  {_plate(text.upper())}")


def _plate(text: str, kind: str = "") -> str:
    """A label on a solid color plate (color terminals), or bold text (plain)."""
    return f"{PLATE[kind]} {text} {RESET}" if _color and not _dod() else f"{BOLD}{text}{RESET}"


def info(msg: str) -> None:
    print(f"{CYAN}::{RESET} {msg}")


def warn(msg: str) -> None:
    progress_done()
    print(f"{YELLOW}!!{RESET} {msg}", file=sys.stderr)


def err(msg: str) -> None:
    progress_done()
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


def _short(title: str, width: int = 78) -> str:
    # DISA titles all open with "Ubuntu 24.04 LTS ..." — drop the subject,
    # the operator knows which host they're on.
    if title.startswith("Ubuntu 24.04 LTS"):
        title = title[len("Ubuntu 24.04 LTS"):].lstrip(" ,")
        title = title[:1].upper() + title[1:]
    return title if len(title) <= width else title[: width - 1] + "…"


def _width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))


def _clip(text: str, room: int) -> str:
    return text if len(text) <= room else text[: max(room - 1, 1)] + "…"


# ---- progress (TTY only; nothing on a pipe or in a log) ----------------------

def progress(i: int, n: int, label: str) -> None:
    cols = shutil.get_terminal_size((100, 24)).columns
    if not _live() or cols < 60:
        return
    filled = round(24 * i / n) if n else 24
    line = f"  {GRAY}auditing{RESET} {BLUE}{'━' * filled}{GRAY}{'─' * (24 - filled)}{RESET} {i:>3}/{n}  {GRAY}{label}{RESET}"
    sys.stdout.write("\r\033[K" + line)
    sys.stdout.flush()
    global _progress_shown
    _progress_shown = True


_progress_shown = False


def progress_done() -> None:
    """Clear the live progress line, if one is drawn (warnings call this first)."""
    global _progress_shown
    if _progress_shown:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        _progress_shown = False


def _live() -> bool:
    return _color and sys.stdout.isatty()


# ---- the cascade: category → area → finding → evidence ------------------------

AREAS = {
    "ssh": "SSH", "auth": "Accounts & authentication", "audit": "Audit logging",
    "aide": "File integrity (AIDE)", "boot": "Boot & kernel", "filesystem": "Filesystem & permissions",
    "gnome": "Desktop (GNOME)", "packages": "Packages & updates", "services": "Services & firewall",
    "system": "System configuration", "timesync": "Time synchronization",
}
_ORDER = {"fail": 0, "manual": 1, "review": 2, "pass": 3, "na": 4, "unimpl": 5}


def area_of(control) -> str:
    mod = getattr(getattr(control, "check", None), "__module__", "") or ""
    return AREAS.get(mod.rsplit(".", 1)[-1], "Other") if control else "Not automated"


def cascade(rows: list, verbose: bool = False) -> None:
    """rows: (rule, area, status, detail). Open and review items are always
    listed with their reason; passing / n/a rules fold into one count per area
    unless verbose."""
    width = _width()
    for cat in ("CAT I", "CAT II", "CAT III"):
        mine = [r for r in rows if r[0].category == cat and (verbose or r[2] != "unimpl")]
        if not mine:
            continue
        open_ = sum(1 for r in mine if r[2] in ("fail", "manual"))
        catc = globals()[_CAT_COLOR[cat]]
        tail = f" {len(mine)} rules · " + (f"{RED}{open_} open{RESET}" if open_ else f"{GREEN}clean{RESET}")
        if _dod():
            lead = f"  {catc}{BOLD}{cat_label(cat)}{RESET} "
            rule = "─"
        else:
            lead, rule = f"  {_plate(cat, cat)} ", "━"
        rule_len = max(4, width - len(_strip(lead)) - len(_strip(tail)) - 2)
        print(f"\n{lead}{EMBER}{rule * rule_len}{RESET}{tail}")
        areas: dict[str, list] = {}
        for r in sorted(mine, key=lambda r: (_ORDER.get(r[2], 9), r[0].vuln_id)):
            areas.setdefault(r[1], []).append(r)
        names = sorted(areas, key=lambda a: (min(_ORDER.get(r[2], 9) for r in areas[a]), a))
        for ai, area in enumerate(names):
            last_area = ai == len(names) - 1
            print(f"  {EMBER}{'└─' if last_area else '├─'}{RESET} {BOLD}{area}{RESET}")
            stem = "   " if last_area else f"{EMBER}│{RESET}  "
            items = areas[area]
            shown = [r for r in items if verbose or r[2] in ("fail", "manual", "review")]
            folded = {s: 0 if verbose else sum(1 for r in items if r[2] == s) for s in ("pass", "na")}
            lines: list[tuple[str, str]] = []
            for rule, _, status, detail in shown:
                sym, color = _SYMBOL.get(status, ("✗", "RED"))
                col = globals()[color]
                head = f"{col}{sym}{RESET} {BOLD}{rule.vuln_id}{RESET} {GRAY}{rule.stig_id}{RESET}  "
                room = width - 8 - len(_strip(head))
                head += _clip(_short(rule.title, 200), room)
                lines.append((head, detail))
            if folded["pass"]:
                lines.append((f"{GREEN}✓{RESET} {GRAY}{folded['pass']} passing{RESET}", ""))
            if folded["na"]:
                lines.append((f"{GRAY}- {folded['na']} not applicable{RESET}", ""))
            for li, (head, detail) in enumerate(lines):
                last = li == len(lines) - 1
                print(f"  {stem}{EMBER}{'└─' if last else '├─'}{RESET} {head}")
                if detail:
                    pad = f"  {stem}{'   ' if last else EMBER + '│' + RESET + '  '}   "
                    print(f"{pad}{DIM}{_clip(detail, width - 16)}{RESET}")


def _strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _bar(done: int, total: int, n_open: int, width: int = 28) -> str:
    f = round(width * done / total) if total else width
    col = GREEN if not n_open else YELLOW if done >= total * 0.8 else RED
    full, empty = ("#", "-") if _dod() else ("█", "░")
    return f"{col}{full * f}{EMBER}{empty * (width - f)}{RESET}"


def summary(counts: dict[str, int], by_cat_open: dict[str, int],
            by_cat_total: dict[str, int] | None = None, by_cat_pass: dict[str, int] | None = None) -> None:
    width = _width()
    if _dod():
        print(f"\n  {BOLD}POSTURE{RESET} {'─' * (width - 12)}")
    else:
        print(f"\n  {_plate('POSTURE')} {EMBER}{'━' * (width - 14)}{RESET}")
    if by_cat_total:
        for cat in ("CAT I", "CAT II", "CAT III"):
            tot, ok = by_cat_total.get(cat, 0), (by_cat_pass or {}).get(cat, 0)
            if not tot:
                continue
            n_open = by_cat_open.get(cat, 0)
            catc = globals()[_CAT_COLOR[cat]]
            note = f"{RED}{n_open} open{RESET}" if n_open else f"{GREEN}no open findings{RESET}"
            label = cat_label(cat)
            lw = 15 if _dod() else 8
            bar_w = max(8, min(28, width - lw - 34))
            print(f"   {catc}{label:<{lw}}{RESET} {_bar(ok, tot, n_open, bar_w)}  {ok:>3}/{tot:<3}  {note}")
        print()
    fixable, need = counts.get("fail", 0), counts.get("manual", 0)
    words = (("Not a Finding", "Open", "Not Reviewed", "Not Applicable") if _dod()
             else ("not a finding", "open", "need review", "n/a"))
    _flow("   ", [f"{GREEN}✓{RESET} {counts.get('pass', 0)} {words[0]}",
                  f"{RED}✗{RESET} {fixable + need} {words[1]} {GRAY}({fixable} auto-fixable){RESET}",
                  f"{YELLOW}?{RESET} {counts.get('review', 0)} {words[2]}",
                  f"{GRAY}- {counts.get('na', 0)} {words[3]}{RESET}"])
    if counts.get("unimpl"):
        print(f"   {GRAY}· {counts['unimpl']} not reviewed (no automated check){RESET}")
    if by_cat_open.get("CAT I"):
        print(f"\n   {RED}{BOLD}CAT I open — these block an ATO until closed or accepted.{RESET}")


def step(sym: str, color: str, rule, detail: str = "") -> None:
    """One live harden/rollback line, with its outcome cascading underneath."""
    width = _width()
    col = globals()[color]
    catc = globals()[_CAT_COLOR.get(rule.category, "GRAY")]
    print(f"  {col}{sym}{RESET} {BOLD}{rule.vuln_id}{RESET} {catc}{rule.category:<7}{RESET} "
          f"{_clip(_short(rule.title, 200), width - 30)}")
    if detail:
        print(f"    {GRAY}└{RESET} {DIM}{_clip(detail, width - 8)}{RESET}")


def _flow(indent: str, parts: list[str]) -> None:
    """Print parts separated by three spaces, wrapping between parts at the terminal width."""
    room, line = _width() - len(indent), ""
    for part in parts:
        if line and len(_strip(line)) + 3 + len(_strip(part)) > room:
            print(indent + line)
            line = ""
        line = f"{line}   {part}" if line else part
    if line:
        print(indent + line)


def tally(parts: list[tuple[str, str, int, str]]) -> None:
    print()
    _flow("  ", [f"{globals()[c]}{s}{RESET} {BOLD}{n}{RESET} {GRAY}{label}{RESET}"
                 for s, c, n, label in parts if n or c != "GRAY"])


def next_steps(steps: list[tuple[str, str]]) -> None:
    if not steps:
        return
    print(f"\n  {_plate('NEXT')}")
    w = max(len(c) for c, _ in steps)
    for cmd, why in steps:
        if 3 + w + 3 + len(why) <= _width():
            print(f"   {CYAN}{cmd:<{w}}{RESET}   {GRAY}{why}{RESET}")
        else:
            print(f"   {CYAN}{cmd}{RESET}\n     {GRAY}{_clip(why, _width() - 5)}{RESET}")
