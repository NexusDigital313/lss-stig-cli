"""Terminal output — standard library only.

Follows DISA tool conventions (STIG Viewer, SCC, Evaluate-STIG): plain ASCII
structure, the eight standard ANSI colors and never color alone, STIG Viewer
status words (Open, Not a Finding, Not Reviewed, Not Applicable) and
CAT I (High) / CAT II (Medium) / CAT III (Low) severities. Hardened hosts are
often reached over serial consoles and their output ends up in evidence
packages, so everything reads the same with color off.

STIG'd hosts are frequently air-gapped with no PyPI access, so lss-stig has
no third-party runtime dependencies. Color is auto-disabled when stdout is
not a TTY, when NO_COLOR is set, or with --no-color.
"""

from __future__ import annotations

import os
import re
import shutil
import sys

from lss_stig import __version__

_color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(code: str) -> str:
    return f"\033[{code}m" if _color else ""


def _refresh():
    global RED, GREEN, YELLOW, BLUE, CYAN, GRAY, BOLD, DIM, RESET
    RED, GREEN, YELLOW, CYAN = _c("31"), _c("32"), _c("33"), _c("36")
    BLUE, GRAY = CYAN, ""
    BOLD, DIM, RESET = _c("1"), _c("2"), _c("0")


_refresh()


def disable_color() -> None:
    global _color
    _color = False
    _refresh()


SEVERITY = {"CAT I": "High", "CAT II": "Medium", "CAT III": "Low"}

# STIG Viewer status words, matching the .cklb this tool writes (checklist.CKLB_STATUS).
STATUS = {
    "pass":   ("Not a Finding", "GREEN"),
    "fail":   ("Open", "RED"),
    "manual": ("Open", "RED"),
    "review": ("Not Reviewed", "YELLOW"),
    "na":     ("Not Applicable", ""),
    "unimpl": ("Not Reviewed", ""),
}
_STATUS_W = 14
_CAT_COLOR = {"CAT I": "RED", "CAT II": "YELLOW", "CAT III": ""}


def _col(name: str) -> str:
    return globals()[name] if name else ""


def cat_label(cat: str) -> str:
    return f"{cat} ({SEVERITY[cat]})" if cat in SEVERITY else cat


def banner(subtitle: str = "", bench=None) -> None:
    from lss_stig import _edition
    width = _width()
    print(f"\n{BOLD}LSS STIG {__version__}{RESET}"
          + (f"  {YELLOW}OWNER BUILD - UNLICENSED{RESET}" if _edition.EDITION == "owner" else ""))
    if bench is not None:
        print(_clip(bench.stig_name, width))
        print(_clip(f"Version {bench.version}, {bench.release_info}", width))
    if subtitle:
        print(_clip(subtitle, width))
    print("=" * width)


def header(text: str) -> None:
    print(f"\n{BOLD}{text.upper()}{RESET}\n{'-' * _width()}")


def info(msg: str) -> None:
    print(f"INFO: {ascii_text(msg)}")


def warn(msg: str) -> None:
    progress_done()
    print(f"{YELLOW}WARNING:{RESET} {ascii_text(msg)}", file=sys.stderr)


def err(msg: str) -> None:
    progress_done()
    print(f"{RED}ERROR:{RESET} {ascii_text(msg)}", file=sys.stderr)


def _short(title: str, width: int = 78) -> str:
    # DISA titles all open with "Ubuntu 24.04 LTS ..." — drop the subject,
    # the operator knows which host they're on.
    if title.startswith("Ubuntu 24.04 LTS"):
        title = title[len("Ubuntu 24.04 LTS"):].lstrip(" ,")
        title = title[:1].upper() + title[1:]
    return _clip(title, width)


def _width() -> int:
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 120))


_ASCII = str.maketrans({"—": "-", "–": "-", "→": "->", "…": "...", "·": "|", "≤": "<=", "≥": ">=", "\u00a0": " ",
                        "‘": "'", "’": "'", "“": '"', "”": '"'})


def ascii_text(text: str) -> str:
    """Screen text is plain ASCII, so it survives serial consoles and evidence logs."""
    return text.translate(_ASCII).encode("ascii", "replace").decode()


def _clip(text: str, room: int) -> str:
    text = ascii_text(text)
    return text if len(text) <= room else text[: max(room - 3, 1)] + "..."


def _strip(s: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", s)


# ---- progress (TTY only; nothing on a pipe or in a log) ----------------------

_progress_shown = False


def progress(i: int, n: int, label: str) -> None:
    global _progress_shown
    if not (_color and sys.stdout.isatty()) or shutil.get_terminal_size((100, 24)).columns < 60:
        return
    filled = round(20 * i / n) if n else 20
    sys.stdout.write(f"\r\033[KAuditing [{'#' * filled}{'-' * (20 - filled)}] {i:>3}/{n}  {label}")
    sys.stdout.flush()
    _progress_shown = True


def progress_done() -> None:
    """Clear the live progress line, if one is drawn (warnings call this first)."""
    global _progress_shown
    if _progress_shown:
        sys.stdout.write("\r\033[K")
        sys.stdout.flush()
        _progress_shown = False


# ---- findings: category → area → finding → evidence --------------------------

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


def _status(status: str) -> str:
    word, color = STATUS.get(status, ("Open", "RED"))
    return f"{_col(color)}{word:<{_STATUS_W}}{RESET}"


def cascade(rows: list, verbose: bool = False) -> None:
    """rows: (rule, area, status, detail). Open and Not Reviewed items are
    always listed with their reason; Not a Finding / Not Applicable rules fold
    into one count per area unless verbose."""
    width = _width()
    for cat in ("CAT I", "CAT II", "CAT III"):
        mine = [r for r in rows if r[0].category == cat and (verbose or r[2] != "unimpl")]
        if not mine:
            continue
        open_ = sum(1 for r in mine if r[2] in ("fail", "manual"))
        lead = f"{_col(_CAT_COLOR[cat])}{BOLD}{cat_label(cat)}{RESET}"
        tail = f"{len(mine)} rules | " + (f"{RED}{open_} Open{RESET}" if open_ else f"{GREEN}0 Open{RESET}")
        print(f"\n{lead} {'-' * max(4, width - len(_strip(lead)) - len(_strip(tail)) - 2)} {tail}")
        areas: dict[str, list] = {}
        for r in sorted(mine, key=lambda r: (_ORDER.get(r[2], 9), r[0].vuln_id)):
            areas.setdefault(r[1], []).append(r)
        for area in sorted(areas, key=lambda a: (min(_ORDER.get(r[2], 9) for r in areas[a]), a)):
            print(f"  {BOLD}{area}{RESET}")
            items = areas[area]
            for rule, _, status, detail in items:
                if not verbose and status in ("pass", "na"):
                    continue
                head = f"    {_status(status)}  {BOLD}{rule.vuln_id}{RESET}  {rule.stig_id}  "
                print(head + _short(rule.title, width - len(_strip(head))))
                if detail:
                    print(f"{' ' * (6 + _STATUS_W)}{DIM}{_clip(detail, width - 6 - _STATUS_W)}{RESET}")
            if not verbose:
                for s in ("pass", "na"):
                    n = sum(1 for r in items if r[2] == s)
                    if n:
                        print(f"    {_status(s)}  {n} rule{'s' if n != 1 else ''}")


def _bar(done: int, total: int, n_open: int, width: int = 20) -> str:
    f = round(width * done / total) if total else width
    col = GREEN if not n_open else YELLOW if done >= total * 0.8 else RED
    return f"[{col}{'#' * f}{RESET}{'-' * (width - f)}]"


def summary(counts: dict[str, int], by_cat_open: dict[str, int],
            by_cat_total: dict[str, int] | None = None, by_cat_pass: dict[str, int] | None = None) -> None:
    width = _width()
    print(f"\n{BOLD}SUMMARY{RESET}\n{'-' * width}")
    if by_cat_total:
        bar_w = max(6, min(20, width - 42))
        print(f"  {'Severity':<16}{'Progress':<{bar_w + 3}}{'Not a Finding':<15}Open")
        for cat in ("CAT I", "CAT II", "CAT III"):
            tot, ok = by_cat_total.get(cat, 0), (by_cat_pass or {}).get(cat, 0)
            if not tot:
                continue
            n_open = by_cat_open.get(cat, 0)
            open_col = RED if n_open else GREEN
            print(f"  {_col(_CAT_COLOR[cat])}{cat_label(cat):<16}{RESET}{_bar(ok, tot, n_open, bar_w)} "
                  f"{f'{ok}/{tot}':<15}{open_col}{n_open}{RESET}")
        print()
    fixable, need = counts.get("fail", 0), counts.get("manual", 0)
    _flow("  ", [f"{GREEN}Not a Finding:{RESET} {counts.get('pass', 0)}",
                 f"{RED}Open:{RESET} {fixable + need} ({fixable} auto-fixable)",
                 f"{YELLOW}Not Reviewed:{RESET} {counts.get('review', 0) + counts.get('unimpl', 0)}",
                 f"Not Applicable: {counts.get('na', 0)}"])
    if by_cat_open.get("CAT I"):
        print(f"\n  {RED}{BOLD}CAT I findings are Open.{RESET}\n"
              f"  {RED}{BOLD}Close or formally accept them before an ATO.{RESET}")


# harden/rollback step outcomes — word first, like the status column
_STEP = {"→": ("Would fix", "YELLOW"), "✓": ("Fixed", "GREEN"), "◐": ("Still Open", "YELLOW"),
         "✗": ("Error", "RED"), "↺": ("Reverted", "GREEN")}


def step(sym: str, color: str, rule, detail: str = "") -> None:
    """One live harden/rollback line, with its outcome underneath."""
    width = _width()
    word, wcolor = _STEP.get(sym, (sym, color))
    head = f"  {_col(wcolor)}{word:<11}{RESET} {BOLD}{rule.vuln_id}{RESET}  {rule.category:<7}  "
    print(head + _short(rule.title, width - len(_strip(head))))
    if detail:
        print(f"{' ' * 14}{DIM}{_clip(detail, width - 14)}{RESET}")


def _flow(indent: str, parts: list[str], lead: str = "") -> None:
    """Print parts separated by three spaces, wrapping between parts at the terminal width."""
    room, line = _width() - len(indent), ""
    if lead:
        print(lead, end="")
    for part in parts:
        if line and len(_strip(line)) + 3 + len(_strip(part)) > room:
            print(indent + line)
            line = ""
        line = f"{line}   {part}" if line else part
    if line:
        print(indent + line)


def tally(parts: list[tuple[str, str, int, str]]) -> None:
    print()
    _flow("  ", [f"{_col(c) if c != 'GRAY' else ''}{label[:1].upper() + label[1:]}:{RESET} {n}"
                 for _, c, n, label in parts if n or c != "GRAY"])


def next_steps(steps: list[tuple[str, str]]) -> None:
    if not steps:
        return
    print(f"\n{BOLD}NEXT STEPS{RESET}")
    steps = [(c, ascii_text(why)) for c, why in steps]
    w = max(len(c) for c, _ in steps)
    for cmd, why in steps:
        if 2 + w + 3 + len(why) <= _width():
            print(f"  {CYAN}{cmd:<{w}}{RESET}   {why}")
        else:
            print(f"  {CYAN}{cmd}{RESET}\n      {_clip(why, _width() - 6)}")
