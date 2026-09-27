"""Edit a PAM stack without breaking its jump counts.

Ubuntu's pam-auth-update writes stacks like:

    auth  [success=1 default=ignore]  pam_unix.so nullok
    auth  requisite                   pam_deny.so
    auth  required                    pam_permit.so

`success=1` means "skip the next module". Inserting a line anywhere inside a
jump's range silently changes where it lands — DISA's faillock fix text
("add these lines below pam_unix") does exactly that, and on a host with
pam_sss (success=2) it sends a successful login straight into pam_deny.
Every insertion here recomputes each numeric jump so it still lands on the
same module it did before (or, where asked, on a new one).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_LINE = re.compile(r"^(\s*)(-?)(auth|account|password|session)(\s+)(\[[^\]]*\]|\S+)(\s+)(\S+)(.*)$")


@dataclass
class Module:
    line: int        # index into the file's lines
    type: str
    control: str
    module: str      # e.g. pam_unix.so
    args: str


def modules(text: str, type_: str) -> list[Module]:
    out = []
    for i, raw in enumerate(text.splitlines()):
        m = _LINE.match(raw)
        if m and not raw.lstrip().startswith("#") and m.group(3) == type_:
            out.append(Module(i, m.group(3), m.group(5), m.group(7).rsplit("/", 1)[-1], m.group(8).strip()))
    return out


def _jumps(control: str) -> dict[str, int]:
    if not control.startswith("["):
        return {}
    return {k: int(v) for k, v in re.findall(r"(\w+)=(\d+)", control)}


def _set_jumps(control: str, new: dict[str, int]) -> str:
    return re.sub(r"(\w+)=(\d+)", lambda m: f"{m.group(1)}={new.get(m.group(1), int(m.group(2)))}", control)


def insert(text: str, type_: str, inserts: list[tuple[int, str]],
           retarget_success: dict[int, int] | None = None) -> str:
    """Insert module lines into the `type_` stack.

    inserts: [(position, line)] — position is the ordinal (among `type_`
      modules in the ORIGINAL stack) the new line goes in front of;
      len(stack) appends at the end of the stack.
    retarget_success: {old_target_ordinal: index into `inserts`} — any
      `success=N` jump that used to land on old_target now lands on that
      inserted line instead.
    """
    lines = text.splitlines()
    mods = modules(text, type_)
    n_old = len(mods)
    order = sorted(range(len(inserts)), key=lambda k: (inserts[k][0], k))

    # New ordinal of each old module and each inserted line.
    old_to_new, ins_to_new = {}, {}
    new_ord = 0
    j = 0
    for o in range(n_old + 1):
        while j < len(order) and inserts[order[j]][0] == o:
            ins_to_new[order[j]] = new_ord
            new_ord += 1
            j += 1
        if o < n_old:
            old_to_new[o] = new_ord
            new_ord += 1
    old_to_new[n_old] = new_ord  # "past the end"

    # Recompute numeric jumps.
    for o, m in enumerate(mods):
        jumps = _jumps(m.control)
        if not jumps:
            continue
        new_j = {}
        for key, n in jumps.items():
            target = min(o + n + 1, n_old)
            if key == "success" and retarget_success and target in retarget_success:
                nt = ins_to_new[retarget_success[target]]
            else:
                nt = old_to_new[target]
            new_j[key] = nt - old_to_new[o] - 1
        mm = _LINE.match(lines[m.line])
        lines[m.line] = mm.group(1) + mm.group(2) + mm.group(3) + mm.group(4) + _set_jumps(m.control, new_j) + \
            mm.group(6) + mm.group(7) + mm.group(8)

    # Emit lines in one forward pass: each insert goes directly in front of
    # its anchor module (end-of-stack inserts after the last module), in the
    # order requested.
    by_pos: dict[int, list[str]] = {}
    for pos, line in inserts:
        by_pos.setdefault(pos, []).append(line)
    before = {m.line: by_pos.get(o, []) for o, m in enumerate(mods)}
    tail_after = mods[-1].line if mods else len(lines) - 1
    out = []
    for i, line in enumerate(lines):
        out += before.get(i, [])
        out.append(line)
        if i == tail_after:
            out += by_pos.get(n_old, [])
    if not lines:
        out = by_pos.get(n_old, [])
    return "\n".join(out) + "\n"
