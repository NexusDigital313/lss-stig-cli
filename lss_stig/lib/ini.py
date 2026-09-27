"""Minimal INI-style edits that keep comments and layout (gdm, sssd)."""

from __future__ import annotations

import re


def set_ini(text: str, section: str, key: str, value: str) -> str:
    """Set key=value inside [section]: replace an active or commented line in
    that section, else add it at the section end, else append the section."""
    lines = text.splitlines()
    hdr = f"[{section}]"
    start = next((i for i, l in enumerate(lines) if l.strip() == hdr), None)
    if start is None:
        return "\n".join(lines + ["", hdr, f"{key}={value}"]) + "\n"
    end = next((i for i in range(start + 1, len(lines)) if lines[i].strip().startswith("[")), len(lines))
    pat = re.compile(rf"^\s*#?\s*{re.escape(key)}\s*=")
    hits = [i for i in range(start + 1, end) if pat.match(lines[i])]
    active = [i for i in hits if not lines[i].lstrip().startswith("#")]
    target = (active or hits or [None])[-1]
    if target is None:
        lines.insert(end, f"{key}={value}")
    else:
        lines[target] = f"{key}={value}"
        for i in active:
            if i != target:
                lines[i] = "# " + lines[i]
    return "\n".join(lines) + "\n"


def get(text: str, section: str, key: str) -> str | None:
    """Last active `key` value inside [section] (key match is case-insensitive)."""
    cur, val = None, None
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s[0] in "#;":
            continue
        if s.startswith("[") and s.endswith("]"):
            cur = s[1:-1].strip().lower()
        elif cur == section.lower() and "=" in s and s.split("=", 1)[0].strip().lower() == key.lower():
            val = s.split("=", 1)[1].strip()
    return val
