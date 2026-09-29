"""DOD-mandated text, lifted from the STIG catalog itself so it is always the
exact wording of the release being assessed — never retyped."""

from __future__ import annotations

import re
from functools import lru_cache

from lss_stig.lib.registry import load_benchmark

B = "ubuntu2404_v1r6"


def _raw(vuln_id: str) -> dict:
    return next(r.raw for r in load_benchmark(B).rules if r.vuln_id == vuln_id)


@lru_cache(maxsize=None)
def banner() -> str:
    """Standard Mandatory DOD Notice and Consent Banner (plain text)."""
    fix = _raw("V-270691")["fix_text"]
    start = fix.index('"You are accessing')
    end = fix.index('details."', start) + len("details.")
    lines = [l.strip() for l in fix[start + 1:end].splitlines()]
    paras, cur = [], []
    for l in lines:
        if l:
            cur.append(l)
        elif cur:
            paras.append(" ".join(cur))
            cur = []
    if cur:
        paras.append(" ".join(cur))
    return "\n\n".join(paras) + "\n"


@lru_cache(maxsize=None)
def ssh_confirm_script() -> str:
    fix = _raw("V-270694")["fix_text"]
    start = fix.index("#!/bin/bash")
    end = fix.index("\nfi", start) + 3
    return fix[start:end] + "\n"


@lru_cache(maxsize=None)
def gdm_banner_value() -> str:
    """banner-message-text value (single-quoted, \\n-escaped) for GDM."""
    fix = _raw("V-270693")["fix_text"]
    return re.search(r"banner-message-text=('.*?')\s*\n", fix, re.S).group(1)


def normalize(text: str) -> str:
    """Whitespace-insensitive form for "matches exactly" comparisons."""
    text = text.replace("\\n", " ").strip().strip("'\"")
    return " ".join(text.split())
