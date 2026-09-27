"""Ubuntu 24.04 STIG — platform-level rules (crypto, support status)."""

from __future__ import annotations

import json
import subprocess
from datetime import date
from pathlib import Path

from lss_stig.lib import distro
from lss_stig.lib.registry import CheckResult, Control, register

B = "ubuntu2404_v1r6"


# ---- V-270744 CAT I — FIPS mode ----
# Needs an Ubuntu Pro subscription, a FIPS kernel and a reboot — never
# something to do unattended, so this reports only.

FIPS_FLAG = Path("/proc/sys/crypto/fips_enabled")


def _check_fips() -> CheckResult:
    val = FIPS_FLAG.read_text().strip() if FIPS_FLAG.exists() else ""
    ev = f"{FIPS_FLAG}: {val or '(absent)'}"
    if val == "1":
        return CheckResult("pass", "", ev)
    return CheckResult("manual", "FIPS mode off — needs Ubuntu Pro: pro attach <token> && "
                       "pro enable fips-updates, then reboot", ev)


register(B, Control("V-270744", _check_fips))


# ---- V-278917 CAT I — vendor-supported release ----
# 24.04 LTS standard security maintenance runs to April 2029; after that
# the host needs Ubuntu Pro (ESM) to still count as supported.

STANDARD_SUPPORT_END = date(2029, 4, 30)


def _pro_status() -> dict:
    try:
        r = subprocess.run(["pro", "status", "--format", "json"], capture_output=True,
                           text=True, timeout=30)
        return json.loads(r.stdout) if r.returncode == 0 else {}
    except (FileNotFoundError, subprocess.TimeoutExpired, ValueError):
        return {}


def _check_supported(today: date | None = None) -> CheckResult:
    today = today or date.today()
    host = distro.detect()
    ev = [f"os-release: {host.name} (VERSION_ID={host.version})"]
    if host.id != "ubuntu" or host.version != "24.04":
        return CheckResult("fail", f"not Ubuntu 24.04 LTS: {host.name}", ev[0])
    if today <= STANDARD_SUPPORT_END:
        ev.append(f"standard support until {STANDARD_SUPPORT_END.isoformat()}")
        return CheckResult("pass", "", "\n".join(ev))
    pro = _pro_status()
    attached = bool(pro.get("attached"))
    esm = any(s.get("name") == "esm-infra" and s.get("status") == "enabled"
              for s in pro.get("services", []))
    ev.append(f"pro attached: {attached}; esm-infra enabled: {esm}")
    if attached and esm:
        return CheckResult("pass", "", "\n".join(ev))
    return CheckResult("manual", "past standard support — attach Ubuntu Pro and enable esm-infra",
                       "\n".join(ev))


register(B, Control("V-278917", _check_supported))
