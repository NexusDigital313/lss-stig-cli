"""Ubuntu 24.04 STIG — GNOME desktop and GDM login screen.

All not-applicable on hosts without a desktop.

Several of these rules only require a setting to be *locked*. Locking alone
freezes whatever the value is — and GNOME's defaults are automount ON,
autorun allowed, smart-card removal does nothing. So every fix here sets the
secure value AND locks it; locking the insecure default would pass the
assessor's check while making the host worse.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

from lss_stig.controls.ubuntu2404 import dod
from lss_stig.lib import dconf, keyval, pkg
from lss_stig.lib.ini import set_ini  # noqa: F401  (re-exported for tests)
from lss_stig.lib.registry import CheckResult, Control, RollbackEntry, register

B = "ubuntu2404_v1r6"


def _uint(v: str | None) -> int | None:
    m = re.fullmatch(r"(?:uint32\s+)?(\d+)", (v or "").strip())
    return int(m.group(1)) if m else None


def _dconf_rule(vuln_id: str, check_settings=None, locks=None, fix_settings=None) -> None:
    register(B, Control(vuln_id,
                        lambda: dconf.check(check_settings, locks),
                        lambda: dconf.apply(fix_settings, locks)))


# ---- V-270711 CAT I — Ctrl-Alt-Del logout disabled ----
MK = "org/gnome/settings-daemon/plugins/media-keys"
_dconf_rule("V-270711",
            {(MK, "logout"): lambda v: (v or "").replace(" ", "") in ("@as[]", "['']", "[]")},
            fix_settings={(MK, "logout"): "@as []"})

# ---- V-270678 — lock after 10 minutes idle ----
# DISA's fix text writes idle-delay=900 / lock-delay=600, which fails DISA's own
# check (idle ≤ 600, lock-delay 0). We implement what the check verifies.
SS, SESSION = "org/gnome/desktop/screensaver", "org/gnome/desktop/session"
_dconf_rule("V-270678",
            {(SS, "lock-enabled"): lambda v: v == "true",
             (SS, "lock-delay"): lambda v: _uint(v) == 0,
             (SESSION, "idle-delay"): lambda v: _uint(v) is not None and 0 < _uint(v) <= 600},
            locks=[f"/{SS}/lock-enabled", f"/{SS}/lock-delay", f"/{SESSION}/idle-delay"],
            fix_settings={(SS, "lock-enabled"): "true", (SS, "lock-delay"): "uint32 0",
                          (SESSION, "idle-delay"): "uint32 600"})

# ---- V-270679 — automount can't be re-enabled by users ----
MH = "org/gnome/desktop/media-handling"
_dconf_rule("V-270679",
            {(MH, "automount-open"): lambda v: v == "false"},
            locks=[f"/{MH}/automount-open"],
            fix_settings={(MH, "automount"): "false", (MH, "automount-open"): "false"})

# ---- V-274872 — autorun can't be re-enabled by users ----
_dconf_rule("V-274872",
            {(MH, "autorun-never"): lambda v: v == "true"},
            locks=[f"/{MH}/autorun-never"],
            fix_settings={(MH, "autorun-never"): "true"})

# ---- V-274873 — smart card removal action can't be overridden ----
SC = "org/gnome/settings-daemon/peripherals/smartcard"
_dconf_rule("V-274873",
            {(SC, "removal-action"): lambda v: (v or "").strip("'\"") in ("lock-screen", "force-logout")},
            locks=[f"/{SC}/removal-action"],
            fix_settings={(SC, "removal-action"): "'lock-screen'"})

# ---- V-274871 — lock screen shows no desktop content ----
_dconf_rule("V-274871",
            {(SS, "picture-uri"): lambda v: v in ("''", '""')},
            locks=[f"/{SS}/picture-uri"],
            fix_settings={(SS, "picture-uri"): "''"})


# ---- GDM login banner (V-270692 enable, V-270693 text) ----

GREETER = Path("/etc/gdm3/greeter.dconf-defaults")
LOGIN = "org/gnome/login-screen"


def _greeter_value(key: str) -> str | None:
    if not GREETER.exists():
        return None
    return dconf.parse_value(GREETER.read_text(), LOGIN, key)


def _greeter_rule(vuln_id: str, key: str, value_fn, ok) -> None:
    def check() -> CheckResult:
        if not pkg.is_installed("gdm3"):
            return CheckResult("na", "GDM not installed")
        v = _greeter_value(key)
        shown = v if v is None or len(v) < 80 else v[:77] + "..."
        ev = f"{GREETER}: [{LOGIN}] {key}={shown}"
        if not ok(v):
            return CheckResult("fail", f"{key} {'not set' if v is None else 'incorrect'}", ev)
        return CheckResult("pass", "", ev)

    def fix() -> list[RollbackEntry]:
        out = keyval.edit_file(GREETER, lambda t: set_ini(t, LOGIN, key, value_fn()), f"set {key} in {GREETER}")
        subprocess.run(["dconf", "update"], capture_output=True)
        return out  # the greeter reads it at next GDM start; restarting GDM would kill sessions

    register(B, Control(vuln_id, check, fix))


_greeter_rule("V-270692", "banner-message-enable", lambda: "true", lambda v: v == "true")
_greeter_rule("V-270693", "banner-message-text", dod.gdm_banner_value,
              lambda v: v is not None and dod.normalize(v) == dod.normalize(dod.banner()))
