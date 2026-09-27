import unittest
from unittest import mock

from lss_stig.controls.ubuntu2404 import auth, services
from lss_stig.lib import pamstack, site

STOCK = """# /etc/pam.d/common-auth
auth\t[success=1 default=ignore]\tpam_unix.so nullok
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
auth\toptional\t\t\tpam_cap.so
"""

WITH_SSS = """auth\t[success=2 default=ignore]\tpam_unix.so nullok
auth\t[success=1 default=ignore]\tpam_sss.so use_first_pass
auth\trequisite\t\t\tpam_deny.so
auth\trequired\t\t\tpam_permit.so
auth\toptional\t\t\tpam_cap.so
"""


def simulate(text: str, results: dict[str, str]) -> str:
    """Walk an auth stack: results maps module(+arg) → 'success'|'fail'.
    Returns 'granted' or 'denied'."""
    mods = pamstack.modules(text, "auth")
    i, ok = 0, False
    while i < len(mods):
        m = mods[i]
        key = m.module + (" " + m.args.split()[0] if m.args else "")
        r = results.get(key, results.get(m.module, "success"))
        c = m.control
        if c.startswith("["):
            act = dict(kv.split("=") for kv in c[1:-1].split())
            a = act.get(r, act.get("default", "ignore"))
            if a == "die":
                return "denied"
            if a.isdigit():
                ok = ok or r == "success"
                i += int(a) + 1
                continue
            if a == "ok" and r == "success":
                ok = True
        elif c == "requisite" and r != "success":
            return "denied"
        elif c == "required":
            if r != "success":
                return "denied"
            ok = True
        elif c == "sufficient" and r == "success":
            return "granted"
        i += 1
    return "granted" if ok else "denied"


class PamStackTests(unittest.TestCase):
    def test_faillock_on_stock_stack(self):
        out = auth.add_faillock(STOCK)
        mods = [(m.control, m.module, m.args) for m in pamstack.modules(out, "auth")]
        self.assertEqual(mods[0], ("requisite", "pam_faillock.so", "preauth"))
        self.assertEqual(mods[1][1], "pam_unix.so")
        self.assertEqual(mods[1][0], "[success=1 default=ignore]")  # skips authfail, lands on authsucc
        self.assertEqual(mods[2], ("[default=die]", "pam_faillock.so", "authfail"))
        self.assertEqual(mods[3][2], "authsucc")
        self.assertEqual(mods[4][1], "pam_deny.so")

    def test_faillock_behaviour(self):
        for stack in (STOCK, WITH_SSS):
            out = auth.add_faillock(stack)
            self.assertEqual(simulate(out, {}), "granted")
            self.assertEqual(simulate(out, {"pam_unix.so": "fail", "pam_sss.so": "fail"}), "denied")
            self.assertEqual(simulate(out, {"pam_faillock.so preauth": "fail"}), "denied")      # locked
            self.assertEqual(simulate(out, {"pam_faillock.so authsucc": "fail"}), "denied")     # locked
            self.assertEqual(simulate(out, {"pam_unix.so": "fail"}),
                             "granted" if stack is WITH_SSS else "denied")                     # sss fallback

    def test_faillock_idempotent_and_refuses_unknown_layout(self):
        once = auth.add_faillock(STOCK)
        self.assertEqual(auth.add_faillock(once), once)
        with self.assertRaises(RuntimeError):
            auth.add_faillock("auth required pam_unix.so\n")

    def test_faildelay_inserted_first_without_breaking_jumps(self):
        out = auth._set_faildelay(STOCK)
        mods = pamstack.modules(out, "auth")
        self.assertEqual(mods[0].module, "pam_faildelay.so")
        self.assertIn("delay=4000000", mods[0].args)
        self.assertEqual(mods[1].control, "[success=1 default=ignore]")
        self.assertEqual(simulate(out, {}), "granted")

    def test_faildelay_raised_in_place(self):
        src = "auth optional pam_faildelay.so delay=2000000\n" + STOCK
        self.assertIn("delay=4000000", auth._set_faildelay(src))

    def test_comments_and_other_types_untouched(self):
        src = "# auth [success=9] pam_x.so\npassword [success=1 default=ignore] pam_unix.so\n" + STOCK
        out = auth.add_faillock(src)
        self.assertIn("# auth [success=9] pam_x.so", out)
        self.assertIn("password [success=1 default=ignore] pam_unix.so", out)


class FaillockConfTests(unittest.TestCase):
    def test_flags_uncommented(self):
        out = auth._set_faillock_conf("# audit\n# silent\n# deny = 3\n")
        self.assertIn("\naudit\n", "\n" + out)
        self.assertIn("\nsilent\n", out)


class SiteTests(unittest.TestCase):
    def test_validation(self):
        self.assertEqual(site.validate("time_server", "tick.usno.navy.mil"), "")
        self.assertEqual(site.validate("admin_email", "isso@example.mil"), "")
        self.assertNotEqual(site.validate("admin_email", "isso"), "")
        self.assertNotEqual(site.validate("audit_remote_server", "localhost"), "")
        self.assertNotEqual(site.validate("audit_remote_server", "::1"), "")
        self.assertNotEqual(site.validate("bogus", "x"), "")


class MiscTests(unittest.TestCase):
    def test_apt_unauthenticated_regex(self):
        self.assertTrue(services._UNAUTH.search('APT::Get::AllowUnauthenticated "true";'))
        self.assertFalse(services._UNAUTH.search('APT::Get::AllowUnauthenticated "false";'))

    def test_space_left(self):
        from pathlib import Path
        from lss_stig.controls.ubuntu2404 import audit
        self.assertTrue(audit._space_left_ok("25%", Path("/")))
        self.assertFalse(audit._space_left_ok("10%", Path("/")))
        self.assertFalse(audit._space_left_ok("75", Path("/")))  # 75 MB ≪ 25% of any real disk

    def test_chrony_maxpoll(self):
        from lss_stig.controls.ubuntu2404 import timesync
        self.assertEqual(timesync._maxpoll("iburst maxpoll 16"), 16)
        self.assertIsNone(timesync._maxpoll("iburst"))


if __name__ == "__main__":
    unittest.main()
