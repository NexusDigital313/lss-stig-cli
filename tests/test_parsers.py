import unittest

from lss_stig.controls.ubuntu2404.auth import blank_password_accounts, strip_nullok
from lss_stig.controls.ubuntu2404.boot import logout_value
from lss_stig.lib.sshd import parse_occurrences


class SshdParseTests(unittest.TestCase):
    def test_finds_all_uncommented_occurrences(self):
        text = ("# X11Forwarding no\n"
                "X11Forwarding yes\n"
                "x11forwarding=no\n"
                "Match User bob\n"
                "    X11Forwarding yes\n")
        occ = parse_occurrences(text, "X11Forwarding", "f")
        self.assertEqual([(o.lineno, o.value, o.in_match) for o in occ],
                         [(2, "yes", False), (3, "no", False), (5, "yes", True)])

    def test_prefix_keyword_not_matched(self):
        self.assertEqual(parse_occurrences("PermitEmptyPasswordsX no\n", "PermitEmptyPasswords"), [])


class PamTests(unittest.TestCase):
    def test_strip_nullok(self):
        src = ("auth [success=1 default=ignore] pam_unix.so nullok\n"
               "password [success=1] pam_unix.so obscure nullok_secure yescrypt\n"
               "# pam_unix.so nullok stays in comments\n")
        out = strip_nullok(src)
        self.assertNotIn("so nullok\n", out)
        self.assertIn("pam_unix.so obscure yescrypt", out)
        self.assertIn("# pam_unix.so nullok stays in comments", out)

    def test_no_change_when_clean(self):
        src = "auth required pam_unix.so\n"
        self.assertEqual(strip_nullok(src), src)


class ShadowTests(unittest.TestCase):
    def test_blank_accounts(self):
        shadow = "root:*:19000:0:99999:7:::\nbob::19000:0:99999:7:::\nsvc:!:19000::::::\n"
        self.assertEqual(blank_password_accounts(shadow), ["bob"])


class DconfTests(unittest.TestCase):
    def test_logout_value_scoped_to_section(self):
        text = ("[org/gnome/other]\nlogout='x'\n"
                "[org/gnome/settings-daemon/plugins/media-keys]\nlogout=@as []\n")
        self.assertEqual(logout_value(text), "@as []")
        self.assertIsNone(logout_value("[org/gnome/other]\nlogout='x'\n"))


if __name__ == "__main__":
    unittest.main()
