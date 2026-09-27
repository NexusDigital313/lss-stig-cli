import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lss_stig.controls.ubuntu2404 import auth, dod
from lss_stig.controls.ubuntu2404.gnome import set_ini
from lss_stig.lib import auditrules, journal, keyval, sysctl


class AuditCanonTests(unittest.TestCase):
    def same(self, a, b):
        self.assertEqual(auditrules.canon(a), auditrules.canon(b))

    def test_auditctl_output_matches_disa_rule(self):
        self.same("-a always,exit -F path=/bin/su -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-priv_change",
                  "-a always,exit -S all -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=unset -F key=x")

    def test_syscall_order_and_key_ignored(self):
        self.same("-a always,exit -F arch=b64 -S chown,fchown,fchownat,lchown -F auid>=1000 -F auid!=-1 -k perm_chng",
                  "-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -F key=k")

    def test_watch_normalization(self):
        self.same("-w /etc/sudoers.d -p wa -k a", "-w /etc/sudoers.d/ -p aw -k b")
        self.same("-w /var/run/utmp -p wa -k logins", "-w /run/utmp -p wa -k logins")

    def test_arch_and_fields_matter(self):
        b32 = auditrules.canon("-a always,exit -F arch=b32 -S delete_module -F auid>=1000 -F auid!=-1 -k m")
        b64 = auditrules.canon("-a always,exit -F arch=b64 -S delete_module -F auid>=1000 -F auid!=-1 -k m")
        self.assertNotEqual(b32, b64)
        self.assertNotEqual(auditrules.canon("-w /etc/passwd -p wa"), auditrules.canon("-w /etc/passwd -p w"))
        self.assertIsNone(auditrules.canon("-e 2"))


class KeyvalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.f = Path(self.tmp.name) / "pwquality.conf"
        jdir = Path(self.tmp.name) / "j"
        self.p = [mock.patch.object(journal, "JOURNAL_DIR", jdir),
                  mock.patch.object(journal, "BACKUPS_DIR", jdir / "b")]
        for p in self.p:
            p.start()
        journal.set_current_run_id(journal.new_run_id())

    def tearDown(self):
        journal.set_current_run_id(None)
        for p in self.p:
            p.stop()
        self.tmp.cleanup()

    def test_replaces_commented_default_in_place(self):
        self.f.write_text("# minlen = 8\n# dcredit = 0\n")
        keyval.set_value(self.f, "minlen", "15", fmt="minlen = 15")
        self.assertEqual(self.f.read_text(), "# minlen = 8\nminlen = 15\n# dcredit = 0\n")
        self.assertEqual(keyval.get(self.f, "minlen"), "15")

    def test_duplicate_active_lines_leave_one(self):
        self.f.write_text("minlen=8\nminlen = 10\n")
        keyval.set_value(self.f, "minlen", "15")
        active = [l for l in self.f.read_text().splitlines() if not l.startswith("#")]
        self.assertEqual(active, ["minlen=15"])

    def test_whitespace_separator(self):
        self.f.write_text("PASS_MAX_DAYS\t99999\n")
        self.assertEqual(keyval.get(self.f, "PASS_MAX_DAYS", " "), "99999")
        keyval.set_value(self.f, "PASS_MAX_DAYS", "60", " ")
        self.assertEqual(keyval.get(self.f, "PASS_MAX_DAYS", " "), "60")

    def test_noop_when_already_set(self):
        self.f.write_text("minlen = 15\n")
        self.assertEqual(keyval.set_value(self.f, "minlen", "15"), [])


class SysctlOrderTests(unittest.TestCase):
    def test_last_file_by_basename_wins_and_etc_shadows_usr(self):
        with tempfile.TemporaryDirectory() as t:
            etc, usr = Path(t, "etc"), Path(t, "usr")
            etc.mkdir(), usr.mkdir()
            (usr / "10-net.conf").write_text("net.ipv4.tcp_syncookies = 0\n")
            (etc / "10-net.conf").write_text("net.ipv4.tcp_syncookies = 1\n")  # shadows usr copy
            (usr / "50-x.conf").write_text("-net.ipv4.tcp_syncookies=0\n")
            (etc / "99-zz-lss-stig.conf").write_text("net.ipv4.tcp_syncookies = 1\n")
            with mock.patch.object(sysctl, "DIRS", [str(etc), str(usr)]):
                a = sysctl.assignments("net.ipv4.tcp_syncookies")
                self.assertEqual([v for _, v in a], ["1", "0", "1"])
                self.assertEqual(sysctl.persisted("net.ipv4.tcp_syncookies"), "1")


class PamTransformTests(unittest.TestCase):
    COMMON = ("password\t[success=1 default=ignore]\tpam_unix.so obscure yescrypt\n"
              "password\trequisite\t\t\tpam_deny.so\n")

    def test_unix_hash_switch(self):
        out = auth._set_unix_hash(self.COMMON)
        self.assertIn("pam_unix.so obscure sha512 rounds=100000", out)
        self.assertNotIn("yescrypt", out)

    def test_pwquality_inserted_before_pam_unix(self):
        out = auth._set_pwq_line(self.COMMON).splitlines()
        self.assertTrue(out[0].startswith("password\trequisite") and "pam_pwquality.so retry=3" in out[0])

    def test_pwquality_retry_fixed(self):
        src = "password requisite pam_pwquality.so retry=5 minlen=15\n" + self.COMMON
        out = auth._set_pwq_line(src).splitlines()[0]
        self.assertIn("retry=3", out)
        self.assertIn("minlen=15", out)
        self.assertNotIn("retry=5", out)

    def test_cert_policies_scoped_to_active_module(self):
        conf = """use_pkcs11_module = opensc;
        pkcs11_module coolkey {
          cert_policy = none;
        }
        pkcs11_module opensc {
          # cert_policy = none;
          cert_policy = ca, signature, ocsp_on, crl_auto;
        }"""
        self.assertEqual(auth.cert_policies(conf), ["ca,signature,ocsp_on,crl_auto"])


class GdmIniTests(unittest.TestCase):
    def test_uncomments_within_section(self):
        src = "[org/gnome/login-screen]\n# banner-message-enable=true\n\n[other]\nbanner-message-enable=false\n"
        out = set_ini(src, "org/gnome/login-screen", "banner-message-enable", "true")
        self.assertIn("[org/gnome/login-screen]\nbanner-message-enable=true\n", out)
        self.assertIn("[other]\nbanner-message-enable=false", out)

    def test_adds_missing_section(self):
        out = set_ini("[a]\nx=1\n", "org/gnome/login-screen", "k", "v")
        self.assertTrue(out.endswith("[org/gnome/login-screen]\nk=v\n"))


class DodTextTests(unittest.TestCase):
    def test_banner_consistent_across_rules(self):
        b = dod.normalize(dod.banner())
        self.assertTrue(b.startswith("You are accessing a U.S. Government (USG) Information System"))
        self.assertTrue(b.endswith("See User Agreement for details."))
        self.assertEqual(b, dod.normalize(dod.gdm_banner_value()))
        self.assertIn(b, dod.normalize(dod.ssh_confirm_script()))

    def test_confirm_script_shape(self):
        s = dod.ssh_confirm_script()
        self.assertTrue(s.startswith("#!/bin/bash\n"))
        self.assertTrue(s.rstrip().endswith("fi"))


if __name__ == "__main__":
    unittest.main()
