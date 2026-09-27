import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lss_stig.lib import journal, sshd

MAIN = """Include /etc/ssh/sshd_config.d/*.conf
X11Forwarding yes
PermitEmptyPasswords no
"""
CLOUD = "PasswordAuthentication yes\nX11Forwarding yes\n"


class SshdFixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.main = root / "sshd_config"
        self.d = root / "sshd_config.d"
        self.d.mkdir()
        self.main.write_text(MAIN)
        (self.d / "50-cloud-init.conf").write_text(CLOUD)
        jdir = root / "journal"
        self.patches = [
            mock.patch.object(sshd, "SSHD_CONFIG", self.main),
            mock.patch.object(sshd, "SSHD_CONFIG_D", self.d),
            mock.patch.object(sshd, "DROPIN", self.d / "00-lss-stig.conf"),
            mock.patch.object(sshd, "reload", lambda: True),
            mock.patch.object(journal, "JOURNAL_DIR", jdir),
            mock.patch.object(journal, "BACKUPS_DIR", jdir / "backups"),
        ]
        for p in self.patches:
            p.start()
        journal.set_current_run_id(journal.new_run_id())

    def tearDown(self):
        journal.set_current_run_id(None)
        for p in self.patches:
            p.stop()
        self.tmp.cleanup()

    def _effective_from_files(self, key):
        return None  # force file-based evaluation, no sshd binary needed

    def test_check_flags_conflicts_then_fix_passes(self):
        with mock.patch.object(sshd, "effective", self._effective_from_files):
            before = sshd.check_setting("X11Forwarding", "no")
            self.assertEqual(before.status, "fail")
            self.assertIn("50-cloud-init.conf", before.detail)

            with mock.patch.object(sshd, "validate", lambda: (True, "ok")):
                entries = sshd.set_settings({"X11Forwarding": "no"})

            self.assertEqual(sshd.check_setting("X11Forwarding", "no").status, "pass")
        self.assertIn("X11Forwarding no", (self.d / "00-lss-stig.conf").read_text())
        self.assertIn("# lss-stig: X11Forwarding yes", self.main.read_text())
        # untouched keyword stays as it was
        self.assertIn("PasswordAuthentication yes", (self.d / "50-cloud-init.conf").read_text())
        self.assertEqual(len(entries), 3)  # main, cloud-init, drop-in

    def test_failed_validation_reverts_everything(self):
        with mock.patch.object(sshd, "validate", lambda: (False, "bad")):
            with self.assertRaises(RuntimeError):
                sshd.set_settings({"X11Forwarding": "no"})
        self.assertEqual(self.main.read_text(), MAIN)
        self.assertEqual((self.d / "50-cloud-init.conf").read_text(), CLOUD)
        self.assertFalse((self.d / "00-lss-stig.conf").exists())

    def test_refuses_without_include(self):
        self.main.write_text("X11Forwarding yes\n")
        with self.assertRaises(RuntimeError):
            sshd.set_settings({"X11Forwarding": "no"})


if __name__ == "__main__":
    unittest.main()
