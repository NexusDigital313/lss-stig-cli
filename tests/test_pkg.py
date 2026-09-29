import subprocess
import unittest
from unittest import mock

from lss_stig.controls.ubuntu2404 import aide
from lss_stig.lib import pkg

POLICY = """vlock:
  Installed: (none)
  Candidate: (none)
  Version table:
auditd:
  Installed: (none)
  Candidate: 1:3.1.2-2.1build1.1
  Version table:
     1:3.1.2-2.1build1.1 500
"""


def done(stdout=""):
    return subprocess.CompletedProcess([], 0, stdout, "")


class CandidateTests(unittest.TestCase):
    def test_parses_policy(self):
        # opensc-pkcs11 prints nothing at all when apt has never heard of it
        with mock.patch.object(pkg.subprocess, "run", return_value=done(POLICY)):
            self.assertEqual(pkg._no_candidate(["vlock", "auditd", "opensc-pkcs11"]), ["vlock", "opensc-pkcs11"])

    def test_refreshes_lists_once_then_fails_clearly(self):
        calls = []
        with mock.patch.object(pkg, "_lists_refreshed", False), \
             mock.patch.object(pkg, "_no_candidate", return_value=["vlock"]), \
             mock.patch.object(pkg, "_run", side_effect=calls.append):
            with self.assertRaisesRegex(RuntimeError, "universe"):
                pkg._ensure_candidates(["vlock"])
            with self.assertRaises(RuntimeError):
                pkg._ensure_candidates(["vlock"])
        self.assertEqual(calls, [["apt-get", *pkg._APT_OPTS, "update"]])

    def test_refresh_fixes_stale_lists(self):
        with mock.patch.object(pkg, "_lists_refreshed", False), \
             mock.patch.object(pkg, "_no_candidate", side_effect=[["vlock"], []]), \
             mock.patch.object(pkg, "_run") as run:
            pkg._ensure_candidates(["vlock"])
        run.assert_called_once()


class InstallTests(unittest.TestCase):
    def test_one_transaction_for_missing_only(self):
        with mock.patch.object(pkg.distro, "is_debian_family", return_value=True), \
             mock.patch.object(pkg, "is_installed", side_effect=lambda p: p == "aide"), \
             mock.patch.object(pkg, "_ensure_candidates"), \
             mock.patch.object(pkg, "_run") as run:
            out = pkg.install("aide", "aide-common")
        self.assertEqual(run.call_args[0][0][-2:], ["--no-install-recommends", "aide-common"])
        self.assertEqual(out[0].undo, [["apt-get", "purge", "-y", "aide-common"]])


class AideInstalledTests(unittest.TestCase):
    def test_aide_without_aide_common_fails(self):
        with mock.patch.object(pkg, "is_installed", side_effect=lambda p: p == "aide"):
            r = aide._check_installed()
        self.assertEqual(r.status, "fail")
        self.assertIn("aide-common", r.detail)


class JournaldGroupTests(unittest.TestCase):
    def test_dropin_undo_restarts_journald(self):
        import tempfile
        from pathlib import Path
        from lss_stig.controls.ubuntu2404 import filesystem
        from lss_stig.lib import journal
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(filesystem, "JOURNALD_DROPIN", Path(d) / "x.conf"), \
             mock.patch.object(journal, "BACKUPS_DIR", Path(d) / "b"), \
             mock.patch.object(journal, "_current_run_id", "r"), \
             mock.patch.object(filesystem.systemd, "run") as run:
            out = filesystem._journald_group()
            self.assertIn("Group=systemd-journal", (Path(d) / "x.conf").read_text())
            self.assertEqual(out[0].undo[-1], ["systemctl", "restart", "systemd-journald.service"])
            run.assert_any_call("restart", "systemd-journald.service")
            run.reset_mock()
            self.assertEqual(filesystem._journald_group(), [])  # idempotent: no second restart
            run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
