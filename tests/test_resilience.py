import io
import unittest
from unittest import mock

from lss_stig import cli
from lss_stig.lib import pkg


class PkgDepsTests(unittest.TestCase):
    def test_undo_purges_pulled_in_dependencies(self):
        snaps = iter([{"base"}, {"base", "sssd", "libnss-sss", "tzdata-legacy"}])
        with mock.patch.object(pkg.distro, "is_debian_family", return_value=True), \
             mock.patch.object(pkg, "is_installed", return_value=False), \
             mock.patch.object(pkg, "_ensure_candidates"), \
             mock.patch.object(pkg, "_run") as run, \
             mock.patch.object(pkg, "_dpkg_installed", side_effect=lambda: next(snaps)):
            (entry,) = pkg.install("sssd")
        self.assertIn("--no-install-recommends", run.call_args[0][0])
        self.assertEqual(entry.undo, [["apt-get", "purge", "-y", "libnss-sss", "sssd", "tzdata-legacy"]])
        self.assertIn("+2 dependencies", entry.action)


class TolerantStreamTests(unittest.TestCase):
    def test_write_after_terminal_loss_is_swallowed(self):
        class Gone(io.StringIO):
            def write(self, s):
                raise OSError(5, "Input/output error")
        t = cli._Tolerant(Gone())
        self.assertEqual(t.write("x"), 1)
        self.assertEqual(t.write("yz"), 2)
        t.flush()


RID = "20260101T000000Z-0123abcd"


class RollbackMarkTests(unittest.TestCase):
    def test_each_rule_marked_as_it_completes(self):
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from lss_stig import rollback
        from lss_stig.lib import journal
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.object(journal, "JOURNAL_DIR", Path(d)), \
             mock.patch.object(rollback, "syslog"):
            journal.write_run(RID, {"V-1": [{"action": "a", "undo": [["true"]]}],
                                     "V-2": [{"action": "b", "undo": [["false"]]}]})
            calls = []
            real = journal.mark_rolled_back
            with mock.patch.object(journal, "mark_rolled_back",
                                   side_effect=lambda r, ids: (calls.append(list(ids)), real(r, ids))):
                args = SimpleNamespace(run_id=RID, last=False, rule=None, list=False, yes=True)
                with mock.patch("sys.stdout", io.StringIO()), mock.patch("sys.stderr", io.StringIO()):
                    rollback.run_rollback(args)
            self.assertEqual(calls, [["V-1"]])              # V-2's undo failed → stays pending
            self.assertEqual(journal.read_run(RID)["rolled_back"], ["V-1"])


if __name__ == "__main__":
    unittest.main()
