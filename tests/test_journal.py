import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from lss_stig import rollback
from lss_stig.lib import journal


class JournalRollbackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.jdir = root / "journal"
        self.patches = [
            mock.patch.object(journal, "JOURNAL_DIR", self.jdir),
            mock.patch.object(journal, "BACKUPS_DIR", self.jdir / "backups"),
        ]
        for p in self.patches:
            p.start()
        self.target = root / "etc" / "conf"
        self.target.parent.mkdir()
        self.target.write_text("original\n")

    def tearDown(self):
        for p in self.patches:
            p.stop()
        journal.set_current_run_id(None)
        self.tmp.cleanup()

    def test_two_rules_editing_same_file_roll_back_to_original(self):
        run_id = journal.new_run_id()
        journal.set_current_run_id(run_id)
        b1 = journal.backup_file(str(self.target))
        self.target.write_text("after rule 1\n")
        b2 = journal.backup_file(str(self.target))
        self.target.write_text("after rule 2\n")
        self.assertNotEqual(b1, b2)
        journal.write_run(run_id, {
            "V-1": [{"action": "a", "undo": [], "path": str(self.target), "backup": b1}],
            "V-2": [{"action": "b", "undo": [], "path": str(self.target), "backup": b2}],
        })
        args = SimpleNamespace(last=True, run_id=None, rule=None)
        self.assertEqual(rollback.run_rollback(args), 0)
        self.assertEqual(self.target.read_text(), "original\n")

    def test_rejects_malformed_run_id(self):
        args = SimpleNamespace(last=False, run_id="../../etc/passwd", rule=None)
        self.assertEqual(rollback.run_rollback(args), 1)

    def test_string_undo_is_never_executed(self):
        run_id = journal.new_run_id()
        journal.write_run(run_id, {"V-1": [{"action": "x", "undo": "touch /tmp/pwned", "path": "", "backup": ""}]})
        with mock.patch("subprocess.run") as run:
            rc = rollback.run_rollback(SimpleNamespace(last=True, run_id=None, rule=None))
            run.assert_not_called()
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
