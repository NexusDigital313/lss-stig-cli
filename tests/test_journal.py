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

    def test_last_moves_to_previous_run(self):
        journal.set_current_run_id(None)
        self.target.write_text("run1\n")
        journal.write_run("20260101T000000Z-aaaaaaaa", {
            "V-1": [{"action": "a", "undo": [["true"]], "path": "", "backup": ""}]})
        journal.write_run("20260102T000000Z-bbbbbbbb", {
            "V-2": [{"action": "b", "undo": [["true"]], "path": "", "backup": ""}]})
        last = SimpleNamespace(last=True, run_id=None, rule=None)
        with mock.patch.object(rollback, "info") as info:
            rollback.run_rollback(last)
            rollback.run_rollback(last)
            self.assertEqual(rollback.run_rollback(last), 0)
        said = " ".join(str(c) for c in info.call_args_list)
        self.assertIn("bbbbbbbb", said)
        self.assertIn("aaaaaaaa", said)
        self.assertIn("already rolled back", said)
        self.assertEqual(journal.read_run("20260101T000000Z-aaaaaaaa")["rolled_back"], ["V-1"])

    def test_failed_undo_stays_pending(self):
        journal.write_run("20260101T000000Z-cccccccc", {
            "V-1": [{"action": "a", "undo": [["false"]], "path": "", "backup": ""}],
            "V-2": [{"action": "b", "undo": [["true"]], "path": "", "backup": ""}]})
        rollback.run_rollback(SimpleNamespace(last=True, run_id=None, rule=None))
        data = journal.read_run("20260101T000000Z-cccccccc")
        self.assertEqual(list(journal.pending_controls(data)), ["V-1"])

    def test_locked_audit_rules_regenerate_instead_of_load(self):
        with mock.patch.object(rollback.auditrules, "immutable", return_value=True), \
             mock.patch.object(rollback.shutil, "which", return_value="/usr/sbin/augenrules"), \
             mock.patch("subprocess.run") as run:
            ok, msg = rollback._run_undo("V-1", ["augenrules", "--load"])
        self.assertTrue(ok)
        self.assertEqual(run.call_args[0][0], ["augenrules"])

    def test_no_edit_warning_for_harden_own_changes(self):
        run_id = journal.new_run_id()
        journal.set_current_run_id(run_id)
        b1 = journal.backup_file(str(self.target))
        self.target.write_text("after rule 1\n")
        b2 = journal.backup_file(str(self.target))
        self.target.write_text("after rule 2\n")
        journal.write_run(run_id, {
            "V-1": [{"action": "a", "undo": [], "path": str(self.target), "backup": b1}],
            "V-2": [{"action": "b", "undo": [], "path": str(self.target), "backup": b2}],
        })
        with mock.patch.object(rollback, "warn") as warn:
            rollback.run_rollback(SimpleNamespace(last=True, run_id=None, rule=None))
        warn.assert_not_called()

    def test_restore_into_removed_dir_is_skipped(self):
        b = Path(self.tmp.name) / "bkp"
        b.write_text("x")
        ok, msg = rollback._restore_backup("V-1", str(b), str(Path(self.tmp.name) / "gone" / "f"))
        self.assertTrue(ok)
        self.assertIn("no longer exists", msg)

    def test_statoverride_remove_is_idempotent(self):
        err = rollback.subprocess.CalledProcessError(2, [], stderr="dpkg-statoverride: warning: no override present\n")
        with mock.patch("subprocess.run", side_effect=err):
            ok, _ = rollback._run_undo("V-1", ["dpkg-statoverride", "--remove", "/usr/bin/journalctl"])
        self.assertTrue(ok)

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
