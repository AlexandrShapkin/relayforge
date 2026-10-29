#!/usr/bin/env python3
"""Crash recovery and clean/preserved filesystem installation, without services."""
import contextlib
import importlib.util
import os
import subprocess
import sys
import stat
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/activation_transaction.py'
if Path(__file__).with_name('activation_transaction.py').exists():
    SOURCE = Path(__file__).with_name('activation_transaction.py')
spec = importlib.util.spec_from_file_location('activation', SOURCE)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class ActivationTests(unittest.TestCase):
    def fixture(self, root):
        root.chmod(0o700)
        units = [root / 'http.service', root / 'tunnel.service']
        for i, path in enumerate(units):
            path.write_bytes(f'exact baseline {i}\n\n'.encode())
            path.chmod(0o644)
        (root / 'current').symlink_to('baseline')
        targets = {p: a.file_state(b'candidate\n', 0o644) for p in units}
        targets.update({root / 'root-map': a.file_state(b'approved\n', 0o600),
                        root / 'previous': {'link': 'baseline'},
                        root / 'current': {'link': 'candidate'}})
        return targets

    def test_clean_first_install_and_preserve_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            audit = root / 'new/state/audit'
            planned = a.private_file(audit, limit=8 * 1024 * 1024)
            self.assertFalse(audit.parent.exists())
            self.assertIn(str(audit), planned)
            a.private_file(audit, True, 8 * 1024 * 1024)
            audit.write_bytes(b'existing audit\n')
            a.private_file(audit, True, 8 * 1024 * 1024)
            self.assertEqual(audit.read_bytes(), b'existing audit\n')
            self.assertEqual(audit.stat().st_mode & 0o777, 0o600)

    def test_every_interruption_restores_exact_state_and_selectors(self):
        for stop in range(6):
            with self.subTest(stop=stop), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                targets = self.fixture(root)
                before = {str(p): a.state(p) for p in targets}
                journal = root / 'journal'
                t = a.Transaction(journal, targets, True)
                for path in list(targets)[:stop]:
                    t.apply(path)
                # Reopen exactly as an independent process after SIGKILL.
                t = a.Transaction(journal, targets)
                t.rollback()
                t.rollback()
                self.assertEqual({str(p): a.state(p) for p in targets}, before)

    def test_sigkill_process_reopens_durable_journal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            t = a.Transaction(root / 'journal', targets, True)
            payload = root / 'targets.json'
            payload.write_text(__import__('json').dumps({str(p): v for p, v in targets.items()}))
            code = """
import importlib.util,json,os,signal,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('a',sys.argv[1]);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
t=a.Transaction(Path(sys.argv[2]),json.loads(Path(sys.argv[3]).read_text()))
for p in list(t.targets)[:3]: t.apply(p)
os.kill(os.getpid(),signal.SIGKILL)
"""
            run = subprocess.run([sys.executable, '-B', '-c', code, a.__file__, str(t.path), str(payload)])
            self.assertEqual(run.returncode, -9)
            reopened = a.Transaction(t.path, targets)
            reopened.rollback()
            for path in targets:
                self.assertEqual(a.state(path), reopened.doc['targets'][str(path)]['before'])

    def test_existing_root_map_and_unrelated_files_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            (root / 'root-map').write_bytes(b'owner existing exact bytes\n')
            (root / 'root-map').chmod(0o600)
            (root / 'unrelated').write_bytes(b'untouched')
            t = a.Transaction(root / 'journal', targets, True)
            for path in targets:
                t.apply(path)
            t.rollback()
            self.assertEqual((root / 'root-map').read_bytes(), b'owner existing exact bytes\n')
            self.assertEqual((root / 'unrelated').read_bytes(), b'untouched')

    def test_crash_after_temp_sync_before_rename(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            t = a.Transaction(root / 'journal', targets, True)
            path = next(iter(targets))
            with patch.object(a.os, 'replace', side_effect=OSError('crash')):
                with self.assertRaises(OSError):
                    t.apply(path)
            t = a.Transaction(root / 'journal', targets)
            t.rollback()
            self.assertEqual(a.state(path), t.doc['targets'][str(path)]['before'])
            self.assertTrue(t.temporary(path).exists())

    def test_unknown_target_refuses_all_restoration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            t = a.Transaction(root / 'journal', targets, True)
            for path in targets:
                t.apply(path)
            path = next(iter(targets))
            path.write_bytes(b'unknown owner change')
            with self.assertRaises(RuntimeError):
                t.rollback()
            self.assertEqual(path.read_bytes(), b'unknown owner change')
            self.assertEqual(os.readlink(root / 'current'), 'candidate')
            path.write_bytes(b'candidate\n')
            t.rollback()

    def test_partial_temporary_does_not_block_known_target_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            t = a.Transaction(root / 'journal', targets, True)
            path = next(iter(targets))
            t.apply(path)
            partial = t.temporary(path)
            partial.write_bytes(b'partial failed write')
            t.rollback()
            self.assertEqual(a.state(path), t.doc['targets'][str(path)]['before'])
            self.assertEqual(partial.read_bytes(), b'partial failed write')

    def test_planning_race_is_refused_before_journal_or_target_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            path = next(iter(targets))
            expected = a.state(path)
            path.write_bytes(b'concurrent owner change')
            with self.assertRaises(RuntimeError):
                a.Transaction(root / 'journal', targets, True, expected_before={path: expected})
            self.assertFalse((root / 'journal').exists())
            self.assertEqual(path.read_bytes(), b'concurrent owner change')

    def test_committed_attempt_is_not_rolled_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            targets = self.fixture(root)
            t = a.Transaction(root / 'journal', targets, True)
            for path in targets:
                t.apply(path)
            t.commit()
            a.Transaction(root / 'journal', targets).rollback()
            self.assertEqual(os.readlink(root / 'current'), 'candidate')

    def test_commit_io_failures_remain_recoverable(self):
        for failure in ('write', 'replace', 'file-fsync', 'directory-fsync'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                targets = self.fixture(root)
                tx = a.Transaction(root / 'journal', targets, True)
                for path in targets:
                    tx.apply(path)
                real_write, real_sync = a.write, a.os.fsync
                def failing_write(path, value, temporary):
                    if failure == 'write':
                        raise OSError('write failed')
                    return real_write(path, value, temporary)
                def failing_sync(fd):
                    directory = stat.S_ISDIR(os.fstat(fd).st_mode)
                    # Guard is persisted before injecting journal failures.
                    if failure == ('directory-fsync' if directory else 'file-fsync'):
                        raise OSError('fsync failed')
                    return real_sync(fd)
                a.private_file(tx.path.with_name('journal.commit-in-progress'), True)
                with patch.object(a, 'write', failing_write), patch.object(a.os, 'fsync', failing_sync):
                    with patch.object(a.os, 'replace', side_effect=OSError('rename failed')) if failure == 'replace' else contextlib.nullcontext():
                        with self.assertRaises(OSError):
                            tx.commit()
                self.assertEqual(tx.doc['status'], 'pending')
                reopened = a.Transaction(tx.path, targets)
                self.assertEqual(reopened.doc['status'], 'pending')
                reopened.rollback()
                for path in targets:
                    self.assertEqual(a.state(path), reopened.doc['targets'][str(path)]['before'])

    def test_commit_guard_cleanup_failure_never_publishes_memory_status(self):
        for failure in ('unlink', 'directory-fsync'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                targets = self.fixture(root)
                tx = a.Transaction(root / 'journal', targets, True)
                for path in targets:
                    tx.apply(path)
                real_sync = a.sync
                def sync(path):
                    if not tx.path.with_name('journal.commit-in-progress').exists():
                        raise OSError('guard removal fsync failed')
                    real_sync(path)
                with patch.object(Path, 'unlink', side_effect=OSError('unlink failed')) if failure == 'unlink' else patch.object(a, 'sync', sync):
                    with self.assertRaises(OSError):
                        tx.commit()
                self.assertEqual(tx.doc['status'], 'pending')
                reopened = a.Transaction(tx.path, targets)
                # The committed journal itself was durably synced before guard
                # removal; a surviving guard conservatively requires rollback.
                self.assertEqual(reopened.doc['status'], 'pending' if failure == 'unlink' else 'committed')

    def test_symlinks_hardlinks_modes_and_oversize_are_blockers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / 'audit'
            file.symlink_to(root / 'missing')
            with self.assertRaises(RuntimeError):
                a.private_file(file)
            file.unlink()
            file.write_bytes(b'keep')
            file.chmod(0o600)
            os.link(file, root / 'hardlink')
            with self.assertRaises(RuntimeError):
                a.private_file(file)
            (root / 'hardlink').unlink()
            with self.assertRaises(RuntimeError):
                a.private_file(file, limit=1)
            file.chmod(0o644)
            with self.assertRaises(RuntimeError):
                a.private_file(file)


if __name__ == '__main__':
    unittest.main()
