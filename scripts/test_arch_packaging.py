"""Focused packaging security and exact-head release gate regression tests."""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


release = module('release_arch', 'ci/release_arch.py')
purge = module('user_data', 'packaging/user_data.py')


class GateTests(unittest.TestCase):
    def setUp(self):
        self.sha = 'a' * 40
        self.runs = {}
        for index, (workflow, jobs) in enumerate(release.REQUIRED.items(), 1):
            run = {'id': index, 'head_sha': self.sha, 'head_branch': 'main', 'event': 'push',
                   'repository': {'full_name': release.REPO}, 'path': f'.github/workflows/{workflow}',
                   'run_number': 10, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success'}
            self.runs[workflow] = run

    def api(self, path):
        if '/jobs?' in path:
            number = int(path.split('/')[2])
            workflow = list(release.REQUIRED)[number - 1]
            jobs = [{'name': name, 'conclusion': 'success'} for name in release.REQUIRED[workflow]]
            return {'total_count': len(jobs), 'jobs': jobs}
        workflow = path.split('/')[2]
        return {'workflow_runs': [self.runs[workflow]]}

    def test_both_exact_head_workflows_and_jobs_required(self):
        self.assertEqual(release.accepted_runs(self.sha, self.api), {'tests.yml': 1, 'rdc-independent.yml': 2})
        for key, value in [('head_sha', 'b' * 40), ('head_branch', 'topic'), ('event', 'pull_request'),
                           ('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'skipped')]:
            with self.subTest(key=key, value=value):
                old = self.runs['tests.yml'][key]
                self.runs['tests.yml'][key] = value
                self.assertIsNone(release.accepted_runs(self.sha, self.api))
                self.runs['tests.yml'][key] = old

    def test_unknown_or_skipped_required_job_blocks(self):
        def get(path):
            result = self.api(path)
            if '/jobs?' in path:
                result['jobs'][0]['conclusion'] = 'skipped'
            return result
        self.assertIsNone(release.accepted_runs(self.sha, get))

    def test_failed_latest_run_cannot_reuse_old_success(self):
        def get(path):
            result = self.api(path)
            if 'workflow_runs' in result:
                newer = dict(result['workflow_runs'][0], id=3, run_number=11, conclusion='failure')
                result['workflow_runs'].append(newer)
            return result
        self.assertIsNone(release.accepted_runs(self.sha, get))

    def test_immutable_asset_mismatch_refuses_before_download(self):
        with self.assertRaises(ValueError):
            release.verify_existing(Path('/unused'), {'package'},
                                    {'tag_name': 'v0.1.2', 'target_commitish': self.sha, 'assets': []},
                                    self.sha, 'v0.1.2')


class PurgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.config = self.home / '.config/relayforge'
        self.config.mkdir(parents=True, mode=0o700)
        self.file = self.config / 'http-token'
        self.file.write_text('synthetic secret never returned')
        self.file.chmod(0o600)
        self.uid = patch.object(purge.os, 'getuid', return_value=self.file.stat().st_uid)
        self.uid.start()
        self.addCleanup(self.uid.stop)
        # CI may run Python discovery as root; tests simulate ordinary ownership.
        if os.getuid() == 0:
            self.fail('ordinary-user descriptor tests must run as non-root')

    def plan(self, confirm=None):
        return purge.purge(self.home, ['.config/relayforge/http-token'], confirm)

    def test_dry_run_and_nonterminal_confirmation_preserve_bytes(self):
        plan = self.plan()
        self.assertFalse(plan['applied'])
        self.assertNotIn('synthetic secret', json.dumps(plan))
        with patch.object(purge.os, 'isatty', return_value=False), self.assertRaises(ValueError):
            self.plan(plan['confirmation'])
        self.assertTrue(self.file.exists())

    def test_confirmed_exact_file_only_and_repeat(self):
        sentinel = self.home / 'evidence'
        sentinel.write_text('retain')
        plan = self.plan()
        with patch.object(purge.os, 'isatty', return_value=True), patch('builtins.input', return_value='PURGE RelayForge user files'):
            self.assertTrue(self.plan(plan['confirmation'])['applied'])
        self.assertFalse(self.file.exists())
        self.assertEqual(sentinel.read_text(), 'retain')
        self.assertTrue(self.plan()['plan']['files'][0]['absent'])

    def test_changed_plan_and_unlisted_paths_refused(self):
        plan = self.plan()
        self.file.write_text('changed')
        with self.assertRaises(ValueError):
            self.plan(plan['confirmation'])
        with self.assertRaises(ValueError):
            purge.purge(self.home, ['.local/state/relayforge/evidence'])

    def test_symlink_hardlink_and_unsafe_modes_refused(self):
        self.file.chmod(0o644)
        with self.assertRaises(ValueError):
            self.plan()
        self.file.chmod(0o600)
        other = self.home / 'other'
        os.link(self.file, other)
        with self.assertRaises(ValueError):
            self.plan()
        self.file.unlink()
        self.file.symlink_to(other)
        with self.assertRaises(ValueError):
            self.plan()
        self.file.unlink()
        self.file.write_text('fixture')
        self.file.chmod(0o600)
        self.config.chmod(0o777)
        with self.assertRaises(ValueError):
            self.plan()


if __name__ == '__main__':
    unittest.main()
