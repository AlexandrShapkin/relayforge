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

    def test_independent_accept_must_match_merged_pr_head(self):
        head = 'b' * 40
        pr = {'number': 111, 'merged_at': 'now', 'merge_commit_sha': self.sha,
              'base': {'ref': 'main', 'repo': {'full_name': release.REPO}}, 'head': {'sha': head}}
        comments = []
        def get(path):
            return [pr] if path.startswith('commits/') else comments
        self.assertFalse(release.accepted_merge(self.sha, get))
        comments.append({'user': {'login': 'outsider'}, 'body': f'Independent technical ACCEPT: {head}'})
        self.assertFalse(release.accepted_merge(self.sha, get))
        comments.append({'user': {'login': 'AlexandrShapkin'}, 'body': f'Independent technical ACCEPT: {head}'})
        self.assertTrue(release.accepted_merge(self.sha, get))
        comments.append({'user': {'login': 'AlexandrShapkin'}, 'body': f'Independent technical REJECT: {head}'})
        self.assertFalse(release.accepted_merge(self.sha, get))
        pr['head']['sha'] = 'c' * 40
        self.assertFalse(release.accepted_merge(self.sha, get))

    def test_release_bytes_and_lifecycle_must_match_checksums(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            pkgver = '0.1.0.r10.g' + self.sha[:12]
            name = f'relayforge-{pkgver}-1-x86_64.pkg.tar.zst'
            (directory / name).write_bytes(b'synthetic package bytes')
            digest = hashlib.sha256((directory / name).read_bytes()).hexdigest()
            (directory / 'source.json').write_text(json.dumps({'source_sha': self.sha,
                'pkgver': pkgver, 'tag': 'v0.1.10', 'activation_allowed': False}))
            (directory / 'arch-packages.txt').write_text('signed snapshot inventory')
            (directory / 'rustc.txt').write_text('rustc fixture')
            (directory / 'lifecycle.json').write_text(json.dumps({'source_sha': self.sha,
                'package': name, 'sha256': digest, 'lifecycle': 'PASS'}))
            original = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                               for p in sorted(directory.iterdir()))
            (directory / 'SHA256SUMS').write_text(original)
            identity, assets = release.release_files(directory, self.sha, {'tests.yml': 1})
            self.assertEqual(identity['source_sha'], self.sha)
            self.assertEqual(assets, release.ASSETS | {name})
            (directory / 'SHA256SUMS').write_text(original)
            (directory / name).write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                release.release_files(directory, self.sha, {'tests.yml': 1})

    def test_pending_main_drains_oldest_first_and_retains_rerun_verification(self):
        commits = ['a' * 40, 'b' * 40, 'c' * 40]
        def inspect(sha, get):
            return 'success', {'rdc-independent.yml': commits.index(sha) + 1}
        with patch.object(release, 'inspect_runs', side_effect=inspect), patch.object(release, 'accepted_merge', return_value=True):
            plan = release.pending_main(commits[-1], commits, [], self.api)
            self.assertEqual([p['sha'] for p in plan], commits)
            published = [{'target_commitish': commits[0], 'tag_name': 'v0.1.10', 'draft': False}]
            with patch.object(release.subprocess, 'run'), patch.object(release, 'release_files', return_value=({'tag': 'v0.1.10'}, {'package'})), patch.object(release, 'verify_existing') as verify:
                self.assertEqual(release.pending_main(commits[-1], commits[:1], published, self.api), [])
                verify.assert_called_once()
                self.assertEqual(release.pending_main(commits[0], commits[:1], published, self.api)[0]['sha'], commits[0])

    def test_remote_tag_peels_lightweight_and_nested_annotated_tags(self):
        tag = 'v0.1.10'
        for depth in (0, 1, 2):
            objects = ['b' * 40, 'c' * 40][:depth] + [self.sha]
            def get(path):
                if path == f'git/ref/tags/{tag}':
                    return {'ref': f'refs/tags/{tag}', 'object': {
                        'type': 'tag' if depth else 'commit', 'sha': objects[0]}}
                index = objects.index(path.rsplit('/', 1)[1])
                return {'sha': objects[index], 'object': {
                    'type': 'commit' if index + 1 == depth else 'tag', 'sha': objects[index + 1]}}
            with self.subTest(depth=depth):
                self.assertEqual(release.tag_commit(tag, get), self.sha)

    def test_matching_release_metadata_cannot_hide_wrong_git_tag(self):
        existing = {'tag_name': 'v0.1.10', 'target_commitish': self.sha,
                    'assets': [{'name': 'package'}]}
        for annotated in (False, True):
            def get(path):
                obj = {'type': 'commit', 'sha': 'b' * 40}
                if path.startswith('git/ref/'):
                    return {'ref': 'refs/tags/v0.1.10', 'object':
                            {'type': 'tag', 'sha': 'c' * 40} if annotated else obj}
                return {'sha': 'c' * 40, 'object': obj}
            with self.subTest(annotated=annotated), patch.object(release.subprocess, 'run') as download:
                with self.assertRaisesRegex(ValueError, 'tag commit conflict'):
                    release.verify_existing(Path('/unused'), {'package'}, existing,
                                            self.sha, 'v0.1.10', get)
                download.assert_not_called()

    def test_tag_noncommit_cycles_missing_and_malformed_objects_fail_closed(self):
        for obj in ({'type': 'tree', 'sha': self.sha},
                    {'type': 'tag', 'sha': self.sha},
                    {'type': 'commit', 'sha': 'short'}):
            def get(path):
                return {'ref': 'refs/tags/v0.1.10', 'sha': self.sha, 'object': obj}
            with self.subTest(obj=obj), self.assertRaises(ValueError):
                release.tag_commit('v0.1.10', get)
        with self.assertRaises(RuntimeError):
            release.tag_commit('v0.1.10', lambda _: (_ for _ in ()).throw(RuntimeError('404')))

    def test_history_rejects_unrelated_draft_duplicate_missing_and_changed_assets(self):
        tag = 'v0.1.10'
        existing = {'tag_name': tag, 'target_commitish': self.sha, 'draft': False,
                    'assets': [{'name': 'package'}]}
        cases = [([dict(existing, tag_name='v9.9.9')], 'source conflict'),
                 ([dict(existing, target_commitish='b' * 40)], 'source conflict'),
                 ([dict(existing, draft=True)], 'incomplete release history'),
                 ([existing, existing], 'incomplete release history'),
                 ([dict(existing, assets=[])], 'inventory differs'),
                 ([existing], 'bytes differ')]
        for releases, message in cases:
            with self.subTest(message=message):
                def download(args, **kwargs):
                    if args[:3] == ['gh', 'release', 'download']:
                        (Path(args[args.index('--dir') + 1]) / 'package').write_bytes(b'changed')
                def files(destination, sha, runs):
                    (destination / 'package').write_bytes(b'expected')
                    return {'tag': tag}, {'package'}
                def get(path):
                    return {'ref': f'refs/tags/{tag}', 'object': {'type': 'commit', 'sha': self.sha}}
                with patch.object(release, 'inspect_runs', return_value=('success', {'rdc-independent.yml': 2})), patch.object(release, 'accepted_merge', return_value=True), patch.object(release, 'release_files', side_effect=files), patch.object(release.subprocess, 'run', side_effect=download):
                    with self.assertRaisesRegex(ValueError, message):
                        release.pending_main('b' * 40, [self.sha], releases, get)

    def test_history_skips_only_after_real_tag_and_byte_verification(self):
        tag = 'v0.1.10'
        existing = {'tag_name': tag, 'target_commitish': self.sha, 'draft': False,
                    'assets': [{'name': 'package'}]}
        downloads = []
        def download(args, **kwargs):
            downloads.append(args[:3])
            if args[:3] == ['gh', 'release', 'download']:
                (Path(args[args.index('--dir') + 1]) / 'package').write_bytes(b'tested')
        def files(destination, sha, runs):
            (destination / 'package').write_bytes(b'tested')
            return {'tag': tag}, {'package'}
        def get(path):
            return {'ref': f'refs/tags/{tag}', 'object': {'type': 'commit', 'sha': self.sha}}
        with patch.object(release, 'inspect_runs', return_value=('success', {'rdc-independent.yml': 2})), patch.object(release, 'accepted_merge', return_value=True), patch.object(release, 'release_files', side_effect=files), patch.object(release.subprocess, 'run', side_effect=download):
            self.assertEqual(release.pending_main('b' * 40, [self.sha], [existing], get), [])
        self.assertEqual(downloads, [['gh', 'run', 'download'], ['gh', 'release', 'download']])

    def test_history_missing_ci_or_artifacts_cannot_be_skipped(self):
        existing = {'tag_name': 'v0.1.10', 'target_commitish': self.sha, 'draft': False}
        for state in ('pending', 'failed'):
            with patch.object(release, 'inspect_runs', return_value=(state, None)):
                with self.assertRaisesRegex(ValueError, 'exact-head CI'):
                    release.pending_main('b' * 40, [self.sha], [existing])
        with patch.object(release, 'inspect_runs', return_value=('success', {'rdc-independent.yml': 2})), patch.object(release, 'accepted_merge', return_value=True), patch.object(release.subprocess, 'run', side_effect=RuntimeError('artifact expired')):
            with self.assertRaisesRegex(RuntimeError, 'artifact expired'):
                release.pending_main('b' * 40, [self.sha], [existing])

    def test_pending_predecessor_blocks_later_publication(self):
        commits = ['a' * 40, 'b' * 40]
        with patch.object(release, 'inspect_runs', return_value=('pending', None)):
            self.assertEqual(release.pending_main(commits[-1], commits, [], self.api), [])
        with patch.object(release, 'inspect_runs', return_value=('failed', None)):
            self.assertEqual(release.pending_main(commits[-1], commits, [], self.api), [])

    def test_pending_main_without_review_fails_closed(self):
        with patch.object(release, 'inspect_runs', return_value=('success', {'rdc-independent.yml': 1})), patch.object(release, 'accepted_merge', return_value=False):
            with self.assertRaisesRegex(ValueError, 'review handoff missing'):
                release.pending_main(self.sha, [self.sha], [], self.api)

    def test_release_notes_need_reviewed_problem_narrative(self):
        pr = {'merged_at': 'now', 'merge_commit_sha': self.sha, 'base': {'ref': 'main'},
              'html_url': 'https://github.com/example/pull/1', 'body': 'title only'}
        with self.assertRaisesRegex(ValueError, 'narrative required'):
            release.merge_narrative(self.sha, lambda _: [pr])
        text = 'Previous manual copies lacked a native installation contract. Pacman now owns installed binaries and inactive templates.'
        pr['body'] = '## Problem and resulting behavior\n' + text + '\n## Verification\ninternal checks'
        result = release.merge_narrative(self.sha, lambda _: [pr])
        self.assertIn(text, result)
        self.assertNotIn('internal checks', result)


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
