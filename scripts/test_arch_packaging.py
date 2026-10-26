"""Focused packaging security and exact-head release gate regression tests."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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
        extras = patch.object(release, 'tunnel_assets', return_value=set())
        extras.start()
        self.addCleanup(extras.stop)
        self.sha = 'a' * 40
        self.tag = 'v0.1.10'
        self.package = f'relayforge-0.1.0.r10.g{self.sha[:12]}-1-x86_64.pkg.tar.zst'
        self.source_names = release.source_names
        names = patch.object(release, 'source_names', return_value=(self.tag, self.package))
        names.start()
        self.addCleanup(names.stop)
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

    def test_historical_names_use_committed_version_and_first_parent_revision(self):
        def command(*args):
            if args == ('git', 'show', f'{self.sha}:Cargo.toml'):
                return '[workspace.package]\nversion = "0.2.9"\n'
            self.assertEqual(args, ('git', 'rev-list', '--first-parent', '--count', self.sha))
            return '321'
        with patch.object(release, 'command', side_effect=command):
            self.assertEqual(self.source_names(self.sha),
                             ('v0.2.321', f'relayforge-0.2.9.r321.g{self.sha[:12]}-1-x86_64.pkg.tar.zst'))

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

    def test_pending_main_drains_oldest_first_and_verifies_published_trigger(self):
        commits = ['a' * 40, 'b' * 40, 'c' * 40]
        def inspect(sha, get):
            return 'success', {'rdc-independent.yml': commits.index(sha) + 1}
        with patch.object(release, 'inspect_runs', side_effect=inspect), patch.object(release, 'accepted_merge', return_value=True):
            plan = release.pending_main(commits[-1], commits, [], self.api)
            self.assertEqual([p['sha'] for p in plan], commits)
            published = [{'target_commitish': commits[0], 'tag_name': self.tag, 'draft': False}]
            with patch.object(release, 'verify_published') as verify:
                self.assertEqual(release.pending_main(commits[-1], commits[:1], published, self.api), [])
                verify.assert_called_once()
                # A repeated completion validates the durable release, too.
                self.assertEqual(release.pending_main(commits[0], commits[:1], published, self.api), [])


    def test_partial_draft_still_requires_exact_head_ci_and_accept(self):
        draft = {'tag_name': self.tag, 'target_commitish': self.sha, 'draft': True, 'id': 321}
        for state in ('pending', 'failed'):
            with self.subTest(state=state), patch.object(release, 'inspect_runs', return_value=(state, None)):
                self.assertEqual(release.pending_main(self.sha, [self.sha], [draft], self.api), [])
        runs = {'tests.yml': 1, 'rdc-independent.yml': 2}
        with patch.object(release, 'inspect_runs', return_value=('success', runs)):
            with patch.object(release, 'accepted_merge', return_value=False):
                with self.assertRaisesRegex(ValueError, 'review handoff'):
                    release.pending_main(self.sha, [self.sha], [draft], self.api)
            with patch.object(release, 'accepted_merge', return_value=True):
                self.assertEqual(release.pending_main(self.sha, [self.sha], [draft], self.api),
                                 [{'sha': self.sha, 'run_id': 2}])
        with patch.object(release, 'inspect_runs', return_value=('success', runs)):
            conflicting = dict(draft, tag_name='v9.9.9')
            with self.assertRaisesRegex(ValueError, 'source conflict'):
                release.pending_main(self.sha, [self.sha], [conflicting], self.api)

    def test_draft_remote_digest_inventory_and_tag_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            data = {'package': b'package bytes', 'SHA256SUMS': b'trusted manifest bytes'}
            for name, content in data.items():
                (directory / name).write_bytes(content)
            def assets(mapping):
                return [{'id': i + 1, 'name': name, 'size': len(content),
                         'digest': 'sha256:' + hashlib.sha256(content).hexdigest()}
                        for i, (name, content) in enumerate(mapping.items())]
            draft = {'id': 321, 'draft': True, 'tag_name': self.tag,
                     'target_commitish': self.sha, 'assets': assets(data)}
            release.verify_draft_uploaded(directory, set(data), draft, self.sha, self.tag, self.durable_api)
            for invalid in (dict(draft, draft=False),
                            dict(draft, target_commitish='b' * 40),
                            dict(draft, tag_name='v9.9.9'),
                            dict(draft, assets=draft['assets'][:1]),
                            dict(draft, assets=draft['assets'] + draft['assets'][:1]),
                            dict(draft, assets=[dict(draft['assets'][0], digest='sha256:' + '0' * 64),
                                                draft['assets'][1]]),
                            dict(draft, assets=[dict(draft['assets'][0], size=999),
                                                draft['assets'][1]])):
                with self.subTest(invalid=str(invalid)[:80]), self.assertRaises(ValueError):
                    release.verify_draft_uploaded(directory, set(data), invalid,
                                                  self.sha, self.tag, self.durable_api)
            with self.assertRaisesRegex(ValueError, 'tag target'):
                release.verify_draft_uploaded(directory, set(data), draft, self.sha, self.tag,
                                              lambda _: {'ref': f'refs/tags/{self.tag}',
                                                         'object': {'type': 'commit', 'sha': 'b' * 40}})

    def test_publish_resumes_exact_draft_by_release_id_only(self):
        draft = {'id': 321, 'draft': True, 'tag_name': self.tag,
                 'target_commitish': self.sha, 'assets': []}
        calls = []
        def api(path, *args):
            calls.append((path, args))
            if path.startswith('compare/'):
                return {'status': 'identical', 'merge_base_commit': {'sha': self.sha}}
            if path == 'releases/321':
                return dict(draft, draft=False) if args == ('-X', 'PATCH', '-F', 'draft=false') else draft
            self.fail(f'unexpected API path or mutation: {path} {args}')
        runs = {'tests.yml': 1, 'rdc-independent.yml': 2}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            with patch.object(release, 'accepted_runs', return_value=runs), \
                 patch.object(release, 'accepted_merge', return_value=True), \
                 patch.object(release, 'merge_narrative', return_value='reviewed'), \
                 patch.object(release, 'release_files', return_value=({'tag': self.tag},
                                  release.ASSETS | {self.package})), \
                 patch.object(release, 'verify_provenance'), \
                 patch.object(release, 'all_releases', return_value=[draft]), \
                 patch.object(release, 'api', side_effect=api), \
                 patch.object(release, 'verify_draft_uploaded') as verified, \
                 patch.object(release, 'verify_existing') as published, \
                 patch.object(release.subprocess, 'run') as gh:
                release.publish(directory, self.sha, runs)
                verified.assert_called_once()
                published.assert_called_once()
                gh.assert_not_called()
        self.assertEqual([x[0] for x in calls],
                         [f'compare/{self.sha}...main', 'releases/321', 'releases/321'])

    def test_publication_rejects_unverified_partial_draft_before_patch(self):
        draft = {'id': 321, 'draft': True, 'tag_name': self.tag,
                 'target_commitish': self.sha, 'assets': []}
        calls = []
        def api(path, *args):
            calls.append((path, args))
            if path.startswith('compare/'):
                return {'status': 'identical', 'merge_base_commit': {'sha': self.sha}}
            if path == 'releases/321' and not args:
                return draft
            self.fail('unsafe mutation before verification')
        runs = {'tests.yml': 1, 'rdc-independent.yml': 2}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(release, 'accepted_runs', return_value=runs), \
             patch.object(release, 'accepted_merge', return_value=True), \
             patch.object(release, 'merge_narrative', return_value='reviewed'), \
             patch.object(release, 'release_files', return_value=({'tag': self.tag},
                                  release.ASSETS | {self.package})), \
             patch.object(release, 'verify_provenance'), \
             patch.object(release, 'all_releases', return_value=[draft]), \
             patch.object(release, 'api', side_effect=api), \
             patch.object(release, 'verify_draft_uploaded', side_effect=ValueError('asset digest mismatch')):
            with self.assertRaisesRegex(ValueError, 'asset digest mismatch'):
                release.publish(Path(tmp), self.sha, runs)
        self.assertEqual([x[0] for x in calls],
                         [f'compare/{self.sha}...main', 'releases/321'])

    def test_new_draft_is_looked_up_by_id_not_by_tag(self):
        draft = {'id': 321, 'draft': True, 'tag_name': self.tag,
                 'target_commitish': self.sha, 'assets': []}
        calls = []
        def api(path, *args):
            calls.append((path, args))
            if path.startswith('compare/'):
                return {'status': 'identical', 'merge_base_commit': {'sha': self.sha}}
            if path == 'git/tags':
                return {'sha': 'c' * 40}
            if path == 'git/refs':
                return {'ref': f'refs/tags/{self.tag}'}
            if path == 'releases/321':
                return dict(draft, draft=False) if args == ('-X', 'PATCH', '-F', 'draft=false') else draft
            self.fail(f'unexpected API: {path} {args}')
        runs = {'tests.yml': 1, 'rdc-independent.yml': 2}
        with tempfile.TemporaryDirectory() as tmp, \
             patch.object(release, 'accepted_runs', return_value=runs), \
             patch.object(release, 'accepted_merge', return_value=True), \
             patch.object(release, 'merge_narrative', return_value='reviewed'), \
             patch.object(release, 'release_files', return_value=({'tag': self.tag},
                                  release.ASSETS | {self.package})), \
             patch.object(release, 'verify_provenance'), \
             patch.object(release, 'all_releases', side_effect=[[], [draft]]), \
             patch.object(release, 'api', side_effect=api), \
             patch.object(release, 'verify_draft_uploaded') as validated, \
             patch.object(release, 'verify_existing') as published, \
             patch.object(release.subprocess, 'run') as gh:
            release.publish(Path(tmp), self.sha, runs)
            validated.assert_called_once()
            published.assert_called_once()
            gh.assert_called_once()
            self.assertEqual(gh.call_args.args[0][:3], ['gh', 'release', 'create'])
        self.assertFalse(any(path.startswith('releases/tags/') for path, _ in calls))

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

    def durable_fixture(self):
        identity = {'source_sha': self.sha, 'pkgver': '0.1.0.r10.g' + self.sha[:12],
                    'tag': self.tag, 'activation_allowed': False}
        digest = hashlib.sha256(b'tested package').hexdigest()
        files = {self.package: b'tested package', 'source.json': json.dumps(identity).encode(),
                 'arch-packages.txt': b'snapshot inventory', 'rustc.txt': b'rustc fixture',
                 'lifecycle.json': json.dumps({'source_sha': self.sha, 'package': self.package,
                     'sha256': digest, 'lifecycle': 'PASS'}).encode()}
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, data in files.items():
                (directory / name).write_bytes(data)
            (directory / 'SHA256SUMS').write_bytes(self.checksums(files))
            release.release_files(directory, self.sha, {'tests.yml': 1, 'rdc-independent.yml': 2})
            files = {p.name: p.read_bytes() for p in directory.iterdir()}
        existing = {'tag_name': self.tag, 'target_commitish': self.sha, 'draft': False,
                    'assets': [{'name': n} for n in files]}
        return existing, files

    @staticmethod
    def checksums(files):
        return ''.join(f'{hashlib.sha256(data).hexdigest()}  {name}\n'
                       for name, data in sorted(files.items()) if name != 'SHA256SUMS').encode()

    def durable_api(self, path):
        self.assertEqual(path, f'git/ref/tags/{self.tag}')
        return {'ref': f'refs/tags/{self.tag}', 'object': {'type': 'commit', 'sha': self.sha}}

    def durable_commands(self, files, anchored_manifest):
        def run(args, **kwargs):
            self.assertTrue(kwargs['check'])
            if args[:3] == ['gh', 'release', 'download']:
                directory = Path(args[args.index('--dir') + 1])
                for name, data in files.items():
                    (directory / name).write_bytes(data)
            elif args[:3] == ['gh', 'attestation', 'verify']:
                self.assertEqual(args[args.index('--repo') + 1], release.REPO)
                self.assertEqual(args[args.index('--signer-workflow') + 1],
                                 f'{release.REPO}/.github/workflows/release-arch.yml')
                self.assertEqual(args[args.index('--source-ref') + 1], 'refs/heads/main')
                self.assertIn('--deny-self-hosted-runners', args)
                # Independent trust store: rewriting Release files/checksums
                # cannot change the digest authenticated by the signer.
                if Path(args[3]).read_bytes() != anchored_manifest:
                    raise subprocess.CalledProcessError(1, args)
            else:
                self.fail(f'ephemeral artifact or unexpected command: {args[:3]}')
        return run

    def test_new_merge_after_seven_day_expiration_uses_only_durable_history(self):
        existing, files = self.durable_fixture()
        later = 'b' * 40
        def names(sha):
            return (self.tag, self.package) if sha == self.sha else ('v0.1.11', 'next-package')
        def inspect(sha, get):
            self.assertEqual(sha, later, 'historical CI/artifacts expired eight days ago')
            return 'success', {'tests.yml': 3, 'rdc-independent.yml': 4}
        with patch.object(release, 'source_names', side_effect=names), patch.object(release, 'inspect_runs', side_effect=inspect), patch.object(release, 'accepted_merge', return_value=True) as review, patch.object(release.subprocess, 'run', side_effect=self.durable_commands(files, files['SHA256SUMS'])) as commands:
            self.assertEqual(release.pending_main(later, [self.sha, later], [existing], self.durable_api),
                             [{'sha': later, 'run_id': 4}])
            review.assert_called_once_with(later, self.durable_api)
            self.assertEqual(commands.call_count, 2)

    def test_history_metadata_inventory_and_tag_tampering_fail_closed(self):
        existing, files = self.durable_fixture()
        cases = [([dict(existing, tag_name='v9.9.9')], 'source conflict'),
                 ([dict(existing, target_commitish='b' * 40)], 'source conflict'),
                 ([existing, existing], 'conflicting release history'),
                 ([dict(existing, assets=[])], 'inventory differs'),
                 ([dict(existing, assets=existing['assets'] + existing['assets'][:1])], 'inventory differs')]
        for releases, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                release.pending_main('b' * 40, [self.sha], releases, self.durable_api)
        def wrong_tag(path):
            return {'ref': f'refs/tags/{self.tag}', 'object': {'type': 'commit', 'sha': 'c' * 40}}
        with self.assertRaisesRegex(ValueError, 'tag commit conflict'):
            release.pending_main('b' * 40, [self.sha], [existing], wrong_tag)

    def test_durable_asset_and_self_reported_checksum_tampering_fail_closed(self):
        existing, original = self.durable_fixture()
        for name in original:
            for rewrite_checksums in (False, True):
                if name == 'SHA256SUMS' and rewrite_checksums:
                    continue  # Regenerating an unchanged inventory restores it.
                with self.subTest(name=name, rewrite_checksums=rewrite_checksums):
                    files = dict(original)
                    files[name] += b'tampered'
                    if rewrite_checksums:
                        files['SHA256SUMS'] = self.checksums(files)
                    with patch.object(release.subprocess, 'run', side_effect=self.durable_commands(files, original['SHA256SUMS'])):
                        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
                            release.pending_main('b' * 40, [self.sha], [existing], self.durable_api)

    def test_missing_assets_or_independent_attestation_fail_closed(self):
        existing, files = self.durable_fixture()
        for missing in files:
            remaining = {n: data for n, data in files.items() if n != missing}
            with self.subTest(missing=missing), patch.object(release.subprocess, 'run', side_effect=self.durable_commands(remaining, files['SHA256SUMS'])):
                with self.assertRaises(FileNotFoundError):
                    release.pending_main('b' * 40, [self.sha], [existing], self.durable_api)
        # Covers unavailable, invalid signature, wrong signer/ref, or absent
        # provenance: any nonzero verification exit must propagate.
        def missing_attestation(args, **kwargs):
            if args[:3] == ['gh', 'attestation', 'verify']:
                raise subprocess.CalledProcessError(1, args)
            return self.durable_commands(files, files['SHA256SUMS'])(args, **kwargs)
        with patch.object(release.subprocess, 'run', side_effect=missing_attestation):
            with self.assertRaises(subprocess.CalledProcessError):
                release.pending_main('b' * 40, [self.sha], [existing], self.durable_api)

    def test_authenticated_but_inconsistent_metadata_and_inventory_fail_closed(self):
        existing, original = self.durable_fixture()
        for name, field, value in [('source.json', 'tag', 'v9.9.9'),
                                   ('release.json', 'source_sha', 'c' * 40),
                                   ('release.json', 'required_runs', {'tests.yml': 1}),
                                   ('lifecycle.json', 'lifecycle', 'FAIL')]:
            files = dict(original)
            record = json.loads(files[name])
            record[field] = value
            files[name] = json.dumps(record).encode()
            files['SHA256SUMS'] = self.checksums(files)
            with self.subTest(field=field), patch.object(release.subprocess, 'run', side_effect=self.durable_commands(files, files['SHA256SUMS'])):
                with self.assertRaises(ValueError):
                    release.pending_main('b' * 40, [self.sha], [existing], self.durable_api)
        for manifest in (b'', original['SHA256SUMS'] * 2,
                         original['SHA256SUMS'] + b'0' * 64 + b'  ../outside\n'):
            files = dict(original, SHA256SUMS=manifest)
            with patch.object(release.subprocess, 'run', side_effect=self.durable_commands(files, manifest)):
                with self.assertRaises(ValueError):
                    release.pending_main('b' * 40, [self.sha], [existing], self.durable_api)

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

    def test_unpublished_missing_or_tampered_tested_bytes_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination = Path(tmp)
            runs = {'tests.yml': 1, 'rdc-independent.yml': 2}
            with patch.object(release.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'expired')):
                with self.assertRaises(subprocess.CalledProcessError):
                    release.download_tested(destination, self.sha, runs)
            _, files = self.durable_fixture()
            for name, data in files.items():
                (destination / name).write_bytes(data)
            (destination / self.package).write_bytes(b'tampered after testing')
            with patch.object(release.subprocess, 'run') as download:
                with self.assertRaisesRegex(ValueError, 'checksum mismatch'):
                    release.download_tested(destination, self.sha, runs)
                args = download.call_args.args[0]
                self.assertEqual(args[:4], ['gh', 'run', 'download', '2'])
                self.assertEqual(args[args.index('--name') + 1], f'relayforge-arch-source-{self.sha}')

    def test_publication_requires_manifest_provenance_before_any_write(self):
        _, files = self.durable_fixture()
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name, data in files.items():
                (directory / name).write_bytes(data)
            runs = {'tests.yml': 1, 'rdc-independent.yml': 2}
            with patch.object(release, 'accepted_runs', return_value=runs), patch.object(release, 'accepted_merge', return_value=True), patch.object(release, 'merge_narrative', return_value='reviewed narrative'), patch.object(release.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'missing provenance')), patch.object(release, 'api') as writes:
                with self.assertRaises(subprocess.CalledProcessError):
                    release.publish(directory, self.sha, runs)
                writes.assert_not_called()

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
