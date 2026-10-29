"""Release matrix, independent receipt and checksum integrity regressions."""
import json
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import test_arch_packaging as arch_tests

release = arch_tests.release
module = arch_tests.module

receipt = module('ubuntu_release', 'ci/ubuntu_release.py')


class UbuntuReleaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sha = 'a' * 40
        self.pkgver = '0.1.0.r10.g' + self.sha[:12]
        self.package = f'relayforge_{self.pkgver}_amd64.deb'
        self.source = {'source_sha': self.sha, 'pkgver': self.pkgver,
                       'activation_allowed': False, 'distribution': 'ubuntu-24.04',
                       'package_architecture': 'amd64',
                       'binaries_sha256': {'relayforge-agent': 'b' * 64, 'relayforge-mcp': 'c' * 64}}
        (self.root / self.package).write_bytes(b'exact independently tested package')
        (self.root / 'source.json').write_text(json.dumps(self.source))
        receipt.receipt(self.root, self.sha)
        (self.root / 'source.json').rename(self.root / 'ubuntu-source.json')
        self.sums = {self.package: release.digest(self.root / self.package),
                     'source.json': release.digest(self.root / 'ubuntu-source.json')}
        (self.root / 'ubuntu-SHA256SUMS').write_text(''.join(f'{v}  {k}\n' for k, v in self.sums.items()))

    def verify(self):
        return release.verify_ubuntu(self.root, self.sha, self.package)

    def test_exact_independently_tested_inventory(self):
        self.assertEqual(self.verify(), {self.package, 'ubuntu-source.json',
                                        'ubuntu-SHA256SUMS', 'ubuntu-verification.json'})

    def test_missing_and_corrupt_assets_fail_closed(self):
        for name in self.verify():
            path = self.root / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.unlink()
                with self.assertRaises((ValueError, FileNotFoundError)):
                    self.verify()
                path.write_bytes(original + b'changed')
                with self.assertRaises(ValueError):
                    self.verify()
                path.write_bytes(original)

    def test_wrong_source_arch_activation_and_receipt_rejected(self):
        for field, value in [('source_sha', 'd' * 40), ('package_architecture', 'arm64'),
                             ('distribution', 'ubuntu-22.04'), ('activation_allowed', True),
                             ('binaries_sha256', {})]:
            with self.subTest(field=field):
                (self.root / 'ubuntu-source.json').write_text(json.dumps(dict(self.source, **{field: value})))
                with self.assertRaises(ValueError): self.verify()
        (self.root / 'ubuntu-source.json').write_text(json.dumps(self.source))
        path = self.root / 'ubuntu-verification.json'
        original = json.loads(path.read_text())
        for field, value in [('source_sha', 'd' * 40), ('installed_checks', 'skipped'),
                             ('sha256', '0' * 64), ('activation_allowed', True)]:
            path.write_text(json.dumps(dict(original, **{field: value})))
            with self.subTest(field=field), self.assertRaises(ValueError): self.verify()

    def test_duplicate_or_traversal_checksums_rejected(self):
        path = self.root / 'ubuntu-SHA256SUMS'
        original = path.read_text()
        for extra in [original, '0' * 64 + '  ../escape\n']:
            path.write_text(original + extra)
            with self.assertRaises(ValueError): self.verify()

    def test_historical_matrix_derived_only_from_committed_source(self):
        with patch.object(release, 'command', return_value='') as command:
            self.assertEqual(release.ubuntu_assets(self.sha), set())
            command.assert_called_once_with('git', 'ls-tree', self.sha, '--', 'ci/ubuntu_release.py')
        with patch.object(release, 'command', return_value='tracked'), \
                patch.object(release, 'source_names', return_value=('v0.1.10', f'relayforge-{self.pkgver}-1-x86_64.pkg.tar.zst')):
            self.assertIn(self.package, release.ubuntu_assets(self.sha))

    def test_combined_manifest_and_durable_history_cover_ubuntu(self):
        fixture = arch_tests.GateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        existing, files = fixture.durable_fixture()
        ubuntu = {name: (self.root / name).read_bytes() for name in self.verify()}
        files.update(ubuntu)
        files['SHA256SUMS'] = fixture.checksums(files)
        existing['assets'] = [{'name': name} for name in files]
        with patch.object(release, 'ubuntu_assets', return_value=set(ubuntu)):
            for name, data in files.items():
                (self.root / name).write_bytes(data)
            _, names = release.release_files(self.root, self.sha,
                                             {'tests.yml': 1, 'rdc-independent.yml': 2})
            self.assertTrue(set(ubuntu) <= names)
            for name in ubuntu:
                self.assertIn(name, (self.root / 'SHA256SUMS').read_text())
            with patch.object(release.subprocess, 'run',
                              side_effect=fixture.durable_commands(files, files['SHA256SUMS'])):
                release.verify_published(existing, self.sha, fixture.tag,
                                         fixture.package, fixture.durable_api)
            # A rewritten package and self-reported checksum cannot replace
            # the authenticated manifest, even after Actions artifacts expire.
            files[self.package] += b'tampered'
            files['SHA256SUMS'] = fixture.checksums(files)
            with patch.object(release.subprocess, 'run',
                              side_effect=fixture.durable_commands(files, (self.root / 'SHA256SUMS').read_bytes())):
                with self.assertRaises(subprocess.CalledProcessError):
                    release.verify_published(existing, self.sha, fixture.tag,
                                             fixture.package, fixture.durable_api)

    def test_new_matrix_requires_successful_independent_ubuntu_job(self):
        fixture = arch_tests.GateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with patch.object(release, 'ubuntu_assets', return_value={self.package}):
            self.assertIsNone(release.accepted_runs(fixture.sha, fixture.api))
            def api(path):
                result = fixture.api(path)
                if path.startswith('actions/runs/2/jobs'):
                    result['jobs'].append({'name': 'ubuntu-release', 'conclusion': 'success'})
                    result['total_count'] += 1
                return result
            self.assertIsNotNone(release.accepted_runs(fixture.sha, api))
            for outcome in ('skipped', 'failure', 'cancelled'):
                def bad(path):
                    result = api(path)
                    if path.startswith('actions/runs/2/jobs'):
                        result['jobs'][-1]['conclusion'] = outcome
                    return result
                with self.subTest(outcome=outcome):
                    self.assertIsNone(release.accepted_runs(fixture.sha, bad))
