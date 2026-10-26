"""Tunnel startup, migration and supply-chain negative regression fixtures."""
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


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = load('tunnel_guard', 'packaging/tunnel.py')
upstream = load('tunnel_upstream', 'ci/tunnel_upstream.py')
release = load('release_arch_tunnel', 'ci/release_arch.py')


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.root = self.home / guard.RELATIVE
        self.root.mkdir(parents=True, mode=0o700)
        self.key = self.root / 'runtime-key'
        self.key.write_text('new-test-key')
        self.key.chmod(0o600)
        self.config = guard.profile('tunnel_' + 'a' * 32, str(self.key))
        self.profile = self.root / 'profile.json'
        self.profile.write_text(json.dumps(self.config))
        self.profile.chmod(0o600)

    def accept(self):
        fds = guard.checked(str(self.home))
        for fd in fds:
            os.close(fd)

    def test_strict_profile_and_secret_validation(self):
        self.accept()
        for path in (self.key, self.profile):
            path.chmod(0o644)
            with self.assertRaises(ValueError): self.accept()
            path.chmod(0o600)
        for value in ('', 'a\nb', 'a\x00b'):
            self.key.write_text(value)
            with self.assertRaises(ValueError): self.accept()

    def test_missing_symlink_hardlink_and_parent_refusal(self):
        self.key.unlink()
        with self.assertRaises(FileNotFoundError): self.accept()
        self.key.symlink_to(self.profile)
        with self.assertRaises(OSError): self.accept()
        self.key.unlink(); os.link(self.profile, self.key)
        with self.assertRaises(ValueError): self.accept()
        self.key.unlink(); self.key.write_text('fresh'); self.key.chmod(0o600)
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): self.accept()
        self.root.chmod(0o700)
        moved = self.root.with_name('moved')
        self.root.rename(moved); self.root.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(OSError): self.accept()

    def test_extra_settings_and_unrestricted_targets_denied(self):
        for change in ('command', 'channel', 'http', 'endpoint', 'secret', 'logging'):
            config = json.loads(json.dumps(self.config))
            if change == 'command': config['mcp']['commands'][0]['command'] = '/bin/sh'
            if change == 'channel': config['mcp']['commands'].append({'channel': 'extra', 'command': '/bin/sh'})
            if change == 'http': config['mcp']['server_urls'] = [{'channel': 'main', 'url': 'http://localhost'}]
            if change == 'endpoint': config['control_plane']['base_url'] = 'https://other.invalid'
            if change == 'secret': config['control_plane']['api_key'] = 'file:/legacy/key'
            if change == 'logging': config['log']['http_raw_unsafe'] = True
            self.profile.write_text(json.dumps(config))
            with self.assertRaises(ValueError): self.accept()

    def test_exec_uses_opened_inputs_and_cleans_environment(self):
        with patch.object(guard, 'package_check'), patch.object(guard.os, 'execve') as execute, patch.dict(os.environ, {'MCP_COMMAND': '/bin/sh', 'CONTROL_PLANE_BASE_URL': 'https://other.invalid'}):
            guard.launch(str(self.home))
            client, args, env = execute.call_args.args
            self.assertEqual(client, '/usr/bin/tunnel-client')
            self.assertEqual(set(env), {'HOME', 'PATH', 'LANG'})
            self.assertIn('command=/usr/bin/relayforge-mcp --readonly-stdio,channel=main', args)
            config_fd = int(args[3].rsplit('/', 1)[1])
            key_fd = int(args[5].rsplit('/', 1)[1])
            self.key.rename(self.key.with_name('saved-key'))
            self.key.write_text('changed-path')
            self.assertEqual(os.read(key_fd, 100), b'')  # validation consumed it
            os.lseek(key_fd, 0, os.SEEK_SET)
            self.assertEqual(os.read(key_fd, 100), b'new-test-key')
            os.close(config_fd); os.close(key_fd)

    def test_setup_refuses_noninteractive_and_existing_destination(self):
        before = self.profile.read_bytes(), self.key.read_bytes()
        with patch.object(guard.sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(ValueError): guard.setup(str(self.home), 'tunnel_' + 'a' * 32)
        with patch.object(guard.sys.stdin, 'isatty', return_value=True), patch.object(guard.sys.stdout, 'isatty', return_value=True), patch('builtins.input', return_value='CREATE FRESH RELAYFORGE TUNNEL'), patch.object(guard.getpass, 'getpass', return_value='fresh'):
            with self.assertRaises(FileExistsError): guard.setup(str(self.home), 'tunnel_' + 'a' * 32)
        self.assertEqual(before, (self.profile.read_bytes(), self.key.read_bytes()))

    def test_setup_new_state_preserves_legacy_and_has_no_service_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / '.config/relayforge').mkdir(parents=True, mode=0o700)
            legacy = home / '.config/tunnel-client'; legacy.mkdir(mode=0o700)
            evidence = legacy / 'relayforge-local.yaml'; evidence.write_text('private legacy sentinel')
            with patch.object(guard.sys.stdin, 'isatty', return_value=True), patch.object(guard.sys.stdout, 'isatty', return_value=True), patch('builtins.input', return_value='CREATE FRESH RELAYFORGE TUNNEL'), patch.object(guard.getpass, 'getpass', return_value='fresh'), patch.object(guard.subprocess, 'run') as run:
                guard.setup(str(home), 'tunnel_' + 'b' * 32)
                run.assert_not_called()
            self.assertEqual(evidence.read_text(), 'private legacy sentinel')
            for fd in guard.checked(str(home)): os.close(fd)

    def test_service_condition_validates_readonly_snapshots_without_skipping_packages(self):
        # Runtime credential snapshots normally live under /run/user/UID.
        with tempfile.TemporaryDirectory(dir=ROOT) as tmp:
            credentials = Path(tmp)
            for name, source in (('profile', self.profile), ('runtime-key', self.key)):
                (credentials / name).write_bytes(source.read_bytes())
                (credentials / name).chmod(0o400)
            with patch.object(guard, 'package_check') as package:
                guard.service_check(str(self.home), str(credentials))
                package.assert_called_once()
            (credentials / 'runtime-key').chmod(0o600)
            (credentials / 'runtime-key').write_text('different')
            with patch.object(guard, 'package_check'):
                with self.assertRaises(ValueError): guard.service_check(str(self.home), str(credentials))
            (credentials / 'runtime-key').unlink()
            (credentials / 'runtime-key').symlink_to(self.key)
            with patch.object(guard, 'package_check'):
                with self.assertRaises(OSError): guard.service_check(str(self.home), str(credentials))
            with patch.object(guard, 'package_check', side_effect=ValueError('corrupt package')):
                with self.assertRaises(ValueError): guard.service_check(str(self.home), str(credentials))

    def test_package_failure_blocks_before_exec(self):
        with patch.object(guard.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'pacman')), patch.object(guard.os, 'execve') as execute:
            with self.assertRaisesRegex(guard.Refused, 'installed-package'): guard.launch(str(self.home))
            execute.assert_not_called()


class SupplyChainTests(unittest.TestCase):
    def test_tamper_and_missing_signature_verification_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            name = 'tunnel-client-v0.0.18-linux-amd64.zip'
            (directory / name).write_bytes(b'archive')
            digest = hashlib.sha256(b'archive').hexdigest()
            (directory / 'SHA256SUMS.txt').write_text(f'{digest}  {name}\n')
            lock = {'version': '0.0.18', 'repository': 'openai/tunnel-client', 'workflow': 'openai/tunnel-client/.github/workflows/release.yml', 'source_sha': '2' * 40,
                    'assets': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}}
            with patch.object(upstream.subprocess, 'run') as verifier:
                upstream.verify(directory, lock)
                self.assertEqual(verifier.call_count, 2)
                self.assertIn('--deny-self-hosted-runners', verifier.call_args.args[0])
            with patch.object(upstream.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'gh')):
                with self.assertRaises(subprocess.CalledProcessError): upstream.verify(directory, lock)
            (directory / name).write_bytes(b'tampered')
            with patch.object(upstream.subprocess, 'run') as verifier:
                with self.assertRaises(ValueError): upstream.verify(directory, lock)
                verifier.assert_not_called()

    def test_release_assets_use_committed_historical_contract(self):
        sha = 'a' * 40
        with patch.object(release, 'command', return_value=''):
            self.assertEqual(release.tunnel_assets(sha), set())
        lock = json.loads((ROOT / 'packaging/arch/tunnel-client/upstream.json').read_text())
        with patch.object(release, 'command', side_effect=['tracked lock', json.dumps(lock)]):
            self.assertEqual(release.tunnel_assets(sha), {'tunnel-client-0.0.18-1-x86_64.pkg.tar.zst'})
        lock['version'] = '../escape'
        with patch.object(release, 'command', side_effect=['tracked lock', json.dumps(lock)]):
            with self.assertRaises(ValueError): release.tunnel_assets(sha)

    def test_release_manifest_includes_both_tested_packages(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); sha = 'a' * 40
            pkgver = '0.1.0.r10.g' + sha[:12]
            package = f'relayforge-{pkgver}-1-x86_64.pkg.tar.zst'
            tunnel = 'tunnel-client-0.0.18-1-x86_64.pkg.tar.zst'
            for name in (package, tunnel, 'arch-packages.txt', 'rustc.txt'):
                (directory / name).write_bytes(b'tested fixture')
            digest = hashlib.sha256(b'tested fixture').hexdigest()
            (directory / 'source.json').write_text(json.dumps({'source_sha': sha, 'pkgver': pkgver,
                'tag': 'v0.1.10', 'activation_allowed': False, 'tunnel_package': tunnel}))
            (directory / 'lifecycle.json').write_text(json.dumps({'source_sha': sha, 'package': package,
                'sha256': digest, 'lifecycle': 'PASS', 'tunnel_package': tunnel,
                'tunnel_sha256': digest, 'tunnel_lifecycle': 'PASS'}))
            original = ''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n'
                               for p in sorted(directory.iterdir()))
            (directory / 'SHA256SUMS').write_text(original)
            with patch.object(release, 'tunnel_assets', return_value={tunnel}):
                _, assets = release.release_files(directory, sha, {'tests.yml': 1})
                self.assertEqual(assets, release.ASSETS | {package, tunnel})
                self.assertIn(tunnel, (directory / 'SHA256SUMS').read_text())
                (directory / tunnel).write_bytes(b'tampered')
                with self.assertRaises(ValueError): release.release_files(directory, sha, {'tests.yml': 1})

    def test_release_requires_independent_package_and_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp); name = 'tunnel-client-0.0.18-1-x86_64.pkg.tar.zst'
            (directory / name).write_bytes(b'client')
            digest = hashlib.sha256(b'client').hexdigest()
            identity = {'tunnel_package': name}
            lifecycle = {'tunnel_package': name, 'tunnel_lifecycle': 'PASS', 'tunnel_sha256': digest}
            with patch.object(release, 'tunnel_assets', return_value={name}):
                self.assertEqual(release.verify_tunnel(directory, 'a' * 40, identity, lifecycle, {name: digest}), {name})
                for field in ('tunnel_package', 'tunnel_lifecycle', 'tunnel_sha256'):
                    bad = dict(lifecycle); bad.pop(field)
                    with self.assertRaises(ValueError): release.verify_tunnel(directory, 'a' * 40, identity, bad, {name: digest})
                (directory / name).write_bytes(b'tampered')
                with self.assertRaises(ValueError): release.verify_tunnel(directory, 'a' * 40, identity, lifecycle, {name: digest})


if __name__ == '__main__': unittest.main()
