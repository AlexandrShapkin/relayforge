#!/usr/bin/python3
"""Destructive pacman acceptance: ONLY inside a fresh disposable CI container."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def run(*args, ok=True, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, **kwargs)
    if (result.returncode == 0) != ok:
        raise RuntimeError(f'{args[0:3]} unexpected exit {result.returncode}: {result.stderr}')
    return result.stdout


def main():
    if os.getuid() != 0 or not Path('/run/relayforge-disposable-ci').is_file():
        raise SystemExit('disposable root container required')
    packages = list(Path('.build/arch-dist').glob('*.pkg.tar.zst'))
    assert len(packages) == 1
    package = packages[0].resolve()
    identity = json.loads(Path('.build/arch-dist/source.json').read_text())
    version = identity['pkgver']
    assert package.name == f'relayforge-{version}-1-x86_64.pkg.tar.zst'
    assert run('pacman', '-Qp', str(package)).strip() == f'relayforge {version}-1'
    inventory = run('bsdtar', '-tf', str(package)).splitlines()
    expected = {'usr/bin/relayforge-mcp', 'usr/bin/relayforge-agent',
                'usr/bin/relayforge-user-data', 'usr/lib/systemd/user/relayforge-mcp-http.service',
                'usr/share/relayforge/source.json', 'usr/share/doc/relayforge/arch-packaging.md',
                'usr/share/licenses/relayforge/LICENSE'}
    assert {name for name in inventory if not name.endswith('/') and not name.startswith('.')} == expected
    assert not {'.INSTALL', '.CHANGELOG'} & set(inventory)
    # Reject special files/links and surprising permissions in the assembled package.
    listing = run('bsdtar', '-tvf', str(package)).splitlines()
    assert all(line.startswith(('-', 'd')) for line in listing)
    assert all('rws' not in line[:10] and 'rwxrwx' not in line[:10] for line in listing)
    for name in expected:
        assert subprocess.check_output(['bsdtar', '-xOf', str(package), name])  # no empty placeholders
    home = Path('/home/builder')
    sentinel = home / 'unrelated-evidence'
    sentinel.write_text('retained')
    config = home / '.config/relayforge'
    config.mkdir(parents=True, mode=0o700, exist_ok=True)
    token = config / 'http-token'
    token.write_text('a7' * 32)
    token.chmod(0o600)
    run('chown', '-R', 'builder:builder', str(config))
    run('chown', 'builder:builder', str(sentinel))
    # Capture service state before each transaction; no hooks may start/enable it.
    def inactive():
        assert not list(home.glob('.config/systemd/user/*.wants/relayforge*'))
        # Inspect all running processes: package installation must spawn no daemon.
        assert not run('pgrep', '-x', 'relayforge-mcp', ok=False)

    def smoke():
        inactive()
        run('pacman', '-Qkk', 'relayforge')
        assert json.loads(Path('/usr/share/relayforge/source.json').read_text()) == identity
        run('runuser', '-u', 'builder', '--', 'python3', '-B',
            'scripts/offline_mcp_smoke.py', '/usr/bin/relayforge-mcp')
        run('runuser', '-u', 'builder', '--', 'python3', '-B',
            'scripts/offline_artifact_acceptance.py', '/usr/bin/relayforge-mcp')
        reply = json.loads(run('runuser', '-u', 'builder', '--', '/usr/bin/relayforge-agent',
                               input='{"version":0,"operation":"shell","command":"id"}\n'))
        assert reply['ok'] is False
        assert sentinel.read_text() == 'retained' and token.read_text() == 'a7' * 32

    # Missing/truncated/not-an-archive: pacman must fail without installation.
    run('pacman', '-U', '--noconfirm', '/missing.pkg.tar.zst', ok=False)
    bad = Path('/tmp/corrupt.pkg.tar.zst')
    bad.write_bytes(package.read_bytes()[:64])
    run('pacman', '-U', '--noconfirm', str(bad), ok=False)
    bad.write_text('not an archive')
    run('pacman', '-U', '--noconfirm', str(bad), ok=False)
    # Unowned filesystem conflict and duplicate package ownership both refuse.
    conflict = Path('/usr/bin/relayforge-mcp')
    conflict.write_text('unrelated owner')
    run('pacman', '-U', '--noconfirm', str(package), ok=False)
    assert conflict.read_text() == 'unrelated owner'
    conflict.unlink()  # known fixture created immediately above, not host cleanup
    fixture = Path('/tmp/conflict-package')
    (fixture / 'usr/bin').mkdir(parents=True)
    (fixture / 'usr/bin/relayforge-mcp').write_text('other package')
    (fixture / '.PKGINFO').write_text('pkgname = conflict-fixture\npkgver = 1-1\npkgdesc = fixture\narch = x86_64\n')
    run('bsdtar', '-caf', '/tmp/conflict.pkg.tar.zst', '-C', str(fixture), '.PKGINFO', 'usr')
    run('pacman', '-U', '--noconfirm', '/tmp/conflict.pkg.tar.zst')
    run('pacman', '-U', '--noconfirm', str(package), ok=False)
    run('pacman', '-R', '--noconfirm', 'conflict-fixture')
    run('pacman', '-U', '--noconfirm', str(package))
    smoke()
    installed_hash = hashlib.sha256(Path('/usr/bin/relayforge-mcp').read_bytes()).hexdigest()
    # Reinstall exact bytes: no config, state or service side effects.
    run('pacman', '-U', '--noconfirm', str(package))
    smoke()
    # A second actual makepkg package (same compiled payload, pkgrel=2) proves
    # ALPM upgrade/downgrade semantics; never publish this synthetic fixture.
    work = Path('.build/makepkg')
    recipe = work / 'PKGBUILD'
    original = recipe.read_text()
    recipe.write_text(original.replace('pkgrel=1\n', 'pkgrel=2\n'))
    try:
        run('runuser', '-u', 'builder', '--', 'bash', '-c', 'cd .build/makepkg && makepkg --repackage --noconfirm')
    finally:
        recipe.write_text(original)
    newer = work / f'relayforge-{version}-2-x86_64.pkg.tar.zst'
    assert run('vercmp', f'{version}-2', f'{version}-1').strip() == '1'
    assert run('vercmp', '0.1.0.r10.g000000000000', '0.1.0.r9.gffffffffffff').strip() == '1'
    run('pacman', '-U', '--noconfirm', str(newer.resolve()))
    smoke()
    run('pacman', '-U', '--noconfirm', str(package))
    smoke()
    assert hashlib.sha256(Path('/usr/bin/relayforge-mcp').read_bytes()).hexdigest() == installed_hash
    # Integration must use installed bytes; absence/failure is fatal, never skipped.
    for script in ('offline_development_workflow.py', 'offline_authorized_development.py',
                   'test_tunnel_artifact_isolation.py'):
        print(run('runuser', '-u', 'builder', '--', 'env', 'RELAYFORGE_CI_SYSTEMD_SYSTEM=1',
                  'python3', '-B', f'scripts/{script}', '/usr/bin/relayforge-mcp'), flush=True)
    # Unit definition from the installed package, not legacy deploy templates.
    run('systemd-analyze', '--user', 'verify', '/usr/lib/systemd/user/relayforge-mcp-http.service')
    run('loginctl', 'enable-linger', 'builder')
    run('systemctl', 'start', 'user@1000.service')
    run('runuser', '-u', 'builder', '--', 'env', 'XDG_RUNTIME_DIR=/run/user/1000',
        'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus',
        'python3', '-B', 'ci/installed-unit.py')
    inactive()
    run('cp', '/usr/bin/relayforge-user-data', '/tmp/installed-user-data.py')
    run('pacman', '-R', '--noconfirm', 'relayforge')
    run('pacman', '-Q', 'relayforge', ok=False)
    assert all(not Path('/' + name).exists() for name in expected)
    inactive()
    assert token.read_text() == 'a7' * 32 and sentinel.read_text() == 'retained'
    # Purge is separate: test installed script saved as fixture before removal.
    run('runuser', '-u', 'builder', '--', 'python3', '-B', 'ci/purge-fixture.py')
    record = {'source_sha': identity['source_sha'], 'package': package.name,
                      'sha256': hashlib.sha256(package.read_bytes()).hexdigest(),
                      'installed_binary_sha256': installed_hash, 'lifecycle': 'PASS'}
    evidence = Path('.build/arch-dist/lifecycle.json')
    evidence.write_text(json.dumps(record, sort_keys=True) + '\n')
    with Path('.build/arch-dist/SHA256SUMS').open('a') as sums:
        sums.write(hashlib.sha256(evidence.read_bytes()).hexdigest() + '  lifecycle.json\n')
    print(json.dumps(record))


if __name__ == '__main__':
    main()
