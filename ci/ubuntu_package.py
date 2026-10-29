#!/usr/bin/env python3
"""Build a non-activating Ubuntu package from an exact tested Cargo output.

No credentials, operator HOME, runtime selectors or live host state are inputs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from package_identity import identity


FILES = {
    'packaging/user_data.py': ('usr/bin/relayforge-user-data', 0o755),
    'packaging/arch/relayforge-mcp-http.service':
        ('usr/lib/systemd/user/relayforge-mcp-http.service', 0o644),
    'packaging/arch/relayforge-mcp-oauth.service':
        ('usr/lib/systemd/user/relayforge-mcp-oauth.service', 0o644),
    'packaging/arch/relayforge-tunnel-http.service':
        ('usr/lib/systemd/user/relayforge-tunnel-http.service', 0o644),
    'packaging/oauth/resource.example.json':
        ('usr/share/doc/relayforge/resource.example.json', 0o644),
    'packaging/oauth/tunnel.example.json':
        ('usr/share/doc/relayforge/tunnel.example.json', 0o644),
    'docs/oauth-http.md': ('usr/share/doc/relayforge/oauth-http.md', 0o644),
    'docs/ubuntu-packaging.md': ('usr/share/doc/relayforge/ubuntu-packaging.md', 0o644),
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def install_file(source, target, mode):
    if not source.is_file() or source.is_symlink():
        raise ValueError(f'missing or unexpected source file: {source}')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(mode)


def package(binary_dir, dist, expected_sha):
    record = identity()
    if expected_sha != record['source_sha']:
        raise ValueError('source SHA does not match exact checkout')
    if run('git', 'status', '--porcelain', '--untracked-files=normal'):
        raise ValueError('dirty source checkout')
    if run('dpkg', '--print-architecture') != 'amd64':
        raise ValueError('Ubuntu amd64 package build required')
    if not Path('/etc/os-release').read_text().count('VERSION_ID="24.04"'):
        raise ValueError('Ubuntu 24.04 builder required')
    for tool in ('dpkg-deb', 'dpkg'):
        if not shutil.which(tool):
            raise ValueError(f'missing {tool}')
    epoch = int(run('git', 'show', '-s', '--format=%ct', 'HEAD'))
    pkgver = record['pkgver']
    binaries = {name: binary_dir / name for name in ('relayforge-mcp', 'relayforge-agent')}
    for name, path in binaries.items():
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            raise ValueError(f'missing built binary: {name}')
    record.update({'distribution': 'ubuntu-24.04', 'package_architecture': 'amd64',
                   'binaries_sha256': {name: sha256(path) for name, path in binaries.items()}})
    dist.mkdir(parents=True, exist_ok=True)
    filename = f'relayforge_{pkgver}_amd64.deb'
    with tempfile.TemporaryDirectory(prefix='relayforge-deb-', dir=dist) as temp:
        root = Path(temp)
        for name, path in binaries.items():
            install_file(path, root / 'usr/bin' / name, 0o755)
        for source, (target, mode) in FILES.items():
            install_file(Path(source), root / target, mode)
        info = root / 'usr/share/relayforge/source.json'
        info.parent.mkdir(parents=True, exist_ok=True)
        info.write_text(json.dumps(record, sort_keys=True) + '\n')
        copyright_file = root / 'usr/share/doc/relayforge/copyright'
        copyright_file.write_text('Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n'
                                  'Upstream-Name: RelayForge\n'
                                  'Source: https://github.com/AlexandrShapkin/relayforge\n'
                                  'License: Apache-2.0\n'
                                  ' See /usr/share/common-licenses/Apache-2.0.\n')
        control = root / 'DEBIAN/control'
        control.parent.mkdir(mode=0o755)
        control.write_text(f'''Package: relayforge
Version: {pkgver}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: RelayForge project
Depends: libc6 (>= 2.39), libgcc-s1, python3, bubblewrap, git, openssh-client, iproute2, systemd
Description: Restricted MCP diagnostics bridge (manual activation only)
 A deny-by-default MCP gateway and limited Linux agent.
 Package installation never starts services or authorizes device access.
''')
        for f in (info, copyright_file, control):
            f.chmod(0o644)
        # Reproducible timestamps and deterministic root ownership in the archive;
        # root privileges are neither needed nor requested for the build.
        for node in root.rglob('*'):
            os.utime(node, (epoch, epoch), follow_symlinks=False)
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(root),
                        str(dist / filename)], check=True,
                       env={**os.environ, 'SOURCE_DATE_EPOCH': str(epoch)})
    (dist / 'source.json').write_text(json.dumps(record, sort_keys=True) + '\n')
    checksums = {filename: sha256(dist / filename), 'source.json': sha256(dist / 'source.json')}
    (dist / 'SHA256SUMS').write_text(''.join(f'{digest}  {name}\n'
                                            for name, digest in sorted(checksums.items())))
    print(json.dumps({'package': filename, 'sha256': checksums[filename],
                      'source_sha': expected_sha, 'activation_allowed': False}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary-dir', required=True, type=Path)
    parser.add_argument('--dist', required=True, type=Path)
    parser.add_argument('--sha', required=True)
    args = parser.parse_args()
    package(args.binary_dir, args.dist, args.sha)


if __name__ == '__main__':
    main()
