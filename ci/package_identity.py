"""Bind a makepkg recipe/archive to committed source, never ignored material."""
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tomllib


def identity():
    sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    revision = int(subprocess.check_output(['git', 'rev-list', '--first-parent', '--count', 'HEAD'], text=True))
    version = tomllib.loads(Path('Cargo.toml').read_text())['workspace']['package']['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or not re.fullmatch('[0-9a-f]{40}', sha):
        raise ValueError('invalid source identity')
    pkgver = f'{version}.r{revision}.g{sha[:12]}'
    # Independent immutable SemVer release sequence; main history is never rewritten.
    major, minor, _ = version.split('.')
    return {'schema_version': 1, 'source_sha': sha, 'source_version': version,
            'revision': revision, 'pkgver': pkgver, 'tag': f'v{major}.{minor}.{revision}',
            'architecture': 'x86_64', 'activation_allowed': False}


def prepare(directory):
    record = identity()
    archive = directory / 'relayforge-source.tar'
    # Add generated public identity, not arbitrary workspace files.
    data = (json.dumps(record, sort_keys=True) + '\n').encode()
    with tarfile.open(archive, 'a') as stream:
        member = tarfile.TarInfo('packaging/arch/source.json')
        member.size, member.mode = len(data), 0o644
        stream.addfile(member, io.BytesIO(data))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    recipe = Path('packaging/arch/PKGBUILD').read_text().replace(
        'pkgver=0.1.0\n', f"pkgver={record['pkgver']}\n").replace('@SOURCE_SHA256@', checksum)
    (directory / 'PKGBUILD').write_text(recipe)
    (directory.parent / 'arch-dist/source.json').write_bytes(data)
    return record


if __name__ == '__main__':
    print(json.dumps(prepare(Path(sys.argv[1])), sort_keys=True))
