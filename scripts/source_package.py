"""Build/verify an offline operational-source bundle; never installs or activates."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'deploy/activation_transaction.py', 'deploy/attended_activation.py',
    'deploy/attended_upgrade.py', 'deploy/runtime_artifact.py',
    'deploy/systemd/relayforge-mcp-http.service',
    'deploy/systemd/relayforge-tunnel.service', 'deploy/relayforge-tunnel-mcp.sh',
    'scripts/test_activation_transaction.py', 'scripts/test_attended_activation.py',
    'scripts/test_attended_upgrade.py', 'scripts/test_runtime_artifact.py',
    'scripts/source_package.py', 'scripts/test_source_package.py',
    'ci/arch-source.sh', '.github/workflows/rdc-independent.yml', 'docs/arch-source-ci.md',
)
ROLES = {'parent': {'binary': 'bin/relayforge-mcp', 'argv': ['--readonly-stdio']},
         'worker': {'binary': 'bin/relayforge-mcp', 'argv': ['--readonly-worker']}}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def build(binary, output):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    # git show reads only committed source, never ignored owner material or local changes.
    files = {name: subprocess.check_output(['git', 'show', f'{commit}:{name}'], cwd=ROOT)
             for name in SOURCES}
    files['bin/relayforge-mcp'] = binary.read_bytes()
    files['manifest.json'] = encoded({'schema_version': 1, 'commit': commit,
        'sha256': digest(files['bin/relayforge-mcp']), 'binary': 'relayforge-mcp'})
    files['package.json'] = encoded({'schema_version': 1, 'commit': commit,
        'kind': 'operational-source-fixture', 'activation_allowed': False,
        'roles': ROLES, 'baseline_receipt': None, 'owner_approval': None})
    files['seal.json'] = encoded({name: {'sha256': digest(data),
        'mode': 0o500 if name.startswith('bin/') else 0o400} for name, data in files.items()})
    output.mkdir(parents=True, exist_ok=False)
    archive = output / f'relayforge-arch-source-v1-{commit}.tar.gz'
    # Stable tar headers; gzip timestamp is irrelevant to the recorded archive digest.
    with tarfile.open(archive, 'w:gz') as tar:
        for name, data in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), (0o500 if name.startswith('bin/') else 0o400)
            tar.addfile(info, io.BytesIO(data))
    verify(archive, commit)
    archive.with_suffix(archive.suffix + '.sha256').write_text(f'{digest(archive.read_bytes())}  {archive.name}\n')
    return archive


def verify(archive, commit):
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise ValueError('full commit required')
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        expected = set(SOURCES) | {'bin/relayforge-mcp', 'manifest.json', 'package.json', 'seal.json'}
        if len(members) != len(expected) or {m.name for m in members} != expected:
            raise ValueError('unexpected package inventory')
        if any(not m.isfile() or m.size > 128 * 1024 * 1024 for m in members):
            raise ValueError('unsafe package member')
        files = {m.name: tar.extractfile(m).read() for m in members}
        seal = json.loads(files['seal.json'])
        if set(seal) != expected - {'seal.json'}:
            raise ValueError('invalid seal inventory')
        for member in members:
            mode = 0o500 if member.name.startswith('bin/') else 0o400
            if member.mode != mode:
                raise ValueError('unsafe package mode')
            if member.name != 'seal.json' and seal[member.name] != {
                    'sha256': digest(files[member.name]), 'mode': mode}:
                raise ValueError('package seal mismatch')
        if encoded(json.loads(files['manifest.json'])) != encoded({'schema_version': 1, 'commit': commit,
                'sha256': digest(files['bin/relayforge-mcp']), 'binary': 'relayforge-mcp'}):
            raise ValueError('invalid binary manifest')
        if encoded(json.loads(files['package.json'])) != encoded({'schema_version': 1, 'commit': commit,
                'kind': 'operational-source-fixture', 'activation_allowed': False,
                'roles': ROLES, 'baseline_receipt': None, 'owner_approval': None}):
            raise ValueError('invalid package manifest/roles/authority')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('build')
    create.add_argument('--binary', type=Path, required=True)
    create.add_argument('--output', type=Path, required=True)
    check = sub.add_parser('verify')
    check.add_argument('archive', type=Path)
    check.add_argument('--commit', required=True)
    args = parser.parse_args()
    if args.command == 'build':
        print(build(args.binary, args.output))
    else:
        verify(args.archive, args.commit)
