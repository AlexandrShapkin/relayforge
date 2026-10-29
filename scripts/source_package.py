"""Build/verify an offline operational-source bundle; never installs or activates."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'deploy/process_roles.py', 'scripts/test_process_roles.py',
    'deploy/activation_transaction.py', 'deploy/attended_activation.py',
    'deploy/attended_upgrade.py', 'deploy/runtime_artifact.py',
    'deploy/systemd/relayforge-mcp-http.service',
    'deploy/systemd/relayforge-tunnel.service', 'deploy/relayforge-tunnel-mcp.sh',
    'scripts/test_activation_transaction.py', 'scripts/test_attended_activation.py',
    'scripts/test_attended_upgrade.py', 'scripts/test_runtime_artifact.py',
    'scripts/source_package.py', 'scripts/test_source_package.py',
    'ci/arch-source.sh', '.github/workflows/rdc-independent.yml', 'docs/arch-source-ci.md',
)
MAX_UNPACKED_BYTES = 160 * 1024 * 1024
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
    expected = set(SOURCES) | {'bin/relayforge-mcp', 'manifest.json', 'package.json', 'seal.json'}
    members, files = [], {}
    total_size = 0
    # Read raw gzip/TAR records, never tarfile.open(): that parser processes
    # PAX/GNU extension payloads BEFORE yielding a member to the caller.
    # The producer needs only fixed-format regular-file headers. All TAR
    # extensions, links, unknown paths and repeated members fail closed.
    max_raw = MAX_UNPACKED_BYTES + 1024 * 1024
    consumed = 0
    with gzip.open(archive, 'rb') as stream:
        def take(length):
            nonlocal consumed
            if length < 0 or consumed + length > max_raw:
                raise ValueError('package decompressed size exceeds limit')
            data = stream.read(length)
            consumed += len(data)
            if len(data) != length:
                raise ValueError('truncated package archive')
            return data

        while True:
            header = take(tarfile.BLOCKSIZE)
            if header == bytes(tarfile.BLOCKSIZE):
                if take(tarfile.BLOCKSIZE) != bytes(tarfile.BLOCKSIZE):
                    raise ValueError('invalid TAR end markers')
                # Fully consume the gzip stream to validate its CRC, rejecting
                # nonzero trailing records and oversized zero padding.
                while True:
                    tail = stream.read(min(65536, max_raw - consumed + 1))
                    if not tail:
                        break
                    consumed += len(tail)
                    if consumed > max_raw or any(tail):
                        raise ValueError('unsafe TAR trailing data')
                break
            if len(members) >= len(expected):
                raise ValueError('unexpected package inventory')
            try:
                member = tarfile.TarInfo.frombuf(header, 'utf-8', 'strict')
            except (tarfile.TarError, UnicodeError, ValueError) as exc:
                raise ValueError('invalid TAR header') from exc
            # In particular, PAX and GNU long-name headers are not regular
            # files; reject them BEFORE accessing their attacker-sized body.
            if not member.isfile() or member.size < 0 or member.size > 128 * 1024 * 1024:
                raise ValueError('unsafe package member')
            if member.name not in expected or member.name in files:
                raise ValueError('unexpected package inventory')
            total_size += member.size
            if total_size > MAX_UNPACKED_BYTES:
                raise ValueError('package unpacked size exceeds limit')
            mode = 0o500 if member.name.startswith('bin/') else 0o400
            if member.mode != mode:
                raise ValueError('unsafe package mode')
            files[member.name] = take(member.size)
            padding = (-member.size) % tarfile.BLOCKSIZE
            if any(take(padding)):
                raise ValueError('invalid TAR padding')
            members.append(member)
    if set(files) != expected:
        raise ValueError('unexpected package inventory')
    seal = json.loads(files['seal.json'])
    if set(seal) != expected - {'seal.json'}:
        raise ValueError('invalid seal inventory')
    for member in members:
        mode = 0o500 if member.name.startswith('bin/') else 0o400
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
