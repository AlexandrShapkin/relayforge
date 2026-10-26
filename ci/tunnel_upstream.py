"""Fetch and authenticate pinned official artifacts before makepkg/execution."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

LOCK = Path('packaging/arch/tunnel-client/upstream.json')


def verify(directory, lock):
    for name, digest in lock['assets'].items():
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('upstream pinned checksum mismatch')
    archive = f"tunnel-client-v{lock['version']}-linux-amd64.zip"
    entries = dict(line.split()[:2][::-1] for line in (directory / 'SHA256SUMS.txt').read_text().splitlines())
    if entries.get(archive) != lock['assets'][archive]:
        raise ValueError('upstream checksum manifest mismatch')
    # gh checks the signature, Fulcio/GitHub trust roots, transparency log and
    # SLSA certificate identity. Parsing an unverified DSSE payload is insufficient.
    for name in (archive, 'SHA256SUMS.txt'):
        subprocess.run(['gh', 'attestation', 'verify', str(directory / name),
            '--bundle', str(directory / f"tunnel-client-v{lock['version']}-provenance.sigstore.json"),
            '--repo', lock['repository'], '--signer-workflow', lock['workflow'],
            '--source-ref', f"refs/tags/v{lock['version']}",
            '--source-digest', lock['source_sha'], '--signer-digest', lock['source_sha'],
            '--deny-self-hosted-runners'], check=True)


def negative_provenance(directory, lock):
    """Exercise the real verifier, not a mocked signature check, before packaging."""
    archive = directory / f"tunnel-client-v{lock['version']}-linux-amd64.zip"
    bundle = directory / f"tunnel-client-v{lock['version']}-provenance.sigstore.json"
    args = ['gh', 'attestation', 'verify', str(archive), '--bundle', str(bundle),
            '--repo', lock['repository'], '--signer-workflow', lock['workflow'],
            '--source-ref', f"refs/tags/v{lock['version']}",
            '--source-digest', '0' * 40, '--deny-self-hosted-runners']
    if subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120).returncode == 0:
        raise ValueError('wrong upstream identity accepted')
    with tempfile.TemporaryDirectory(prefix='tunnel-signature-') as tmp:
        altered = json.loads(bundle.read_text())
        altered['dsseEnvelope']['signatures'][0]['sig'] = 'AAAA'
        bad = Path(tmp) / 'bad-bundle.json'
        bad.write_text(json.dumps(altered))
        args[args.index('--bundle') + 1] = str(bad)
        args[args.index('--source-digest') + 1] = lock['source_sha']
        if subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120).returncode == 0:
            raise ValueError('altered upstream signature accepted')
    print('upstream checksum/provenance and wrong-identity/altered-signature denial: PASS')


def prepare(directory):
    lock = json.loads(LOCK.read_text())
    directory.mkdir(parents=True, exist_ok=True)
    for name in lock['assets']:
        url = f"https://github.com/{lock['repository']}/releases/download/v{lock['version']}/{name}"
        with urllib.request.urlopen(url, timeout=120) as response:
            (directory / name).write_bytes(response.read())
    verify(directory, lock)
    negative_provenance(directory, lock)
    (directory / 'upstream.json').write_text(LOCK.read_text())
    (directory / 'PKGBUILD').write_text(Path('packaging/arch/tunnel-client/PKGBUILD').read_text())


if __name__ == '__main__':
    prepare(Path(sys.argv[1]))
