"""Ubuntu release contract; its presence in committed source versions the matrix."""
import hashlib
import json
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def receipt(directory, sha):
    """Called only after the independent disposable installed checks succeed."""
    source = json.loads((directory / 'source.json').read_text())
    package = f"relayforge_{source['pkgver']}_amd64.deb"
    record = {'schema_version': 1, 'source_sha': sha, 'package': package,
              'sha256': digest(directory / package), 'distribution': 'ubuntu-24.04',
              'architecture': 'amd64', 'installed_checks': 'PASS', 'activation_allowed': False}
    (directory / 'ubuntu-verification.json').write_text(json.dumps(record, sort_keys=True) + '\n')


if __name__ == '__main__':
    import sys
    receipt(Path(sys.argv[1]), sys.argv[2])
