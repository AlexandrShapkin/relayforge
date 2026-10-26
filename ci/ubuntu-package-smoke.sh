#!/usr/bin/env bash
# Run only in the disposable ubuntu:24.04 GitHub-hosted Docker container.
set -euo pipefail
if [ "$(id -u)" -ne 0 ] || [ "${CI_UBUNTU_DISPOSABLE:-}" != 1 ]; then
    echo 'refusing non-disposable package smoke' >&2
    exit 1
fi
if ! grep -qx 'VERSION_ID="24.04"' /etc/os-release; then
    echo 'Ubuntu 24.04 required' >&2
    exit 1
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends python3 bubblewrap git openssh-client iproute2 systemd libgcc-s1 util-linux ca-certificates
cd /workspace
cd .build/ubuntu-dist
sha256sum --check SHA256SUMS
python3 - <<'PY'
import json
from pathlib import Path
import subprocess
record = json.loads(Path('source.json').read_text())
assert record['activation_allowed'] is False
assert record['distribution'] == 'ubuntu-24.04'
packages = list(Path('.').glob('relayforge_*.deb'))
assert len(packages) == 1
package = str(packages[0])
assert subprocess.check_output(['dpkg-deb', '-f', package, 'Version'], text=True).strip() == record['pkgver']
assert subprocess.check_output(['dpkg-deb', '-f', package, 'Architecture'], text=True).strip() == 'amd64'
control = subprocess.check_output(['dpkg-deb', '--ctrl-tarfile', package])
import io,tarfile
with tarfile.open(fileobj=io.BytesIO(control)) as stream:
    assert {m.name.lstrip('./') for m in stream.getmembers() if m.isfile()} == {'control'}
expected = {'usr/bin/relayforge-mcp', 'usr/bin/relayforge-agent', 'usr/bin/relayforge-user-data',
    'usr/lib/systemd/user/relayforge-mcp-http.service',
    'usr/lib/systemd/user/relayforge-mcp-oauth.service',
    'usr/lib/systemd/user/relayforge-tunnel-http.service',
    'usr/share/doc/relayforge/resource.example.json',
    'usr/share/doc/relayforge/tunnel.example.json',
    'usr/share/doc/relayforge/oauth-http.md',
    'usr/share/doc/relayforge/ubuntu-packaging.md',
    'usr/share/doc/relayforge/copyright', 'usr/share/relayforge/source.json'}
listing = subprocess.check_output(['dpkg-deb', '--fsys-tarfile', package])
with tarfile.open(fileobj=io.BytesIO(listing)) as stream:
    members = stream.getmembers()
    actual = {m.name.lstrip('./') for m in members if m.isfile()}
    assert actual == expected, (actual - expected, expected - actual)
    assert all(m.isfile() or m.isdir() for m in members)
    assert all(m.uid == 0 and m.gid == 0 for m in members)
    assert all(not (m.mode & 0o6000) for m in members)
print('native .deb archive inventory and absence of maintainer hooks: PASS')
PY
pkg=$(find . -maxdepth 1 -name 'relayforge_*.deb' -type f -print -quit)
# Corrupted archive must be rejected before any live transaction.
printf 'not a package\n' > /tmp/invalid.deb
if dpkg --unpack /tmp/invalid.deb >/dev/null 2>&1; then exit 1; fi
# Unrelated user data is never a package asset or uninstall target.
mkdir -p /home/probe/.config/relayforge
printf 'retain\n' > /home/probe/.config/relayforge/unrelated-record
# A real dpkg install, not only extracted-file inspection.
dpkg -i "${pkg}"
dpkg --verify relayforge
python3 - <<'PY'
import hashlib,json
from pathlib import Path
record=json.loads(Path('/usr/share/relayforge/source.json').read_text())
for name,digest in record['binaries_sha256'].items():
    assert hashlib.sha256((Path('/usr/bin')/name).read_bytes()).hexdigest()==digest
assert not list(Path('/etc/systemd').rglob('*.wants/relayforge*'))
assert not list(Path('/home').rglob('*.wants/relayforge*'))
assert not Path('/etc/relayforge').exists()
PY
for unit in relayforge-mcp-http relayforge-mcp-oauth; do
    test -f "/usr/lib/systemd/user/${unit}.service"
    systemd-analyze verify "/usr/lib/systemd/user/${unit}.service"
done
# The separately versioned tunnel-client is intentionally not installed by this
# package. Confirm the opt-in unit cannot start when its binary is absent.
python3 - <<'PYUNIT'
from pathlib import Path
unit = Path('/usr/lib/systemd/user/relayforge-tunnel-http.service').read_text()
assert 'ConditionPathExists=/usr/bin/tunnel-client' in unit
assert 'ExecStart=' in unit and '/usr/bin/tunnel-client run' in unit
assert not Path('/usr/bin/tunnel-client').exists()
PYUNIT
# The same restricted MCP test used for the normal CI binary, now from dpkg.
runuser -u nobody -- python3 /workspace/scripts/offline_mcp_smoke.py /usr/bin/relayforge-mcp
runuser -u nobody -- python3 /workspace/scripts/offline_artifact_acceptance.py /usr/bin/relayforge-mcp
printf '%s\n' '{"version":0,"operation":"shell","command":"id"}' | /usr/bin/relayforge-agent | python3 -c 'import json,sys; assert json.load(sys.stdin)["ok"] is False'
dpkg --purge relayforge
test ! -e /usr/bin/relayforge-mcp
test ! -e /usr/lib/systemd/user/relayforge-mcp-oauth.service
test "$(cat /home/probe/.config/relayforge/unrelated-record)" = retain
printf 'Ubuntu package installed restricted MCP, verified no activation and clean removal: PASS\n'
