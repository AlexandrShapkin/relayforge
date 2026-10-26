"""Installed client and denied user-systemd startup; never make a live tunnel."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time


def run(*args, check=True):
    return subprocess.run(args, text=True, capture_output=True, check=check)


def ctl(*args, check=True):
    return run('systemctl', '--user', *args, check=check)


# Installed executable has no .py suffix.
from importlib.machinery import SourceFileLoader
spec = importlib.util.spec_from_loader('guard', SourceFileLoader('guard', '/usr/bin/relayforge-tunnel'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
home = Path.home()
legacy = home / '.config/tunnel-client'
legacy.mkdir(mode=0o700, exist_ok=True)
(legacy / 'relayforge-local.yaml').write_text('retained legacy fixture')
unit = 'relayforge-tunnel.service'
run('systemd-analyze', '--user', 'verify', '/usr/lib/systemd/user/' + unit)
assert ctl('is-enabled', unit, check=False).stdout.strip() == 'disabled'
assert ctl('is-active', unit, check=False).returncode != 0
# Missing profile/key must not start a process.
ctl('start', unit, check=False)
assert ctl('show', '-p', 'MainPID', '--value', unit).stdout.strip() == '0'
assert ctl('show', '-p', 'ConditionResult', '--value', unit).stdout.strip() == 'no'
client = '/usr/bin/tunnel-client'
help_text = run(client, 'run', '--help').stdout
assert '0.0.18' in help_text and '--mcp.command' in help_text and '--config' in help_text
run(client, 'cloudflared', '--help')
root = home / guard.RELATIVE
root.mkdir(mode=0o700)
key = root / 'runtime-key'
profile = root / 'profile.json'
key.write_text('ci-dummy-key-never-valid')
key.chmod(0o600)
valid = guard.profile('tunnel_' + '0' * 32, str(key))
profile.write_text(json.dumps(valid))
profile.chmod(0o600)
run('/usr/bin/relayforge-tunnel', 'check')
# External network is disconnected by the workflow before this fixture.
# Inspect doctor flags; positive startup below validates the actual profile.
doctor_help = run(client, 'doctor', '--help').stdout
assert '--config' in doctor_help
# Unsafe profile settings, weak key mode, symlink and absent key deny the real unit.
for case in ('command', 'key-mode', 'key-symlink', 'missing-key', 'profile-mode', 'extra-channel'):
    profile.write_text(json.dumps(valid))
    profile.chmod(0o600)
    if key.is_symlink():
        key.unlink()
    key.write_text('ci-dummy-key-never-valid')
    key.chmod(0o600)
    if case == 'command':
        bad = json.loads(json.dumps(valid)); bad['mcp']['commands'][0]['command'] = '/bin/sh'
        profile.write_text(json.dumps(bad))
    elif case == 'extra-channel':
        bad = json.loads(json.dumps(valid)); bad['mcp']['server_urls'] = [{'channel': 'other', 'url': 'http://localhost'}]
        profile.write_text(json.dumps(bad))
    elif case == 'key-mode':
        key.chmod(0o644)
    elif case == 'profile-mode':
        profile.chmod(0o644)
    elif case == 'key-symlink':
        key.unlink(); key.symlink_to(profile)
    else:
        key.unlink()
    ctl('reset-failed', unit, check=False)
    ctl('start', unit, check=False)
    for _ in range(50):
        if ctl('show', '-p', 'MainPID', '--value', unit).stdout.strip() == '0':
            break
        time.sleep(.1)
    assert ctl('show', '-p', 'MainPID', '--value', unit).stdout.strip() == '0', case
    assert ctl('is-active', unit, check=False).returncode != 0, case
    ctl('stop', unit, check=False)
# A valid startup uses the actual installed unit/client, with no external network.
if not key.exists(): key.write_text('ci-dummy-key-never-valid')
key.chmod(0o600); profile.chmod(0o600); profile.write_text(json.dumps(valid))
ctl('reset-failed', unit, check=False)
ctl('set-environment', 'MCP_COMMAND=/bin/sh', 'TUNNEL_CLIENT_PROFILE=legacy',
    'CONTROL_PLANE_BASE_URL=https://override.invalid')
ctl('start', unit)
try:
    for _ in range(50):
        pid = int(ctl('show', '-p', 'MainPID', '--value', unit).stdout)
        if pid and Path(f'/proc/{pid}/exe').resolve() == Path('/usr/lib/tunnel-client/tunnel-client'):
            break
        time.sleep(.1)
    else:
        raise AssertionError('installed official client failed to start')
    cmdline = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    assert b'command=/usr/bin/relayforge-mcp --readonly-stdio,channel=main' in cmdline
    assert b'--config' in cmdline and b'--control-plane.api-key' in cmdline
    environment = Path(f'/proc/{pid}/environ').read_bytes().split(b'\0')
    assert all(e.split(b'=')[0] in (b'HOME', b'PATH', b'LANG', b'') for e in environment)
except BaseException:
    # Only dummy CI profile/key data exists in this disconnected container.
    print(run('journalctl', '--user', '-u', unit, '--no-pager', '-n', '35').stdout, file=sys.stderr)
    raise
finally:
    ctl('stop', unit)
    ctl('unset-environment', 'MCP_COMMAND', 'TUNNEL_CLIENT_PROFILE', 'CONTROL_PLANE_BASE_URL')
assert (legacy / 'relayforge-local.yaml').read_text() == 'retained legacy fixture'
assert ctl('is-enabled', unit, check=False).stdout.strip() == 'disabled'
print('installed tunnel client CLI and denied unit startup: PASS')
