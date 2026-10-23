#!/usr/bin/env python3
"""Real API9 readonly-stdio acceptance in disposable systemd user namespaces.

Uses only synthetic configuration and a pinned binary supplied by the caller.
No installed unit, selector, credential or live tunnel is changed.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def inside(home, binary, masked):
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
           'XDG_RUNTIME_DIR': str(home / 'run')}
    def call(operation, path=None):
        args = {'operation': operation}
        if path is not None:
            args['path'] = path
        request = {'jsonrpc': '2.0', 'id': 77, 'method': 'tools/call',
                   'params': {'name': 'relayforge_workstation_develop', 'arguments': args}}
        result = subprocess.run([binary, '--readonly-stdio'], env=env,
                                input=json.dumps(request) + '\n', capture_output=True,
                                text=True, timeout=10, check=True)
        assert 'NEVER_RETURN_THIS' not in result.stdout
        return json.loads(result.stdout)['result']
    caps = json.loads(call('capabilities')['content'][0]['text'])
    assert caps['api_revision'] == 9
    assert caps['artifacts']['configured'] == masked, caps
    assert caps['artifacts']['read_only'] and not caps['write_grants']['source_edit']
    assert not caps['arbitrary_host_shell']
    for op, path in [('artifact.read', 'activation/AUTHORIZATION.md'), ('artifact.list', 'activation')]:
        result = call(op, path)
        assert result['isError'] is (not masked), result
        if masked:
            payload = json.loads(result['content'][0]['text'])
            if op == 'artifact.read':
                assert payload['utf8_text'] == 'Approved fixture report.\n'
            else:
                assert payload['files'] == ['AUTHORIZATION.md']
    escape = home / '.local/state/relayforge/artifacts/fixture/escape.md'
    escape.symlink_to(home / 'outside.md')
    for path in ['unknown/AUTHORIZATION.md', 'activation/../outside.md', '/etc/passwd',
                 'activation/secret.md', 'activation/escape.md']:
        assert call('artifact.read', path)['isError'], path
    escape.unlink()
    if masked:
        mounts = [line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
        for target in ['/home', str(Path.home())]:
            assert 'ro' in [r for r in mounts if r[4] == target][-1][5].split(',')
        assert sorted(p.name for p in Path('/home').iterdir()) == [Path.home().name]
        log = (home / '.local/state/relayforge/workstation-dev-audit.jsonl').read_text()
        assert 'artifact.read' in log and 'artifact.list' in log
        assert 'Approved fixture' not in log
    print(json.dumps({'transport': 'readonly-stdio', 'masked': masked,
                      'configured': caps['artifacts']['configured'],
                      'approved_read_list': 'PASS' if masked else 'baseline denied',
                      'forbidden_paths': 'PASS', 'uid_map': Path('/proc/self/uid_map').read_text().strip()}))


def main():
    if sys.argv[1] == '--inside':
        inside(Path(sys.argv[2]), sys.argv[3], sys.argv[4] == 'yes')
        return
    binary = str(Path(sys.argv[1]).resolve())
    repo = Path(__file__).resolve().parents[1]
    unit = (repo / 'deploy/systemd/relayforge-tunnel.service').read_text()
    # Exercise every sandbox directive from the candidate, excluding only the
    # live RuntimeDirectory and replacing its writable runtime path with fixture.
    hardening = [l for l in unit.splitlines() if l.startswith((
        'NoNewPrivileges=', 'PrivateTmp=', 'ProtectSystem=', 'ProtectHome=',
        'UMask=', 'RestrictAddressFamilies='))]
    assert 'BindReadOnlyPaths=%h/.local/share/relayforge/http-home:/home %h:%h' in unit
    with tempfile.TemporaryDirectory(prefix='tunnel-stdio-77-', dir=repo / '.build') as tmp:
        base = Path(tmp)
        home = base / 'home'
        home.mkdir(mode=0o700)
        (home / 'Projects/relayforge/.git').mkdir(parents=True)
        config = home / '.config/relayforge'
        config.mkdir(parents=True, mode=0o700)
        state = home / '.local/state/relayforge'
        state.mkdir(parents=True, mode=0o700)
        reports = state / 'artifacts/fixture'
        reports.mkdir(parents=True, mode=0o700)
        (reports / 'AUTHORIZATION.md').write_text('Approved fixture report.\n')
        (reports / 'secret.md').write_text('NEVER_RETURN_THIS')
        (home / 'outside.md').write_text('NEVER_RETURN_THIS')
        config_file = config / 'artifact-roots.json'
        config_file.write_text(json.dumps({'roots': {'activation': str(reports)}}))
        config_file.chmod(0o600)
        audit = state / 'workstation-dev-audit.jsonl'
        audit.touch(mode=0o600)
        scaffold = base / 'scaffold'
        scaffold.mkdir(mode=0o700)
        (scaffold / Path.home().name).mkdir(mode=0o700)
        runtime = base / 'runtime'
        runtime.mkdir(mode=0o700)
        # Baseline reproduces configured=false; candidate and restored baseline
        # use exactly the same fixture and executable bytes.
        for masked in [False, True, False]:
            command = ['systemd-run', '--user', '--wait', '--pipe', '--collect',
                       '--unit=relayforge-77-stdio-' + str(time.time_ns())]
            for prop in hardening:
                command += ['-p', prop]
            command += ['-p', f'ReadWritePaths={runtime} {state}']
            if masked:
                command += ['-p', f'BindReadOnlyPaths={scaffold}:/home {Path.home()}:{Path.home()}']
            command += ['/usr/bin/python3', str(Path(__file__).resolve()), '--inside',
                        str(home), binary, 'yes' if masked else 'no']
            run = subprocess.run(command, capture_output=True, text=True, timeout=45)
            print(run.stdout, end='', flush=True)
            print(run.stderr, end='', flush=True)
            run.check_returncode()
    print(json.dumps({'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                      'live_mutations': []}))


if __name__ == '__main__':
    main()
