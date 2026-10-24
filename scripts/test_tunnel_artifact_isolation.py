#!/usr/bin/env python3
"""Real HTTP and readonly-stdio API9 acceptance in disposable USER services.

Synthetic configuration only; no installed services, selectors or credentials.
The positive tests use candidate unit hardening directly, without HOME mounts.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def inside(home, binary, transport, port, negative):
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
           'XDG_RUNTIME_DIR': str(home / 'run'), 'RELAYFORGE_HTTP_PORT': str(port),
           'RELAYFORGE_HTTP_TOKEN_FILE': str(home.parent / 'fixture-token')}
    child = None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    if negative:
        target = {'home': home, 'config': home / '.config/relayforge/artifact-roots.json',
                  'root': home / '.local/state/relayforge/artifacts/fixture',
                  'file': home / '.local/state/relayforge/artifacts/fixture/AUTHORIZATION.md'}[negative]
        assert target.stat().st_uid == 65534
    if transport == 'http':
        child = subprocess.Popen([binary, '--http'], env=env, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
    def rpc(method, params, authenticated=True):
        request = {'jsonrpc': '2.0', 'id': 77, 'method': method, 'params': params}
        if transport == 'stdio':
            run = subprocess.run([binary, '--readonly-stdio'], env=env,
                                 input=json.dumps(request) + '\n', capture_output=True,
                                 text=True, timeout=10, check=True)
            assert 'NEVER_RETURN_THIS' not in run.stdout
            return json.loads(run.stdout)['result']
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + 'a7' * 32
        req = urllib.request.Request(f'http://127.0.0.1:{port}/mcp', data=json.dumps(request).encode(), headers=headers)
        with opener.open(req, timeout=3) as reply:
            return json.load(reply)['result']
    def call(operation, path=None):
        args = {'operation': operation}
        if path is not None:
            args['path'] = path
        return rpc('tools/call', {'name': 'relayforge_workstation_develop', 'arguments': args})
    try:
        for _ in range(100):
            try:
                caps = json.loads(call('capabilities')['content'][0]['text'])
                break
            except urllib.error.URLError:
                time.sleep(.05)
        else:
            raise AssertionError('fixture endpoint unavailable')
        assert caps['api_revision'] == 9 and caps['artifacts']['configured'] is (negative not in ('home', 'config'))
        assert caps['artifacts']['read_only'] and not caps['write_grants']['source_edit']
        assert not caps['arbitrary_host_shell']
        assert any(t['name'] == 'relayforge_workstation_develop' for t in rpc('tools/list', {})['tools'])
        for op, path in [('artifact.read', 'activation/AUTHORIZATION.md'), ('artifact.list', 'activation')]:
            result = call(op, path)
            assert result['isError'] is bool(negative), result
            if not negative:
                payload = json.loads(result['content'][0]['text'])
                assert payload['utf8_text'] == 'Approved fixture report.\n' if op == 'artifact.read' else payload['files'] == ['AUTHORIZATION.md']
        reports = home / '.local/state/relayforge/artifacts/fixture'
        if not negative:
            (reports / 'escape.md').symlink_to(home / 'outside.md')
        for path in ['unknown/AUTHORIZATION.md', 'activation/../outside.md', '/etc/passwd',
                     'activation/secret.md', 'activation/escape.md']:
            assert call('artifact.read', path)['isError'], path
        if not negative:
            (reports / 'escape.md').unlink()
        if not negative:
            # HOME is writable for authorized operations; system mounts retain
            # ProtectSystem=full and no authorization object trusts unmapped UID.
            probe = home / 'owner-write-probe'
            probe.write_text('fixture only')
            probe.unlink()
            log = (home / '.local/state/relayforge/workstation-dev-audit.jsonl').read_text()
            assert 'artifact.read' in log and 'artifact.list' in log
            assert 'Approved fixture' not in log
            if transport == 'http':
                try:
                    rpc('tools/list', {}, authenticated=False)
                except urllib.error.HTTPError as error:
                    assert error.code == 401
                else:
                    raise AssertionError('unauthenticated HTTP accepted')
            config = home / '.config/relayforge/artifact-roots.json'
            config.unlink()
            assert not json.loads(call('capabilities')['content'][0]['text'])['artifacts']['configured']
            assert call('artifact.read', 'activation/AUTHORIZATION.md')['isError']
        print(json.dumps({'transport': transport, 'configured': caps['artifacts']['configured'], 'unmapped_object': negative or None,
                          'discovery_read_list_denials': 'PASS', 'revocation': 'PASS' if not negative else 'unmapped-owner denied',
                          'uid_map': Path('/proc/self/uid_map').read_text().strip()}))
    finally:
        if child:
            child.terminate()
            child.wait(timeout=5)


def recovery_fixture(repo):
    spec = importlib.util.spec_from_file_location('fixture_transaction', repo / 'deploy/activation_transaction.py')
    a = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(a)
    with tempfile.TemporaryDirectory(prefix='recovery-77-', dir=repo / '.build') as tmp:
        root = Path(tmp)
        targets = {}
        for name in ['http.service', 'tunnel.service', 'root-map']:
            path = root / name
            path.write_bytes(b'exact original bytes\n\n')
            path.chmod(0o600 if name == 'root-map' else 0o644)
            targets[path] = a.file_state(b'candidate', path.stat().st_mode & 0o777)
        (root / 'current').symlink_to('baseline')
        targets[root / 'current'] = {'link': 'candidate'}
        tx = a.Transaction(root / 'journal.json', targets, True)
        payload = root / 'targets.json'
        payload.write_text(json.dumps({str(p): value for p, value in targets.items()}))
        payload.chmod(0o600)
        callback = root / 'recover.py'
        callback.write_text("""import importlib.util,json,sys
from pathlib import Path
spec=importlib.util.spec_from_file_location('a',sys.argv[1]);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
root=Path(sys.argv[2]);t=a.Transaction(root/'journal.json',json.loads((root/'targets.json').read_text()));t.rollback();(root/'recovered').write_text('PASS')
""")
        name = 'relayforge-77-recovery-' + str(time.time_ns())
        when = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(time.time() + 4))
        command = ['systemd-run', '--user', '--collect', '--unit=' + name,
                   '--on-calendar=' + when, '--timer-property=Persistent=true',
                   '--timer-property=AccuracySec=1s', '-p', 'NoNewPrivileges=true',
                   '/usr/bin/python3', '-B', str(callback), a.__file__, str(root)]
        try:
            subprocess.run(command, check=True, timeout=10)
            for path in targets:
                tx.apply(path)
            end = time.monotonic() + 15
            while not (root / 'recovered').exists() and time.monotonic() < end:
                time.sleep(.1)
            assert (root / 'recovered').read_text() == 'PASS'
            for path in targets:
                assert a.state(path) == tx.doc['targets'][str(path)]['before']
            print(json.dumps({'independent_calendar_recovery': 'PASS',
                              'persistent_timer': True, 'restored_exact_baselines': True}))
        finally:
            subprocess.run(['systemctl', '--user', 'stop', name + '.timer', name + '.service'],
                           capture_output=True, timeout=10)
            subprocess.run(['systemctl', '--user', 'clean', '--what=state', name + '.timer'],
                           capture_output=True, timeout=10)


def main():
    if sys.argv[1] == '--inside':
        inside(Path(sys.argv[2]), sys.argv[3], sys.argv[4], int(sys.argv[5]), sys.argv[6])
        return
    binary = str(Path(sys.argv[1]).resolve())
    repo = Path(__file__).resolve().parents[1]
    for transport, unit in [('http', 'relayforge-mcp-http.service'), ('stdio', 'relayforge-tunnel.service')]:
        text = (repo / 'deploy/systemd' / unit).read_text()
        assert 'ProtectHome=false\n' in text and 'BindReadOnlyPaths=' not in text
        hardening = [l for l in text.splitlines() if l.startswith((
            'NoNewPrivileges=', 'PrivateTmp=', 'ProtectSystem=', 'ProtectHome=', 'UMask=', 'RestrictAddressFamilies='))]
        for negative in ['', 'home', 'config', 'root', 'file']:
            with tempfile.TemporaryDirectory(prefix='home-access-77-', dir=repo / '.build') as tmp:
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
                file = config / 'artifact-roots.json'
                file.write_text(json.dumps({'roots': {'activation': str(reports)}}))
                file.chmod(0o600)
                (base / 'fixture-token').write_text('a7' * 32)
                (base / 'fixture-token').chmod(0o600)
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                command = ['systemd-run', '--user', '--wait', '--pipe', '--collect',
                           '--unit=relayforge-77-home-' + str(time.time_ns()), '-p', 'RuntimeMaxSec=25']
                for prop in hardening:
                    command += ['-p', prop]
                if negative:
                    target = {'home': home, 'config': file, 'root': reports, 'file': reports / 'AUTHORIZATION.md'}[negative]
                    source = '/etc' if negative in ('home', 'root') else '/etc/hostname'
                    command += ['-p', f'BindReadOnlyPaths={source}:{target}']
                command += ['/usr/bin/python3', str(Path(__file__).resolve()), '--inside',
                            str(home), binary, transport, str(port), negative]
                run = subprocess.run(command, capture_output=True, text=True, timeout=35)
                print(run.stdout, end='', flush=True)
                print(run.stderr, end='', flush=True)
                run.check_returncode()
    recovery_fixture(repo)
    print(json.dumps({'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(), 'live_mutations': []}))


if __name__ == '__main__':
    main()
