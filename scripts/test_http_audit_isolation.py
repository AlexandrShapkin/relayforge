#!/usr/bin/env python3
"""Exact-byte MCP HTTP acceptance in disposable systemd mount namespaces.

Run outside the Codex sandbox. Only transient units and fixture files are used.
"""
import errno
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
from unittest.mock import patch


def inside(home, binary, port, corrected, masked=False, negative=""):
    token = home.parent / "fixture-token"
    if negative and negative not in ["symlink", "hardlink", "mode", "missing-audit"]:
        # Root-owned bind fixtures must appear unmapped, never trusted as owner.
        target = {"ancestor": Path("/home"), "home": home,
                  "config-dir": home / ".config/relayforge",
                  "config-file": home / ".config/relayforge/artifact-roots.json",
                  "root": home / ".local/state/relayforge/artifacts/fixture",
                  "audit": home / ".local/state/relayforge/workstation-dev-audit.jsonl",
                  "file": home / ".local/state/relayforge/artifacts/fixture/AUTHORIZATION.md"}[negative]
        assert target.stat().st_uid == 65534, (negative, target.stat().st_uid)
    if masked and negative != 'ancestor':
        assert sorted(p.name for p in Path('/home').iterdir()) == [Path.home().name]
        mounts = Path('/proc/self/mountinfo').read_text()
        for mount_target in [Path('/home'), Path.home()]:
            rows = [l.split() for l in mounts.splitlines() if l.split()[4] == str(mount_target)]
            assert rows and 'ro' in rows[-1][5].split(','), (mount_target, rows)
        identity = json.loads((home.parent / 'mount-identities.json').read_text())
        for mount_target, key in [(Path('/home'), 'scaffold'), (Path.home(), 'actual_home')]:
            meta = mount_target.stat()
            assert [meta.st_dev, meta.st_ino] == identity[key], (mount_target, key)
        print(json.dumps({'home_mounts_readonly': True, 'other_homes_hidden': True,
                          'mount_identities': identity, 'mountinfo': [l for l in mounts.splitlines() if l.split()[4] in ['/home', str(Path.home())]]}), flush=True)
    audit = home / '.local/state/relayforge/workstation-dev-audit.jsonl'
    try:
        fd = os.open(audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        os.fsync(fd)
        os.close(fd)
        open_errno = 0
    except OSError as error:
        open_errno = error.errno
    if not negative:
        assert open_errno == (0 if corrected else errno.EROFS), open_errno
    # All siblings and configuration remain read-only, even with the exception.
    for path in ([] if negative else [audit.parent / 'sibling', home / '.config/relayforge/http-token',
                 home / '.local/state/relayforge/artifacts/fixture/AUTHORIZATION.md']):
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        except OSError as error:
            assert error.errno == errno.EROFS
        else:
            os.close(fd)
            raise AssertionError('unexpected writable sibling')
    env = {'HOME': str(home), 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
           'XDG_RUNTIME_DIR': str(home / 'run'), 'RELAYFORGE_HTTP_PORT': str(port),
           'RELAYFORGE_HTTP_TOKEN_FILE': str(token)}
    child = subprocess.Popen([binary, '--http'], env=env, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def call(op, path=None, authenticated=True):
        args = {'operation': op}
        if path is not None:
            args['path'] = path
        body = json.dumps({'jsonrpc': '2.0', 'id': 77, 'method': 'tools/call',
                           'params': {'name': 'relayforge_workstation_develop',
                                      'arguments': args}}).encode()
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'}
        if authenticated:
            headers['Authorization'] = 'Bearer ' + ('a7' * 32)
        request = urllib.request.Request(f'http://127.0.0.1:{port}/mcp', data=body, headers=headers)
        with opener.open(request, timeout=3) as reply:
            return json.load(reply)['result']
    try:
        for _ in range(100):
            try:
                caps = call('capabilities')
                break
            except urllib.error.URLError:
                time.sleep(.05)
        else:
            raise AssertionError('HTTP did not start')
        assert json.loads(caps['content'][0]['text'])['api_revision'] == 9
        print(json.dumps({'artifact_root_configured': json.loads(caps['content'][0]['text'])['artifacts']['configured'],
                          'home_parent_uid': Path('/home').stat().st_uid,
                          'uid_map': Path('/proc/self/uid_map').read_text().strip()}), flush=True)
        configured = json.loads(caps['content'][0]['text'])['artifacts']['configured']
        if negative and negative != 'missing-audit':
            if negative in ['ancestor', 'home', 'config-dir', 'config-file']:
                assert not configured, negative
            for op, path in [('artifact.read', 'activation/AUTHORIZATION.md'), ('artifact.list', 'activation')]:
                assert call(op, path)['isError'], (negative, op)
            print(json.dumps({'negative_ownership': negative, 'uid': target.stat().st_uid if negative not in ['symlink', 'hardlink', 'mode'] else os.getuid(), 'result': 'PASS'}), flush=True)
            return
        assert configured == masked, (configured, masked)
        # Exercise the actual package phase, redirecting only its fixed loopback
        # port and owner fixture paths. No phase/service/selector functions run.
        package = Path(binary).parent.parent / 'transition.py'
        if package.exists():
            spec = importlib.util.spec_from_file_location('fixture_transition', package)
            transition = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(transition)
            original_request = urllib.request.Request
            def fixture_request(url, *args, **kwargs):
                assert url == 'http://127.0.0.1:8765/mcp'
                return original_request(f'http://127.0.0.1:{port}/mcp', *args, **kwargs)
            phase_error = None
            with patch.object(transition.m, 'H', home), patch.object(transition, 'P', home / 'expected'), \
                 patch.object(urllib.request, 'Request', fixture_request):
                try:
                    transition.candidate_operations()
                except RuntimeError as error:
                    phase_error = str(error)
            configured = json.loads(caps['content'][0]['text'])['artifacts']['configured']
            expected_error = None if corrected and configured else (
                'artifact operation failed' if configured else 'artifact capabilities incorrect')
            assert phase_error == expected_error, phase_error
            print(json.dumps({'exact_package_candidate_artifact_checks': phase_error or 'PASS'}), flush=True)
        try:
            call('capabilities', authenticated=False)
        except urllib.error.HTTPError as error:
            assert error.code == 401
        else:
            raise AssertionError('unauthenticated request accepted')
        results = []
        for operation, path in [('artifact.read', 'activation/AUTHORIZATION.md'),
                                ('artifact.read', 'activation/operation-1792634926759214000.jsonl'),
                                ('artifact.list', 'activation')]:
            result = call(operation, path)
            assert result['isError'] is (not (corrected and masked)), result
            if not corrected:
                assert 'audit unavailable' in json.dumps(result), result
            elif not masked:
                assert 'artifact denied' in json.dumps(result), result
            elif operation == 'artifact.read':
                assert json.loads(result['content'][0]['text'])['utf8_text'] == (home / '.local/state/relayforge/artifacts/fixture' / path.split('/')[1]).read_text()
            else:
                assert json.loads(result['content'][0]['text'])['files'] == ['AUTHORIZATION.md', 'operation-1792634926759214000.jsonl']
            results.append({'operation': operation, 'path': path, 'isError': result['isError']})
        for path in ['unknown/AUTHORIZATION.md', 'activation/../outside.md', '/etc/passwd',
                     'activation/secret.md', 'activation/escape.md']:
            assert call('artifact.read', path)['isError']
        if corrected:
            log = audit.read_text()
            assert 'artifact.read' in log and 'artifact.list' in log
            assert 'Fixture report' not in log
            # Exceed the existing audit bound: reads must fail closed.
            with audit.open('ab') as stream:
                stream.truncate(8 * 1024 * 1024 + 1)
                stream.flush()
                os.fsync(stream.fileno())
            assert call('artifact.read', 'activation/AUTHORIZATION.md')['isError']
        print(json.dumps({'corrected': corrected, 'audit_open_errno': open_errno,
                          'results': results, 'denied_paths': 'PASS',
                          'authentication': 'PASS', 'siblings_readonly': 'PASS',
                          'audit_fail_closed': 'PASS' if corrected else 'reproduced'}), flush=True)
    finally:
        child.terminate()
        child.wait(timeout=5)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--inside':
        inside(Path(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5] == 'yes', sys.argv[6] == 'yes', sys.argv[7])
        return
    binary = str(Path(sys.argv[1]).resolve())
    assert "--system" not in sys.argv, "user-scope acceptance only"
    system_scope = False
    root = next(parent for parent in Path(__file__).resolve().parents if (parent / '.git').exists())
    with tempfile.TemporaryDirectory(prefix='http-audit-77-', dir=root / '.build') as tmp:
        base = Path(tmp)
        home = base / 'home'
        home.mkdir(mode=0o700)
        (base / 'fixture-token').write_text('a7' * 32)
        (base / 'fixture-token').chmod(0o600)
        scaffold = base / 'scaffold'
        scaffold.mkdir(mode=0o700)
        (scaffold / Path.home().name).mkdir(mode=0o700)
        (base / 'mount-identities.json').write_text(json.dumps({key: [path.stat().st_dev, path.stat().st_ino] for key, path in [('scaffold', scaffold), ('actual_home', Path.home())]}))
        config = home / '.config/relayforge'
        config.mkdir(parents=True, mode=0o700)
        audit = home / '.local/state/relayforge/workstation-dev-audit.jsonl'
        audit.parent.mkdir(parents=True, mode=0o700)
        reports = home / '.local/state/relayforge/artifacts/fixture'
        reports.mkdir(parents=True, mode=0o700)
        (reports / 'AUTHORIZATION.md').write_text('Fixture report only.\n')
        (reports / 'operation-1792634926759214000.jsonl').write_text('{"event":"fixture only"}\n')
        expected = home / 'expected/reports'
        expected.mkdir(parents=True)
        for report in reports.iterdir():
            (expected / report.name).write_bytes(report.read_bytes())
        (reports / 'secret.md').write_text('NEVER_RETURN_THIS')
        (home / 'outside.md').write_text('NEVER_RETURN_THIS')

        (home / 'Projects/relayforge/.git').mkdir(parents=True)
        (config / 'artifact-roots.json').write_text(json.dumps({'roots': {'activation': str(reports)}}))
        (config / 'http-token').write_text(('a7' * 32))
        for path in config.iterdir():
            path.chmod(0o600)
        for corrected, masked, negative in [(False, False, ''), (True, False, ''), (True, True, ''),
                *[(True, True, n) for n in ['ancestor', 'home', 'config-dir', 'config-file', 'root', 'file', 'audit', 'symlink', 'hardlink', 'mode']],
                (False, True, 'missing-audit'),
                (False, False, '')]:
            report = reports / 'AUTHORIZATION.md'
            if report.is_symlink() or report.stat().st_nlink != 1:
                report.unlink()
                report.write_text('Fixture report only.\n')
            report.chmod(0o600)
            if negative == 'hardlink':
                os.link(report, home / 'hardlink.md')
            if negative == 'mode':
                report.chmod(0o666)
            if negative == 'symlink':
                (reports / 'AUTHORIZATION.md').unlink()
                (reports / 'AUTHORIZATION.md').symlink_to(home / 'outside.md')
            elif (reports / 'AUTHORIZATION.md').is_symlink():
                (reports / 'AUTHORIZATION.md').unlink()
                (reports / 'AUTHORIZATION.md').write_text('Fixture report only.\n')
            # A mandatory single-file exception requires an existing regular file.
            audit.write_bytes(b'')
            audit.chmod(0o600)
            if negative == 'missing-audit':
                audit.unlink()
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            command = ['systemd-run', *(['-p', 'User=' + str(os.getuid())] if system_scope else ['--user']), '--wait', '--pipe', '--collect',
                       '--unit=relayforge-77-fixture-' + str(time.time_ns()),
                       '-p', 'ProtectHome=read-only', '-p', 'ProtectSystem=full',
                       '-p', 'PrivateTmp=true', '-p', 'NoNewPrivileges=true', '-p', 'UMask=0077']
            if corrected and negative != "home":
                command += ['-p', 'ReadWritePaths=' + str(audit)]
            if masked and negative != "ancestor":
                command += ['-p', f'BindReadOnlyPaths={scaffold}:/home {Path.home()}:{Path.home()}']
            if negative and negative not in ["ancestor", "symlink", "hardlink", "mode", "missing-audit"]:
                target = {'ancestor': Path('/home'), 'home': home,
                          'config-dir': config, 'config-file': config / 'artifact-roots.json',
                          'root': reports, 'audit': audit, 'file': reports / 'AUTHORIZATION.md'}[negative]
                source = '/etc' if negative in ['ancestor', 'home', 'config-dir', 'root'] else '/etc/hostname'
                command += ['-p', f'BindReadOnlyPaths={source}:{target}']
            command += ['/usr/bin/python3', str(Path(__file__).resolve()), '--inside',
                        str(home), binary, str(port), 'yes' if corrected else 'no', 'yes' if masked else 'no', negative]
            result = subprocess.run(command, capture_output=True, text=True, timeout=30)
            print(json.dumps({'command': command, 'exit_status': result.returncode}), flush=True)
            print(result.stdout, end='', flush=True)
            print(result.stderr, end='', flush=True)
            if result.returncode:
                unit = next(x.split('=', 1)[1] for x in command if x.startswith('--unit='))
                journal = subprocess.run(['journalctl', '--user', '-u', unit, '--no-pager'], capture_output=True, text=True)
                print(journal.stdout, flush=True)
            result.check_returncode()
        audit.unlink()
        prefix = command[:command.index('/usr/bin/python3')]
        unit_index = next(i for i, value in enumerate(prefix) if value.startswith('--unit='))
        prefix[unit_index] = '--unit=relayforge-77-missing-audit-' + str(time.time_ns())
        missing = subprocess.run(prefix + ['-p', 'ReadWritePaths=' + str(audit), '/usr/bin/true'],
                                 timeout=30)
        assert missing.returncode == 226, missing.returncode
        print(json.dumps({'missing_audit_startup': '226/NAMESPACE (expected)'}))
        print(json.dumps({'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                          'original_corrected_restored': 'PASS', 'live_mutations': []}))


if __name__ == '__main__':
    main()
