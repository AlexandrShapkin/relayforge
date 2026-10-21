#!/usr/bin/env python3
"""Real task authorization/workspace fixture; only temporary operator files.

MCP submission checks remain real; direct worker invocation substitutes only for
the deliberately unavailable installed-runtime/systemd scheduler. No live grants.
"""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from offline_development_workflow import deny_namespace_creation


def run(binary):
    with tempfile.TemporaryDirectory(prefix='relayforge-authorized-development-') as temp:
        home = Path(temp)
        env = {'HOME': temp, 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
               'XDG_RUNTIME_DIR': str(home / 'run'), 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null'}
        repo = home / 'Projects/relayforge'
        source = repo / 'scripts/example.py'
        source.parent.mkdir(parents=True)
        source.write_text('def answer():\n    return 41\n')
        test = repo / 'scripts/test_example.py'
        test.write_text('import unittest,os,socket\nfrom example import answer\n'
                        'class ExampleTest(unittest.TestCase):\n'
                        '    def test_answer(self):\n        self.assertEqual(answer(), 42)\n'
                        f'        self.assertFalse(os.path.exists({str(repo / ".env")!r}))\n'
                        '        self.assertFalse(os.path.exists("/etc/passwd"))\n'
                        '        self.assertFalse(os.path.exists("/workspace/scripts/example.py"))\n'
                        '        self.assertEqual([name for _,name in socket.if_nameindex()], ["lo"])\n')
        (repo / '.env').write_text('PRIVATE_FIXTURE_SENTINEL')

        def git(*args):
            return subprocess.check_output(['git', '-C', str(repo), '-c', 'user.name=Fixture',
                                            '-c', 'user.email=fixture@example.invalid', *args],
                                           env=env, text=True).strip()

        git('init', '-q')
        git('add', 'scripts/example.py', 'scripts/test_example.py')
        git('commit', '-qm', 'baseline')
        base = git('rev-parse', 'HEAD')
        before = [(p.read_bytes(), p.stat().st_mtime_ns) for p in [source, test]]
        state = home / '.local/state/relayforge'
        state.mkdir(parents=True, mode=0o700)
        grants = home / '.config/relayforge/task-authorizations'
        grants.mkdir(parents=True, mode=0o700)
        opt_in = grants.parent / 'allow-workstation-development'
        opt_in.write_text('ALLOW_RELAYFORGE_DEVELOPMENT\n')
        opt_in.chmod(0o600)

        def call(operation, **args):
            request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': 'relayforge_workstation_develop',
                                  'arguments': {'operation': operation, **args}}}
            completed = subprocess.run([binary, '--readonly-worker'], env=env,
                                       input=json.dumps(request) + '\n', text=True,
                                       capture_output=True, timeout=12, check=True)
            return json.loads(completed.stdout)['result']

        def value(operation, **args):
            response = call(operation, **args)
            assert response['isError'] is False, response
            return json.loads(response['content'][0]['text'])

        proposal = {'schema_version': 1, 'repository': 'relayforge', 'base_revision': base,
                    'profile': 'python-stdlib-v1', 'edits': [
                        {'path': 'scripts/example.py', 'before': source.read_text(),
                         'after': 'def answer():\n    return 42\n'},
                        {'path': 'scripts/test_example.py', 'before': test.read_text(),
                         'after': test.read_text()}]}

        def prepare(payload=None):
            return value('development.prepare', parameters=payload or proposal)['job_id']

        def authorize(task_key, **changes):
            now = int(time.time())
            grant = {'schema_version': 1, 'job_id': task_key, 'repository': 'relayforge',
                     'base_revision': base, 'profile': 'python-stdlib-v1',
                     'paths': ['scripts/example.py', 'scripts/test_example.py'],
                     'operations': ['source.edit', 'build', 'test', 'diff'],
                     'issued_at': now - 1, 'expires_at': now + 300}
            grant.update(changes)
            path = grants / (task_key + '.json')
            path.write_text(json.dumps(grant))
            path.chmod(0o600)
            return path

        def submit(job_id):
            response = call('development.run', task_id=job_id)
            # Source binaries cannot masquerade as installed runtime images.
            assert response['isError'] is True, response
            assert 'requires a migrated runtime image' in response['content'][0]['text'], response
            assert value('development.inspect', task_id=job_id)['execution_requested']

        def worker(job_id):
            return subprocess.run([binary, '--sandbox-job-worker', job_id], env=env,
                                  capture_output=True, timeout=40)

        assert value('capabilities')['write_grants']['source_edit'] is False
        opt_in.unlink()
        assert call('development.prepare', parameters=proposal)['isError'] is True
        opt_in.write_text('ALLOW_RELAYFORGE_DEVELOPMENT\n')
        opt_in.chmod(0o600)
        for key, invalid in [('repository', 'other'), ('base_revision', '0' * 40),
                             ('profile', 'host-shell'), ('extra', 'denied')]:
            bad = copy.deepcopy(proposal)
            bad[key] = invalid
            assert call('development.prepare', parameters=bad)['isError'] is True
        for path in ['../private.py', '/etc/private.py', 'scripts/../../private.py',
                     '.git/hooks/hook.py', 'scripts/.private.py']:
            bad = copy.deepcopy(proposal)
            bad['edits'][0]['path'] = path
            assert call('development.prepare', parameters=bad)['isError'] is True
        conflict = copy.deepcopy(proposal)
        conflict['edits'][0]['before'] = 'different\n'
        assert call('development.prepare', parameters=conflict)['isError'] is True

        job_id = prepare()
        assert call('development.run', task_id=job_id)['isError'] is True
        assert not value('development.inspect', task_id=job_id)['execution_requested']
        for changes in [{'expires_at': int(time.time()) - 1}, {'paths': ['scripts/example.py']},
                        {'operations': ['source.edit']}, {'expires_at': int(time.time()) + 7200},
                        {'base_revision': 'a' * 40}, {'job_id': 'other'},
                        {'issued_at': int(time.time()) + 10}]:
            authorize(job_id, **changes)
            assert call('development.run', task_id=job_id)['isError'] is True
            assert not value('development.inspect', task_id=job_id)['execution_requested']
        grant = authorize(job_id)
        grant.chmod(0o644)
        assert call('development.run', task_id=job_id)['isError'] is True
        grant.chmod(0o600)
        moved = grants.parent / 'grant-copy.json'
        grant.rename(moved)
        grant.symlink_to(moved)
        assert call('development.run', task_id=job_id)['isError'] is True
        grant.unlink()
        moved.rename(grant)
        with ThreadPoolExecutor(max_workers=8) as pool:
            responses = list(pool.map(lambda _: call('development.run', task_id=job_id), range(8)))
        assert all(r['isError'] is True for r in responses)
        assert sum('requires a migrated runtime image' in r['content'][0]['text']
                   for r in responses) == 1, responses
        assert value('development.inspect', task_id=job_id)['proposal'] == proposal
        assert call('development.run', task_id=job_id)['isError'] is True
        completed = worker(job_id)
        output = value('job.output', task_id=job_id)
        assert completed.returncode == 0, output
        result = json.loads(output['stdout'])
        assert result['ok'] and result['build']['exit_code'] == result['test']['exit_code'] == 0
        assert result['base_revision'] == base and '+    return 42' in result['diff']
        assert result['source_unchanged_by_tests']
        assert worker(job_id).returncode == 2

        expired = prepare()
        authorize(expired)
        submit(expired)
        authorize(expired, expires_at=int(time.time()) - 1)
        assert worker(expired).returncode == 1
        assert value('job.output', task_id=expired)['stdout'] == ''

        running_expiry_proposal = copy.deepcopy(proposal)
        running_expiry_proposal['edits'][1]['after'] = (
            'import unittest,time\nclass Slow(unittest.TestCase):\n'
            '    def test_wait(self):\n        time.sleep(30)\n')
        running_expiry = prepare(running_expiry_proposal)
        authorize(running_expiry, expires_at=int(time.time()) + 5)
        submit(running_expiry)
        assert worker(running_expiry).returncode in (1, 124)
        expiry_output = value('job.output', task_id=running_expiry)
        if expiry_output['stdout']:
            expiry_result = json.loads(expiry_output['stdout'])
            assert not expiry_result['ok'] and expiry_result['test']['exit_code'] == 124
        else:
            assert expiry_output['status']['failure_kind'] == 'authorization_expired'

        stopped_supervisor = copy.deepcopy(proposal)
        stopped_supervisor['edits'][1]['after'] = (
            'import unittest,os,time,signal,ctypes\nclass Adversarial(unittest.TestCase):\n'
            '    def test_stop_supervisor(self):\n'
            '        if os.fork() == 0:\n'
            '            os.setsid()\n'
            '            signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
            '            assert ctypes.CDLL(None).prctl(1,0,0,0,0) == 0\n'
            '            time.sleep(30)\n'
            '            os._exit(0)\n'
            '        os.kill(os.getppid(), signal.SIGSTOP)\n'
            '        time.sleep(30)\n')
        adversarial = prepare(stopped_supervisor)
        authorize(adversarial, expires_at=int(time.time()) + 5)
        submit(adversarial)
        started = time.monotonic()
        assert worker(adversarial).returncode == 124
        assert time.monotonic() - started < 8
        assert value('job.status', task_id=adversarial)['failure_kind'] == 'authorization_expired'
        assert worker(adversarial).returncode == 2

        unavailable = prepare()
        authorize(unavailable)
        submit(unavailable)
        denied = subprocess.run([binary, '--sandbox-job-worker', unavailable], env=env,
                                capture_output=True, timeout=12,
                                preexec_fn=deny_namespace_creation)
        assert denied.returncode != 0
        denied_output = value('job.output', task_id=unavailable)
        assert denied_output['stdout'] == '' and 'bwrap:' in denied_output['stderr']
        assert worker(unavailable).returncode == 2

        revoked = prepare()
        authorize(revoked)
        submit(revoked)
        opt_in.unlink()
        assert worker(revoked).returncode == 1
        assert value('job.output', task_id=revoked)['stdout'] == ''
        opt_in.write_text('ALLOW_RELAYFORGE_DEVELOPMENT\n')
        opt_in.chmod(0o600)

        stale = prepare()
        authorize(stale)
        submit(stale)
        git('commit', '--allow-empty', '-qm', 'advance base')
        assert worker(stale).returncode == 1
        assert value('job.output', task_id=stale)['stdout'] == ''
        git('reset', '--soft', base)  # Only the disposable fixture repository.

        interrupted_proposal = copy.deepcopy(proposal)
        interrupted_proposal['edits'][1]['after'] = (
            'import unittest,time\nclass Slow(unittest.TestCase):\n'
            '    def test_wait(self):\n        time.sleep(30)\n')
        interrupted = prepare(interrupted_proposal)
        authorize(interrupted)
        submit(interrupted)
        process = subprocess.Popen([binary, '--sandbox-job-worker', interrupted], env=env,
                                   start_new_session=True, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        job_dir = state / 'sandbox-jobs' / interrupted
        try:
            deadline = time.monotonic() + 5
            while not (job_dir / 'development.authority.json').exists():
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
            children = Path(f'/proc/{process.pid}/task/{process.pid}/children')
            while not children.read_text().strip():
                assert process.poll() is None and time.monotonic() < deadline
                time.sleep(0.01)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        assert not (job_dir / 'result.json').exists()
        assert worker(interrupted).returncode == 2
        retained = value('development.inspect', task_id=interrupted)
        assert retained['proposal'] == interrupted_proposal
        assert retained['result']['state'] in ('unknown', 'failed')
        assert before == [(p.read_bytes(), p.stat().st_mtime_ns) for p in [source, test]]
        assert not (grants.parent / 'allow-workstation-source-edits').exists()
        return {'ok': True, 'base_revision': base, 'profile': 'python-stdlib-v1',
                'diff': result['diff'], 'build_exit_code': result['build']['exit_code'],
                'test_exit_code': result['test']['exit_code'],
                'checks': ['real_mcp_prepare_and_authorized_worker', 'immutable_proposal',
                           'expired_grant_before_submit_and_execution', 'stale_base',
                           'conflicting_source', 'path_repository_profile_denials',
                           'grant_scope_mode_and_operation_denials', 'duplicate_submit_and_worker',
                           'concurrent_submit_single_winner', 'authorization_deadline_during_test',
                           'outside_watchdog_kills_stopped_supervisor_and_detached_descendants',
                           'private_file_and_network_namespace_denials_inside_task',
                           'unavailable_task_isolation_fails_closed',
                           'global_development_opt_in_rechecked_at_execution',
                           'interrupted_attempt_retained_without_replay', 'checkout_unchanged'],
                'scheduling': 'direct_fixture_worker_only', 'live_acceptance': False}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: offline_authorized_development.py ABS_MCP_BINARY')
    print(json.dumps(run(str(Path(sys.argv[1]).resolve())), sort_keys=True))
