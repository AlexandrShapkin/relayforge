#!/usr/bin/env python3
"""Exercise the real MCP reader and sandbox worker in a disposable HOME.

No grants, systemd units, host checkout writes, network, credentials or GitHub
writes. Worker scheduling is deliberately bypassed; this is not live acceptance.
Missing bubblewrap/user namespaces is a failure, never a simulated pass.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


WORKFLOW = r'''set -eu
test ! -e /workspace/.git
test ! -e /workspace/.env
test ! -e /workspace/src/private.py
test ! -e /etc/passwd
if echo bad >> /workspace/src/example.py 2>/dev/null; then exit 90; fi
mkdir /tmp/dev
cd /tmp/dev
cp /workspace/src/example.py example.py
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null
git init -q
git config user.name Fixture
git config user.email fixture@example.invalid
git add example.py
git commit -qm baseline
python3 - <<'PY'
from pathlib import Path
p = Path('example.py')
assert p.read_text() == 'def answer():\n    return 41\n'
p.write_text('def answer():\n    return 42\n')
PY
python3 -m py_compile example.py
python3 -c 'from example import answer; assert answer() == 42'
git diff --check
python3 - <<'PY'
import json, subprocess
def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()
assert git('diff', '--name-only') == 'example.py'
diff = git('diff', '--', 'example.py')
subprocess.run(['git', 'add', 'example.py'], check=True)
subprocess.run(['git', 'commit', '-qm', 'fixture: correct answer'], check=True)
print(json.dumps({'build_exit_code': 0, 'test_exit_code': 0,
                  'diff': diff, 'commit': git('rev-parse', 'HEAD'),
                  'tracked_clean': git('diff', '--name-only') == '',
                  'scope': 'disposable_sandbox_commit'}))
PY
'''


def run(binary):
    assert len(WORKFLOW.encode()) <= 2048
    with tempfile.TemporaryDirectory(prefix='relayforge-development-') as temp:
        home = Path(temp)
        env = {'HOME': temp, 'PATH': '/usr/bin:/bin', 'LC_ALL': 'C',
               'XDG_RUNTIME_DIR': str(home / 'run'), 'GIT_CONFIG_NOSYSTEM': '1',
               'GIT_CONFIG_GLOBAL': '/dev/null'}
        repo = home / 'Projects/relayforge'
        (repo / 'src').mkdir(parents=True)
        source = repo / 'src/example.py'
        source.write_text('def answer():\n    return 41\n')
        (repo / 'src/private.py').write_text('UNTRACKED_SENTINEL')
        (repo / '.env').write_text('PRIVATE_SENTINEL')
        for args in [('init', '-q', str(repo)), ('-C', str(repo), 'add', 'src/example.py')]:
            subprocess.run(['git', *args], env=env, check=True, capture_output=True)
        before = (source.read_bytes(), source.stat().st_mtime_ns)
        state = home / '.local/state/relayforge'
        state.mkdir(parents=True, mode=0o700)
        jobs = state / 'sandbox-jobs'
        jobs.mkdir(mode=0o700)

        def call(operation, **args):
            request = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                       'params': {'name': 'relayforge_workstation_develop',
                                  'arguments': {'operation': operation, **args}}}
            result = subprocess.run([binary, '--readonly-worker'],
                                    input=json.dumps(request) + '\n', text=True,
                                    capture_output=True, timeout=12, env=env, check=True)
            return json.loads(result.stdout)['result']

        def value(operation, **args):
            result = call(operation, **args)
            assert result['isError'] is False, result
            return json.loads(result['content'][0]['text'])

        def prepare(index, script):
            job_id = f'relayforge-job-1792390000-{index:06x}'
            directory = jobs / job_id
            directory.mkdir(mode=0o700)
            script_file = directory / 'script.sh'
            script_file.write_text(script)
            script_file.chmod(0o600)
            return job_id, directory

        def worker(job_id):
            return subprocess.run([binary, '--sandbox-job-worker', job_id],
                                  env=env, capture_output=True, timeout=20)

        capabilities = value('capabilities')
        assert capabilities['write_grants'] == {'development': False, 'source_edit': False}
        assert 'src' in value('repo.list')['entries']
        assert value('repo.read', path='src/example.py')['utf8_text'].endswith('return 41\n')
        for op, args in [('repo.read', {'path': '../.env'}),
                         ('repo.read', {'path': 'src/private.py'}),
                         ('repo.write', {'path': 'src/example.py', 'content': 'denied'}),
                         ('job.start', {'script': 'true'}),
                         ('workspace.put', {'path': 'x.py', 'content': 'denied'})]:
            assert call(op, **args)['isError'] is True, op

        job_id, directory = prepare(1, WORKFLOW)
        completed = worker(job_id)
        output = value('job.output', task_id=job_id)
        assert completed.returncode == 0, output
        assert output['status']['exit_code'] == 0, output
        evidence = json.loads(output['stdout'])
        assert len(evidence['commit']) == 40 and evidence['tracked_clean']
        receipt = (directory / 'result.json').read_bytes()
        assert worker(job_id).returncode == 2
        assert receipt == (directory / 'result.json').read_bytes()

        for index, script, code in [(2, 'exit 7', 7), (3, 'timeout 1s sleep 5', 124)]:
            failed_id, _ = prepare(index, script)
            assert worker(failed_id).returncode == code
            assert value('job.status', task_id=failed_id)['exit_code'] == code

        chain_id = 'relayforge-job-1792390000-000005'
        chain_dir = jobs / chain_id
        chain_dir.mkdir(mode=0o700)
        for name, text in [('chain.count', '2'), ('step-01.sh', "printf 'verified-input'"),
                           ('step-02.sh', 'test "$(cat)" = verified-input && printf verified-output')]:
            path = chain_dir / name
            path.write_text(text)
            path.chmod(0o600)
        assert worker(chain_id).returncode == 0
        chain = value('job.chain.status', task_id=chain_id)
        assert chain['completed_steps'] == 2 and chain['exit_code'] == 0, chain
        assert value('job.chain.output', task_id=chain_id,
                     parameters={'step': 2})['stdout'] == 'verified-output'
        assert worker(chain_id).returncode == 2

        crashed_id, crashed_dir = prepare(4, 'sleep 30')
        process = subprocess.Popen([binary, '--sandbox-job-worker', crashed_id], env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 5
            while not (crashed_dir / 'worker.claim').exists():
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
        assert not (crashed_dir / 'result.json').exists()
        assert worker(crashed_id).returncode == 2
        # Reconnect through a new MCP process; no receipt means no success.
        assert value('job.status', task_id=crashed_id)['state'] in ('unknown', 'failed')
        assert before == (source.read_bytes(), source.stat().st_mtime_ns)
        assert not (home / '.config').exists(), 'fixture must not create grants'
        return {'ok': True, 'execution': 'real_mcp_and_bubblewrap_worker',
                'workflow': evidence,
                'checks': ['inspection', 'sandbox_edit_build_test_diff_commit',
                           'missing_grants_denied', 'private_paths_denied',
                           'exit_status', 'command_timeout', 'duplicate_refused',
                           'real_chain_handoff_and_replay_denial',
                           'worker_crash_no_replay', 'new_mcp_client_reads_receipts',
                           'host_source_unchanged'],
                'not_tested': ['systemd_scheduling_and_resource_enforcement',
                               'expiring_source_authorization_not_implemented',
                               'secure_tunnel_disconnect', 'live_device_workflow',
                               'github_publication_from_fixture'],
                'production_ready': False}


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('usage: offline_development_workflow.py ABS_MCP_BINARY')
    print(json.dumps(run(str(Path(sys.argv[1]).resolve())), sort_keys=True))
