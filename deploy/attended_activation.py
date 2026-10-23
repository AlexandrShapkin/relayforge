#!/usr/bin/python3
"""Pinned, attended activation with durable, independently scheduled recovery."""
import argparse
import base64
import contextlib
import datetime
import fcntl
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import sys
import time
import uuid

sys.dont_write_bytecode = True
P = Path(__file__).resolve().parent
FROZEN = P / 'frozen'
m = None

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

a = module('activation_transaction', P / 'activation_transaction.py')
WINDOW = 20 * 60


def configure():
    global m, COMMIT, SHA, BASE, CAND, INPUT, REPORTS, CONFIG, AUDIT, LOCK, TUNNEL, UNITS, ATTEMPTS
    m = module('frozen_maintenance', FROZEN / 'maintenance.py')
    pins = json.loads((P / 'activation-pins.json').read_text())
    m.require(pins['baseline'] == {'commit': m.M['commit'], 'sha256': m.M['baseline']}, 'baseline pin changed')
    COMMIT, SHA = pins['candidate']['commit'], pins['candidate']['sha256']
    m.require(re.fullmatch('[0-9a-f]{40}', COMMIT) and re.fullmatch('[0-9a-f]{64}', SHA), 'candidate pin invalid')
    BASE = 'artifacts/' + m.M['commit'] + '-' + m.M['baseline']
    CAND = 'artifacts/' + COMMIT + '-' + SHA
    INPUT = P / 'candidates' / (COMMIT + '-' + SHA)
    REPORTS = m.H / '.local/state/relayforge/artifacts/pr90-04d7ba54a980-v2'
    CONFIG = m.H / '.config/relayforge/artifact-roots.json'
    AUDIT = m.H / '.local/state/relayforge/workstation-dev-audit.jsonl'
    LOCK = m.H / '.local/state/relayforge/development.lock'
    UNITS = m.H / '.config/systemd/user'
    TUNNEL = UNITS / 'relayforge-tunnel.service'
    ATTEMPTS = P / 'attempts'


def unit_bytes(kind, state):
    path = P / (kind + '-configuration') / (state + '.service')
    pin = json.loads(path.with_name('pins.json').read_text())[path.name]
    m.require(m.digest(path) == pin['sha256'] and pin['mode'] == 0o644, 'unit pin changed')
    return path.read_bytes()


def artifact(target, commit, sha):
    path = m.STORE / target
    a.directory(path)
    m.artifact.verify(path / 'relayforge-mcp', path / 'manifest.json', commit, sha)
    for name, mode in [('relayforge-mcp', 0o500), ('manifest.json', 0o400)]:
        a.regular(path / name, mode)


def sealed():
    for name, expected in json.loads((P / 'support-pins.json').read_text()).items():
        m.require(m.digest(FROZEN / name) == expected, 'frozen support changed')
    modes = json.loads((P / 'package-modes.json').read_text())
    for name, expected in json.loads((P / 'package-hashes.json').read_text()).items():
        a.regular(P / name, modes[name])
        m.require(m.digest(P / name) == expected, 'transition package changed')


def configuration():
    # No grant or credential is ever written by this transition. Frozen pins
    # detect changes; only the independently approved root-map is variable.
    expected = set(m.M['configs'])
    observed = set()
    for root in [m.H / '.config/relayforge', m.H / '.config/tunnel-client']:
        for path in root.rglob('*'):
            m.require(not path.is_symlink(), 'configuration symlink')
            a.ancestors(path if path.is_dir() else path.parent)
            if path.is_file() and path != CONFIG:
                observed.add(str(path))
    m.require(observed == expected, 'grant/credential inventory changed')
    for name, item in m.M['configs'].items():
        path = Path(name)
        a.regular(path, item['mode'])
        m.require(m.digest(path) == item['sha256'], 'grant/credential changed')


def invariant():
    m.require(os.getuid() == m.M['uid'], 'wrong physical owner')
    configuration()
    artifact(BASE, m.M['commit'], m.M['baseline'])
    for name, item in m.M['files'].items():
        path = Path(name)
        if path in (m.HTTP, TUNNEL):
            kind = 'http' if path == m.HTTP else 'tunnel'
            a.regular(path, 0o644)
            m.require(path.read_bytes() in [unit_bytes(kind, s) for s in ['baseline', 'candidate']], 'unit changed')
        elif path == m.LAUNCH:
            a.regular(path, 0o700)
            m.require(path.read_bytes() == (FROZEN / 'proposed/relayforge-tunnel-mcp').read_bytes(), 'launcher changed')
        else:
            a.regular(path, item['mode'])
            m.require(m.digest(path) == item['sha256'], 'installed file changed')
    opt_in = m.H / '.config/relayforge/allow-workstation-source-edits'
    m.require(not opt_in.exists() and not opt_in.is_symlink(), 'source edit opt-in present')
    m.require(all(m.props(u)['ActiveState'] == 'inactive' for u in m.LEGACY), 'legacy recovery active')
    for unit in m.M['units']:
        props = m.props(unit)
        m.require(props['NeedDaemonReload'] == 'no' and props['FragmentPath'] == str(UNITS / unit), 'loaded unit changed')
        m.require(props['DropInPaths'] == (str(m.GUARD) if unit == m.LEGACY[1] else ''), 'unexpected drop-in')
        drop = UNITS / (unit + '.d')
        m.require(not drop.exists() or (unit == m.LEGACY[1] and set(drop.iterdir()) == {m.GUARD}), 'unexpected drop-in directory')
    m.require('/usr/bin/false' in m.props(m.LEGACY[1])['ExecStart'], 'legacy guard not loaded')


def merged_roots(before=Ellipsis):
    if before is Ellipsis:
        before = a.state(CONFIG)
    sensitive = ['secret', 'credential', 'token', 'password', 'private', 'id_rsa',
                 'id_ed25519', '.env', '.pem', '.key']
    def name_ok(value, limit):
        return (isinstance(value, str) and 0 < len(value) <= limit
                and not value.startswith('.') and re.fullmatch('[A-Za-z0-9_.-]+', value)
                and not any(word in value.lower() for word in sensitive))
    roots = {}
    if before is not None:
        m.require('data' in before and before['mode'] == 0o600, 'root-map metadata invalid')
        value = json.loads(base64.b64decode(before['data']))
        m.require(set(value) == {'roots'} and isinstance(value['roots'], dict), 'root-map schema invalid')
        roots = value['roots']
        m.require(all(name_ok(key, 32) and isinstance(value, str) and Path(value).is_absolute()
                      for key, value in roots.items()), 'root-map entry invalid')
    m.require('activation' not in roots or roots['activation'] == str(REPORTS), 'activation root collision')
    roots = {**roots, 'activation': str(REPORTS)}
    m.require(len(roots) <= 8, 'root-map capacity exceeded')
    for root in roots.values():
        allowed = [str(m.H / 'Projects/relayforge/.build') + '/',
                   str(m.H / '.local/state/relayforge/artifacts') + '/']
        suffix = next((root[len(prefix):] for prefix in allowed if root.startswith(prefix)), '')
        m.require(name_ok(suffix, 96), 'root-map path invalid')
    data = (json.dumps({'roots': roots}, sort_keys=True) + '\n').encode()
    m.require(len(data) <= 4096, 'root-map too large')
    return data


def prerequisites(create=False):
    a.directory(m.H, private=False)
    repo = m.H / 'Projects/relayforge'
    m.require(repo.is_dir() and (repo / '.git').exists(), 'MCP repository prerequisite missing')
    for leaf in [CONFIG.parent, REPORTS.parent, repo]:
        for component in [leaf, *leaf.parents]:
            if component == m.H:
                break
            if component.exists() or component.is_symlink():
                meta = component.lstat()
                m.require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
                          and meta.st_mode & 0o022 == 0, 'unsafe HOME descendant')
    missing = []
    for path in [AUDIT.parent, CONFIG.parent, ATTEMPTS, REPORTS.parent]:
        missing += a.directory(path, create)
    for path, limit in [(AUDIT, 8 * 1024 * 1024), (LOCK, 1024 * 1024)]:
        missing += a.private_file(path, create, limit)
        if path.exists():
            m.require(os.access(path, os.W_OK) and not os.statvfs(path).f_flag & os.ST_RDONLY,
                      'state file is not writable')
    a.directory(UNITS, private=False)
    missing += a.directory(UNITS / 'timers.target.wants', create, private=False)
    a.directory(m.STORE)
    a.directory(m.STORE / 'artifacts')
    # Catch read-only mounts, missing execute bits, and unit replacement failures
    # before a check reports success. Check never creates probe files.
    for path in [P, m.HTTP.parent, TUNNEL.parent, m.STORE, m.STORE / 'artifacts']:
        a.directory(path, private=False)
    if CONFIG.exists() or CONFIG.is_symlink():
        a.regular(CONFIG)
        merged_roots()
    return sorted(set(missing))


def retained(path, source, modes):
    a.directory(path)
    m.require(set(p.name for p in path.iterdir()) == set(modes), 'retained directory inventory changed')
    for name, mode in modes.items():
        a.regular(path / name, mode)
        m.require((path / name).read_bytes() == (source / name).read_bytes(), 'retained bytes changed')


def ready():
    invariant()
    m.require(a.state(m.STORE / 'current') == {'link': BASE}, 'baseline not selected')
    m.require(a.state(m.STORE / 'previous') in (None, {'link': BASE}), 'previous selector changed')
    for kind, path in [('http', m.HTTP), ('tunnel', TUNNEL)]:
        m.require(path.read_bytes() == unit_bytes(kind, 'baseline'), 'baseline unit changed')
    m.artifact.verify(FROZEN / 'baseline/relayforge-mcp', FROZEN / 'baseline/manifest.json',
                      m.M['commit'], m.M['baseline'])
    a.regular(FROZEN / 'baseline/relayforge-mcp', 0o500)
    a.regular(FROZEN / 'baseline/manifest.json', 0o400)
    m.artifact.verify(INPUT / 'relayforge-mcp', INPUT / 'manifest.json', COMMIT, SHA)
    a.regular(INPUT / 'relayforge-mcp', 0o500)
    a.regular(INPUT / 'manifest.json', 0o400)
    missing = prerequisites()
    for path, source, modes in [(m.STORE / CAND, INPUT, {'relayforge-mcp': 0o500, 'manifest.json': 0o400}),
                               (REPORTS, P / 'reports', {'AUTHORIZATION.md': 0o400, 'operation-1792634926759214000.jsonl': 0o400})]:
        if path.exists() or path.is_symlink():
            retained(path, source, modes)
    recoverable = []
    if ATTEMPTS.exists():
        for path in ATTEMPTS.iterdir():
            a.directory(path)
            journal = path / 'journal.json'
            if journal.exists():
                a.regular(journal)
                transaction = load_attempt(path.name)
                if transaction.doc['status'] == 'pending':
                    m.require(all(a.state(target) == row['before']
                                  for target, row in transaction.doc['targets'].items()),
                              'partially installed attempt requires recovery')
                    for name, data in recovery_templates(path.name, transaction.doc['deadline']).items():
                        m.require(a.state(UNITS / name) in (None, a.file_state(data, 0o600)), 'recovery configuration changed')
                    link = UNITS / 'timers.target.wants' / ('relayforge-activation-' + path.name + '.timer')
                    m.require(not (link.exists() or link.is_symlink()) or
                              (link.is_symlink() and link.resolve() == UNITS / link.name), 'recovery link changed')
                    recoverable.append(path.name)
    m.require(m.command(['loginctl', 'show-user', str(os.getuid()), '-p', 'Linger', '--value']).strip() == 'yes', 'durable user recovery requires lingering')
    m.systemctl('show', 'timers.target', '-p', 'LoadState')
    for tool in [Path('/usr/bin/python3'), Path('/usr/bin/systemctl')]:
        m.require(tool.is_file() and os.access(tool, os.X_OK), 'recovery executable missing')
    needed = sum((INPUT / n).stat().st_size for n in ['relayforge-mcp', 'manifest.json']) + 8 * 1024 * 1024
    for path in [P, m.STORE, CONFIG.parent, AUDIT.parent]:
        cursor = path
        while not cursor.exists():
            cursor = cursor.parent
        m.require(shutil.disk_usage(cursor).free >= needed, 'insufficient installation space')
    m.command(['systemd-analyze', '--user', 'verify',
               str(P / 'http-configuration/candidate.service'),
               str(P / 'tunnel-configuration/candidate.service')])
    local_health(m.M['baseline'])
    return {'status': 'PASS', 'automatically_creatable': missing,
            'automatically_recoverable_attempts': recoverable, 'blockers': [], 'actions_performed': []}


def stage_directory(path, source, modes, attempt):
    if path.exists() or path.is_symlink():
        retained(path, source, modes)
        return
    temporary = path.with_name(path.name + '.stage-' + attempt)
    temporary.mkdir(mode=0o700)
    for name, mode in modes.items():
        target = temporary / name
        a.write(target, a.file_state((source / name).read_bytes(), mode),
                target.with_name(target.name + '.next-' + uuid.uuid4().hex))
    a.sync(temporary)
    m.require(not path.exists() and not path.is_symlink(), 'staging destination appeared')
    os.rename(temporary, path)
    a.sync(path.parent)


def targets(root_map):
    return {m.HTTP: a.file_state(unit_bytes('http', 'candidate'), 0o644),
            TUNNEL: a.file_state(unit_bytes('tunnel', 'candidate'), 0o644),
            CONFIG: a.file_state(root_map, 0o600),
            m.STORE / 'previous': {'link': BASE}, m.STORE / 'current': {'link': CAND}}


def recovery_templates(attempt, deadline):
    name = 'relayforge-activation-' + attempt
    date = datetime.datetime.fromtimestamp(deadline, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    # systemd quoting, including literal specifier escaping. Fixed executable;
    # shell is never used. Attempt is restricted to lowercase hexadecimal.
    script = str(P / 'transition.py').replace('%', '%%').replace('\\', '\\\\').replace('"', '\\"')
    service = f'''[Unit]
Description=RelayForge bounded pending activation recovery
StartLimitIntervalSec=600
StartLimitBurst=3
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -B "{script}" recover --attempt {attempt}
TimeoutStartSec=180
Restart=on-failure
RestartSec=15
UMask=0077
NoNewPrivileges=true
'''.encode()
    timer = f'''[Unit]
Description=RelayForge pending activation deadline
[Timer]
OnCalendar={date}
Persistent=true
AccuracySec=1s
Unit={name}.service
[Install]
WantedBy=timers.target
'''.encode()
    return {name + '.service': service, name + '.timer': timer}


def arm(transaction):
    attempt = transaction.doc['id']
    templates = recovery_templates(attempt, transaction.doc['deadline'])
    for name, data in templates.items():
        path = UNITS / name
        m.require(a.state(path) is None, 'recovery unit collision')
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    a.sync(UNITS)
    m.systemctl('daemon-reload')
    timer = 'relayforge-activation-' + attempt + '.timer'
    m.systemctl('enable', '--now', timer)
    m.require(m.systemctl('is-active', timer).strip() == 'active', 'recovery timer not active')
    link = UNITS / 'timers.target.wants' / timer
    m.require(link.is_symlink() and link.resolve() == UNITS / timer, 'recovery not enabled durably')
    a.sync(link.parent)


def disarm(transaction):
    templates = recovery_templates(transaction.doc['id'], transaction.doc['deadline'])
    timer = 'relayforge-activation-' + transaction.doc['id'] + '.timer'
    link = UNITS / 'timers.target.wants' / timer
    if (UNITS / timer).exists() or link.exists() or link.is_symlink():
        m.systemctl('stop', timer)
    if link.is_symlink() and link.resolve() == UNITS / timer:
        link.unlink()
        a.sync(link.parent)
    elif link.exists() or link.is_symlink():
        raise RuntimeError('recovery link changed')
    for name, expected in templates.items():
        path = UNITS / name
        if path.exists() or path.is_symlink():
            a.regular(path)
            m.require(path.read_bytes() == expected, 'recovery unit changed')
            path.unlink()
    a.sync(UNITS)
    m.systemctl('daemon-reload')



def local_health(expected, require_worker=False):
    # The tunnel may wait for a remote session before it starts its stdio child.
    # Never require that child before giving the physical owner a chance to
    # reconnect. Final candidate acceptance additionally pins the observed child.
    for unit in m.SERVICES:
        props = m.props(unit)
        m.require(props['ActiveState'] == 'active', 'service inactive')
        pid = int(props['MainPID'])
        wanted = expected if unit == m.SERVICES[0] else m.M['files'][str(m.H / '.local/libexec/relayforge/tunnel-client')]['sha256']
        m.require(pid > 0 and hashlib.sha256(Path(f'/proc/{pid}/exe').read_bytes()).hexdigest() == wanted,
                  'service mapped identity mismatch')
    token = (m.H / '.config/relayforge/http-token').read_text().strip()
    body = json.dumps({'jsonrpc': '2.0', 'id': 77, 'method': 'tools/list'}).encode()
    opener = m.urllib.request.build_opener(m.urllib.request.ProxyHandler({}))
    def post(auth):
        headers = {'Accept': 'application/json, text/event-stream', 'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer ' + auth
        request = m.urllib.request.Request('http://127.0.0.1:8765/mcp', data=body, headers=headers)
        try:
            with opener.open(request, timeout=4) as reply:
                return reply.status, reply.read(65537)
        except m.urllib.error.HTTPError as error:
            return error.code, b''
    m.require(post(None)[0] == 401 and post('invalid-activation-probe')[0] == 401,
              'HTTP authentication rejection failed')
    code, data = post(token)
    value = json.loads(data)
    m.require(code == 200 and len(data) <= 65536 and value.get('id') == 77
              and isinstance(value.get('result', {}).get('tools'), list), 'HTTP health failed')
    output = m.command([str(m.H / '.local/libexec/relayforge/tunnel-client'), 'health', '--url-file',
                        str(Path('/run/user') / str(m.M['uid']) / 'relayforge-tunnel/health.url'),
                        '--require-control-plane-poll', '--json'])
    poll = json.loads(output)
    age = time.time() - poll['control_plane_poll']['value']
    m.require(poll['result'] == 'ok' and 0 <= age <= 30, 'authenticated tunnel poll stale')
    if require_worker:
        m.mapped_check(expected)


def wait_health(sha, timeout=45, require_worker=False):
    end = time.monotonic() + timeout
    while True:
        try:
            local_health(sha, require_worker)
            return
        except Exception:
            if time.monotonic() >= end:
                raise RuntimeError('health deadline') from None
            time.sleep(1)


def rollback(transaction, record, owner_requested=False):
    if transaction.doc['status'] == 'rolled-back' or (transaction.doc['status'] == 'committed' and not owner_requested):
        disarm(transaction)
        return
    baseline = m.STORE / BASE
    if not baseline.exists() and not baseline.is_symlink():
        m.artifact.verify(FROZEN / 'baseline/relayforge-mcp', FROZEN / 'baseline/manifest.json',
                          m.M['commit'], m.M['baseline'])
        stage_directory(baseline, FROZEN / 'baseline',
                        {'relayforge-mcp': 0o500, 'manifest.json': 0o400}, transaction.doc['id'] + '-baseline')
    artifact(BASE, m.M['commit'], m.M['baseline'])
    # Restore exact baseline configurations and root-map before selectors.
    # Independent per-target attempts continue even if another target fails.
    m.systemctl('stop', *m.SERVICES)
    transaction.rollback(force=owner_requested)
    m.systemctl('daemon-reload')
    m.systemctl('restart', *m.SERVICES)
    wait_health(m.M['baseline'])
    configuration()
    transaction.doc['status'] = 'rolled-back'
    transaction.save()
    safe_record(record, 'baseline configurations/selectors/root-map restored; local health PASS; remote health UNVERIFIED')
    disarm(transaction)


def safe_record(record, event):
    try:
        record(event)
    except OSError:
        pass


def activate(record):
    plan = ready()
    prerequisites(True)
    for name in plan['automatically_recoverable_attempts']:
        old = load_attempt(name)
        # ready verified exact pre-install disk state and healthy baseline. No
        # restart or target rewrite is needed to finish an abandoned preparation.
        old.doc['status'] = 'rolled-back'
        old.save()
        disarm(old)
        record('completed abandoned preparation=' + name)
    attempt_dir = ATTEMPTS / uuid.uuid4().hex
    attempt_dir.mkdir(mode=0o700)
    a.sync(ATTEMPTS)
    created = int(time.time())
    root_before = a.state(CONFIG)
    previous_before = a.state(m.STORE / 'previous')
    m.require(previous_before in (None, {'link': BASE}), 'previous selector changed')
    expected = {m.HTTP: a.file_state(unit_bytes('http', 'baseline'), 0o644),
                TUNNEL: a.file_state(unit_bytes('tunnel', 'baseline'), 0o644),
                CONFIG: root_before, m.STORE / 'previous': previous_before,
                m.STORE / 'current': {'link': BASE}}
    transaction = a.Transaction(attempt_dir / 'journal.json', targets(merged_roots(root_before)), True,
        metadata={'id': attempt_dir.name, 'created': created, 'deadline': created + WINDOW,
                  'physical_owner_approved': True}, expected_before=expected)
    try:
        arm(transaction)  # Durable recovery is verified BEFORE any config/selector change.
        record('attempt=' + attempt_dir.name)
        stage_directory(m.STORE / CAND, INPUT, {'relayforge-mcp': 0o500, 'manifest.json': 0o400}, transaction.doc['id'])
        stage_directory(REPORTS, P / 'reports', {'AUTHORIZATION.md': 0o400, 'operation-1792634926759214000.jsonl': 0o400}, transaction.doc['id'])
        for path in targets(merged_roots()):
            transaction.apply(path)
            record('installed target=' + ('selector' if path.parent == m.STORE else 'configuration'))
        m.systemctl('daemon-reload')
        m.systemctl('restart', *m.SERVICES)
        wait_health(SHA)
        candidate_operations()
        record('local candidate health/artifacts PASS; waiting for independent owner-side tunnel verification')
        remote(transaction)
        wait_health(SHA, require_worker=True)
        invariant()
        transaction.commit()  # Durable owner-confirmed acceptance before canceling recovery.
        disarm(transaction)
        record('candidate accepted by physical owner; no mutation grant created')
    except BaseException:
        signal.alarm(120)
        # A failed foreground recovery leaves the persistent timer armed and the
        # journal pending. Its separately launched process retries independently.
        rollback(transaction, lambda event: safe_record(record, event))
        raise


def candidate_operations():
    # Fixed loopback endpoint and operations only; authentication bytes stay local.
    token = (m.H / '.config/relayforge/http-token').read_text().strip()
    opener = m.urllib.request.build_opener(m.urllib.request.ProxyHandler({}))

    def call(operation, path=None):
        args = {'operation': operation}
        if path is not None:
            args['path'] = path
        body = json.dumps({'jsonrpc': '2.0', 'id': 90, 'method': 'tools/call',
                           'params': {'name': 'relayforge_workstation_develop',
                                      'arguments': args}}).encode()
        request = m.urllib.request.Request('http://127.0.0.1:8765/mcp', data=body,
            headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json',
                     'Accept': 'application/json, text/event-stream'})
        with opener.open(request, timeout=4) as reply:
            value = json.loads(reply.read(65537))
        m.require(value.get('id') == 90 and 'error' not in value and 'result' in value,
                  'artifact RPC failed')
        return value['result']

    def payload(result):
        m.require(result.get('isError') is False, 'artifact operation failed')
        return json.loads(''.join(item['text'] for item in result.get('content', []) if item.get('type') == 'text'))

    caps = payload(call('capabilities'))
    m.require(caps.get('api_revision') == 9 and caps.get('artifacts', {}).get('configured') is True
              and caps['artifacts'].get('read_only') is True
              and caps.get('arbitrary_host_shell') is False
              and caps.get('write_grants', {}).get('source_edit') is False, 'artifact capabilities incorrect')
    m.require(all(name in caps.get('operations', []) for name in
                  ['development.prepare', 'development.run', 'development.inspect', 'artifact.read', 'artifact.list']),
              'operations missing')
    for name in ['AUTHORIZATION.md', 'operation-1792634926759214000.jsonl']:
        report = payload(call('artifact.read', 'activation/' + name))
        expected = (P / 'reports' / name).read_bytes()
        m.require(report.get('utf8_text', '').encode() == expected and report.get('byte_length') == len(expected),
                  'approved report mismatch')
    payload(call('artifact.list', 'activation'))
    for path in ['unknown/AUTHORIZATION.md', 'activation/../outside.md', '/etc/passwd',
                 'activation/secret.md', 'activation/escape.md']:
        m.require(call('artifact.read', path).get('isError') is True, 'unauthorized path accepted')


def remote(transaction):
    remaining = transaction.doc['deadline'] - time.time() - 90
    m.require(remaining > 0, 'acceptance deadline reached')
    print('Use the independent authenticated tunnel to verify API9 configured=true, artifact read/list, '
          'approved report contents, path denials, source_edit=false and unchanged operation allowlists. '
          'Automatic baseline recovery remains armed. Seconds available: ' + str(int(remaining)), flush=True)
    phrase = 'TUNNEL VERIFIED ' + transaction.doc['id'][:12]
    m.require(input('Physical owner only: type ' + phrase + ': ') == phrase, 'owner-side acceptance denied')
    m.require(time.time() < transaction.doc['deadline'] - 90, 'owner acceptance expired')


def load_attempt(name):
    m.require(re.fullmatch('[0-9a-f]{32}', name) is not None, 'invalid attempt')
    path = ATTEMPTS / name / 'journal.json'
    a.regular(path)
    doc = json.loads(path.read_text())
    # Dynamic root-map bytes can only be the approved merge of the exact saved
    # owner state. Every other target is fixed by the immutable package pins.
    before = doc['targets'][str(CONFIG)]['before']
    root_map = merged_roots(before)
    transaction = a.Transaction(path, targets(root_map))
    m.require(transaction.doc.get('physical_owner_approved') is True
              and transaction.doc['id'] == name
              and transaction.doc['status'] in ('pending', 'committed', 'rolled-back')
              and isinstance(transaction.doc.get('created'), int)
              and transaction.doc['deadline'] == transaction.doc['created'] + WINDOW,
              'invalid attended recovery journal')
    expected = {str(m.HTTP): a.file_state(unit_bytes('http', 'baseline'), 0o644),
                str(TUNNEL): a.file_state(unit_bytes('tunnel', 'baseline'), 0o644),
                str(m.STORE / 'current'): {'link': BASE}}
    for path, value in expected.items():
        m.require(transaction.doc['targets'][path]['before'] == value, 'baseline snapshot changed')
    m.require(transaction.doc['targets'][str(m.STORE / 'previous')]['before'] in
              (None, {'link': BASE}), 'previous snapshot changed')
    return transaction


@contextlib.contextmanager
def locked(create=False, wait=False, readonly=False):
    a.private_file(LOCK, create, 1024 * 1024)
    fd = os.open(LOCK, (os.O_RDONLY if readonly else os.O_RDWR) | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def main():
    configure()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['check', 'activate', 'rollback', 'recover'])
    parser.add_argument('--physical-terminal', action='store_true')
    parser.add_argument('--owner-approved', action='store_true')
    parser.add_argument('--attempt')
    args = parser.parse_args()
    os.umask(0o077)
    sealed()
    m.require(os.getuid() == m.M['uid'], 'wrong physical owner')
    m.require(not any(c in str(P) for c in '\n\r'), 'unsafe package path')
    if args.operation == 'check':
        if LOCK.exists() or LOCK.is_symlink():
            with locked(readonly=True):
                result = ready()
        else:
            result = ready()
        print(json.dumps(result, sort_keys=True))
        return
    if args.operation != 'recover':
        m.require(args.owner_approved and args.physical_terminal and sys.stdin.isatty()
                  and sys.stdout.isatty(), 'new owner approval and physical terminal required')
        m.require(input('Type PHYSICAL TERMINAL READY: ') == 'PHYSICAL TERMINAL READY', 'attendance required')
    else:
        m.require(args.attempt is not None, 'recovery needs durable attempt')
    def deadline(signum, frame):
        raise TimeoutError('bounded operation deadline')
    signal.signal(signal.SIGALRM, deadline)
    signal.signal(signal.SIGTERM, deadline)
    signal.alarm(WINDOW - 30 if args.operation == 'activate' else 150)
    try:
        # Only the minimal safe private lock bootstrap occurs before locking.
        with locked(create=args.operation == 'activate', wait=args.operation == 'recover'):
            log = P / ('operation-' + str(time.time_ns()) + '.jsonl')
            try:
                stream = log.open('x')
            except OSError:
                if args.operation == 'activate':
                    raise
                stream = None
            with stream if stream is not None else contextlib.nullcontext():
                def record(event):
                    try:
                        if stream is None:
                            return
                        stream.write(json.dumps({'time': time.time(), 'event': event}) + '\n')
                        stream.flush()
                        os.fsync(stream.fileno())
                    except OSError:
                        if args.operation == 'activate':
                            raise
                if args.operation == 'activate':
                    a.sync(P)
                    activate(record)
                else:
                    m.require(args.attempt is not None, 'select an exact attempt for rollback')
                    rollback(load_attempt(args.attempt), record, owner_requested=args.operation == 'rollback')
    finally:
        signal.alarm(0)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('FAIL CLOSED: ' + type(error).__name__, file=sys.stderr)
        sys.exit(1)
