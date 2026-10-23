#!/usr/bin/env python3
"""Whole activation flow on real disposable files; only services/remote IO mocked."""
import contextlib
import hashlib
import importlib.util
import json
import os
import shutil
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / 'deploy/attended_activation.py'
if Path(__file__).with_name('transition.py').exists():
    SOURCE = Path(__file__).with_name('transition.py')
spec = importlib.util.spec_from_file_location('attended', SOURCE)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
REAL_REMOTE = t.remote


class AttendedActivationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.package = self.root / 'package'
        self.package.mkdir(mode=0o700)
        self.home = self.root / 'home'
        self.home.mkdir(mode=0o700)
        (self.home / 'Projects/relayforge/.git').mkdir(parents=True)
        self.store = self.home / 'runtime'
        (self.store / 'artifacts').mkdir(parents=True, mode=0o700)
        self.store.chmod(0o700)
        self.units = self.home / '.config/systemd/user'
        self.units.mkdir(parents=True, mode=0o700)
        self.config = self.home / '.config/relayforge/artifact-roots.json'
        self.config.parent.mkdir(mode=0o700)
        self.grant = self.config.parent / 'allow-workstation-development'
        self.grant.write_bytes(b'original grant bytes\n')
        self.grant.chmod(0o600)
        self.events, self.commands = [], []
        baseline, candidate = b'baseline binary fixture', b'candidate binary fixture'
        self.base_sha = hashlib.sha256(baseline).hexdigest()
        self.sha = hashlib.sha256(candidate).hexdigest()
        base = 'artifacts/' + 'b' * 40 + '-' + self.base_sha
        cand = 'artifacts/' + 'c' * 40 + '-' + self.sha
        for path, data, commit in [(self.store / base, baseline, 'b' * 40),
                                   (self.package / 'candidate', candidate, 'c' * 40)]:
            path.mkdir(mode=0o700)
            (path / 'relayforge-mcp').write_bytes(data)
            (path / 'relayforge-mcp').chmod(0o500)
            (path / 'manifest.json').write_text(json.dumps({'commit': commit, 'sha256': hashlib.sha256(data).hexdigest()}))
            (path / 'manifest.json').chmod(0o400)
        shutil.copytree(self.store / base, self.package / 'frozen/baseline')
        (self.store / 'current').symlink_to(base)
        for kind, name in [('http', 'relayforge-mcp-http.service'), ('tunnel', 'relayforge-tunnel.service')]:
            d = self.package / (kind + '-configuration')
            d.mkdir(mode=0o700)
            (d / 'baseline.service').write_bytes((kind + ' exact baseline\n\n').encode())
            (d / 'candidate.service').write_bytes((kind + ' candidate\n').encode())
            (d / 'pins.json').write_text(json.dumps({p.name: {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'mode': 0o644} for p in d.glob('*.service')}))
            path = self.units / name
            path.write_bytes((d / 'baseline.service').read_bytes())
            path.chmod(0o644)
        reports = self.package / 'reports'
        reports.mkdir(mode=0o700)
        for name in ['AUTHORIZATION.md', 'operation-1792634926759214000.jsonl']:
            (reports / name).write_bytes(b'approved report fixture\n')
        def verify(binary, manifest, commit, sha):
            self.assertEqual(hashlib.sha256(binary.read_bytes()).hexdigest(), sha)
            self.assertEqual(json.loads(manifest.read_text()), {'commit': commit, 'sha256': sha})
        def require(ok, reason):
            if not ok:
                raise RuntimeError(reason)
        def command(args):
            self.commands.append(tuple(args))
            return 'yes\n' if args[0] == 'loginctl' else ''
        def systemctl(*args):
            self.commands.append(args)
            if args[:2] == ('enable', '--now'):
                timer = args[2]
                (self.units / 'timers.target.wants' / timer).symlink_to(self.units / timer)
            return 'active\n' if args[0] == 'is-active' else ''
        def atomic(path, data, mode):
            temp = path.with_name(path.name + '.atomic')
            t.a.write(path, t.a.file_state(data, mode), temp)
        fake = SimpleNamespace(H=self.home, STORE=self.store, HTTP=self.units / 'relayforge-mcp-http.service',
            SERVICES=['relayforge-mcp-http.service', 'relayforge-tunnel.service'],
            M={'commit': 'b' * 40, 'baseline': self.base_sha,
               'configs': {str(self.grant): {'sha256': hashlib.sha256(self.grant.read_bytes()).hexdigest(), 'mode': 0o600}}},
            artifact=SimpleNamespace(verify=verify), require=require, command=command,
            systemctl=systemctl, atomic_file=atomic, digest=lambda p: hashlib.sha256(p.read_bytes()).hexdigest(),
            health=lambda sha: self.events.append(('health', sha)), safe=lambda p: t.a.ancestors(p if p.is_dir() else p.parent))
        values = dict(m=fake, P=self.package, FROZEN=self.package / 'frozen', COMMIT='c' * 40, SHA=self.sha, BASE=base, CAND=cand,
            INPUT=self.package / 'candidate', CONFIG=self.config, UNITS=self.units,
            TUNNEL=self.units / 'relayforge-tunnel.service', ATTEMPTS=self.package / 'attempts',
            REPORTS=self.home / '.local/state/relayforge/artifacts/fixture',
            AUDIT=self.home / '.local/state/relayforge/workstation-dev-audit.jsonl',
            LOCK=self.home / '.local/state/relayforge/development.lock',
            invariant=lambda: None, local_health=lambda sha, require_worker=False: self.events.append(('health', sha, require_worker)), candidate_operations=lambda: self.events.append('artifact-check'),
            remote=lambda transaction: self.events.append('owner-confirmed'))
        for key, value in values.items():
            p = patch.object(t, key, value, create=True)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(t.signal, 'alarm', return_value=0)
        p.start()
        self.addCleanup(p.stop)
        self.before = {p: t.a.state(p) for p in [fake.HTTP, t.TUNNEL, self.config, self.store / 'previous', self.store / 'current']}

    def transaction(self):
        path = next(t.ATTEMPTS.glob('*/journal.json'))
        return t.load_attempt(path.parent.name)

    def assert_baseline(self):
        for path, original in self.before.items():
            self.assertEqual(t.a.state(path), original, str(path))
        self.assertEqual(self.grant.read_bytes(), b'original grant bytes\n')

    def test_check_is_readonly_and_lists_clean_install_creations(self):
        result = t.ready()
        self.assertEqual(result['actions_performed'], [])
        self.assertIn(str(t.AUDIT), result['automatically_creatable'])
        self.assertIn(str(t.LOCK), result['automatically_creatable'])
        self.assertFalse(t.AUDIT.parent.exists())
        self.assertFalse(t.ATTEMPTS.exists())
        self.assert_baseline()

    def test_clean_install_preserves_baseline_and_requires_confirmation(self):
        t.activate(self.events.append)
        self.assertEqual(self.transaction().doc['status'], 'committed')
        self.assertEqual(os.readlink(self.store / 'current'), t.CAND)
        self.assertEqual(json.loads(self.config.read_text()), {'roots': {'activation': str(t.REPORTS)}})
        self.assertEqual(t.AUDIT.stat().st_mode & 0o777, 0o600)
        self.assertLess(self.events.index('artifact-check'), self.events.index('owner-confirmed'))
        self.assertLess(self.events.index(('health', self.sha, False)), self.events.index('owner-confirmed'))
        self.assertGreater(self.events.index(('health', self.sha, True)), self.events.index('owner-confirmed'))
        self.assertIn('Restart=on-failure', t.recovery_templates('a' * 32, int(t.time.time()) + 1200)['relayforge-activation-' + 'a' * 32 + '.service'].decode())
        self.assertEqual(self.grant.read_bytes(), b'original grant bytes\n')
        self.assertEqual(set(self.units.iterdir()), {t.m.HTTP, t.TUNNEL, self.units / 'timers.target.wants'})

    def test_existing_map_audit_and_unrelated_files_survive_rejected_acceptance(self):
        t.prerequisites(True)
        original = b'{ "roots": { "other": "' + str(self.home / '.local/state/relayforge/artifacts/other').encode() + b'" } }\n'
        self.config.write_bytes(original)
        self.config.chmod(0o600)
        self.before[self.config] = t.a.state(self.config)
        t.AUDIT.write_bytes(b'old audit, do not truncate\n')
        unrelated = t.AUDIT.parent / 'unrelated'
        unrelated.write_bytes(b'keep exactly')
        with patch.object(t, 'remote', side_effect=EOFError):
            with self.assertRaises(EOFError):
                t.activate(self.events.append)
        self.assert_baseline()
        self.assertEqual(t.AUDIT.read_bytes(), b'old audit, do not truncate\n')
        self.assertEqual(unrelated.read_bytes(), b'keep exactly')
        self.assertEqual(self.transaction().doc['status'], 'rolled-back')

    def test_crash_or_failure_between_each_configuration_and_selector(self):
        # Each subcase gets its own complete filesystem fixture, avoiding replay
        # assumptions or mutation of retained historical receipts.
        for stop in range(1, 6):
            with self.subTest(stop=stop):
                case = AttendedActivationTests()
                case.setUp()
                try:
                    original = t.a.Transaction.apply
                    count = 0
                    def interrupted(transaction, path):
                        nonlocal count
                        original(transaction, path)
                        count += 1
                        if count == stop:
                            raise OSError('simulated post-rename interruption')
                    with patch.object(t.a.Transaction, 'apply', interrupted):
                        with self.assertRaises(OSError):
                            t.activate(case.events.append)
                    case.assert_baseline()
                    case.assertEqual(case.transaction().doc['status'], 'rolled-back')
                finally:
                    case.doCleanups()

    def test_durable_recovery_after_sigkill_ignores_broken_receipts(self):
        # Arm and install without foreground compensation, then reopen the
        # durable journal as the independent user recovery service would.
        t.prerequisites(True)
        root = t.ATTEMPTS / ('a' * 32)
        root.mkdir(mode=0o700)
        tx = t.a.Transaction(root / 'journal.json', t.targets(t.merged_roots()), True)
        tx.doc.update(id=root.name, created=int(t.time.time()), physical_owner_approved=True)
        tx.doc['deadline'] = tx.doc['created'] + 1200
        tx.save()
        t.arm(tx)
        for path in [t.m.HTTP, t.TUNNEL, t.CONFIG, self.store / 'previous', self.store / 'current']:
            tx.apply(path)
        tx = t.load_attempt(root.name)
        t.rollback(tx, lambda event: (_ for _ in ()).throw(OSError('receipt disk unavailable')))
        self.assert_baseline()
        t.rollback(t.load_attempt(root.name), lambda event: None)
        self.assert_baseline()

    def test_preflight_known_blockers_fail_before_any_change(self):
        t.prerequisites(True)
        t.AUDIT.chmod(0o644)
        with self.assertRaises(RuntimeError):
            t.ready()
        self.assert_baseline()
        t.AUDIT.chmod(0o600)
        with patch.object(t.m, 'command', return_value='no\n'):
            with self.assertRaisesRegex(RuntimeError, 'lingering'):
                t.ready()
        self.assert_baseline()
        with patch.object(t.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
            with self.assertRaisesRegex(RuntimeError, 'space'):
                t.ready()
        self.assert_baseline()

    def test_abandoned_preparation_is_automatically_finished(self):
        t.prerequisites(True)
        root = t.ATTEMPTS / ('d' * 32)
        root.mkdir(mode=0o700)
        tx = t.a.Transaction(root / 'journal.json', t.targets(t.merged_roots()), True)
        tx.doc.update(id=root.name, created=int(t.time.time()), physical_owner_approved=True)
        tx.doc['deadline'] = tx.doc['created'] + t.WINDOW
        tx.save()
        self.assertEqual(t.ready()['automatically_recoverable_attempts'], [root.name])
        t.activate(self.events.append)
        self.assertEqual(t.load_attempt(root.name).doc['status'], 'rolled-back')

    def test_accepted_attempt_only_rolls_back_on_new_owner_request(self):
        t.activate(self.events.append)
        tx = self.transaction()
        t.rollback(tx, self.events.append)
        self.assertEqual(os.readlink(self.store / 'current'), t.CAND)
        t.rollback(tx, self.events.append, owner_requested=True)
        self.assert_baseline()

    def test_retry_preserves_staged_candidate_and_reports(self):
        with patch.object(t, 'remote', side_effect=EOFError):
            with self.assertRaises(EOFError):
                t.activate(self.events.append)
        files = list((t.m.STORE / t.CAND).iterdir()) + list(t.REPORTS.iterdir())
        before = [(p.read_bytes(), p.stat().st_ino, p.stat().st_mode) for p in files]
        t.activate(self.events.append)
        self.assertEqual([(p.read_bytes(), p.stat().st_ino, p.stat().st_mode) for p in files], before)

    def test_service_failures_leave_durable_exact_recovery(self):
        for failure in ['enable', 'reload', 'restart', 'health']:
            with self.subTest(failure=failure):
                case = AttendedActivationTests()
                case.setUp()
                try:
                    original = t.m.systemctl
                    reloads = 0
                    failed = False
                    def service(*args):
                        nonlocal reloads, failed
                        if args[0] == 'daemon-reload':
                            reloads += 1
                        if not failed and ((failure == 'enable' and args[0] == 'enable')
                                or (failure == 'reload' and reloads == 2 and args[0] == 'daemon-reload')
                                or (failure == 'restart' and args[0] == 'restart')):
                            failed = True
                            raise OSError('injected service failure')
                        return original(*args)
                    health = lambda sha: (_ for _ in ()).throw(TimeoutError()) if sha == t.SHA else None
                    with patch.object(t.m, 'systemctl', service), contextlib.ExitStack() as stack:
                        if failure == 'health':
                            stack.enter_context(patch.object(t, 'wait_health', side_effect=health))
                        with self.assertRaises((OSError, TimeoutError)):
                            t.activate(case.events.append)
                    case.assert_baseline()
                finally:
                    case.doCleanups()

    def test_existing_lock_content_is_preserved_and_busy_is_a_blocker(self):
        t.prerequisites(True)
        t.LOCK.write_bytes(b'preserve lock content')
        with t.locked():
            with self.assertRaises(BlockingIOError):
                with t.locked(readonly=True):
                    self.fail('busy lock accepted')
        self.assertEqual(t.LOCK.read_bytes(), b'preserve lock content')

    def test_owner_confirmation_has_full_window_and_is_genuine(self):
        tx = SimpleNamespace(doc={'deadline': int(t.time.time()) + 1200, 'id': 'a' * 32})
        self.assertEqual(t.WINDOW, 1200)
        with patch('builtins.input', return_value='TUNNEL VERIFIED ' + 'a' * 12):
            REAL_REMOTE(tx)
        with patch('builtins.input', return_value='TUNNEL VERIFIED'):
            with self.assertRaises(RuntimeError):
                REAL_REMOTE(tx)


if __name__ == '__main__':
    unittest.main()
