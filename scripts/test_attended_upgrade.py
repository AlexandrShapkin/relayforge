"""Disposable selector-only upgrades; real journals and attended recovery units."""
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

DEPLOY = Path(__file__).resolve().parents[1] / 'deploy'

def module(name):
    spec = importlib.util.spec_from_file_location(name, DEPLOY / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result

u = module('attended_upgrade')
a = module('activation_transaction')
r = module('runtime_artifact')


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(lambda: signal.alarm(0))
        self.root = Path(self.tmp.name)
        self.store = self.root / 'runtime'
        self.store.mkdir(mode=0o700)
        (self.store / 'artifacts').mkdir(mode=0o700)
        pins = []
        for value in (b'baseline', b'candidate'):
            commit, sha = hashlib.sha1(value).hexdigest(), hashlib.sha256(value).hexdigest()
            pins.append((commit, sha))
            directory = self.store / 'artifacts' / (commit + '-' + sha)
            directory.mkdir(mode=0o700)
            binary = directory / 'relayforge-mcp'
            binary.write_bytes(value)
            binary.chmod(0o500)
            manifest = directory / 'manifest.json'
            manifest.write_text(json.dumps(dict(schema_version=1, commit=commit, sha256=sha, binary='relayforge-mcp')))
            manifest.chmod(0o400)
        self.base, self.cand = pins
        for name, value in [('BASELINE', self.base), ('CANDIDATE', self.cand)]:
            p = patch.object(u, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.base_link, self.cand_link = ['artifacts/' + '-'.join(p) for p in pins]
        (self.store / 'current').symlink_to(self.base_link)
        (self.store / 'previous').symlink_to('historical-untouched')
        self.attempts = self.root / 'attempts'
        self.attempts.mkdir(mode=0o700)
        self.units = self.root / 'units'
        self.units.mkdir(mode=0o700)
        (self.units / 'timers.target.wants').mkdir(mode=0o700)
        self.protected = self.root / 'protected'
        self.protected.write_bytes(b'ExecStart=/usr/bin/false\nroots grants credentials fixture\n')
        self.events = []
        self.fail_restart = False
        self.fail_health = False
        self.armed = False
        def systemctl(*args):
            self.events.append(args)
            if args[0] == 'restart' and self.fail_restart:
                raise RuntimeError('restart failed')
            if args[:2] == ('enable', '--now'):
                (self.units / 'timers.target.wants' / args[2]).symlink_to(self.units / args[2])
                self.armed = True
            if args[0] == 'stop':
                self.armed = False
            return 'active\n' if args[0] == 'is-active' else ''
        def invariant():
            self.assertEqual(self.protected.read_bytes(), b'ExecStart=/usr/bin/false\nroots grants credentials fixture\n')
        def health(*args, **kwargs):
            if self.fail_health:
                raise TimeoutError('health deadline')
            self.events.append(('health', args[0], kwargs.get('require_worker')))
        b = module('attended_activation')
        b.P = self.root
        b.UNITS = self.units
        b.ATTEMPTS = self.attempts
        b.COMMIT, b.SHA = self.cand
        b.BASE, b.CAND = self.base_link, self.cand_link
        b.m = SimpleNamespace(STORE=self.store, M={'commit': self.base[0], 'baseline': self.base[1], 'files': {}},
                              artifact=r, systemctl=systemctl, require=u.require, command=lambda args: 'yes\n', SERVICES=['http', 'tunnel'])
        b.sealed = lambda: None
        b.invariant = invariant
        b.artifact = lambda target, *pins: r.verify(self.store / target / 'relayforge-mcp', self.store / target / 'manifest.json', *pins)
        b.local_health = b.wait_health = health
        b.remote = lambda t: self.events.append(('remote', t.doc['id']))
        self.b = b
        self.receipt = self.root / 'rollback.json'
        self.receipt.write_text(json.dumps(dict(commit=self.base[0], sha256=self.base[1], restricted_worker_ok=True, live_health_ok=True)))
        self.proof = self.root / 'proof.json'
        self.proof.write_text(json.dumps(dict(artifact_id=u.ARTIFACT, candidate=list(self.cand), baseline=list(self.base), observed=int(time.time()), expires=int(time.time()) + 3600, independent_review=True, recovery_test=True)))
        self.engine = u.Upgrade(b, self.receipt, self.proof)
        self.engine.preserved = lambda recovery=False: invariant()

    def activate(self):
        return self.engine.activate(lambda auth: True)

    def attempt(self):
        return next(self.attempts.iterdir()).name

    def setup_real_preservation(self):
        self.b.m.H = self.root
        self.b.m.M['units'] = []
        self.b.m.props = lambda unit: {'NeedDaemonReload': 'no',
            'FragmentPath': str(self.units / unit),
            'DropInPaths': str(self.units /
                'relayforge-local-recover.service.d/issue77-maintenance.conf')
                if unit == 'relayforge-local-recover.service' else '',
            'ExecStart': '/usr/bin/false'}
        for path in [self.root / '.config', self.root / '.config/relayforge',
                     self.root / '.config/tunnel-client',
                     self.units / 'relayforge-local-recover.service.d']:
            path.mkdir(mode=0o700)
        guard = self.units / 'relayforge-local-recover.service.d/issue77-maintenance.conf'
        guard.write_bytes(b'[Service]\\nExecStart=\\nExecStart=/usr/bin/false\\n')
        guard.chmod(0o600)
        return guard

    def seal_inventory(self):
        roots = [self.root / '.config/relayforge', self.root / '.config/tunnel-client',
                 self.units, self.store / 'artifacts']
        objects = {}
        for root in roots:
            for path in [root, *root.rglob('*')]:
                if path.is_dir():
                    objects[str(path)] = {'directory': path.stat().st_mode & 0o777}
                elif path.is_symlink():
                    objects[str(path)] = {'link': os.readlink(path)}
                else:
                    objects[str(path)] = {'mode': path.stat().st_mode & 0o777,
                                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
        snapshot = self.root / 'upgrade-preserved.json'
        snapshot.write_text(json.dumps({'roots': [str(p) for p in roots], 'objects': objects}))
        snapshot.chmod(0o600)
        self.engine.preserved = lambda recovery=False: u.Upgrade.preserved(
            self.engine, recovery=recovery)

    def test_preservation_inventory_blocks_configuration_and_legacy_guard_changes(self):
        guard = self.setup_real_preservation()
        self.seal_inventory()
        self.engine.check()
        self.activate()
        self.engine.invariant()
        guard.write_bytes(b'changed guard')
        with self.assertRaises(RuntimeError):
            self.engine.invariant()

    def test_candidate_missing_after_selection_does_not_block_recovery(self):
        self.setup_real_preservation()
        self.seal_inventory()
        self.engine.check()
        damaged = self.store / self.cand_link / 'relayforge-mcp'
        self.assertTrue(damaged.exists())
        def corrupt_after_selector(_transaction):
            self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})
            damaged.unlink()
            raise RuntimeError('candidate disappeared')
        self.b.remote = corrupt_after_selector
        with self.assertRaisesRegex(RuntimeError, 'candidate disappeared'):
            self.activate()
        attempt = self.attempt()
        self.assertEqual(self.engine.load(attempt).doc['status'], 'rolled-back')
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
        self.assertTrue((self.store / self.base_link / 'relayforge-mcp').exists())
        self.assertFalse(damaged.exists(), 'damaged candidate preserved as evidence')
        self.assertFalse(self.armed)
        self.engine.invariant(recovery=True)
        with self.assertRaises(Exception):
            self.engine.invariant()

    def test_scheduled_recovery_after_sigkill_ignores_missing_candidate(self):
        self.setup_real_preservation()
        self.seal_inventory()
        pid = os.fork()
        if pid == 0:
            def crash_after_selection(_):
                (self.store / self.cand_link / 'relayforge-mcp').unlink()
                os.kill(os.getpid(), signal.SIGKILL)
            self.b.remote = crash_after_selection
            self.activate()
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
        attempt = self.attempt()
        self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})
        with patch.object(u.time, 'time', return_value=time.time() + u.WINDOW + 1):
            self.engine.recover(attempt)
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
        self.assertEqual(self.engine.load(attempt).doc['status'], 'rolled-back')
        self.assertFalse((self.store / self.cand_link / 'relayforge-mcp').exists())

    def test_candidate_inventory_drift_after_arming_rejects_commit_but_rollback_succeeds(self):
        self.setup_real_preservation()
        self.seal_inventory()
        self.engine.check()
        extra = self.store / self.cand_link / 'unsealed-report.txt'
        def drift_during_confirmation(_transaction):
            self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})
            self.assertTrue(self.armed)
            extra.write_text('not in sealed inventory')
            # Remote confirmation would otherwise succeed.
        self.b.remote = drift_during_confirmation
        with self.assertRaisesRegex(RuntimeError, 'installed inventory changed'):
            self.activate()
        attempt = self.attempt()
        self.assertEqual(self.engine.load(attempt).doc['status'], 'rolled-back')
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
        self.assertTrue(extra.exists(), 'candidate drift retained as evidence')
        self.assertFalse(self.armed)
        self.engine.invariant(recovery=True)
        with self.assertRaisesRegex(RuntimeError, 'installed inventory changed'):
            self.engine.invariant()

    def test_completed_attempt_does_not_disable_candidate_preflight_inventory(self):
        self.setup_real_preservation()
        self.seal_inventory()
        self.b.remote = lambda _: (_ for _ in ()).throw(RuntimeError('reject candidate'))
        with self.assertRaisesRegex(RuntimeError, 'reject candidate'):
            self.activate()
        self.assertEqual(self.engine.load(self.attempt()).doc['status'], 'rolled-back')
        extra = self.store / self.cand_link / 'unexpected-link'
        target = self.root / 'unsealed-target'
        target.write_text('external')
        extra.symlink_to(target)
        # A retained journal must not silently switch later read-only checks
        # into recovery mode.
        with self.assertRaisesRegex(RuntimeError, 'unapproved preservation symlink'):
            self.engine.check()
        self.engine.invariant(recovery=True)

    def test_sealed_external_configuration_symlink_is_rejected(self):
        self.setup_real_preservation()
        outside = self.root / 'external-grant.json'
        outside.write_text('{"read_only":true}')
        grant = self.root / '.config/relayforge/artifact-roots.json'
        grant.symlink_to(outside)
        self.seal_inventory()
        with self.assertRaisesRegex(RuntimeError, 'unapproved preservation symlink'):
            self.engine.check()
        outside.write_text('{"read_only":false}')
        with self.assertRaisesRegex(RuntimeError, 'unapproved preservation symlink'):
            self.engine.check()

    def test_sealed_systemd_enablement_symlink_is_narrow_and_target_hashed(self):
        self.setup_real_preservation()
        unit = self.units / 'relayforge-tunnel.service'
        unit.write_text('[Unit]\\nDescription=Test\\n')
        unit.chmod(0o600)
        wants = self.units / 'default.target.wants'
        wants.mkdir(mode=0o700)
        link = wants / unit.name
        link.symlink_to('../' + unit.name)
        self.seal_inventory()
        self.engine.check()
        unit.write_text('[Unit]\\nDescription=Modified\\n')
        with self.assertRaisesRegex(RuntimeError, 'installed inventory changed'):
            self.engine.check()
        unit.write_text('[Unit]\\nDescription=Test\\n')
        link.unlink()
        outside = self.root / 'outside-unit.service'
        outside.write_text('[Unit]\\nDescription=External\\n')
        link.symlink_to(outside)
        self.seal_inventory()
        with self.assertRaisesRegex(RuntimeError, 'systemd enablement link escapes inventory'):
            self.engine.check()

    def test_readonly_preflight_missing_receipt_and_stale_evidence(self):
        before = sorted(str(p) for p in self.root.rglob('*'))
        self.assertEqual(self.engine.check()['actions_performed'], [])
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob('*')))
        document = json.loads(self.proof.read_text())
        document['observed'] -= 7200
        self.proof.write_text(json.dumps(document))
        with self.assertRaises(RuntimeError):
            self.engine.check()
        self.receipt.unlink()
        with self.assertRaises(Exception):
            self.engine.check()
        self.assertFalse(list(self.attempts.iterdir()))

    def test_success_preserves_previous_and_guard_and_durably_commits(self):
        attempt = self.activate()
        self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})
        self.assertEqual(a.state(self.store / 'previous'), {'link': 'historical-untouched'})
        self.assertEqual(self.engine.load(attempt).doc['status'], 'committed')
        self.assertFalse(self.armed)
        self.engine.recover(attempt)
        self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})

    def test_owner_denial_and_stale_selector_after_approval(self):
        with self.assertRaises(RuntimeError):
            self.engine.activate(lambda auth: False)
        def approve(auth):
            (self.store / 'current').unlink()
            (self.store / 'current').symlink_to('unexpected')
            return True
        with self.assertRaises(RuntimeError):
            self.engine.activate(approve)
        self.assertFalse(list(self.attempts.iterdir()))

    def test_approval_expiration_blocks_journal_creation(self):
        now = time.time()
        def approve(auth):
            clock.return_value = now + 61
            return True
        with patch.object(u.time, 'time', return_value=now) as clock:
            with self.assertRaises(RuntimeError):
                self.engine.activate(approve)
        self.assertFalse(list(self.attempts.iterdir()))

    def test_recovery_armed_before_selector_and_failed_arm_does_not_mutate(self):
        def arm(t):
            self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
            raise RuntimeError('timer failed')
        with patch.object(self.b, 'arm', arm), self.assertRaises(RuntimeError):
            self.activate()
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
        self.assertFalse(any(event[0] == 'restart' for event in self.events))

    def test_timeout_rolls_back_and_failed_restart_retains_recovery(self):
        self.b.remote = lambda t: (_ for _ in ()).throw(TimeoutError())
        with self.assertRaises(TimeoutError):
            self.activate()
        self.assertEqual(self.engine.load(self.attempt()).doc['status'], 'rolled-back')
        # New attempt, failed candidate AND rollback restart: durable retry state.
        self.fail_restart = True
        with self.assertRaises(RuntimeError):
            self.activate()
        pending = [p.name for p in self.attempts.iterdir() if self.engine.load(p.name).doc['status'] == 'rolling-back'][0]
        self.assertTrue(self.armed)
        self.fail_restart = False
        self.engine.recover(pending, early=True)
        self.assertEqual(self.engine.load(pending).doc['status'], 'rolled-back')

    def test_commit_failure_recovers_but_disarm_failure_never_undoes_commit(self):
        with patch.object(self.b.a.Transaction, 'commit', side_effect=OSError('disk')), self.assertRaises(OSError):
            self.activate()
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
        with patch.object(self.b, 'disarm', side_effect=OSError('manager')), self.assertRaises(OSError):
            self.activate()
        committed = [p.name for p in self.attempts.iterdir() if self.engine.load(p.name).doc['status'] == 'committed'][0]
        self.engine.recover(committed)
        self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})

    def test_foreign_selector_blocks_pending_recovery_without_restart(self):
        attempt = 'f' * 32
        directory = self.attempts / attempt
        directory.mkdir(mode=0o700)
        now = int(time.time())
        transaction = self.b.a.Transaction(directory / 'journal.json', self.engine.targets(), True,
            metadata={'id': attempt, 'created': now, 'deadline': now + u.WINDOW,
                      'physical_owner_approved': True})
        self.b.arm(transaction)
        transaction.apply(self.store / 'current')
        (self.store / 'current').unlink()
        (self.store / 'current').symlink_to('foreign')
        with self.assertRaises(RuntimeError):
            self.engine.recover(attempt, early=True)
        self.assertEqual(os.readlink(self.store / 'current'), 'foreign')
        self.assertTrue(self.armed)
        self.assertFalse(any(event[0] == 'restart' for event in self.events))

    def test_package_entrypoint_requires_terminal_and_readonly_check_lock(self):
        self.b.m.M['uid'] = os.getuid()
        locks = []
        @contextlib.contextmanager
        def locked(**kwargs):
            locks.append(kwargs)
            yield
        self.b.locked = locked
        with patch.object(sys, 'argv', ['transition.py', 'activate']), \
                patch.object(sys.stdin, 'isatty', return_value=False):
            with self.assertRaises(RuntimeError):
                u.run(self.b, self.receipt, self.proof)
        self.assertFalse(list(self.attempts.iterdir()))
        # Check dispatch uses the shared lock without bootstrapping files.
        with patch.object(sys, 'argv', ['transition.py', 'check']), \
                patch.object(u.Upgrade, 'check', return_value={'actions_performed': []}):
            u.run(self.b, self.receipt, self.proof)
        self.assertEqual(locks[-1], {'readonly': True, 'wait': False})

    def test_all_package_operations_dispatch_to_shared_upgrade_engine(self):
        # R3 wrapper intent, exercised through the tracked entrypoint. Every
        # operation is mocked: no scheduler, terminal prompt or host access.
        self.b.m.M['uid'] = os.getuid()
        attempt = 'a' * 32
        for operation in ('check', 'activate', 'recover'):
            with self.subTest(operation=operation):
                engine = Mock()
                argv = ['transition.py', operation]
                if operation == 'recover':
                    argv += ['--attempt', attempt]
                with patch.object(sys, 'argv', argv), \
                        patch.object(sys.stdin, 'isatty', return_value=True), \
                        patch.object(sys.stdout, 'isatty', return_value=True), \
                        patch.object(self.b, 'locked', return_value=contextlib.nullcontext()) as locked, \
                        patch.object(u.signal, 'signal'), patch.object(u.signal, 'alarm'), \
                        patch.object(u, 'Upgrade', return_value=engine) as constructor:
                    u.run(self.b, self.receipt, self.proof)
                constructor.assert_called_once_with(self.b, self.receipt, self.proof)
                locked.assert_called_once_with(readonly=operation == 'check',
                                               wait=operation == 'recover')
                self.assertEqual([call[0] for call in engine.method_calls], [operation])
                if operation == 'recover':
                    engine.recover.assert_called_once_with(attempt)

    def test_package_integrity_failure_prevents_engine_dispatch(self):
        self.b.m.M['uid'] = os.getuid()
        for operation in ('check', 'activate', 'recover'):
            with self.subTest(operation=operation), \
                    patch.object(sys, 'argv', ['transition.py', operation]), \
                    patch.object(self.b, 'sealed', side_effect=RuntimeError('tampered')), \
                    patch.object(self.b, 'locked') as locked, \
                    patch.object(u, 'Upgrade') as constructor:
                with self.assertRaisesRegex(RuntimeError, 'tampered'):
                    u.run(self.b, self.receipt, self.proof)
                locked.assert_not_called()
                constructor.assert_not_called()

    def test_sigkill_after_selector_independent_recovery_and_stale_state(self):
        pid = os.fork()
        if pid == 0:
            self.b.remote = lambda t: os.kill(os.getpid(), signal.SIGKILL)
            self.activate()
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), -signal.SIGKILL)
        attempt = self.attempt()
        self.assertEqual(a.state(self.store / 'current'), {'link': self.cand_link})
        with self.assertRaises(RuntimeError):
            self.engine.recover(attempt)
        with patch.object(u.time, 'time', return_value=time.time() + u.WINDOW + 1):
            self.engine.recover(attempt)
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
        # A foreign selector must never be overwritten even by recovery.
        (self.store / 'current').unlink()
        (self.store / 'current').symlink_to('foreign')
        with self.assertRaises(RuntimeError):
            self.activate()


if __name__ == '__main__':
    unittest.main()
