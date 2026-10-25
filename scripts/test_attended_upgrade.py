"""Disposable selector-only upgrades; real journals and attended recovery units."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

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
        b.m = SimpleNamespace(STORE=self.store, M={'commit': self.base[0], 'baseline': self.base[1]},
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
        self.engine.preserved = invariant

    def activate(self):
        return self.engine.activate(lambda auth: True)

    def attempt(self):
        return next(self.attempts.iterdir()).name

    def test_preservation_inventory_blocks_configuration_and_legacy_guard_changes(self):
        self.b.m.H = self.root
        self.b.m.M['units'] = []
        self.b.m.props = lambda unit: {'ExecStart': '/usr/bin/false'}
        for path in [self.root / '.config', self.root / '.config/relayforge',
                     self.root / '.config/tunnel-client',
                     self.units / 'relayforge-local-recover.service.d']:
            path.mkdir(mode=0o700)
        guard = self.units / 'relayforge-local-recover.service.d/issue77-maintenance.conf'
        guard.write_bytes(b'[Service]\nExecStart=\nExecStart=/usr/bin/false\n')
        guard.chmod(0o600)
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
        self.engine.preserved = lambda: u.Upgrade.preserved(self.engine)
        self.engine.check()
        self.activate()
        # The snapshot still matches after scheduler objects were retired.
        self.engine.invariant()
        guard.write_bytes(b'changed guard')
        with self.assertRaises(RuntimeError):
            self.engine.invariant()

    def test_readonly_preflight_missing_receipt_and_stale_evidence(self):
        before = sorted(str(p) for p in self.root.rglob('*'))
        self.assertEqual(self.engine.check()['actions_performed'], [])
        self.assertEqual(before, sorted(str(p) for p in self.root.rglob('*')))
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

    def test_recovery_armed_before_selector_and_failed_arm_does_not_mutate(self):
        def arm(t):
            self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})
            raise RuntimeError('timer failed')
        with patch.object(self.b, 'arm', arm), self.assertRaises(RuntimeError):
            self.activate()
        self.assertEqual(a.state(self.store / 'current'), {'link': self.base_link})

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
