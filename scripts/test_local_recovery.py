#!/usr/bin/env python3
"""Offline isolated tests for the opt-in local recovery guard."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "deploy/relayforge-local-recover.py"
loader = importlib.machinery.SourceFileLoader("rf_recovery", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

FAKE = """#!/bin/sh
cat >/dev/null
printf '%s\\n' '{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"relayforge_workstation_develop"}]}}'
"""


def write(path, data, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(mode)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        self.guard = mod.Recovery(self.home)
        self.guard.state.mkdir(parents=True)
        self.guard.state.chmod(0o700)
        self.guard.binary.parent.mkdir(parents=True)
        write(self.guard.lock, "", 0o600)
        write(self.guard.grant, mod.GRANT, 0o600)
        write(self.guard.runtime_key, b"only-test-placeholder", 0o600)
        write(self.guard.baseline, FAKE, 0o700)
        # No live systemd mutation in tests.
        self.guard.unit_state = lambda: "active"

    def test_healthy_release_is_left_untouched(self):
        write(self.guard.binary, FAKE, 0o700)
        before = self.guard.binary.read_bytes()
        self.assertEqual(self.guard.repair(), {
            "worker_valid": True, "restored": False, "service": "untouched",
        })
        self.assertEqual(self.guard.binary.read_bytes(), before)
        self.assertFalse(self.guard.audit.exists())

    def test_bad_release_recovers_from_fixed_known_good(self):
        write(self.guard.binary, "#!/bin/sh\nexit 7\n", 0o700)
        self.assertFalse(self.guard.probe(self.guard.binary))
        result = self.guard.repair()
        self.assertTrue(result["restored"])
        self.assertTrue(self.guard.probe(self.guard.binary))
        self.assertIn("restore_verified_worker", self.guard.audit.read_text())
        self.assertFalse((self.guard.binary.parent /
                          ".relayforge-recovery-pending").exists())

    def test_absent_or_wrong_grant_fails_closed(self):
        self.guard.grant.unlink()
        with self.assertRaisesRegex(mod.RecoveryError, "local_opt_in_missing"):
            self.guard.repair()
        write(self.guard.grant, b"bad", 0o600)
        with self.assertRaisesRegex(mod.RecoveryError, "local_opt_in_missing"):
            self.guard.repair()
        write(self.guard.grant, mod.GRANT, 0o644)
        with self.assertRaisesRegex(mod.RecoveryError, "local_opt_in_missing"):
            self.guard.repair()

    def test_invalid_baseline_is_never_installed(self):
        write(self.guard.binary, "#!/bin/sh\nexit 1\n", 0o700)
        write(self.guard.baseline, "#!/bin/sh\nexit 1\n", 0o700)
        old = self.guard.binary.read_bytes()
        with self.assertRaisesRegex(mod.RecoveryError, "no_verified_known_good"):
            self.guard.repair()
        self.assertEqual(old, self.guard.binary.read_bytes())

    def test_symlinked_binary_and_baseline_denied(self):
        write(self.guard.binary, "#!/bin/sh\nexit 1\n", 0o700)
        original = self.guard.baseline.read_bytes()
        self.guard.baseline.unlink()
        write(self.home / "outside", original, 0o700)
        self.guard.baseline.symlink_to(self.home / "outside")
        self.assertFalse(self.guard.probe(self.guard.baseline))
        with self.assertRaisesRegex(mod.RecoveryError, "no_verified_known_good"):
            self.guard.repair()

    def test_busy_build_lock_preserves_current_release(self):
        import fcntl
        # flock conflicts across independently opened file descriptions.
        with open(self.guard.lock, "rb") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(mod.RecoveryError, "development_busy"):
                self.guard.repair()

    def test_unknown_service_never_restarted(self):
        self.guard.unit_state = lambda: "unknown"
        write(self.guard.binary, FAKE, 0o700)
        self.assertEqual(self.guard.repair()["service"], "untouched")

    def test_recovery_entrypoints_are_fixed(self):
        installer = (SOURCE.parent / "install-local-recovery.sh").read_text()
        unit = (SOURCE.parent / "systemd/relayforge-local-recover.service").read_text()
        timer = (SOURCE.parent / "systemd/relayforge-local-recover.timer").read_text()
        self.assertIn("ALLOW_RELAYFORGE_SELF_RECOVERY", installer)
        self.assertIn("ProtectSystem=strict", unit)
        self.assertIn("ProtectHome=read-only", unit)
        self.assertIn("OnUnitActiveSec=5min", timer)
        self.assertNotIn("/bin/bash -c", unit)
        self.assertNotIn("curl ", installer)


if __name__ == "__main__":
    unittest.main()
