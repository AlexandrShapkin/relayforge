#!/usr/bin/env python3
"""Offline isolated tests for the opt-in local recovery guard."""
import importlib.machinery
import importlib.util
import os
import sys
import json
import hashlib
from pathlib import Path
import stat
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "deploy/relayforge-local-recover.py"
sys.path.insert(0, str(SOURCE.parent))
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
    # Test-only corruption/recreation of owned fixture artifacts.
    if path.is_file() and not path.is_symlink():
        path.chmod(0o700)
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
        self.install_runtime(FAKE)
        write(self.guard.lock, "", 0o600)
        write(self.guard.grant, mod.GRANT, 0o600)
        write(self.guard.runtime_key, b"only-test-placeholder", 0o600)
        write(self.guard.baseline, FAKE, 0o700)
        # No live systemd mutation in tests.
        self.guard.unit_state = lambda: "active"

    def install_runtime(self, data):
        store = self.home / ".local/libexec/relayforge/runtime"
        digest = hashlib.sha256(data.encode()).hexdigest()
        version = store / "artifacts" / ("a" * 40 + "-" + digest)
        version.mkdir(parents=True, exist_ok=True)
        write(version / "relayforge-mcp", data, 0o500)
        write(version / "manifest.json", json.dumps({"schema_version": 1, "commit": "a" * 40,
              "sha256": digest, "binary": "relayforge-mcp"}), 0o400)
        current = store / "current"
        if current.is_symlink():
            current.unlink()
        current.symlink_to("artifacts/" + version.name, target_is_directory=True)

    def test_healthy_release_is_left_untouched(self):
        self.install_runtime(FAKE)
        before = self.guard.binary.read_bytes()
        self.assertEqual(self.guard.repair(), {
            "worker_valid": True, "restored": False, "service": "untouched",
        })
        self.assertEqual(self.guard.binary.read_bytes(), before)
        self.assertFalse(self.guard.audit.exists())

    def test_hash_valid_but_nonfunctional_runtime_is_not_healthy(self):
        self.install_runtime("#!/bin/sh\nexit 7\n")
        self.assertFalse(self.guard.probe(self.guard.binary))
        with self.assertRaisesRegex(mod.RecoveryError, "operator_rollback_required"):
            self.guard.repair()

    def test_bad_release_never_installs_unattested_historical_backup(self):
        write(self.guard.binary, "#!/bin/sh\nexit 7\n", 0o700)
        old = self.guard.binary.read_bytes()
        baseline = self.guard.baseline.read_bytes()
        with self.assertRaisesRegex(mod.RecoveryError, "operator_rollback_required"):
            self.guard.repair()
        self.assertEqual(self.guard.binary.read_bytes(), old)
        self.assertEqual(self.guard.baseline.read_bytes(), baseline)

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
        with self.assertRaisesRegex(mod.RecoveryError, "operator_rollback_required"):
            self.guard.repair()
        self.assertEqual(old, self.guard.binary.read_bytes())

    def test_symlinked_binary_and_baseline_denied(self):
        write(self.guard.binary, "#!/bin/sh\nexit 1\n", 0o700)
        original = self.guard.baseline.read_bytes()
        self.guard.baseline.unlink()
        write(self.home / "outside", original, 0o700)
        self.guard.baseline.symlink_to(self.home / "outside")
        self.assertFalse(self.guard.probe(self.guard.baseline))
        with self.assertRaisesRegex(mod.RecoveryError, "operator_rollback_required"):
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
        self.install_runtime(FAKE)
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
