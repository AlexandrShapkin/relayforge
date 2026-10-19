#!/usr/bin/env python3
"""Offline guard tests. No production systemctl invocation."""
import importlib.machinery
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import subprocess

SOURCE = Path(__file__).resolve().parents[1] / "deploy/relayforge-host-recovery.py"
loader = importlib.machinery.SourceFileLoader("rf_host_recovery", str(SOURCE))
spec = importlib.util.spec_from_loader(loader.name, loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)


class HostRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)
        for rel in (".config/relayforge", ".local/state/relayforge-host-recovery"):
            directory = self.home / rel
            directory.mkdir(parents=True, mode=0o700)
            directory.chmod(0o700)
        self.guard = mod.HostRecovery(self.home)
        self.guard.grant.write_bytes(mod.GRANT)
        self.guard.grant.chmod(0o600)
        self.guard.hostname = lambda: "ru0"
        self.states = {unit: "active" for unit in mod.UNITS}
        self.commands = []

        def fake_run(args):
            self.commands.append(args)
            unit = args[-1]
            if args[3] == "show":
                # Alternate show argument layout never used in this guard.
                raise AssertionError("unexpected arguments")
            if "show" in args:
                state = self.states[unit]
                if state == "unknown":
                    return subprocess.CompletedProcess(args, 1, "")
                return subprocess.CompletedProcess(
                    args, 0, "Id=" + unit + "\nLoadState=loaded\n"
                    "UnitFileState=enabled\nActiveState=" + state + "\n")
            if "start" in args:
                if unit not in mod.UNITS:
                    raise AssertionError("unexpected unit")
                return subprocess.CompletedProcess(args, 0, "")
            raise AssertionError("unexpected command")

        self.guard._run = fake_run

    def test_active_services_are_not_touched(self):
        outcome = self.guard.repair()
        self.assertEqual(set(outcome["outcomes"]), set(mod.UNITS))
        self.assertEqual(set(outcome["outcomes"].values()), {"untouched"})
        self.assertFalse(self.guard.audit.exists())
        self.assertFalse(any("start" in cmd for cmd in self.commands))

    def test_only_inactive_allowlisted_service_is_started(self):
        self.states["assistant-hub-local.service"] = "inactive"
        result = self.guard.repair()["outcomes"]
        self.assertEqual(result["assistant-hub-local.service"], "start_requested")
        self.assertEqual(result["personal-xray.service"], "untouched")
        starts = [c for c in self.commands if "start" in c]
        self.assertEqual(starts, [[
            "systemctl", "--user", "start", "--no-block", "--",
            "assistant-hub-local.service"]])
        self.assertIn("start_requested", self.guard.audit.read_text())

    def test_failed_service_recovery_is_rate_limited(self):
        self.states["personal-xray.service"] = "failed"
        self.assertEqual(self.guard.repair()["outcomes"]["personal-xray.service"],
                         "start_requested")
        self.commands.clear()
        self.assertEqual(self.guard.repair()["outcomes"]["personal-xray.service"],
                         "cooldown")
        self.assertFalse(any("start" in c for c in self.commands))

    def test_no_grant_and_wrong_grant_fail_closed(self):
        self.guard.grant.unlink()
        with self.assertRaisesRegex(mod.GuardError, "local_opt_in_missing"):
            self.guard.repair()
        self.guard.grant.write_bytes(b"wrong")
        self.guard.grant.chmod(0o600)
        with self.assertRaisesRegex(mod.GuardError, "local_opt_in_missing"):
            self.guard.repair()
        self.assertEqual(self.commands, [])

    def test_wrong_host_cannot_run(self):
        self.guard.hostname = lambda: "srv0"
        with self.assertRaisesRegex(mod.GuardError, "host_denied"):
            self.guard.repair()
        self.assertEqual(self.commands, [])

    def test_symlink_grant_and_audit_fail_closed(self):
        outside = self.home / "outside"
        outside.write_bytes(mod.GRANT)
        outside.chmod(0o600)
        self.guard.grant.unlink()
        self.guard.grant.symlink_to(outside)
        with self.assertRaisesRegex(mod.GuardError, "local_opt_in_missing"):
            self.guard.repair()
        self.guard.grant.unlink()
        self.guard.grant.write_bytes(mod.GRANT)
        self.guard.grant.chmod(0o600)
        self.states["personal-xray.service"] = "inactive"
        self.guard.audit.symlink_to(outside)
        with self.assertRaisesRegex(mod.GuardError, "audit_unavailable"):
            self.guard.repair()
        self.assertFalse(any("start" in c for c in self.commands))

    def test_unknown_and_disabled_services_never_start(self):
        self.states["personal-xray.service"] = "unknown"
        result = self.guard.repair()["outcomes"]
        self.assertEqual(result["personal-xray.service"], "untouched")
        self.assertEqual(self.guard.unit_state("ssh.service"), "unknown")

    def test_future_receipt_prevents_retry_after_clock_rollback(self):
        self.states["assistant-hub-local.service"] = "inactive"
        self.assertFalse(self.guard.may_attempt(
            "assistant-hub-local.service", 10,
            [{"unit": "assistant-hub-local.service", "at": 100000}]))
        self.assertTrue(self.guard.may_attempt(
            "assistant-hub-local.service", 4000,
            [{"unit": "assistant-hub-local.service", "at": 1}]))

    def test_audit_unsafe_mode_rejected_before_start(self):
        self.states["personal-xray.service"] = "failed"
        self.guard.audit.write_text("")
        self.guard.audit.chmod(0o644)
        with self.assertRaisesRegex(mod.GuardError, "audit_unavailable"):
            self.guard.repair()
        self.assertFalse(any("start" in c for c in self.commands))

    def test_systemd_units_and_installer_remain_opt_in(self):
        root = SOURCE.parent
        installer = (root / "install-host-recovery.sh").read_text()
        service = (root / "systemd/relayforge-host-recovery.service").read_text()
        timer = (root / "systemd/relayforge-host-recovery.timer").read_text()
        self.assertIn("ALLOW_RELAYFORGE_HOST_RECOVERY", installer)
        self.assertIn("Linger", installer)
        self.assertIn("ProtectSystem=strict", service)
        self.assertIn("ProtectHome=read-only", service)
        self.assertIn("OnUnitActiveSec=10min", timer)
        self.assertNotIn("curl ", installer)
        self.assertNotIn("/bin/bash -c", service)


if __name__ == "__main__":
    unittest.main()
