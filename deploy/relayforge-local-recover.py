#!/usr/bin/env python3
"""Operator-opted-in local RelayForge recovery, independent of ChatGPT/RDC.

This cannot recover an offline laptop or missing network. It does not read
credentials, run arbitrary commands, or accept a caller-controlled path.
"""
from __future__ import annotations

import fcntl
from runtime_artifact import verify_installed, opened, ArtifactError
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys
import time

PROBE = '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
GRANT = b"ALLOW_RELAYFORGE_SELF_RECOVERY\n"
SERVICE = "relayforge-tunnel.service"


class RecoveryError(Exception):
    pass


def regular_owned(path: Path, max_bytes: int, executable: bool = False) -> bool:
    try:
        meta = path.lstat()
        return (stat.S_ISREG(meta.st_mode)
                and meta.st_uid == os.getuid()
                and meta.st_size <= max_bytes
                and (meta.st_mode & 0o022) == 0
                and (not executable or bool(meta.st_mode & 0o100)))
    except OSError:
        return False


def private_dir(path: Path) -> bool:
    try:
        meta = path.lstat()
        return (stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == os.getuid()
                and (meta.st_mode & 0o077) == 0)
    except OSError:
        return False


def fixed_command(args: list[str], timeout: int = 8, input_text: str | None = None
                  ) -> subprocess.CompletedProcess:
    # Fixed caller-supplied argument vectors, never shell=True or custom
    # subprocess env. External command stdout is capped in the caller.
    return subprocess.run(
        args, input=input_text, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=timeout, check=False,
    )


class Recovery:
    def __init__(self, home: Path) -> None:
        self.home = home
        self.repo = home / "Projects/relayforge"
        self.binary = home / ".local/libexec/relayforge/runtime/current/relayforge-mcp"
        self.state = home / ".local/state/relayforge"
        self.baseline = self.state / "mcp-hot-last-good"
        self.lock = self.state / "development.lock"
        self.audit = self.state / "local-recovery.jsonl"
        self.grant = home / ".config/relayforge/allow-self-recovery"
        self.runtime_key = home / ".config/relayforge/tunnel/runtime-key"

    def allowed(self) -> bool:
        if not regular_owned(self.grant, len(GRANT)):
            return False
        try:
            return self.grant.read_bytes() == GRANT and (
                stat.S_IMODE(self.grant.stat().st_mode) == 0o600
            )
        except OSError:
            return False

    def probe(self, binary: Path) -> bool:
        if binary != self.binary:
            return False  # historical backups have no accepted provenance here
        try:
            selected = verify_installed(binary)
            # Check and execute one pinned, frozen inode; never re-open current.
            with opened(selected) as (fd, meta):
                if meta.st_mode & 0o222:
                    return False
                with os.fdopen(os.dup(fd), "rb") as file:
                    if hashlib.file_digest(file, "sha256").hexdigest() != selected.parent.name[41:]:
                        return False
                reply = fixed_command([f"/proc/{os.getpid()}/fd/{fd}", "--readonly-worker"],
                                      timeout=8, input_text=PROBE)
            if reply.returncode or len(reply.stdout) > 32 * 1024:
                return False
            value = json.loads(reply.stdout)
            tools = value.get("result", {}).get("tools", [])
            return (value.get("jsonrpc") == "2.0" and value.get("id") == 1
                    and isinstance(tools, list)
                    and any(isinstance(t, dict) and t.get("name") == "relayforge_workstation_develop" for t in tools))
        except (ArtifactError, OSError, ValueError, TypeError, AttributeError, subprocess.TimeoutExpired):
            return False

    def unit_state(self) -> str:
        try:
            reply = fixed_command(
                ["systemctl", "--user", "show", SERVICE,
                 "--property=Id,LoadState,ActiveState"], timeout=6)
            if reply.returncode:
                return "unknown"
            props = dict(line.split("=", 1) for line in reply.stdout.splitlines()
                         if "=" in line and len(line) < 160)
            if (props.get("Id") != SERVICE
                    or props.get("LoadState") != "loaded"):
                return "unknown"
            state = props.get("ActiveState", "")
            if state in ("active", "activating", "inactive", "failed"):
                return state
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
        return "unknown"

    def preflight(self) -> None:
        if not self.allowed():
            raise RecoveryError("local_opt_in_missing")
        if not private_dir(self.state):
            raise RecoveryError("private_state_unavailable")
        if not regular_owned(self.runtime_key, 16 * 1024):
            raise RecoveryError("runtime_key_unavailable")

    def audit_event(self, action: str) -> None:
        if not private_dir(self.state):
            raise RecoveryError("private_state_unavailable")
        if self.audit.exists() and (
                not regular_owned(self.audit, 1024 * 1024)
                or stat.S_IMODE(self.audit.stat().st_mode) != 0o600):
            raise RecoveryError("audit_unavailable")
        line = json.dumps({"at": int(time.time()), "action": action},
                          separators=(",", ":")) + "\n"
        try:
            fd = os.open(self.audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                         os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as file:
                file.write(line)
                file.flush()
                os.fsync(file.fileno())
        except OSError as exc:
            raise RecoveryError("audit_unavailable") from exc

    def restore_binary(self) -> bool:
        if self.probe(self.binary):
            return False
        raise RecoveryError("verified_runtime_missing_operator_rollback_required")

    def start_if_needed(self) -> str:
        status = self.unit_state()
        if status in ("active", "activating", "unknown"):
            return "untouched"
        # Only start a known installed unit. Never restart an active tunnel
        # merely because its network/control-plane heartbeat is stale.
        self.audit_event("start_inactive_tunnel")
        if status == "failed":
            try:
                result = fixed_command(
                    ["systemctl", "--user", "reset-failed", SERVICE], timeout=6)
                if result.returncode:
                    raise RecoveryError("reset_failed")
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RecoveryError("reset_failed") from exc
        try:
            result = fixed_command(
                ["systemctl", "--user", "start", SERVICE], timeout=12)
            if result.returncode:
                raise RecoveryError("start_failed")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RecoveryError("start_failed") from exc
        return "start_requested"

    def check(self) -> dict[str, object]:
        return {
            "worker_valid": self.probe(self.binary),
            "known_good_valid": False,
            "automatic_binary_restore": False,
            "unit_state": self.unit_state(),
            "recovery_opted_in": self.allowed(),
        }

    def repair(self) -> dict[str, object]:
        self.preflight()
        # The same lock serializes with repo.sync and release builds.
        # Never restore the executable while cargo is linking it.
        if not regular_owned(self.lock, 8 * 1024):
            raise RecoveryError("development_lock_missing")
        try:
            with open(self.lock, "rb") as lock:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise RecoveryError("development_busy") from exc
                restored = self.restore_binary()
                if not self.probe(self.binary):
                    raise RecoveryError("worker_still_invalid")
                service = self.start_if_needed()
        except OSError as exc:
            raise RecoveryError("development_lock_unavailable") from exc
        return {"worker_valid": True, "restored": restored, "service": service}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "repair"):
        print('{"ok":false,"reason":"invalid_operation"}')
        return 2
    # Do not trust HOME supplied to the subprocess by a remote MCP caller.
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    guard = Recovery(home)
    try:
        result = guard.check() if sys.argv[1] == "check" else guard.repair()
        print(json.dumps({"ok": True, **result}, separators=(",", ":")))
        return 0
    except RecoveryError as exc:
        print(json.dumps({"ok": False, "reason": str(exc)},
                         separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
