#!/usr/bin/env python3
"""Opt-in, host-local ru0 user-service recovery. No MCP, SSH, RDC or GitHub.

The guard only requests a start for two exact enabled user services that are
inactive/failed. It never restarts an active service, changes unit files, or
uses a caller-specified unit, host, path or command.
"""
from __future__ import annotations

import fcntl
import json
import os
from pathlib import Path
import pwd
import socket
import stat
import subprocess
import sys
import time

GRANT = b"ALLOW_RELAYFORGE_HOST_RECOVERY\n"
UNITS = ("assistant-hub-local.service", "personal-xray.service")
COOLDOWN_SECONDS = 3600
MAX_AUDIT = 128 * 1024


class GuardError(Exception):
    pass


def regular_private(path: Path, max_bytes: int) -> bool:
    try:
        meta = path.lstat()
        return (stat.S_ISREG(meta.st_mode) and meta.st_uid == os.getuid()
                and stat.S_IMODE(meta.st_mode) == 0o600
                and meta.st_size <= max_bytes)
    except OSError:
        return False


def owned_directory(path: Path, private: bool = False) -> bool:
    try:
        meta = path.lstat()
        return (stat.S_ISDIR(meta.st_mode) and meta.st_uid == os.getuid()
                and not (meta.st_mode & (0o077 if private else 0o022)))
    except OSError:
        return False


def run_fixed(argv: list[str], timeout: int = 6) -> subprocess.CompletedProcess:
    return subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, text=True, timeout=timeout,
                          check=False)


class HostRecovery:
    def __init__(self, home: Path) -> None:
        self.home = home
        self.config_dir = home / ".config/relayforge"
        self.grant = self.config_dir / "allow-host-recovery"
        self.state = home / ".local/state/relayforge-host-recovery"
        self.audit = self.state / "audit.jsonl"
        self.lock = self.state / "guard.lock"

    def hostname(self) -> str:
        return socket.gethostname().split(".", 1)[0]

    def host_allowed(self) -> bool:
        return self.hostname() == "ru0"

    def opted_in(self) -> bool:
        if not (owned_directory(self.config_dir) and
                regular_private(self.grant, len(GRANT))):
            return False
        try:
            return self.grant.read_bytes() == GRANT
        except OSError:
            return False

    def _run(self, argv: list[str]) -> subprocess.CompletedProcess:
        return run_fixed(argv)

    def unit_state(self, unit: str) -> str:
        # The unit comes exclusively from UNITS. No caller-selected units.
        if unit not in UNITS:
            return "unknown"
        try:
            result = self._run([
                "systemctl", "--user", "show", "--no-pager",
                "--property=Id,LoadState,UnitFileState,ActiveState", "--", unit
            ])
            if result.returncode or len(result.stdout) > 4096:
                return "unknown"
            props = dict(line.split("=", 1) for line in result.stdout.splitlines()
                         if "=" in line and len(line) < 180)
            if (props.get("Id") != unit or props.get("LoadState") != "loaded"
                    or props.get("UnitFileState") != "enabled"):
                return "unknown"
            state = props.get("ActiveState")
            return state if state in ("active", "activating", "inactive", "failed") else "unknown"
        except (OSError, ValueError, subprocess.TimeoutExpired):
            return "unknown"

    def preflight(self) -> None:
        if not self.host_allowed():
            raise GuardError("host_denied")
        if not self.opted_in():
            raise GuardError("local_opt_in_missing")
        if not (owned_directory(self.home / ".local")
                and owned_directory(self.home / ".local/state")
                and owned_directory(self.state, private=True)):
            raise GuardError("private_state_unavailable")

    def audit_lines(self) -> list[dict]:
        if not self.audit.exists():
            return []
        if not regular_private(self.audit, MAX_AUDIT):
            raise GuardError("audit_unavailable")
        try:
            fd = os.open(self.audit, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as stream:
                raw = stream.read(MAX_AUDIT + 1)
            if len(raw) > MAX_AUDIT:
                raise GuardError("audit_unavailable")
            lines = []
            for line in raw.splitlines():
                record = json.loads(line)
                if (not isinstance(record, dict)
                        or type(record.get("at")) is not int
                        or record.get("event") != "start_requested"
                        or record.get("unit") not in UNITS):
                    raise GuardError("audit_unavailable")
                lines.append(record)
            return lines
        except (OSError, ValueError, UnicodeDecodeError) as exc:
            raise GuardError("audit_unavailable") from exc

    def may_attempt(self, unit: str, now: int, records: list[dict]) -> bool:
        for record in records:
            if record["unit"] == unit and now - record["at"] < COOLDOWN_SECONDS:
                # Includes future timestamps (clock rollback): fail closed.
                return False
        return True

    def audit_before_start(self, unit: str, now: int) -> None:
        if self.audit.exists() and not regular_private(self.audit, MAX_AUDIT):
            raise GuardError("audit_unavailable")
        payload = (json.dumps({"at": now, "event": "start_requested", "unit": unit},
                              separators=(",", ":")) + "\n").encode()
        try:
            fd = os.open(self.audit, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                         os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                meta = os.fstat(stream.fileno())
                if (meta.st_uid != os.getuid()
                        or stat.S_IMODE(meta.st_mode) != 0o600
                        or meta.st_size + len(payload) > MAX_AUDIT):
                    raise GuardError("audit_unavailable")
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except OSError as exc:
            raise GuardError("audit_unavailable") from exc

    def check(self) -> dict:
        return {"host_allowed": self.host_allowed(), "opted_in": self.opted_in(),
                "state_private": owned_directory(self.state, private=True),
                "units": {unit: self.unit_state(unit) if self.host_allowed()
                          else "unknown" for unit in UNITS}}

    def repair(self) -> dict:
        self.preflight()
        # Serialize concurrent guard executions. Never wait for a stuck run.
        try:
            fd = os.open(self.lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "r+b") as lock:
                meta = os.fstat(lock.fileno())
                if meta.st_uid != os.getuid() or stat.S_IMODE(meta.st_mode) != 0o600:
                    raise GuardError("lock_unavailable")
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise GuardError("guard_busy") from exc
                records = self.audit_lines()
                now = int(time.time())
                outcomes = {}
                for unit in UNITS:
                    state = self.unit_state(unit)
                    if state not in ("inactive", "failed"):
                        outcomes[unit] = "untouched"
                        continue
                    if not self.may_attempt(unit, now, records):
                        outcomes[unit] = "cooldown"
                        continue
                    self.audit_before_start(unit, now)
                    # This records an attempt even if systemctl fails. A
                    # crashing service cannot trigger an unlimited start loop.
                    records.append({"at": now, "event": "start_requested", "unit": unit})
                    try:
                        result = self._run([
                            "systemctl", "--user", "start", "--no-block", "--", unit
                        ])
                        outcomes[unit] = ("start_requested" if result.returncode == 0
                                          else "start_failed")
                    except (OSError, subprocess.TimeoutExpired):
                        outcomes[unit] = "start_failed"
                return {"outcomes": outcomes}
        except OSError as exc:
            raise GuardError("lock_unavailable") from exc


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in ("check", "repair"):
        print('{"ok":false,"reason":"invalid_operation"}')
        return 2
    guard = HostRecovery(Path(pwd.getpwuid(os.getuid()).pw_dir))
    try:
        result = guard.check() if sys.argv[1] == "check" else guard.repair()
        print(json.dumps({"ok": True, **result}, separators=(",", ":")))
        return 0
    except GuardError as exc:
        print(json.dumps({"ok": False, "reason": str(exc)}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
