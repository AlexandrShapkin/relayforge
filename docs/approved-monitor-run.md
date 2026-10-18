# First operator-approved production-adjacent job: ru1 health snapshot

A narrowly scoped action `monitor.run` is available only through
`relayforge_change_prepare` and `relayforge_change_commit`, after
manual ThinkPad approval. Unlike the inert `probe.restart`, it controls
one **real, noncritical** systemd user oneshot job:

- **Target**: `ru1` only.
- **Unit**: `assistant-hub-monitor.service` only.
- **Command**: `systemctl --user start -- assistant-hub-monitor.service`.
- **Meaning**: run the existing periodic Assistant Hub health snapshot
  one additional time. No web listener or persistent daemon is restarted.

The local MCP adapter and remote Rust agent enforce distinct boundaries.
The approval record contains exactly `{"host":"ru1","action":"monitor.run"}`;
it cannot supply arbitrary unit names, arguments, filenames or hosts.
The agent independently checks its /etc/hostname equals the expected
ru1 hostname, verifies that the systemd unit is loaded, a oneshot and
currently inactive, and then checks systemd Result and ExecMainStatus
after it runs. If any precondition fails, no job is started.

The operation uses the same operator-approved single-use claim and
audit trail as scratch file creation. Direct MCP service restarts
remain unavailable; the tunnel continues to deny `relayforge_agent_probe_restart`
and `relayforge_agent_file`.

**Limitations:** A successful systemd oneshot exit is not a guarantee
that the application health snapshot has accurate external data. Unit
files can be edited by the already trusted Unix owner, and there is
no separate cryptographic ChatGPT actor identity yet. As with all
operations, no automatic rollback can reverse effects of a completed
oneshot job. The production connectivity components (SSH, RDC, Happ,
Xray, nginx, tunnel) are not in this allowlist.

Test readiness using `relayforge_agent_query` `user.service.status`
on ru1. Do not invoke the action until a human has reviewed the
approval text and approved the exact single-use request.

## Independent approval and execution expiry

A `monitor.run` proposal remains available for manual approval for
**300 seconds after preparation**. Once approved through the local
terminal, a separate **180-second** commit window starts. A successful
one-time grant is consumed before the agent receives `monitor.run`.
The previous legacy five-minute combined expiry is not extended for
already-issued approvals. Both deadlines and current stage are visible
through `relayforge_change_status`, without revealing file content.

The CLI prints the exact post-confirmation execution expiration. If the
execution window expires, create and individually approve a new request;
do not attempt to reuse or bypass the expired authorization.
