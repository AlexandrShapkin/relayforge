# User-service health diagnostics

RelayForge agents support two new read-only operations over authenticated
SSH (and through the private MCP tunnel's existing `relayforge_agent_query`):

- `user.service.list` — at most 64 user-owned systemd services and timers
  on an allowlisted Linux VPS. Each item contains only unit name, load,
  active and substate. Human-readable unit descriptions are deliberately
  omitted because they can contain credentials.
- `user.service.status` — one exact user-owned `.service`, `.socket`
  or `.timer` unit and only fixed systemd properties: Id, LoadState,
  ActiveState, SubState, UnitFileState, Result and NRestarts.
  Nonexistent units fail closed.

Both the local MCP adapter and remote agent reject malformed names, extra
arguments, arbitrary shell commands, restarts, stops, systemd environment
properties, executable definitions and journald text. The user manager is
accessed as the existing unprivileged SSH identity; no sudo or listener.

This makes it possible to diagnose Assistant Hub and its timers, RDC,
and personal proxy units on `ru0`; Assistant Hub demo and monitoring timers
on `ru1`; and RDC on `srv0`, **without changing service states**.

Any future real service restart must be a separate, explicit, narrowly
scoped privilege with an independently tested recovery path. No real
production restart is enabled by this feature.
