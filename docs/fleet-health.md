# Read-only user-service fleet overview

`relayforge_fleet_health` takes no arguments and checks three allowlisted
Rust agents in parallel. It issues one `user.service.list` call per host
over the existing strictly host-verified SSH bridge, and compares returned
user services and timers against the following pilot baseline:

- `ru0`: Assistant Hub local, personal Xray, Remote Desktop, and the
  Assistant Hub backup, Google Calendar and university calendar timers.
- `ru1`: Assistant Hub demo, Remote Desktop, backup timer and monitor timer.
- `srv0`: Remote Desktop.

Responses contain a timestamp, aggregate status and per-unit active/sub
states. A unit absent from the result is `missing`, and the host is
`degraded`. SSH errors, invalid remote JSON and bad scopes are marked
`unreachable`; no failed host can cause a green overall result.

This is an intentionally narrow pilot baseline, not a general monitoring
system or guaranteed service-level health check: systemd `active` does not
guarantee application readiness, scheduled timers may fire without
completing successfully, and results reflect the instant of inspection.
The tool does not restart services, read logs, expose unit environment,
or change network settings. It can run from the private ChatGPT MCP tunnel
or the local Codex stdio client. Host timeout behavior is bounded by
each underlying SSH process.

A future operator-approved restart should use this tool for before/after
context and apply a separately reviewed service-specific rollback policy.
