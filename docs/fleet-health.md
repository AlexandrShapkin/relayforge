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

## Job execution assurance (2026-10)

The fleet overview now reads `user.jobs.summary` rather than only
`user.service.list`. The agent returns the original bounded user-unit
inventory **plus** fixed telemetry for scheduled Assistant Hub jobs.
It observes systemd's `Result`, `ExecMainCode`, `ExecMainStatus`,
`ExecMainExitTimestampMonotonic`, and the timer's last/next fire times.
It never returns unit contents, command lines, environment variables or
journald entries.

Statuses are interpreted conservatively:

- `success`: a zero-exit oneshot completion observed since this boot,
  more recent than the job's maximum age.
- `failed`: the timer is inactive or systemd reports failed execution.
- `stale`: there is an observed success but it is older than the
  configured per-job freshness window.
- `unverified`: no completion observed since reboot or insufficient
  evidence of a successful exit; **not** claimed to be a failed backup.
- `running`: systemd indicates an active oneshot; completion not yet
  verified.

Backup jobs use a 48-hour maximum age, Google Calendar a two-hour
maximum, university calendar four hours, and ru1 monitor two hours.
These are conservative diagnostic thresholds, not deployment SLAs.
The timestamps are reported as systemd strings, and freshness is
calculated from monotonic exit timestamps and /proc/uptime. After reboot
previous results are explicitly **unverified**, even if a timer remembers
an earlier wall-clock trigger.

Fleet `overall` is `healthy` only if required services and timers
are active **and** every scheduled job has confirmed recent success.
`attention` means services/timers are active but at least one job
is running or not verifiable; `degraded` covers failed/stale/missing
jobs, missing core services or unreachable nodes. The snapshot is
non-mutating and does not guarantee the integrity of files in backup
archives or the semantic correctness of imported calendar events.


## Private artifact evidence (2026-10 pilot)

The remote agent's existing `user.jobs.summary` operation now includes
`artifact_results`. No new MCP tool or write privilege is required. It
checks **fixed paths only**, never paths from a ChatGPT or SSH request:

- ru0 most recent private backup folder: SQLite `PRAGMA quick_check(1)`
  in immutable read-only mode and bytewise equality of the private copied
  owner-verifier with the original (only the boolean is returned);
- ru1 latest dated, compressed demo backup: bounded gzip decompression in
  memory and SQLite `PRAGMA quick_check(1)`, without extraction to disk;
- ru0 main calendar's shared SQLite store: structural integrity only.
  Without a **source-specific successful sync receipt**, the Google Main
  mirror remains `unverified` even if the database is readable;
- ru0 university feed status: JSON schema, bounded nonnegative aggregate
  event count and file age. The upstream subscription is explicitly **not
  independently verified**, so the mirror stays `unverified`;
- ru1 latest appended health snapshot: limited JSON record with sanitized
  booleans for aggregator, VPN HTTP probe and RDC. An unsuccessful external
  probe is marked `failed`, even when its systemd sampler exited zero.

SQLite content is never returned, and no personal calendar events,
credentials, owner verifier, individual monitor readings or archive paths
are disclosed. The verifier invokes only a fixed Python 3 stdlib
`sqlite3`/gzip script in isolated mode via an argument vector, bounded
by `timeout 6s`. Read-only SQLite URIs are used; gzip is decompressed
inside memory with a 16 MiB cap. Results never authorize restoration,
deletion, restarting or rescheduling.

The fleet summary aggregates `verified`, `unverified`, `stale` and
`failed` artifact states: an unverified artifact means `attention`,
a failed/stale/missing one means `degraded`. This checks structural
integrity and freshness of *local* evidence, not successful recovery
from backup or independent freshness of a Google/university source.
