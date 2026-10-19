# Development continuity when Remote Desktop Commander quota is exhausted

This repository intentionally supports a **development path that does not need
Remote Desktop Commander (RDC), a running ThinkPad, or access to a private
device**.

## Working path — GitHub and disposable CI runners

1. Use the connected GitHub integration to inspect files on `main`, create a
   short-lived branch, and commit focused source changes. Do **not** edit
   `main` directly.
2. Open a pull request against `main`. GitHub-hosted checks run automatically:
   the existing `Rust checks` workflow and
   `RDC-independent development verification`.
3. Review CI conclusions and logs through GitHub. The independent workflow
   performs formatting, strict Clippy, Rust tests, Linux release builds, and a
   local JSON-RPC MCP handshake/deny-by-default smoke test **without connecting
   to any real device**.
4. On success, review and merge the PR. No SSH, computer tool or RDC command
   is needed for those source-control steps.
5. The independent workflow stores a short-lived Linux x86_64 binary archive
   and a SHA-256 digest as GitHub Actions artifacts. The digest detects
   accidental changes; it is **not** a cryptographic publisher signature.
   Artifacts expire after seven days. These are untrusted CI build products
   until separately reviewed and verified for their target host.
6. After merging, use the Actions tab to invoke
   `RDC-independent development verification` via `workflow_dispatch`
   when an independent main-branch build or packaging run is needed.

**The CI workflow cannot and must not automatically deploy** a release to
ThinkPad or a VPS. It never receives SSH credentials, API keys, ADB keys,
router configuration or device secrets. GitHub's `GITHUB_TOKEN` is read-only
(`contents: read`). No self-hosted runner and no production machine is
required for the builds.

## Existing infrastructure diagnosis without RDC

The private ChatGPT RelayForge plugin can already inspect the approved
Linux VPS hosts and read-only RouterOS and authorized Android ADB devices.
Its private tunnel is installed on ThinkPad and therefore requires that
ThinkPad and the tunnel remain online. This path has **its own connection
and availability dependencies**, but it is not billed as RDC usage.

The current RelayForge MCP does not provide an arbitrary ThinkPad terminal,
general filesystem operations on the laptop, or unattended remote
administration. The VPN health probe on ru1 and unverified upstream calendar
freshness should not be treated as proof of a RelayForge development failure.

## Workstation status (source ready; deployment separate)

The new `relayforge_workstation_status` tool is a **no-argument,
read-only** local workstation summary through the preexisting private
Secure MCP Tunnel. It reports whether the fixed RelayForge Git tree is
present/on `main`/free of tracked modifications and non-ignored untracked
files, uptime, memory available,
whether the user tunnel service is active and whether a recent
authenticated control-plane poll was recorded. It never discloses
filesystem listings or untracked filenames, secrets, environment variables, Git remote URLs
or process command lines. Its internal fixed git/systemctl/health checks
have timeouts and return `unverified` rather than claiming a healthy
host if any required evidence is missing.

Source code and CI tests alone do **not** activate a tool on ThinkPad.
Deployment requires updating the ThinkPad MCP binary and refreshing
the private ChatGPT plugin after a separate review. Do not spend an
almost-exhausted RDC quota simply to run repetitive builds; use
GitHub-hosted verification first.

## Capabilities still missing when RDC is gone

GitHub editing/CI replaces repository inspection, commits, builds, tests,
reviews and PR merges. It does **not** replace RDC's access to:

- Uncommitted, private, or untracked ThinkPad files and live user processes.
- Interactive local terminal, GUI application control and workstation
  configuration.
- Installing built binaries on ThinkPad and restarting its live user services.
- SSH access through ThinkPad to devices that are not reached directly by
  a separate authorized management channel.
- Physical USB ADB pairing, local operator approvals and hardware recovery.

The secure successor should add **narrowly scoped** workstation inventory,
read-only filesystem access in explicitly approved roots, and a bounded
deployment/update operation with audit, verification and rollback. The
existing requirement for an **actual local human approval** of a dangerous
change remains: no tool, workflow, background agent or remote shell may
self-approve. Do not turn GitHub Actions or an issue/comment poller into a
general-purpose remote shell; that would give repository text and CI jobs
implicit authority over the operator's computer.

## Emergency rules

- If RDC reaches 0%, continue source development on GitHub through the
  connected tools and verify every proposed code change with CI.
- Do not infer that a green CI proves an actual VPS/router/phone deployment.
- Keep `main` clean and avoid new permanent branches or background
  development timers.
- Request a separate, explicit approval before any security-sensitive local
  access or deployment capability is enabled.

## Workstation development bridge (requires separately deployed binary)

The `relayforge_workstation_develop` tool provides a bounded replacement
for part of RDC on the authorized ThinkPad. Without local opt-in, the tool
supports read-only Git status, public tracked repository listings and small
tracked source reads. It never accepts executable names or shell arguments.

Mutating operations (scheduling fixed `git pull --ff-only origin main`,
scheduling fixed Cargo release builds, and restarting the tunnel user
service) require a **local opt-in file**:
`~/.config/relayforge/allow-workstation-development`, mode 0600,
containing exactly `ALLOW_RELAYFORGE_DEVELOPMENT\n`. Its owner must match
the invoking user. The operator must explicitly choose to create it locally.
Direct edits of existing tracked sources require **both** that opt-in and
a separate, locally operator-created 0600 file at
`~/.config/relayforge/allow-workstation-source-edits` containing exactly
`ALLOW_RELAYFORGE_SOURCE_EDITS\n`. It is **not** installed by the
bootstrap procedure. All mutations are audited before execution and
fail closed when auditing is unavailable. Release builds, Git sync and
service restarts also refuse a dirty tracked checkout or a non-main branch. No root
commands, arbitrary shell, untracked private files, SSH keys, GUI control,
or general process management are exposed by this initial stage.

Use `repo.sync` and `build.start` separately and monitor background jobs
with `task.status` / `task.logs`; changes must pass GitHub CI before host
sync. Restarting the private tunnel temporarily disconnects MCP until the
service reconnects. Do not assume local activation simply because CI passes.

This initial bridge is **not RDC feature parity**: it establishes the
repo-specific development and update path required to evolve RelayForge
without another RDC session. More general workstation functionality needs
separate policy, audit, containment and verification.

## Limited local shell and process visibility

The optional `shell.sandbox` workstation operation executes a bounded
15-second shell command **inside bubblewrap namespaces**, not as an
unrestricted host terminal. The command can read (but **not write**) the
fixed RelayForge checkout at `/workspace`; transient `/tmp` is writable. The sandbox has no network, other
home directories, operator SSH secrets, user service bus, or persistent
runtime directories. The tool passes a fixed bubblewrap argument vector;
user text is executed only by the isolated shell. The local development
opt-in and private mutation audit are required for every call. If
bubblewrap or its namespace support is absent, the command fails closed.

Read-only `process.list` exposes PID, executable basename, elapsed time
and memory use, but never full command lines or environment variables.
`user.services` lists the workstation user's systemd services. Neither
operation can terminate processes or change service configuration. Use
`tunnel.restart` only after a verified release build; it can temporarily
disconnect ChatGPT.

This does not replace RDC's interactive terminal sessions, process input,
file transfer outside the fixed checkout or GUI support. Those require
separate explicit authorizations, confinement and testing.

## Stable MCP operation contract and bounded output

The workstation development tool has a **stable request schema**: the `operation`
field is a string and the local server validates the exact operation and its
arguments. A new operation can be added on the server without changing this
parameter's enumerated type in the ChatGPT plugin. All unknown operations,
unknown arguments and unexpected nested `parameters` are denied, not passed
to a shell. `capabilities` returns the deployed operation list, API revision
and boolean local opt-in statuses so a client can verify the live server
independently of cached plugin tool descriptions.

Once the plugin is refreshed to the new schema, future additions that use
existing fields (or the reserved `parameters` object) will not require a
schema change. Initial plugin refresh after this upgrade is still necessary.

Local diagnostic output and file reads are capped **during acquisition**, not
only after a subprocess or large file has already exhausted memory. Retained
limits: 64 KiB per command stream and 48 KiB per tracked source file.
Excess output is denied; timeout and output caps are not permission grants.

The established no-RDC update sequence is:

1. Make and validate changes in GitHub, then merge to `main`.
2. Invoke `repo.sync`, await completion through `task.status` and `task.logs`,
   and verify the new checkout is clean.
3. Invoke `build.start`, await `Result=success` and `ExecMainStatus=0`.
4. On a hot-stdio deployment, leave the tunnel running and invoke
   `capabilities` or another MCP operation: the persistent parent loads the
   new release binary for each request. Verify `relayforge_workstation_status`
   continues to report a recent authenticated poll.
5. After the one-time transition to hot-stdio, `tunnel.restart` is refused
   by new workers. A manual restart is reserved for explicit transport
   maintenance, with an independent recovery path.

This path still depends on GitHub, ChatGPT and the Secure MCP Tunnel for
connectivity and identity, but it consumes no Remote Desktop Commander quota.

## Collision-safe workstation background operations

Fixed Git sync, Cargo release build, and tunnel restart now use private,
time-stamped random transient systemd unit IDs. The former second-resolution
unit names could collide when multiple operations were requested quickly,
causing `systemd-run` to refuse scheduling. Existing ten-digit task receipts
remain readable; the new receipt format is
`relayforge-dev-<unix-seconds>-<six-lowercase-hex-digits>` (32 characters).

All three operations acquire the same lock in the private RelayForge local
state directory. This serializes source syncing, compilation, and tunnel
restart rather than permitting a restart during an active build. They wait at
most 600 seconds to acquire the lock and have an 1800-second systemd task
timeout. Callers must still inspect `task.status` and `task.logs` for
success; scheduling is not proof of successful execution.

A restarted tunnel still needs live authenticated poll verification.

## Stable tunnel stdio parent and worker hot swap

The `--readonly-stdio` entrypoint is now a long-lived JSON-RPC relay rather
than the tool executor. It preserves the Secure MCP Tunnel stdio connection
while spawning the **fixed** released MCP binary with `--readonly-worker`
for each incoming request. Each worker uses the identical remote allowlist
and processes one request only. The caller cannot provide the executable,
environment, shell or worker arguments. Notifications remain silent. Failed,
timed-out, malformed or oversized new worker replies fall back to the
parent's already-running restricted executable (`/proc/self/exe`) for the
same request; if that also fails, the parent returns a generic MCP error.
The fallback does not use a user-supplied executable and does not weaken
the tunnel's operation allowlist. This protects the current live connection
from a bad on-disk upgrade, but **does not survive a parent restart**.
A durable on-disk last-known-good release and boot recovery remain future work.

Consequently a new local Cargo release build replaces the **next** worker
without disconnecting the tunnel or requiring a plugin reconnect. The
`tools/list` response can reflect newly deployed operations without
restarting the control-plane session; the ChatGPT client may still require
a manual Refresh tools when the displayed parameter schema changes.

**One-time transition:** an already running legacy `--readonly-stdio`
process does not learn this behaviour merely by replacing its executable.
After verifying CI and compiling the new binary, the tunnel must be
restarted once (or the parent upgraded through a separate planned handoff)
to activate hot-stdio. Future normal source builds must not restart it.
Before the one-time transition, verify a rollback/recovery channel.

This is a session-continuity improvement, not a guarantee of permanent
tunnel connectivity: the OpenAI control plane, ThinkPad networking, and
user service must still be running. It does not remove ChatGPT or GitHub
provider dependencies. The optional `--readonly-worker` command is
restricted to tunnel policy; never substitute the unrestricted default
stdio mode.

### One-time activation with rollback

`deploy/relayforge-hot-activate.sh EXPECTED_MAIN_SHA` is a **local-user-only**
one-time bootstrap after the reviewed merge is present on ThinkPad. It refuses
a different commit or dirty tracked checkout, saves the previous release MCP
to private local state, runs a fresh locked release build and offline MCP smoke
tests, restarts the tunnel once, and requires a **fresh** authenticated
control-plane poll. If compilation, testing or tunnel recovery fails, it
restores the previous MCP binary and attempts to restart the service.
A verified new worker is also copied into local state as an initial
last-known-good artifact. This is a recovery best effort, not a substitute
for human physical recovery after a machine/network failure.

Do not execute this bootstrap through an MCP approval-bypass mechanism or
give it API credentials. The operator must review the exact merge and
authorize the one-time service restart separately.
