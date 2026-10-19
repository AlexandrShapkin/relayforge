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
