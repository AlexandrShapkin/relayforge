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
present/on `main`/free of tracked modifications, uptime, memory available,
whether the user tunnel service is active and whether a recent
authenticated control-plane poll was recorded. It never discloses
filesystem listings, secrets, environment variables, Git remote URLs
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
