# Independent local RelayForge recovery (RDC replacement prerequisite)

This recovery path is **independent of the ChatGPT plugin, Secure MCP Tunnel,
GitHub and RDC while ThinkPad itself remains powered and the local user systemd
manager is running**. It cannot restore power, internet connectivity, a lost
SSH key or a destroyed user home. It does not provide remote emergency
administration of ru0/srv0 and is not complete RDC parity.

## Scope and safety

The operator may explicitly install an opt-in **user** systemd timer:

- Every five minutes, starting three minutes after boot, it executes an
  installed copy of \`relayforge-local-recover.py\` in a constrained oneshot
  unit, separate from the tunnel process.
- It probes exactly two fixed paths: the installed RelayForge MCP binary and
  the previously preserved \`mcp-hot-last-good\` binary. Probe means a
  bounded **offline** JSON-RPC \`tools/list\` request to \`--readonly-worker\`.
- If the installed binary fails the probe, a verified previous baseline may
  be atomically restored under the same development lock used by Git sync and
  release builds. The baseline is **never automatically replaced** with a
  newer build merely because a build succeeded.
- If the user tunnel unit is \`inactive\` or \`failed\`, it may issue a
  fixed \`systemctl --user start relayforge-tunnel.service\` after checking
  the installed worker and local runtime-key file. It never restarts an active
  tunnel just because a heartbeat is stale; network outages are not treated
  as reasons to rotate credentials or repeatedly restart a running daemon.
- It never executes a user-supplied shell command, reads runtime-key
  **contents**, writes SSH files, retrieves GitHub updates, handles production
  services, or exposes private path contents. Actions are audited in a
  0600 private local JSONL file before mutations.

This is a watchdog for **local binary regressions and a stopped tunnel**.
The existing tunnel service already has \`Restart=on-failure\`, but that
alone cannot undo a broken binary across a user-session restart.

## Local opt-in and installation

This procedure has to be executed by the **local ThinkPad operator**, not
through a remote ChatGPT approval. Review the diff and source first:

\`\`\`bash
mkdir -p ~/.config/relayforge
( umask 077; printf 'ALLOW_RELAYFORGE_SELF_RECOVERY\n' > \
    ~/.config/relayforge/allow-self-recovery )
chmod 600 ~/.config/relayforge/allow-self-recovery
cd ~/Projects/relayforge
bash deploy/install-local-recovery.sh
\`\`\`

The installer verifies grant ownership, mode 0600 and exact marker; copies the
fixed source to \`~/.local/libexec/relayforge/relayforge-local-recover.py\`;
installs fixed local service and timer definitions; performs a **read-only**
status check; then enables the timer. It does **not** restart the tunnel.

Check without making changes:

\`\`\`bash
python3 ~/.local/libexec/relayforge/relayforge-local-recover.py check
systemctl --user status relayforge-local-recover.timer --no-pager
\`\`\`

A subsequent \`repair\` call always requires the local opt-in and existing
private state. When it is running, the development lock is acquired
non-blockingly so the guard never races with Cargo or Git deployment.

Disable the guard independently of the tunnel (e.g. before debugging):

\`\`\`bash
systemctl --user disable --now relayforge-local-recover.timer
\`\`\`

Do not remove the known-good baseline or existing runtime credentials until
a separate verified recovery plan exists. Reverting the installed guard does
not remove, stop, or modify the existing Secure MCP Tunnel.

## Required acceptance tests before dropping RDC

1. Validate the timer starts after a real ThinkPad reboot **with the local
   user logged out** (linger must already be enabled).
2. In a controlled maintenance window, simulate an invalid worker binary
   and verify the private baseline restores without breaking a running
   parent MCP session.
3. Simulate a \`failed\` tunnel systemd unit without deleting runtime keys;
   verify the guard retries safely and authenticated control-plane polling
   resumes.
4. Verify a deliberately unavailable internet connection **does not** make
   the guard repeatedly restart an otherwise healthy tunnel.
5. Verify that an unavailable/corrupt baseline causes **no** replacement
   and produces a bounded, redacted failure.
6. Verify on ru0/srv0 that another, genuinely independent management path
   exists if ThinkPad is offline. This local timer does not solve that.

The above are **not** considered completed by green CI alone. CI tests
a disposable local fixture, grant denials, atomic recovery, symlink refusal,
lock contention and unit definitions without touching a real device.

## Read-only verification from ChatGPT

After deploying API revision 7, call `relayforge_workstation_develop`
with `{"operation":"recovery.inspect"}`. It inspects only fixed
`relayforge-local-recover.service` and `.timer` systemd metadata. It
reports whether opt-in and the timer are active, whether a timer trigger
and service completion have been observed, and whether the last exit
succeeded. No journals, unit contents, environment, paths or secrets
are returned. A green result is `verified_last_run`.

This is evidence of a clean **recent systemd run**, not a successful
simulated failure-recovery test or a true external break-glass channel.
