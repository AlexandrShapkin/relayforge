# Independent ru0 production user-service recovery

Status: **source and offline tests only** until locally installed, reboot-tested,
and fault-injection tested on ru0. This guard is a separate mechanism from the
ThinkPad MCP/tunnel watchdog. It does not need ChatGPT, GitHub, RDC, ThinkPad,
the MCP tunnel, or network connectivity to request a local service start.

## Scope

The host-local timer checks exactly two *user* services on ru0:

- assistant-hub-local.service
- personal-xray.service

An enabled, loaded service in inactive or failed state may receive
one systemctl --user start --no-block request per hour. The audit entry is
fsynced **before** that request; even a failed start is rate-limited.
The timer runs at ten-minute intervals with jitter. Active/activating,
disabled, missing, unknown or unrecognized services are left alone.

The guard never restarts healthy services, never stops anything, never uses
sudo, never changes systemd unit contents, never restores application data,
never executes dynamic commands, and does not operate on remote-desktop.
It neither checks application-level health nor repairs host-level internet,
SSH, root system services, databases, firewalls or a powered-off host.
Manual maintenance that requires keeping a service stopped must first disable
this timer. The guard only requests a start; a successful command exit is not
proof of application recovery.

**No remote MCP or CI path may create the opt-in grant or enable the timer.**
Installation is a deliberately separate human-operated ru0 action.

## Preconditions

1. Independently open ru0 through an authenticated provider console, or a
   separately verified management path. Do not treat RelayForge on ThinkPad
   as a break-glass channel when ThinkPad is offline.
2. Confirm the expected ru0 account owns both user units, and that user
   lingering is enabled so the user manager survives logout/reboot.
   The installer checks loginctl Linger=yes and refuses otherwise.
3. Review the commit, Python guard, systemd unit/timer, and installer
   on ru0. Copy them into a controlled local directory with the exact
   deploy/ layout. CI artifacts are not automatically trusted.
4. Validate existing service recovery and rollback with a maintenance window,
   backups and an independent console. The guard does not replace that plan.

## Explicit opt-in and installation (locally on ru0)

Use the real target ru0 account, not root. The local path below assumes
the reviewed repository's deploy/ directory is available in the checkout.

~~~sh
mkdir -p ~/.config/relayforge
( umask 077; printf 'ALLOW_RELAYFORGE_HOST_RECOVERY\n' \
    > ~/.config/relayforge/allow-host-recovery )
chmod 600 ~/.config/relayforge/allow-host-recovery
bash deploy/install-host-recovery.sh
systemctl --user is-enabled relayforge-host-recovery.timer
systemctl --user is-active relayforge-host-recovery.timer
python3 ~/.local/libexec/relayforge/relayforge-host-recovery.py check
~~~

The installer does not start or restart the two production services itself.
It checks hostname ru0, local grant content/ownership/mode, presence of user
lingering, and destination directory safety. It then installs the fixed
standalone worker and timer, and enables the timer. The guard itself checks
the same grant on every repair attempt. Grant and audit files must be private;
unexpected files/symlinks fail closed. No network package downloads occur.

## Acceptance tests before declaring RDC independence

These are *real host* tests, not satisfied by CI:

1. After installing, observe a successful timer completion and its next
   scheduled monotonic run, including after a real reboot and logout.
2. While the guard is enabled and both services healthy, verify **no**
   production start request is audited.
3. During an approved maintenance window, stop one allowlisted service;
   verify the timer requests a start, and verify **actual application
   functionality** independently (not just systemd active).
4. Confirm another recovery cycle within one hour is in cooldown, and
   deliberately broken/disabled units do not cause an unbounded loop.
5. Verify the operator can disable the guard and restore service manually
   through an **independent console** if the guard or ThinkPad is unavailable.
6. Check production backup integrity and an independent provider-level
   recovery path for ru0. Repeat an appropriate scope on srv0 separately.

## Disable / back out locally

~~~sh
systemctl --user disable --now relayforge-host-recovery.timer
~~~

Disabling the timer does not stop any application services and does not remove
the local audit. To remove the opt-in, the local operator may separately
remove the exact ~/.config/relayforge/allow-host-recovery file. Never
auto-delete the audit or recovery evidence as part of a remote repair.

## Control-plane boundary

This guard is *not* a generic production-service MCP controller. It is a
host-local safety prerequisite for a future per-unit, single-use,
operator-approved control plane. Implementing a remote restart/stop tool
before verifying the independent console and restart recovery would widen
the failure blast radius. The existing read-only agent and local pilot
approvals retain their current restrictions.
