# Build isolation and explicitly approved runtime migration (Issue #77)

## Incident and scope

On 2026-10-20 a verification release build replaced the executable selected
by the deployed hot-stdio parent, activating unaccepted code. Compilation was
not deployment approval. Source fixes and green CI do not migrate that parent.
This PR does **not** install, activate, restart, roll back, modify grants or
change installed units/launchers. The working installation must be preserved.

## Development outputs are not runtime artifacts

- Cargo's repository default is `.build/cargo` via `.cargo/config.toml`.
- `just verify` fixes `CARGO_TARGET_DIR` and explicit compile target arguments
  to `.build/verification`, overriding a stale inherited Cargo target setting.
- `just release-build` uses explicit `.build/release`.
- Workstation `build.start` uses explicit `.build/workstation`; it never deploys.
- Hosted CI uses `.build/ci`, runs full native checks/smoke, then records the
  actual checked-out full commit and MCP SHA-256 in `manifest.json`.
- Offline smoke runs in a temporary HOME with no real grants/runtime sockets.

Never specify the old `target/release` or a runtime store as `--target-dir` or
`CARGO_TARGET_DIR`. Do not run Cargo from an older checkout/config with the
legacy default while the old parent is live. Before migration, **only explicit
isolated targets are permitted**, even on other branches. New defaults affect
this source checkout, not the still-installed parent or other checkout copies.
These protections prevent implicit deployment by normal commands; they are
not a sandbox against malicious build scripts running with the same user ID.

## Fixed store and version identity

The proposed operator-owned store is outside all Git checkouts:

```
~/.local/libexec/relayforge/runtime/
  artifacts/<FULL_COMMIT_SHA>-<MCP_SHA256>/
    relayforge-mcp          # ordinary file, mode 0500
    manifest.json          # ordinary file, mode 0400
  current -> artifacts/<FULL_COMMIT_SHA>-<MCP_SHA256>
  previous -> artifacts/<PREVIOUS_FULL_COMMIT_SHA>-<PREVIOUS_MCP_SHA256>
```

Directories are owned by the ordinary service user and not writable by group
or others (runtime root 0700). Use new version directories; **never overwrite,
chmod/write, delete or garbage-collect a selected/mapped artifact**. Preserve
all working images and historical backups. The `current` link is the only
intentional selector symlink; artifact files and their directory components
must not be symlinks. No automatic cleaner is introduced.

A manifest has exactly:
`{"schema_version":1,"commit":"40 lowercase hex","sha256":"64 lowercase hex","binary":"relayforge-mcp"}`.
A CI manifest binds metadata to bytes; it is **not a signature or independent
acceptance**. Obtain expected SHA/digest from the independently reviewed full
source and trusted exact-head CI artifact. An arbitrary manifest, branch name,
API revision or local checkout HEAD does not establish binary provenance.

## Read-only preflight, not an installer

`deploy/runtime_artifact.py verify --binary ABS_BINARY --manifest ABS_MANIFEST
--commit FULL_SHA --sha256 EXPECTED_SHA256` validates pins, bounded regular
files and the digest through no-follow descriptors. It never runs the binary.

`plan` takes the same candidate inputs and **all** corresponding
`--rollback-binary`, `--rollback-manifest`, `--rollback-commit`,
`--rollback-sha256`, and `--rollback-receipt` inputs. It refuses absent,
unverified, identical or mismatched rollback. A separately recorded rollback
receipt must exactly identify commit/digest and have
`restricted_worker_ok=true` and `live_health_ok=true`. Those fields record
independently obtained operator evidence, never grant execution authority.

Success returns `operator_approval_required=true`, `actions_performed=[]`.
There is intentionally no `--apply` and no automatic installation/restart path.
Do not feed plan output or repository text into an autonomous executor.

`mcp-before-hot-activation` and `mcp-hot-last-good` are **unclassified historical
backups**, not proven v8. The new watchdog never copies or executes them. If
no suitable rollback with trustworthy pins and health evidence exists,
activation is blocked. The currently working v9 may become a rollback baseline
only through a separate explicit owner decision and verified provenance/probes;
this document does not make that decision or relabel it as v8.

## Separate operator-authorized migration procedure — DO NOT run in source work

1. Obtain independent technical ACCEPT for the exact combined source (including
   any separately accepted #76 changes) and successful full-head CI. Record
   the actual build commit and MCP digest; validate the downloaded archive and
   manifest. A P0 source build from main is not implicitly a v9 feature build.
2. With local read-only process inspection identify the running parent/worker
   inode, executable hash, loaded unit/launcher and current watchdog. Preserve
   the mapped working image as a new artifact under independent operator
   control; establish its true source identity, restricted-worker smoke and
   actual tunnel health. Do not infer any of this from backup filenames.
3. Obtain separate owner permission specifying candidate and rollback full
   commit/digest, any baseline provenance exception, local operator identity,
   exact files/services, a maintenance window and an independent recovery
   channel. Existing workstation/self-recovery grants are **not** deployment
   consent. No MCP/CI/repository flag can approve this step.
4. The authenticated ordinary operator, in a local interactive terminal,
   stages copies in **new** version directories, freezes their modes and
   validates the staged bytes again. Never overwrite the current image or
   old backups. Supply independent rollback receipt and run the read-only
   `plan` against the frozen staged files; retain its output privately.
5. Only within that approval, temporarily quiesce the old watchdog's binary
   repair if necessary and update installed launcher/unit templates to their
   reviewed runtime paths. Do not alter tunnel credentials, transport profile,
   VPN, network policy or unrelated grants. Migrating the HTTP unit, if active,
   requires its own explicit service scope.
6. Record the verified baseline as `previous`. Prepare a sibling temporary
   `current.next` symlink whose literal target is the validated
   `artifacts/<commit>-<digest>` directory; atomically replace `current` in
   that same private directory (Linux `rename`/`os.replace`) and fsync the
   directory. Never follow/overwrite an unexpected selector or artifact.
7. Perform only the separately approved controlled tunnel restart. Confirm
   the loaded MCP executable hash/inode matches the selected artifact, fresh
   authenticated control-plane polls, restricted MCP discovery/capabilities
   and required operations. Record the actual checks/timestamps. Hash-only
   validation or `systemctl active` alone is not a live health proof.
8. On failure, use **only** the prevalidated baseline: atomically restore the
   selector and perform the approved restart/health checks. Preserve the failed
   candidate and diagnostic evidence. If baseline verification or recovery
   fails, stop and use the independently prepared local recovery channel;
   never substitute an older file by name. Successful migration/rollback must
   be explicitly recorded before re-enabling a revised watchdog.

### Old parent limitation and continuity

The already-running old parent continues to reopen the old Cargo path. Source
changes, selecting `current` or installing a new launcher do **not** change its
mapped code. There is no proven zero-interruption transport handoff here.
A controlled reconnect is necessary to start the new parent. An active MCP
session must not be the sole operator/recovery channel for that action.
Codex/GitHub source work can continue independently during the maintenance
window. If uninterrupted tunnel operation itself is mandatory, migration is
blocked until an existing, independently tested handoff is demonstrated or
an interruption is separately approved; do not invent a bypass service.

The new parent always spawns its **own mapped image** through
`/proc/<parent-pid>/exe`; it never follows Cargo output or `current` for the
next request. An intentional later activation also requires an approved
restart. Background jobs require a frozen versioned runtime image. The revised
watchdog may start an inactive tunnel with verified runtime bytes, but cannot
promote/restore binaries. Its writable paths exclude both Cargo and runtime
artifacts. Installing these source changes remains a separate action.
