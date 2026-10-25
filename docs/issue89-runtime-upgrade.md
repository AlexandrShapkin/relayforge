# Issue #89: selector-only attended upgrade source

This is source preparation, not an installed transition package or activation
approval. Base: `f279914b17a0ed3e1b58f89ff7c8e4c366ffb13e`. Owning task:
[#89](https://github.com/AlexandrShapkin/relayforge/issues/89).

Scope: `deploy/attended_upgrade.py` reuses the exact-state journal in
`activation_transaction.py` and the independent scheduler, lock, authenticated
health and physical-owner tunnel acceptance mechanisms in
`attended_activation.py`. The new engine changes only `current` and restarts the
already installed HTTP/tunnel pair within a future approved transaction. It
records `previous` as an unchanged journal target; it never repoints it to make
a historical image into rollback authority. All images remain installed.

Non-goals: deployment, repairing/installing units or launchers, staging artifacts,
root approval, changing grants/credentials, network changes, removing the legacy
watchdog guard, merge, or claiming #89's end-to-end live acceptance. The installed
`issue77-maintenance.conf` with `ExecStart=/usr/bin/false` is intentional. Both its
bytes and its loaded override must remain unchanged; its recurring timer is not
this transaction's recovery mechanism.

## Pins and independent evidence

Candidate CI artifact: **12583938383**; source
`52387f09f661dd587c202e726430ceded44255ab`; MCP SHA-256
`f38f691e668fdd15d14a12f5794219957df686878fa52c8d243e4bd6842732c8`.
Baseline source: `4b3c0b7087d45707ca3fe2ae8d875c1ade6d2eaf`; MCP SHA-256
`a3bee8cfc3dd72cc26382af265dd6e84d4f34e7eb038c1202ab45ead8e6493f5`.
These are fixed engine pins, not discovered from a mutable selector.

Read-only verification of retained candidate and canonical installed baseline
confirmed these manifest/byte identities during source preparation. No executable
was run. Prior Issue #89 preparation records CI run 40155263306 and independent
source acceptance for the candidate; this does not approve this transaction.
No fresh independent rollback-health receipt has been established here.
Preflight must remain blocked until one exists. Historical `previous`, active
services and matching hashes do not substitute for that receipt.

The existing exact-pin rollback receipt schema is required unchanged. A separate
private evidence document has exactly `artifact_id` (integer), `candidate` and
`baseline` (two-element commit/digest arrays), integer `observed` and `expires`
Unix seconds, and `independent_review=true`, `recovery_test=true`. Observation
must be within one hour, expiration must cover the full transaction window and
be within two hours of observation. The new sealed package must pin both evidence
files and their independently established provenance. These ordinary local
metadata files are neither signatures nor authorization. This source never
creates them or converts a missing check into a positive receipt.

## Package boundary and transaction

A future independently reviewed package must configure a **new** attended backend
and have its sealed `transition.py` call
`attended_upgrade.run(backend, rollback_receipt, evidence)`. The source engine has
no auto-running deployment CLI. Do not call the old activation entrypoint, reuse
the frozen first-activation package, or repin its historical files in place.
Its `sealed()` must cover the engine, dispatcher, all support/probe code, pins,
receipts and preservation snapshot. Reuse the existing `arm`, `disarm`,
`recovery_templates`, `locked`, `local_health`, `wait_health` and `remote`
mechanisms; the new dispatcher must route `recover --attempt ID` back into this
engine. The backend's old `ready`, `invariant`, `activate` and `rollback` are not
used. Existing private lock/attempt directories, tools, manager and lingering
must already be available; this engine does not bootstrap host policy.

`upgrade-preserved.json` is a private 0600, at most 1 MiB sealed inventory with
exactly `roots` and `objects`. Roots, in order, are the ordinary owner's
`.config/relayforge`, `.config/tunnel-client`, user unit directory and runtime
`artifacts` directory. Every descendant and root is recorded by absolute path:
directories as `{"directory":MODE}`, regular files as `{"mode":MODE,"sha256":HASH}`,
links as `{"link":LITERAL_TARGET}`. No credential bodies enter the snapshot.
Missing/extra objects, ownership, bytes, modes or loaded unit/drop-in changes
block the transaction. Only exact journal-bound per-attempt scheduler files and
enablement links may temporarily extend that inventory. Activation checks every
artifact, including the candidate. **Recovery excludes only the exact rejected
candidate directory and its descendants from inventory comparison**, and
never reads or requires that candidate's image/manifest. It still validates
sealed recovery code, a healthy frozen baseline, all other artifacts, the
protected configuration, launchers, loaded units and allowed selector states.
Corrupted candidate bytes are retained as evidence, never repaired or deleted.

Symlinks are **not** authorized inside credential/grant/transport configuration
or any artifact tree, even if they appear in the sealed snapshot. The only
static inventory symlinks allowed are systemd enablement links directly in
one-level `.wants` directories under the protected unit directory, whose
lexically resolved targets must be same-named, owner-safe ordinary unit files
directly in the protected unit directory and included as hashed objects in the
sealed snapshot. Per-attempt recovery links remain separately bound to exact
scheduler templates and journals. The fixed installed unit inventory remains
in the backend's sealed maintenance manifest.

The bounded implementation/verification plan is:

1. Validate sealed inputs, inventory, both frozen artifacts, current baseline,
   independent fresh rollback evidence and authenticated baseline worker/tunnel
   health under the shared read-only lock. Reject unfinished attempts.
2. Under the exclusive lock and process deadline, ask the physical owner for an
   attempt-specific approval naming both pins, scope and deadline. Approval must
   complete within 60 seconds. Recheck after approval.
3. Fsync a private exact-state journal, then arm and verify a distinct persistent
   per-attempt calendar recovery timer **before** selector mutation. This uses
   the existing scheduler's durable enablement link and separate process.
4. Atomically replace and fsync `current`; restart only the approved service pair.
   Require mapped executable identity, HTTP authentication rejection/success,
   fresh authenticated tunnel poll and restricted worker checks through the
   existing probes. Obtain the existing independent physical-owner tunnel
   confirmation; recheck health, inventory, selectors and deadline.
5. Commit with the existing durable commit guard before disarming recovery.
   Exceptions/timeouts trigger exact-baseline rollback with a separate bounded
   foreground recovery budget. A crash leaves independent scheduled recovery.
   Failed rollback/restart/health retains the journal and scheduled evidence.
   Foreign selectors are never overwritten; committed attempts are never
   automatically rolled back, including after failed timer disarm.

The acceptance window is 20 minutes with a 90-second margin. Scheduled recovery
uses the existing 180-second service limit, persistent calendar timer, bounded
restart policy and shared lock. A powered-off user manager cannot recover until
it runs again. A separately tested physical recovery channel remains mandatory.
A failed arm happens before runtime mutation. Abandoned pre-arm attempt evidence
is retained and may require attended diagnosis; it is never silently deleted.

## Verification and remaining gates

Disposable tests cover approval rejection, stale selectors, immutable inventory
and guard, missing receipts, exact baseline restoration **after the rejected
candidate has disappeared**, failed arm/restart, timeout, SIGKILL with
independently reopened recovery despite candidate damage, restricted systemd
enablement symlinks and denied sealed symlinks escaping credential/grant roots,
and commit/disarm failures.
The existing transaction suite additionally tests every commit durability failure
and crash between write, rename and fsync. Hosted native/security checks remain
mandatory; fixture success is not platform or live-health evidence.

Activation remains blocked on a newly sealed/reviewed package and dispatcher,
independent exact-pin baseline provenance and fresh restricted-worker/authenticated
tunnel receipts, independent recovery drill/channel, separately authorized
staging of the candidate, exact-head transaction review and CI, and fresh physical
owner approval for the bounded interruption/reconnect. No such approval is
requested or supplied by source work. After a separately approved activation,
#89 still requires one-time directory authorization, original AUTHORIZATION.md
read, path denial, audit and revocation proof through authenticated MCP.

Release/milestone: N/A, source-only operational preparation. No installation or
live readiness is claimed. Preserve the source worktree for its Draft PR and
all pre-existing ignored evidence. Cleanup requires provenance/inventory review;
no existing artifact is obsolete merely because this source was written.
