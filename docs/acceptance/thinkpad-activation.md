# ThinkPad activation and first development acceptance — issue #77

Prepared 2026-10-21. **Not an activation authorization or a live PASS.**
This supplement instantiates [runtime-artifacts](../runtime-artifacts.md) and
[development-tasks](../development-tasks.md), without installing anything.

## Verified source and integration sequence

GitHub main: `98f9cab77778932d9236dc9009f345af9c62ecc1`.
Preserve history; after owner merge authorization use merge commits in order:

1. #84 `a8ba09591fe3c5a008a1300f2c2f2e233f56fecd` into main.
2. #86 `6fdb9a902d955d43580bbccedf9755a6887b9c98` into main.
3. Verify #87 still contains #86; retarget #87 to main after #86 merges,
   then merge #87 `85ba4b84a2dc8e9d0937647f2f36283c1d7c1826`.

Do not squash/rebase the dependency away or cherry-pick #86 again into #87.
Recheck main/heads, combined diff and exact-head CI after every integration.
All three remain Draft. Source ACCEPT is recorded in PR conversation comments,
not formal human review or merge consent. No inline threads were returned.

Exact-head successful Rust / RDC-independent workflow runs, respectively:

| PR | Rust | RDC-independent |
|---|---|---|
| #84 | 39601796292 | 39601796086 |
| #86 | 39605760962 | 39605760751 |
| #87 | 39611418413 | 39611418577 |

The isolated integration rehearsal merged all three without conflicts; its
code tree is `6e374c62bf89444d7f60929cdffe95b961b61925` before these preparation
files. None of these changes was already present in main. #78 is already
present and must not be reapplied. Preserve #76 independently.

## Unresolved live evidence — stop before activation

Both `relayforge_status` and workstation `capabilities` were rejected by the
session tool layer: `MCP tool call requires approval, but approval policy is
never`. This is a tooling restriction, not a ThinkPad health result. GitHub CLI
network access also failed; the GitHub connector provided source evidence.

The installed API revision 9, running hash/inode, parent/worker relation,
launcher, watchdog installation, historical backups and recovery channel have
**not** been revalidated. Do not use this workstation/container as a substitute
for the actual ThinkPad. Do not probe secrets, environment or raw command lines.

An ordinary owner at the ThinkPad terminal must privately record:

- Actual service MainPID and MCP child PIDs (fixed service/cgroup inspection).
  For each PID, read `/proc/PID/exe`, `stat -L /proc/PID/exe` and
  `sha256sum /proc/PID/exe`; record device/inode, UID, modes and SHA-256.
  Inspect parent IDs with `ps -o pid,ppid,comm`, not command/environment dumps.
  Compare workers' mapped images with the parent and on-disk legacy image.
- Installed fixed launcher path and sanitized executable selection, loaded
  unit restrictions, recovery helper/timer versions and their hashes. Avoid
  dumping tunnel profiles, credentials or journal lines into public evidence.
- Fixed artifact store inventory, manifest/source pins, ownership, modes,
  no-follow validation, filesystem compatibility and available disk space.
- A physically available local terminal (or an independently already authorized
  recovery channel) usable while the tunnel is disconnected. Demonstrate that
  the operator can inspect the fixed unit and run the approved rollback there.
  The timer alone is insufficient: revised recovery refuses to select binaries.

Unattested `mcp-hot-last-good` / `mcp-before-hot-activation` remain historical
evidence. A filename, local HEAD, API number or manifest alone is not provenance.
Smallest alternative: establish the currently mapped working image's exact
source and trusted build/hash record. If these cannot be independently matched,
reject it as a verified baseline. Separately approve building a reviewed prior
source in an isolated target, validate bytes and compatibility offline, then
approve a bounded baseline live validation/recovery window. A rebuild alone
does not establish live health. No provenance exception is silently granted.

## Required private activation record

Every field below is currently **PENDING**, except source PR pins above:

| Field | Required evidence |
|---|---|
| accepted_source | Final combined full SHA, independent ACCEPT and exact-head CI |
| candidate_sha256 | Digest of extracted MCP bytes, trusted build provenance |
| rollback_commit / rollback_sha256 | Independent provenance, distinct bytes |
| rollback_health | Offline restricted worker/smoke plus actual live tunnel receipt |
| operator_home / UID | Actual absolute ThinkPad home and ordinary service UID |
| launcher | Actual installed fixed launcher and reviewed replacement hash |
| recovery | Available independent terminal/channel, tested command access |
| approval | Owner, exact artifacts/files/services, window, restart and rollback scope |

#87 artifact 12350636801 (run 39611418577, expires 2026-10-28) has archive
digest `05b28e9cbd51b70d01d0dd260792438963ebfad92920017cf54899b400a40232`.
This is the **ZIP digest**, not the MCP binary digest; #87 also lacks #84.
It is not the final combined candidate. No binary digest is asserted here.

Resolve absolute paths from the verified owner home, never from a remote
request: `HOME/.local/libexec/relayforge/runtime/artifacts/COMMIT-SHA256/`
with `relayforge-mcp` 0500 and `manifest.json` 0400; private store 0700,
owned by that UID. The selectors are absolute
`HOME/.local/libexec/relayforge/runtime/current` and `previous`, with literal
relative targets `artifacts/COMMIT-SHA256`. All components except these explicit
selectors must be regular directories/files without symlinks. Never build into
this store or `target/release`; use explicit isolated Cargo targets everywhere.

## Operator procedure after separate explicit authorization

1. Finish the private record; absent pins, health or recovery block the procedure.
   Validate trusted archive/manifest, ELF architecture and target libc; run
   `python3 -B scripts/offline_mcp_smoke.py ABS_BINARY` for each verified artifact
   using its corresponding reviewed source in a disposable HOME. Run restricted
   worker discovery/capabilities with no real grants. Inspect the smoke's result;
   byte verification alone does not prove executable compatibility or live health.
2. Stage copies only into new version directories; fail if destinations exist.
   Freeze modes and fsync files/directories. Preserve mapped legacy bytes/backups.
   Revalidate both frozen artifacts with the reviewed helper:

   ```sh
   python3 -B deploy/runtime_artifact.py verify \
     --binary "$CANDIDATE/relayforge-mcp" --manifest "$CANDIDATE/manifest.json" \
     --commit "$CANDIDATE_COMMIT" --sha256 "$CANDIDATE_SHA256"
   python3 -B deploy/runtime_artifact.py plan \
     --binary "$CANDIDATE/relayforge-mcp" --manifest "$CANDIDATE/manifest.json" \
     --commit "$CANDIDATE_COMMIT" --sha256 "$CANDIDATE_SHA256" \
     --rollback-binary "$ROLLBACK/relayforge-mcp" \
     --rollback-manifest "$ROLLBACK/manifest.json" \
     --rollback-commit "$ROLLBACK_COMMIT" --rollback-sha256 "$ROLLBACK_SHA256" \
     --rollback-receipt "$ROLLBACK_RECEIPT"
   ```

   Variables are owner-recorded absolute paths and trusted pins, not suggested
   defaults. Retain `actions_performed=[]`; this helper does not install/select.
3. In the approved window, quiesce only the identified old binary-repair guard
   if required. Replace only the reviewed launcher/helper/unit files listed in
   the approval. Preserve exact old copies and a recovery script outside the
   tunnel. Do not run tunnel activation/key-creation scripts. Do not change SSH,
   network, VPN, transport credentials, unrelated services or source-edit grants.
4. Validate `previous` identifies the frozen rollback. For selection, hold the
   existing development lock; use a fresh sibling symlink with literal target
   `artifacts/CANDIDATE_COMMIT-CANDIDATE_SHA256`, verify any existing selector
   matches the approved preflight, `os.replace(temp, current)`, then fsync the
   store directory. Fail on unexpected files/targets; never overwrite artifacts.
   Review the exact local atomic-selection command with the populated record
   before approval. No speculative installer is supplied by this preparation.
5. Restart only the separately approved `relayforge-tunnel.service` with
   `systemctl --user restart relayforge-tunnel.service`. Reconnect through the
   existing authenticated Secure MCP Tunnel. Within 120 seconds require fresh
   authenticated polls, restricted discovery, workstation `capabilities` and
   `tunnel.inspect`, and local mapped parent/worker hashes matching the candidate.
   Advertised API currently says 8 in source; the reported installed 9 is not a
   valid version-order test. Require exact executable identity and the operations
   `development.prepare`, `development.run`, `development.inspect`.
6. Failure includes wrong mapped bytes, no authenticated reconnect within the
   approved deadline, missing operations, failed restricted health, unexpected
   service effects or lost independent recovery. Initiate rollback locally:
   revalidate rollback bytes; atomically select the recorded literal rollback
   target using the same guarded replace/fsync; then
   `systemctl --user restart relayforge-tunnel.service`. Repeat identity and
   authenticated health checks. Preserve candidate/failed receipts. If recovery
   fails, stop and use the independent terminal; never guess another backup.
7. Capture UTC times, approved record, selector before/after, process hashes,
   sanitized health/receipt results and operator recovery evidence privately.
   Publish only redacted conclusions. Keep #77 open until actual verification.

Exact absolute paths, digests and selector commands cannot be finalized while
the live prerequisites are unknown. This procedure is intentionally blocked,
not described as executable or rollback-verified.

## First real task through the actual tunnel

Preparation includes `scripts/test_development_acceptance.py` and
`first-task.patch`: add a regression that the offline smoke consumes the same
isolated release output as Cargo. It tests real `scripts/verify.py` behavior,
uses only the stdlib, and needs no network or Git credentials. The initial
test must be tracked on the allowlisted ThinkPad repository before preparation;
do not silently substitute a different repository or an untracked file.
The patch uses zero context; when rehearsing it in a disposable copy, use
`git apply --unidiff-zero first-task.patch`.

After installation and explicit task preparation/authorization approval:

1. Authenticate using the existing tunnel; record exact active identity,
   advertised operations and fresh tunnel health. Select fixed `relayforge`;
   record its clean exact HEAD and tracked file hashes/mtimes locally. Keep
   static `source_edit` disabled. If global development opt-in is absent, its
   separate local approval is required too.
2. Read `scripts/verify.py` and `scripts/test_development_acceptance.py` with
   `repo.read` over MCP. Build `development.prepare` parameters with
   `schema_version=1`, `repository=relayforge`, exact `base_revision`,
   `profile=python-stdlib-v1`, and exactly two edits. `verify.py` before=after;
   test before=tracked text, after=the supplied patch applied to that text.
   Resolve text from this base, not from stale preparation files. Preparation
   creates the immutable isolated-task inputs; the worker creates the editable
   workspace. Save the returned job ID and full proposal durably.
3. Inspect proposal through `development.inspect`. The local operator creates
   the matching private 0600 task grant under private 0700
   `HOME/.config/relayforge/task-authorizations/JOB_ID.json`, with exact base,
   sorted two paths, four operations from development-tasks.md, current issuance
   and expiry five minutes later (never more than one hour). No MCP grant writer.
4. `development.run(task_id=JOB_ID)` once. Poll `job.status` and `job.output`
   through the tunnel. Require finished exit 0, untruncated bounded logs,
   compile/test exit 0, two discovered tests, exact base/profile/paths,
   `source_unchanged_by_tests=true`, `ok=true`, and precisely `first-task.patch`.
   Export immutable proposal, structured output and diff to durable external
   evidence before any cleanup. Unknown/interrupted/truncated results fail.
5. Repeat `development.run` for the same job ID: require denial and no new
   execution. For expiry, prepare a distinct identical proposal, obtain a
   separately reviewed short local grant, wait until its recorded expiry, then
   require submission denial with no worker. Inspect both receipts. Do not
   delete claims or extend/reuse a grant to retry. Running expiry has CI evidence
   but needs a separately scoped live task if live enforcement is to be claimed.
6. Through the separately authorized GitHub interface, create a new branch from
   the exact base, apply only retained test after-text, commit and create a Draft
   PR. Compare against exported diff and run exact-head CI. Never pass GitHub
   credentials/network to the worker. Publication permission is separate from
   local task authorization; without it retain evidence and report that gate.
7. Verify original checkout HEAD/status, source bytes and mtimes are unchanged;
   repeat authenticated capabilities/tunnel health. Check scheduled worker
   resource restrictions/cancellation separately before claiming them verified.
   Retain task receipts and artifact/recovery evidence; remove nothing unique.

PASS requires the actual tunnel calls, real installed worker scheduling, local
grant, retained result, authorized GitHub PR, unchanged checkout and final
accessibility. CI fixtures and locally rehearsing the patch do not satisfy it.
