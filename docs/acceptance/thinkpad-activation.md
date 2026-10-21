# ThinkPad activation and first development acceptance — issue #77

Prepared 2026-10-21. **Not an activation authorization or a live PASS.**
This supplement instantiates [runtime-artifacts](../runtime-artifacts.md) and
[development-tasks](../development-tasks.md), without installing anything.

## Activation decision — 2026-10-22

**BLOCKED: do not activate.** Combined source is accepted; actual active runtime,
trusted rollback, target compatibility and independent recovery remain unknown.
The October 21 observations below are historical; this record supersedes their
pending CI/review status without asserting any new live device observation.

| Decision field | Status | Evidence |
|---|---|---|
| Combined source | VERIFIED | Independent separate-context review of all 18 changed files against main `98f9cab77778932d9236dc9009f345af9c62ecc1`: **combined source-scope ACCEPT** at `f93982ddc97716cf1d5c96dbcaefa8775234e116`; no blocking findings |
| Hosted exact-head CI | VERIFIED | [Rust](https://github.com/AlexandrShapkin/relayforge/actions/runs/39640121329) and [RDC-independent](https://github.com/AlexandrShapkin/relayforge/actions/runs/39640121420), including verify-offline and sandbox-integration, completed successfully at that SHA; run/job API independently read back |
| Candidate executable identity/build provenance | VERIFIED | Artifact `12365206918`, produced by verify-offline at that exact source; downloaded archive, manifest and actual binary hashes independently checked below |
| Candidate restricted offline health | VERIFIED | Hosted restricted MCP smoke passed before packaging; downloaded exact bytes also passed `offline_mcp_smoke.py` in disposable HOME, including parent-image pinning and denials; no device access |
| Candidate ThinkPad compatibility | BLOCKED | ELF x86-64, interpreter `/lib64/ld-linux-x86-64.so.2`, highest required GLIBC symbol `GLIBC_2.39`; actual ThinkPad architecture/libc and offline health not collected. Jammy sandbox CI builds its own binary and does not prove compatibility of this downloaded artifact |
| Active MCP parent/worker PID, PPID, mapped path/hash/inode | BLOCKED | No authorized device inspection result; clean PR #87 checkout, API 9 and healthy tunnel do not identify mapped bytes |
| Installed launcher/hash, units, recovery helper/timer, selectors, store inventory, ownership/modes/free space | BLOCKED | Installed state not inspected; repository templates are not device evidence |
| Rollback executable/hash/source provenance | BLOCKED | No actual mapped or historical backup bytes collected; no candidate classified as trustworthy rollback |
| Rollback offline and live health | BLOCKED | No pinned artifact or actual restricted-worker/live-health receipts |
| Approved absolute artifact/selector paths | BLOCKED | Actual owner home/store/selectors unverified; illustrative paths below are not approved installed paths |
| Affected launcher/service | BLOCKED | Intended tunnel migration concerns `relayforge-tunnel.service`; actual launcher/executable selection unverified. HTTP unit, if affected, needs explicit separate scope |
| Independent recovery channel | BLOCKED | Operator terminal or independently authorized channel has not been demonstrated usable during tunnel failure |
| Human source merge approval | BLOCKED | All four PRs remain Draft; no merge authorized; formal PR #88 review submissions absent |
| Runtime activation/restart/rollback approval | BLOCKED | No exact artifact/service/window authorization; do not request activation before missing evidence is collected |
| Live task/grants/publication acceptance | BLOCKED | Installed interface lacks development.prepare/run/inspect; no real authorized task completed |
| Release/publication of a distributable | NOT APPLICABLE | This decision does not authorize a release |

Candidate digest chain (SHA-256):

- GitHub artifact ZIP: `05ea5f0eb91ab07fed9cb4278b8d846d8e842cf42785be9c926094282c5a7edc`.
  API digest and downloaded bytes agree.
- Inner tar: `6e0681401ef5af0acd66550b7b1347576e9c8d1d92b76339526cd907d1ef79e6`.
  Included checksum and calculated bytes agree.
- `relayforge-mcp`: `c0d160a2d011e5dc85b9a894c5fae15b8b3c18f65ed98dc5dd8f9bf432c8437d`.
  Calculated bytes agree with manifest commit
  `f93982ddc97716cf1d5c96dbcaefa8775234e116` and manifest digest.

These are trusted GitHub exact-head build/byte associations, not a signed
attestation, ThinkPad installation, or live acceptance. Preserve downloaded
archive/manifest/binary and smoke output privately. Do not install this artifact
until target compatibility and all other activation gates pass.

Independent review examined artifact ownership/selectors/distinct rollback,
durable submission/worker claims and crash denial, failure-closed network and
filesystem confinement, grants/revocation/expiry, editable-workspace boundaries,
external watchdog/descendant termination, retained results, external publication,
PR interactions and build/runtime separation. LOW finding at the reviewed
source's acceptance step 4 (line 199): zero-context fixture versus default-context
returned diff. The step below now requires exact semantic content, not equal
patch bytes. No code changed. Source ACCEPT applies to the pinned combined tree;
this documentation amendment is separate and has no new exact-head CI claim.
No formal GitHub APPROVE or human/runtime approval is implied.

### Required next evidence, before an activation authorization request

The earlier RelayForge capability call was denied with
`MCP tool call requires approval, but approval policy is never`.
No retry or alternate channel is authorized to bypass that session restriction.
There is no established separately authorized ThinkPad terminal in this session.
The smallest next action is an ordinary local operator's read-only inspection,
using the existing procedure below. Initial commands at the **actual ThinkPad**:

```sh
systemctl --user show relayforge-tunnel.service relayforge-mcp-http.service \
  relayforge-local-recover.service relayforge-local-recover.timer \
  -p Id -p MainPID -p ControlGroup -p FragmentPath -p DropInPaths \
  -p ActiveState -p SubState -p Result -p ExecMainStatus
ps -u "$(id -u)" -o pid,ppid,comm
getconf GNU_LIBC_VERSION
uname -m
```

The tunnel MainPID may identify tunnel-client, not MCP. Identify parent/worker
through the actual service cgroup and PID/PPID tree. For each identified numeric
PID, privately run `readlink /proc/PID/exe`,
`stat -L -c 'device=%d inode=%i uid=%u mode=%a size=%s' /proc/PID/exe`, and
`sha256sum /proc/PID/exe` (replace PID locally). Recheck if a process changes.
Privately inspect the returned installed unit paths and launcher, then follow
the existing bounded store/manifest/backup/recovery inspection below. Return
sanitized identities only; no environment, arguments, credentials or profiles.
Do not invoke recovery repair or restart services to collect this evidence.

Evaluate rollback only after those actual identities are recorded. Unknown
mapped bytes cannot become a verified baseline by renaming or adding a manifest.
If no trusted prior artifact is recoverable, separately authorize an isolated
reviewed-baseline build and offline checks, then a bounded baseline live-health
and independent-recovery validation. Build success alone is not rollback health.

Verification/rollback criteria remain steps 1, 5 and 6 below: exact mapped bytes,
authenticated reconnect within 120 seconds, required operations, restricted
health and independent recovery; any mismatch or deadline failure requires the
separately approved pinned rollback, never a guessed backup.

Owner approval still required separately for: source merges in the sequence
below; any baseline live-validation window; exact frozen candidate/rollback,
installed launcher/helper/unit files and selector changes; controlled tunnel
restart/interruption/rollback window (HTTP separately if affected); local
opt-in/task-specific expiring grants; and external publication of the live task.
No blanket permission request is appropriate while artifact/recovery fields
remain BLOCKED. Retarget #88 to accepted main only after #84, #86 and #87 are
individually integrated under owner authority; the rehearsal is not a substitute.

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
   `source_unchanged_by_tests=true`, `ok=true`, and exactly the changed path and
   before/after content specified by `first-task.patch`. Diff context may differ;
   do not require patch-byte equality.
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
