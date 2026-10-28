# Arch Linux package lifecycle (Issue #110)

Optional independently versioned Secure MCP Tunnel packaging and guarded migration:
[managed tunnel](managed-tunnel.md). New releases include both pacman packages;
historical releases retain their original immutable asset inventory.

The core distribution is one `relayforge` x86_64 pacman package, with a separate
optional `tunnel-client` dependency. MCP and
agent share a source/protocol revision and coordinated security gates; splitting
these two small binaries would add version coordination without a separately
supported installation lifecycle. Ubuntu/Debian packaging is future-only. Ubuntu
CI runners remain compiler and integration platforms, not a `.deb` target.

## Package ownership and explicit setup

The package owns `/usr/bin/relayforge-{mcp,agent,user-data}`, the inactive
`/usr/lib/systemd/user/relayforge-mcp-http.service`, public source identity under
`/usr/share/relayforge`, license and this guide. It owns no HOME files, grants,
credential material, runtime selectors, tunnel client or active configuration.
There are no install scripts, privileged post-install hooks or service actions.
Dependencies are ordinary Arch runtime packages; no root daemon is installed.

Installation is **not** authorization. On a separately approved host, obtain the
package and SHA256SUMS from the same immutable Release. Independently verify the
full `source_sha`, exact-head CI links and expected checksum (a checksum downloaded
alongside an arbitrary file is not authentication). Where available verify GitHub
provenance with `gh attestation verify PACKAGE --repo AlexandrShapkin/relayforge`.
Use `pacman -Qip PACKAGE` and `pacman -Qlp PACKAGE` before `sudo pacman -U PACKAGE`.
Standard filenames are `relayforge-PKGVER-1-x86_64.pkg.tar.zst`.

For stdio, an operator can explicitly configure their client to run
`/usr/bin/relayforge-mcp --readonly-stdio`; this does not configure a tunnel or
mutation grants. Agent stdio is a local trusted transport, not a network daemon.
For HTTP, separately review the unit and authorization policy, create a new
owner-private `~/.config/relayforge/http-token` locally, then explicitly run
`systemctl --user daemon-reload` and `systemctl --user start relayforge-mcp-http`.
Enable at login with `systemctl --user enable relayforge-mcp-http` only when
separately intended. No lingering, tunnel registration, network change or grants
are created by the package. Existing local unit overrides take precedence: stop
and reconcile them before activation, rather than silently reusing legacy paths.
Do not reuse old grants/configuration by default. Binding is loopback; external
transport and credential setup remain independently attended host work.

## Update, downgrade and removal

Preserve the current validated package bytes/checksum and independent rollback
channel. Explicitly quiesce the service before updating with `pacman -U NEW`;
package update neither stops nor restarts mapped old processes. Recheck ownership,
unit configuration and pins before an explicitly approved restart and authenticated
functional verification. Do not equate installed bytes with mapped/live bytes.
Repeated install uses the same contract. Path conflicts fail; never use
`--overwrite` or `--nodeps` to bypass them. Missing, corrupt or untrusted archives
are blockers. `pacman -Qkk relayforge` checks owned files after transactions.

Downgrade only with `pacman -U PREVIOUS_VALIDATED_PACKAGE`, verifying the stored
bytes first. It replaces package-owned files, not user state, running processes,
protocol receipts or grants. A package downgrade is not a functional recovery
receipt; repeat independently authorized service/health and compatibility checks.
Supported source compatibility is provisional 0.1.x; breaking source contracts
require a minor version change and migration guidance, not a patch release.

Before uninstall, explicitly stop and disable the opted-in user service and any
separately managed RelayForge transport, from an independent attended terminal.
Use `pacman -R relayforge`; inspect dependencies before considering `-Rns`.
Pacman removes only owned files. It preserves user configuration, credentials,
reports, historical binaries, receipts and unrelated tunnel clients. Run a user
manager daemon-reload afterwards and verify no obsolete process remains mapped.
Neither pacman removal nor this source task performs a legacy runtime reset.

User-data purge is a **separate** optional operation before package removal (or
using the retained reviewed tool afterwards). `relayforge-user-data --file
.config/relayforge/http-token` prints a dry-run plan with a confirmation digest;
repeat with `--confirm DIGEST` and type the requested phrase on an attended
terminal to delete only that file. `artifact-roots.json` may be separately named.
This is intentionally not a recursive HOME cleaner. The tool refuses root,
symlink/non-owned/writable parents, non-private or multiply linked files,
unlisted names, changed identity and non-terminal confirmation. It never reads
credential bodies. Repeated plans for absent files are safe. Stop services first;
concurrent same-UID changes cannot be made atomic with unlink and require local
quiescence. Grants beyond these two files, logs, reports, evidence, service
configuration and recovery state are retained for individual owner review.

## Build and tested artifact contract

`packaging/arch/PKGBUILD` is the canonical recipe. `ci/arch-source.sh`, as an
ordinary user from a clean full Git checkout, creates a `git archive` of committed
source only, injects public source identity and its SHA-256 into a private recipe
copy, then calls `makepkg`. The template checksum placeholder must be rendered by
this wrapper; it never skips source checksums. All Cargo outputs are isolated.
Ignored evidence and HOME are not package inputs. An isolated directory can be
selected with `CARGO_TARGET_DIR` when invoking the wrapper; the recipe itself
uses its isolated makepkg source target directory. Build dependencies are
base-devel, rust, python and git. CI uses the pinned official Arch image and
signed 2026-09-25 archive snapshot; recorded package inventory and `rustc -Vv`
identify the build environment, not a reproducible-build claim.

PKGVER is `SOURCE_VERSION.rFIRST_PARENT_COUNT.gSHORT_SHA`; `vercmp` tests cover
numeric ordering across revision digit boundaries. Full SHA, not the short name,
is authoritative. Release tags use independent SemVer `vMAJOR.MINOR.COUNT`;
COUNT is the monotonically increasing main first-parent revision. Main must not
be rewritten. Source version compatibility and distribution sequence are recorded
separately. Synthetic pkgrel=2 CI packages test ALPM upgrade/downgrade and are
never published; they do not prove recovery from an arbitrary historical release.

Every branch push and PR runs the existing mandatory Rust, Python, functional
and security checks without path filters. Main gets the same complete checks at
its own SHA. Arch CI builds unprivileged, installs the actual assembled package
with pacman in a fresh disposable Arch systemd container, runs installed MCP and
agent checks, authorization/HTTP/security and bubblewrap fixtures, verifies the
actual installed user unit, repeated installation, upgrade/downgrade, archive
failures, both ownership conflicts, removal and separate confirmed purge.
Privileged container integration exists only on the disposable hosted runner,
with no host HOME, runtime, production mounts, credentials or devices exposed.
Existing Ubuntu native and security gates remain mandatory. Skips/unknowns for
required checks block publication. Physical authenticated tunnel and recovery
are host-only attestations; CI proves neither live readiness nor installation.

The release workflow responds only to completed main **push** workflows. A
read-only gate queries both workflow identities, exact source SHA and latest
attempts, requiring Rust `test` plus independent `verify-offline`, `arch-source`
and `sandbox-integration` success. Only its trusted publication job has contents
write and provenance permissions. It downloads the tested Arch run's
bytes, rechecks checksums and CI, confirms a merged main PR/history and the independent exact-head handoff, enforces
monotonic immutable identity, creates an annotated tag and draft release, verifies
all uploaded bytes, then publishes. Release notes use the independently reviewed PR’s “Problem and resulting behavior”
narrative plus explicit installation/compatibility/rollback instructions; missing
narratives block publication. No rebuild or PR/branch publication occurs.
A complete published release is skipped only after deriving its tag/package name
from committed source, resolving the actual remote Git tag to that source, and
checking the exact asset inventory and every asset digest. Historical validation
downloads Release assets, never the original seven-day Actions artifacts or old
CI job results. `SHA256SUMS` must have independently verified GitHub build
provenance from this repository's `release-arch.yml` publisher on `refs/heads/main`,
using GitHub-hosted runners. That authenticated manifest covers the package,
source identity, installed lifecycle evidence and release/build/run records;
rewriting assets and self-reported checksums cannot replace the signed evidence.
The publisher may run on a newer main revision while draining earlier revisions;
the signed manifest binds the package source rather than treating the publisher's
checkout SHA as the package source. Both package and manifest attestations are
required publication outputs. Missing/unsupported provenance fails closed.
Unpublished revisions still require current successful exact-source CI and review,
downloadable tested package bytes and verified input/lifecycle checksums before
attestation or publication. Expired unpublished artifacts require reconciliation.
For existing releases,
any mismatch or partial publication fails without overwrite and needs owner
reconciliation. Workflow concurrency serializes publication. Every completion scans pending
first-parent main revisions since introduction of this policy, oldest first, so
coalesced/delayed completion events do not silently lose a release. An unfinished
predecessor defers later publication; failed exact-main revisions are not released.
The next completion drains eligible pending revisions in order; missing review,
partial releases or bounded-history overflow fail for owner reconciliation. Publication uses a
no-overwrite contract; GitHub server-side immutable-release settings are not
changed by this PR. Distribution authority is the owner's bounded Issue #110
request for automatic accepted-main releases; this task does not itself merge,
publish, deploy or change repository administration. Independent acceptance and
owner merge authority remain separate from author checks. Before merge, the
independent session must record a maintainer-authored PR comment containing the
standalone line `Independent technical ACCEPT: FULL_PR_HEAD_SHA`. A later
`Independent technical REJECT: FULL_PR_HEAD_SHA` revokes it; the latest matching
handoff wins. This records the separate session's review, not GitHub APPROVE,
and must never be posted by the implementing session to certify itself. Missing
handoffs or excessive comment pagination block publication for owner review.

## Attended legacy migration boundary

Do not run a reset from MCP, CI or a remote-only terminal. The physical owner must
first authorize exact scope and establish an independent recovery channel; stopping
the tunnel loses the current chat connection. Before **any** removal, collect a
read-only inventory of loaded/enabled RelayForge units/timers, process executable
identity, selectors, grants/configuration paths (metadata only), pacman ownership,
independent tunnel-client dependencies and all untouched worktrees. Store a
restrictive owner-local offline backup of unique binaries, receipts and
configuration; do not attach credential bodies to GitHub or Releases.

A cleanup manifest must name every proven-owned legacy file/service and expected
UID, mode, inode/digest and pacman owner. Review a dry-run, reject unknown/shared
ownership, symlinks, identity changes or missing backup/rollback evidence. Apply
only from the attended physical terminal with a fresh explicit confirmation of
that exact manifest and service list. Stop/disable only those proven
RelayForge-managed units/timers. Never recursively remove HOME, checkouts,
`.build`, retained evidence, historical recovery images, Codex processes,
unrelated tunnel clients/credentials, shared services, VPN or SSH. This PR adds
no executable legacy remover: the private inventory/backup and reviewed manifest
are prerequisites for a separately bounded implementation, not guessed inputs.

After approved removal verify no legacy RelayForge units/processes/managed files
remain active, preserved data and independent connectivity remain intact, and
record private receipts. A fresh package install, new local authorization,
authenticated tunnel acceptance and independent rollback tests require their
own attended scope. Issue #89 remains open until approved authenticated artifact
behavior passes on that installation. Failed historical R3 provenance remains
failed; source packaging does not relabel it or erase its evidence.


## Ubuntu release extension (Issue #116)

Source revisions containing `ci/ubuntu_release.py` additionally require the
independent `ubuntu-release` job and publish the verified Ubuntu 24.04 amd64
`.deb` and namespaced source/checksum/verification records in the same immutable
release. See [Ubuntu packaging](ubuntu-packaging.md). Historical Arch-only
releases keep their committed-source inventory and authenticated provenance
requirements. Arch package, tunnel-client and installed lifecycle gates remain
mandatory. This extension does not authorize deployment or service activation.

## CI and independent handoff enforcement (Issue #110)

The trusted `Independent review handoff` workflow publishes the commit status
`Independent technical ACCEPT` before merge. It reads only owner-authored PR
comments, never a mutable PR description or PR executable code. After an actual
independent review, the owner relays the report and these standalone lines:

```
Independent technical ACCEPT: FULL_PR_HEAD_SHA
Independent technical ACCEPT base: FULL_REVIEWED_MAIN_BASE_SHA
```

Head changes, base changes, comment edits/deletion and a subsequent exact-head
REJECT invalidate the status. This attests a separately performed review; it
cannot prove the external review occurred and does not grant merge authority.
The implementing session must never manufacture the handoff. Historical release
handoffs retain their existing exact-head contract and audit trail.

**Manual GitHub administration required:** main was unprotected at inspection.
Require pull requests, strict up-to-date branches, and required statuses `test`,
`verify-offline`, `arch-source`, `ubuntu-release`, `sandbox-integration`, and
`Independent technical ACCEPT` (bind to GitHub Actions where supported). Disable
force pushes/deletion and bypass, including administrator bypass where feasible.
Keep the owner merge-authority decision separate. Bootstrap this new trusted
workflow only after independent exact-head review: it cannot execute as a new
`pull_request_target` workflow until installed on main. Do not count absence of
its status during bootstrap as acceptance. Protection/settings changes need
separate owner administration; this source change does not configure them.
Strict up-to-date protection is required to close base-change/status race windows.

Branch pushes with a matching same-repository open main PR at the exact SHA
skip duplicate suites; the PR event runs full checks. Other branch pushes, tags
(Rust), main and explicit dispatch retain their coverage. Opening a PR after
push discovery can still cause two full suites; safety takes precedence over
eliminating that race. Fork PRs run full PR checks. PR base edits rerun PR checks.
No path filters or test assertions were removed. Required status enforcement
must use PR checks, not interpret skipped branch jobs as verification.

Only pinned `just 1.40.0` installation is cached, keyed by OS, architecture and
full compiler identity; only main push saves the cache. Main cannot restore
fork/PR branch cache scopes. Version is checked on every restore. This preserves
the locked-source build on misses and avoids adding a binary download trust root.
Workspace/package outputs are deliberately not cached across trust boundaries:
installed package, sandbox, native and release provenance verification remain
independent. Cache contents are an optimization, never release artifacts.

Both required workflow completion events remain release triggers, but only the
latest successful completion (including rerun attempt identity) scans release
history. Earlier/pending/failed peers defer; a successful retry can recover.
Every elected scan retains both exact-main workflow/job checks, oldest-first
backlog handling, authenticated historical assets and immutable idempotency.
This source task does not rerun publishers or publish backlog releases.
