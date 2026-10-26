# Arch Linux package lifecycle (Issue #110)

The canonical distribution is one `relayforge` x86_64 pacman package. MCP and
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
write and optional provenance permissions. It downloads the tested Arch run's
bytes, rechecks checksums and CI, confirms a merged main PR/history, enforces
monotonic immutable identity, creates an annotated tag and draft release, verifies
all uploaded bytes, then publishes. No rebuild or PR/branch publication occurs.
A complete existing release is skipped only when exact inventory/bytes match;
any mismatch or partial publication fails without overwrite and needs owner
reconciliation. Workflow concurrency serializes releases. Publication uses a
no-overwrite contract; GitHub server-side immutable-release settings are not
changed by this PR. Distribution authority is the owner's bounded Issue #110
request for automatic accepted-main releases; this task does not itself merge,
publish, deploy or change repository administration. Independent acceptance and
owner merge authority remain separate from author checks.

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
