# Arch source verification (Issue #89)

> Issue #110 adds the canonical [pacman lifecycle](arch-packaging.md). The
> operational source TAR below remains historical/offline evidence, not the normal
> installation channel. Only the trusted release job now requests provenance
> write permissions; Arch installed-package verification extends this job.


The `arch-source` job in RDC-independent verification builds the exact checked-out
PR SHA on a disposable GitHub runner. The official Arch image is digest-pinned;
pacman uses the signed 2026-09-25 Arch Linux Archive snapshot. Package versions
and rustc identity accompany the artifacts. Updating either pin requires review.
This is an Arch userspace/ABI build, not an Arch kernel or user-systemd test.
The [Arch Archive](https://wiki.archlinux.org/title/Arch_Linux_Archive) supplies
dated package snapshots. Provenance support follows
[GitHub's action contract](https://github.com/actions/attest-build-provenance/tree/v3).

Existing Rust/Python workspace checks retain their required Ubuntu gates. Ubuntu release
smoke and Jammy bubblewrap integration remain in RDC-independent verification.
Arch reuses MCP tests, operational Python suites and synthetic offline smoke.
No service manager, live host connection, private configuration, credentials,
grants, installed runtime, owner evidence or selector is used by the Arch job.
Native systemd/security gates are unchanged; a container result cannot replace
them. Unsupported native environments must fail or remain unverified.

The version-1 operational source package contains an explicit committed-source
allowlist, the newly built MCP binary, strict runtime manifest, explicit parent
(`--readonly-stdio`) and worker (`--readonly-worker`) roles sharing that image,
and hash/mode seals. `source_package.py verify ARCHIVE --commit FULL_SHA` checks
inventory, member types, modes, schemas, roles and bytes without extraction or
execution. Obtain the archive checksum from trusted exact-head Actions evidence;
an internally consistent seal alone is not authenticated provenance.

This bundle is for offline operational verification. Run its existing synthetic
transaction/attended activation/upgrade tests in a disposable source checkout.
It deliberately contains no host-specific frozen maintenance backend, physical
owner approvals, baseline health receipt or deployment entrypoint. Source upgrade
pins retain their reviewed historical meaning; they are not relabeled as this
build. A usable host package requires a separately authorized and reviewed
adapter, genuine baseline/protected-instance recovery evidence and fresh approval.
Nothing here stages, activates, installs, merges or deploys.

Exact-SHA binary and package archives plus SHA256SUMS are retained seven days.
PR jobs have read-only permissions and no OIDC. Public-repository manual runs on
main additionally attest both archives using GitHub build provenance; verify with
`gh attestation verify ARCHIVE --repo AlexandrShapkin/relayforge`. Other events
and unsupported repositories provide checksums/source identity only, not signed
provenance. No GitHub Release or package-registry publication is performed.

Acceptance: both existing Ubuntu workflows pass at the same source SHA; Arch
build, MCP smoke, manifest/seal negatives and existing offline recovery suites
pass; artifacts identify that SHA. CI is source evidence, never live readiness.
Independent exact-head acceptance remains required before leaving Draft.

## R3 test portability (Issue #89)

The original ignored regression sources were inspected read-only at
`.build/issue89-operational-upgrade-20261025-r3/test_package.py` and
`test_process_roles.py` in the same directory, plus
`.build/issue89-owner-recovery-drill-20261025-dbus-fix/test_timer_trigger.py`.
Only test intent and synthetic fixtures are portable; these paths are provenance
notes, never test dependencies. No private seals, receipts or host evidence are
included.

The bounded port reuses `test_source_package.py` for exact support-source copies,
synthetic seal bytes/modes/inventory, support-code tampering and refusal of receipt
slots even after resealing. `test_attended_upgrade.py` exercises all three
operations through the tracked shared engine entrypoint and rejects integrity
failure before lock acquisition or engine construction. Existing process-role
tests already cover the R3 synthetic process fixtures. Existing unittest discovery,
Arch suite selection and extracted-bundle verification run these tests unchanged.
Acceptance requires focused suites, full Python discovery and the existing native
and exact-head hosted gates. No production implementation or CI job is added.

The original `transition.py`, configured backend and `package_integrity.py` are
host-package adapters, absent from tracked source. Their exact wrapper dispatch,
first-activation exclusion and recovery-template path assertions cannot be claimed
by testing the shared engine. Likewise the typed timer tests call
`owner_drill.timer_trigger`, which exists only in the ignored drill adapter.
Its typed `busctl` GetUnit/uint64 parsing is not the tracked recovery status parser.
Porting those tests would require a separately scoped decision about their original
implementation; no replacement parser, skipped tests or tests of copied code are
introduced here. Timer parsing remains unverified by tracked CI.

Installed provenance/pins, genuine restricted-worker identity, protected baseline
rollback, native user-systemd timer firing/recovery and physical owner acceptance
remain host-only checks. The previously reported failed recovery service also
requires separate diagnosis and authority. Source CI cannot establish these facts
or authorize runtime, service, selector, permission or recovery-unit changes.
