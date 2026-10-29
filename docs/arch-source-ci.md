# Arch package and source verification (Issues #89 / #110)

The `arch-source` job builds the exact full checked-out source with the official
digest-pinned Arch image and signed 2026-09-25 archive snapshot. Package inventory
and rustc identity accompany artifacts. Updating either pin requires review.
The [canonical pacman lifecycle](arch-packaging.md) is the normal distribution
contract; the operational source TAR is retained for offline verification and
historical evidence, not used as a host installer or a recovery receipt.

Arch construction runs as an ordinary user. A separate disposable systemd
container installs the assembled package with pacman, exercises installed binaries
and the actual user-unit definition, functional/security/HTTP/bubblewrap behavior,
upgrade/downgrade, removal and separate purge. No production paths, credentials,
owner grants, ThinkPad/VPS connection or installed host selector are inputs.
Existing Ubuntu workspace and native sandbox/security gates remain mandatory;
a container success never establishes physical-host readiness.

The version-1 operational source fixture retains its committed-source allowlist,
MCP binary, strict runtime manifest, explicit parent (`--readonly-stdio`) and
worker (`--readonly-worker`) roles sharing that image, and hash/mode seals.
`source_package.py verify ARCHIVE --commit FULL_SHA` checks inventory, member
types, modes, schemas, roles and bytes without extraction or execution. An
internally consistent seal alone is not authenticated provenance. The extracted
fixture runs portable transaction/activation/upgrade regressions; no private
maintenance backend, owner approval or real baseline-health receipt is supplied.

Exact-SHA pacman and operational-source artifacts, environment identity,
SHA256SUMS and the installed lifecycle receipt are retained seven days. Build and
test jobs use read-only permissions without OIDC or persisted checkout credentials.
Only the separate trusted accepted-main release job may attest/publish pacman
bytes after both exact-head workflows pass; it cannot deploy them. Independent
exact-head acceptance remains required before leaving Draft.

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
