# Readiness evidence, 2026-10-21

Owning issue: #77, OPEN. No operational readiness claim.

## Scope and result

Prepared existing PR integration, runtime migration/rollback prerequisites and
the first real Python acceptance task. No architecture expansion, runtime or
infrastructure mutation. Original checkout stays at #87's accepted HEAD, clean.
An isolated local clone contains history-preserving rehearsal merges and the
preparation commit. Local `.git` for the original checkout is read-only.

GitHub main revalidated as `98f9cab77778932d9236dc9009f345af9c62ecc1`.
PR #76 remains open Draft at `3c85d9aae390e4a1b34c1bf64a547cf37e6599e9`;
it was neither changed nor incorporated. No prohibited PR was accessed.

Merge rehearsal #84 -> #86 -> #87: no conflicts, no duplicate main changes.
Rehearsal commit `f50bbf3b8daf818a0c15bc17929e483de8092e08`, tree
`6e374c62bf89444d7f60929cdffe95b961b61925`. This is not an accepted release.

Exact source heads and successful hosted runs were re-read through GitHub's
run API, including each run's `head_sha`, `status` and `conclusion`:

| PR | Exact HEAD | Rust / offline run IDs |
|---|---|---|
| 84 | a8ba09591fe3c5a008a1300f2c2f2e233f56fecd | 39601796292 / 39601796086 |
| 86 | 6fdb9a902d955d43580bbccedf9755a6887b9c98 | 39605760962 / 39605760751 |
| 87 | 85ba4b84a2dc8e9d0937647f2f36283c1d7c1826 | 39611418413 / 39611418577 |

Source-scope automated ACCEPT evidence (reported separate-context reviews):

- https://github.com/AlexandrShapkin/relayforge/pull/84#issuecomment-6316957300
- https://github.com/AlexandrShapkin/relayforge/pull/86#issuecomment-6316957916
- https://github.com/AlexandrShapkin/relayforge/pull/87#issuecomment-6317796029

All inline review-thread lists were empty. No unresolved blocking source
finding is recorded in that evidence. This session did not conduct a new
independent review or obtain formal human approvals. No separate Security check
was reported in the prior evidence; this is not a security certification.

## Local verification

All Cargo checks used the explicit isolated target
`/tmp/relayforge-readiness-20261021/.build/verification`, never runtime outputs.
Dependencies were available offline; no lockfile or tool installation changed.

| Check | Actual result |
|---|---|
| cargo fmt --all -- --check | PASS |
| cargo clippy --workspace --all-targets --locked --offline -- -D warnings | PASS |
| cargo test --workspace --locked --offline | FAIL: 15 agent tests pass, 3 user-systemd assertions fail in this container |
| cargo test --workspace --exclude relayforge-agent --locked --offline | PASS: includes 114 MCP tests |
| cargo build --release --locked --offline -p relayforge-agent -p relayforge-mcp | PASS |
| python3 -B -m unittest discover -s scripts -p 'test_*.py' | PASS: 25 before preparation, 26 after new baseline test |
| offline_mcp_smoke.py | PASS: restricted discovery, denials, parent pinning |
| offline_development_workflow.py | FAIL CLOSED: NETLINK_ROUTE socket denied by container |
| offline_authorized_development.py | FAIL CLOSED: same Bubblewrap restriction |
| first-task.patch in copied two-file Python workspace | PASS: compile and exactly 2 tests with -I -S |
| git diff --check | PASS |

Agent failures: `inventories_return_bounded_read_only_data`,
`user_units_are_read_only_and_validate_parameters`,
`user_unit_status_returns_fixed_properties_only`. Do not weaken these tests or
change host services/policy to green this environment. Hosted per-PR full suites
pass; combined-tree full hosted CI remains UNVERIFIED.

Reproduce using an explicit isolated CARGO_TARGET_DIR, required commands in
AGENTS.local.md, and both fixtures from docs/development-tasks.md. A compatible
disposable Linux runner with user-systemd and Bubblewrap isolation is required
for the complete suite. The new test only invokes `verify.commands`, never
executes Cargo, runtime selection, deployment or a service.

## Tool and authorization blockers

- `gh` cannot connect to api.github.com in this restricted shell. Read-only
  GitHub connector calls worked.
- RelayForge status/capabilities and GitHub `create_tree` were rejected:
  `MCP tool call requires approval, but approval policy is never`.
  This is session tool enforcement, not owner refusal or a live-host failure.
  No repeated permission request or alternative credential path was attempted.
- Consequently: no PR/issue mutation, remote branch, new hosted run, runtime
  inspection, executable provenance, rollback health or independent recovery
  availability was established. No owner merge authority was granted.
- The next source action is publish this preserved preparation branch for
  combined-tree hosted CI/review using an allowed GitHub write interface.
  Do not merge the rehearsal as a replacement for #84/#86/#87; retain their
  individual history and follow the sequence in thinkpad-activation.md.
- The next operational action is enable an authorized read-only RelayForge
  inspection path or have the independent local operator return the bounded
  private identity/recovery evidence. Then populate exact pins and paths before
  requesting the separate bounded activation approval. No broad deployment
  permission is requested while those prerequisites remain unknown.

Task-specific local grants and external GitHub publication each remain separate
gates after activation. #77 must remain open. The prepared acceptance files
must first be tracked on the selected ThinkPad base; stale proposals are invalid.

## Cleanup inventory

Keep all original branches/worktrees, Draft PRs, historical/runtime evidence and
unknown pre-existing caches. The preparation clone, its local commits and an
exported Git bundle/patch/evidence are retained because remote publication is
blocked. Reproducible isolated Cargo outputs may be removed only after tests
finish, processes release them and the source/evidence exports are verified.
No runtime or other user's files are cleanup candidates.
