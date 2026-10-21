# Local recovery after runtime/build isolation (Issue #77)

This is a source proposal, not an installed upgrade. The existing installed
watchdog and its grants/units are unchanged by the PR. Migration requires the
separate owner-controlled procedure in [runtime artifacts](runtime-artifacts.md).

The revised watchdog reads the fixed runtime/current selector, validates the
versioned artifact manifest/digest and frozen file permissions, probes a pinned
restricted worker, and may start an
inactive/failed tunnel under the existing local opt-in. It never restores,
installs, copies or selects executable bytes. Unknown/active service state is
left untouched. Invalid/missing artifacts fail closed with an operator-rollback
requirement. Content hash verification is not a live MCP or tunnel health claim.

Historical `mcp-hot-last-good` and `mcp-before-hot-activation` files are preserved
but neither executed nor called proven v8. Rollback requires independently
verified source/digest and health evidence plus separate owner permission.
The updated unit can write only the existing private state directory, not
Cargo output or runtime artifacts. Installing its helper/unit is a separately
approved local interactive step and refuses an unmigrated launcher/runtime.

Run `python3 -B scripts/test_local_recovery.py` for temporary-fixture tests.
No real services or grants are changed by those tests. Hosted CI also runs
artifact/rollback/isolation tests. A positive recovery artifact check is not
independent ACCEPT or evidence that these source changes are installed.
