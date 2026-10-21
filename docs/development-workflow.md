# Bounded development workflow evidence (#85)

This phase is source-only. #77 owns runtime migration/rollback; #75 and Draft
#76 own four-project inventory. Neither green CI nor this fixture establishes
ThinkPad readiness. Live capability/status reads in the development session
were denied by the tool approval policy, so the installed revision, grants and
current tunnel health are unverified.

| Capability | Available implementation | Tested evidence / remaining block |
|---|---|---|
| Discover/read fixed repository | `repo.list`, `repo.read`, `repo.status` | Real MCP fixture reads tracked source; private/untracked/traversal reads denied |
| Four-project inventory | Draft #76 | Preserve existing review evidence; not on main or independently accepted here |
| Source editing | `repo.write`, separate static local grant | Fixed checkout only; **blocked** for safe isolated task development |
| Task-scoped editable worktree | Not implemented | Next source dependency: exact base, repository/path allowlist, no shared checkout mutation |
| Expiring source authorization | Not implemented | Static grant is insufficient for bounded task expiry; no grant created by this task |
| Isolated build output | #78 merged | Explicit isolated Cargo target; runtime activation remains separate |
| Build edited repository | `build.start` requires clean main | **Blocked**: existing writes and clean-main builds do not compose |
| Offline development experiment | Existing bubblewrap worker | Real source copy/edit, Python compile/test, diff and disposable Git commit pass |
| Logs / exit / durable result | `job.status`, `job.output`, `job.chain.*` | Real worker/MCP success, exit 7, timeout 124 and chain handoff checked |
| Duplicate / interrupted attempt | Persistent single-use `worker.claim` | Concurrent claim test; repeated/previously crashed attempts refused; no automatic replay |
| Cancellation | Existing `job.stop` / systemd unit | Live cancellation unverified; fixture kills only its own worker process group |
| Resource limits | Worker unit time, memory, CPU, process and file limits | Source-configured; systemd enforcement requires separate acceptance |
| Reconnect | Durable receipts read by fresh MCP clients | Local process reconnect checked; actual Secure MCP Tunnel disconnect unverified |
| Commit / PR | Disposable sandbox commit; external authorized GitHub workflow | Fixture has no credentials/network; durable PR publication remains outside sandbox |
| Recovery / activation | Read-only artifact preflight and operator procedure | Known-good rollback provenance/live probes and independent ACCEPT still required |
| Autonomous supervision | Codex Smart #163 | No interface change needed for this milestone; #164 remains inactive |

## Reproduce without a device or grants

Use a disposable Linux environment with Git, Python 3, bubblewrap and working
unprivileged user namespaces. Missing sandbox support fails the test; there is
no host-shell fallback. No systemd service or local grant is created.

```sh
CARGO_TARGET_DIR="$PWD/.build/verification" cargo build --release --locked -p relayforge-mcp
python3 -B scripts/offline_development_workflow.py "$PWD/.build/verification/release/relayforge-mcp"
```

The fixture creates a temporary HOME, tracks one source file, and uses actual
restricted MCP calls for inspection/denials. It seeds private job inputs and
invokes the real fixed worker CLI directly, deliberately bypassing systemd
scheduling. Inside bubblewrap the worker copies only the allowlisted source to
its disposable `/tmp`, edits it, compiles/tests, checks the diff and commits.
The structured stdout contains the diff, commit and exit evidence. The commit
objects disappear with the sandbox: this is not a recoverable published PR.
The task's GitHub PR is separate source-development evidence.

All host fixture source bytes and mtimes must remain unchanged. Failure,
timeout, sequential handoff, duplicate attempt and killed-worker cases use real
workers. Fresh MCP processes read the resulting receipts. The crashed attempt
has no terminal success and cannot run again. There is no expiring permission
test because that contract is not implemented; testing a fake expiry would
not establish authorization enforcement.

The integration job pins the disposable `ubuntu-22.04` image. The previous
`ubuntu-latest` run used Ubuntu 24.04.5 and failed inside Bubblewrap's loopback
setup (`RTM_NEWADDR: Operation not permitted`), consistent with Noble's
[restricted user namespace capabilities](https://documentation.ubuntu.com/release-notes/24.04/).
Runtime flags remain `--unshare-all`; AppArmor/sysctls are not relaxed. The
separate integration job builds its own exact-head binary for Jammy's libc;
full workspace/native Python checks retain the current Ubuntu image. GitHub
[retires this runner on April 17, 2027](https://github.com/actions/runner-images/issues/14254);
replace it with a verified compatible disposable environment before retirement.
The Rust checks workflow also continues to use the current Ubuntu image.

Real negative tests compare host/sandbox network namespace identities, require
only loopback, and reject external IPv4/IPv6 TEST-NET routes and private host
files. Test-only libseccomp fault injection denies namespace creation to the
actual worker/Bubblewrap subprocess while leaving ordinary fork/exec available.
That attempt must publish a nonzero receipt, never execute its script on the
host, and remain non-replayable. Missing libseccomp or unavailable isolation
fails verification; no test is skipped or replaced with a mock.

Claims are synced before execution and retained through terminal/unknown
states. An ambiguous crash requires inspection and an explicitly new job, not
resuming or deleting the claim to replay scripts. Existing conservative
`job.remove` checks still govern cleanup; no automatic cleaner is introduced.
An old installed worker cannot gain this protection from source changes.

## Operator gates and next acceptance

Follow [the existing migration procedure](runtime-artifacts.md), in order:
independent ACCEPT and exact-head CI; trustworthy candidate pins; independently
verified distinct rollback with restricted-worker and actual tunnel health
receipts; separate owner authorization naming artifacts/services/window and an
independent recovery channel; staged frozen-byte preflight; approved atomic
selection/restart; actual authenticated reconnect and executable identity checks.
If any prerequisite is missing, activation is blocked. This task performs none
of those runtime mutations and cannot verify rollback health remotely by fiat.

The next source milestone is an isolated editable repository workspace with a
versioned, narrowly scoped, expiring authorization and fixed offline build/test
profiles, reusing the current worker/receipts. Then extend this fixture through
that API, including expiry, stale-base, concurrent edits, cancellation and
recoverable diff export. GitHub publication stays in the authorized external
workflow; credentials must not enter the sandbox. After independent review and
separate live authorization, perform the real ThinkPad/tunnel end-to-end test.
Full operational readiness requires that real execution to succeed.
