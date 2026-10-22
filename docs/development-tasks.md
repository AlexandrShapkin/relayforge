# Initial authorized development tasks (#85)

Source-only, version 1: one fixed repository (`relayforge`), at most four
`scripts/**/*.py` files, and one offline profile (`python-stdlib-v1`). This is
an isolated editable sandbox workspace using existing job IDs, workers, status,
logs, cancellation and receipts. It neither edits the shared checkout nor
creates a second executor. It does not implement a full persistent Git worktree,
Cargo dependency provisioning, automatic GitHub publication or autonomous Codex.

## API and immutable proposal

Use `relayforge_workstation_develop`:

- `development.prepare`, with exactly `parameters`: `schema_version=1`,
  `repository="relayforge"`, full lowercase `base_revision`,
  `profile="python-stdlib-v1"`, and `edits`.
- Each edit has exactly `path`, `before`, `after`. Paths are unique, public
  Python paths below `scripts/`, without hidden/traversal components. Each
  text is at most 8192 UTF-8 bytes and empty or newline-terminated. The whole
  canonical proposal is at most 24 KiB. Include unchanged dependent/test files
  explicitly; no other repository files are mounted.
- Preparation checks current HEAD against the exact supplied commit and checks
  every `before` against the corresponding local Git blob. Stale/conflicting
  inputs fail before task creation. Git uses pinned directory descriptors,
  bounded reads, disabled hooks/pager/replacements and forbidden lazy network
  protocols. Linked worktrees and alternate object stores are refused.
- The result has `job_id`, `state="prepared"` and
  `operator_task_authorization_required=true`. Preparation stores immutable
  input records, not edited source. There is no proposal-overwrite operation.
- `development.inspect`, with exactly `task_id`, returns the retained proposal,
  authorization validity, submission marker and existing job status. Unknown
  execution is not successful execution.
- `development.run`, with exactly `task_id`, validates the local grant and
  current base again, durably records a single submission, then uses the
  existing fixed worker scheduler. Duplicate submissions are refused. An
  ambiguous scheduler outcome retains all evidence; never automatically retry.

Preparation/submission require the existing local development opt-in and audit.
The old broad source-edit grant does not authorize this task API. MCP cannot
write, approve or extend a task grant. Read-only inspection requires no new grant.

## Separate local authorization; do not create it during source work

After the #77 runtime/rollback gates and separate owner authorization, the actual
local operator reviews the full immutable proposal and can create a regular,
owner-held 0600 file at the fixed location:

`~/.config/relayforge/task-authorizations/<job_id>.json`

The directory must be private 0700. All ancestors are opened without following
symlinks; files must be regular, single-link, owner-held, private and bounded.
The exact JSON keys and values are:

```json
{
  "schema_version": 1,
  "job_id": "<returned job ID>",
  "repository": "relayforge",
  "base_revision": "<exact 40-character source commit>",
  "profile": "python-stdlib-v1",
  "paths": ["scripts/example.py", "scripts/test_example.py"],
  "operations": ["source.edit", "build", "test", "diff"],
  "issued_at": 1792584000,
  "expires_at": 1792584300
}
```

Paths must exactly match the sorted proposal paths. Times are Unix seconds;
issuance must not be in the future, expiry must be strictly later than now and
issuance, and the total lifetime must not exceed 3600 seconds. These example
times are inert. No AI/CI/repository instruction can approve this local action.
Grant removal prevents a queued worker from starting. During execution, expiry
is an externally enforced lease; immediate cancellation uses existing `job.stop`.

## Execution and recovery

The worker rechecks the task grant, global development opt-in and base revision
before entering Bubblewrap. It mounts only immutable proposal/expiry records
and the compiled-in fixed profile, with no checkout, `.git`, credentials, host
HOME or network. The profile constructs its editable source tree in private
`/tmp`, applies the exact approved edits, compiles Python and discovers/runs
standard-library unittests. Zero discovered tests fails verification. Each
command has a 15-second cap bounded by the authorization expiry; output and file
sizes are limited. Tests changing the approved source produce failure.

A Rust watchdog outside the sandbox also enforces both wall-clock expiry and a
monotonic maximum. On expiry it kills its owned Bubblewrap process; the trusted
separate PID-namespace reaper's parent-death SIGKILL terminates all descendants,
including detached children. The profile cannot disable this by stopping its
Python supervisor. Do not change to `--as-pid-1` or remove `--die-with-parent`.
Expiry is a nonzero receipt (`124`, `authorization_expired`), never a green job.

Existing `job.status` / `job.output` retain exit status and structured stdout:
base commit, profile/interpreter version, build/test status and bounded logs,
source consistency, unified diff and `ok`. Missing or truncated output is not
success. Existing single-use claims protect terminal and interrupted tasks.
An interrupted proposal remains readable for recovery but may not be replayed;
create/review/authorize an explicitly new task. Existing `job.stop` cancels only
its own systemd unit; live scheduling, resource and cancellation acceptance
remain separate. Conservative `job.remove` recognizes only the new fixed
record names as well as existing job artifacts; no automatic cleanup is added.

## Reproduce and publish externally

```sh
CARGO_TARGET_DIR="$PWD/.build/verification" cargo build --release --locked -p relayforge-mcp
python3 -B scripts/offline_authorized_development.py "$PWD/.build/verification/release/relayforge-mcp"
```

The real fixture creates **only temporary** local operator grant files. It
exercises missing/expired/mismatched grants, expiry after submission and during
execution, stale base, conflicting before-text, path/profile/operation denials,
symlinked grants, concurrent single-winner submission, private-file/network
denials, killed worker and stopped-supervisor/detached-descendant expiry.
Repository source bytes and mtimes remain unchanged. Source binaries are
correctly refused by the installed-runtime scheduler; the fixture invokes the
same worker directly after that refusal. It does not pretend to test systemd.

To publish, the authorized external ChatGPT/GitHub workflow reads the exact
proposal, terminal receipt and retained diff, verifies `ok`, exit statuses,
untruncated output and base, then uses the existing GitHub integration to create
a short-lived branch and commit exactly the approved `after` content on that
base. If GitHub main advanced, stop/rebase/retest with a new task and grant.
Open a scoped PR and collect exact-head CI and independent review. No credential
enters the sandbox, and no worker publishes, merges or deploys. Actual live
ThinkPad-to-ChatGPT-to-GitHub acceptance remains unverified until authorized and
executed; offline success cannot establish operational readiness.
