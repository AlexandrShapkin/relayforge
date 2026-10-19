# RDC-independent overnight Codex executor

This is an operator-triggered GitHub Actions run, not ChatGPT Tasks, an
internet-facing executor, a workstation daemon, or an automatic recurring
schedule. Eight small serialized stages run in two disposable GitHub-hosted
jobs, four stages per job. Each stage starts from origin/main, edits at most
one existing file and at most 180 changed lines. Only four read-only
diagnostic modules for Android and MikroTik RouterOS may be modified.

## Activation (requires operator action)

1. Review and merge the executor PR after exact-SHA CI and human review.
2. In the repository's GitHub Actions secrets, set OPENAI_API_KEY. Never put
   it in source, a chat message, a PR or CI output. This cannot reuse local
   ThinkPad Codex sign-in; API usage may incur separate charges.
3. If desired, enable the GitHub repository setting allowing Actions to
   create and approve PRs. The executor creates only Draft PRs and never
   approves them. Without that setting, pushed branches may need manual PRs.
4. In GitHub Actions choose RelayForge opt-in nightly Codex (Draft PR only)
   and manually select Run workflow on main. The workflow has NO cron.
5. Use Cancel workflow to stop it. No resident timer remains.

Codex executes with the workspace-write sandbox and approval policy NEVER.
Its workspace is a disposable copy of source files WITHOUT .git. No GitHub
token, SSH agent, tunnel key or device credential is passed to Codex. The
wrapper copies back ONLY the exact one-file allowlist candidate, then checks
all Git changes for unsafe paths, deletions, symlinks and excessive diffs.

Before pushing, the wrapper performs cargo fmt --check, cargo test
--workspace --locked and cargo clippy. It then uses the short-lived GitHub
Actions token to push a branch and attempt a Draft PR. It never merges,
approves, deploys, restarts a device or mutates production infrastructure.

Important: PRs created using the default GITHUB_TOKEN generally do not
trigger ordinary PR/push CI. The Draft PR must pass independently triggered
exact-SHA checks and review before merging. Green executor tests alone do
not authorize deployment.

The Codex process has a 20-minute timeout; each batch has a 300-minute
deadline. API consumption is charged by the connected API account. The
executor DOES NOT enforce a monetary/token budget. Absence of a key or
runner identity makes it fail closed. This is a source-only, limited pilot,
not a full replacement for interactive desktop access.

Offline checks (no API key required):

    python3 scripts/nightly_codex.py --plan
    python3 scripts/test_nightly_codex.py

Review each branch, Draft PR and GitHub Actions run individually.
