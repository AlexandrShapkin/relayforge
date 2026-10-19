# Sequential sandbox jobs on ThinkPad

RelayForge's existing job.start runs one isolated, offline script in a fixed
bubblewrap namespace. The new job.chain.start schedules a **single** bounded
background systemd worker with 2–6 scripts executed sequentially. Script N
receives script N-1's stdout as stdin. A nonzero exit code, missing/malformed
receipt, oversized/non-UTF8 handoff or truncated output blocks every
subsequent step. There is no parallel fan-out or automatic retry.

Example invocation with the existing workstation development plugin:

    {
      "operation": "job.chain.start",
      "parameters": {
        "scripts": [
          "printf 'relayforge\n'",
          "tr '[:lower:]' '[:upper:]'",
          "sed 's/FORGE/CHAIN/'"
        ]
      }
    }

After scheduling, save the returned job_id. Each step uses the same
read-only allowlisted Git-tracked source file mounts as job.start. No live
repository write, Git metadata, SSH identities, network sockets, secrets,
service bus, open desktop, external provider or persistent shared /tmp is
exposed to any step. The only data transmitted forward is the preceding
step's bounded UTF-8 stdout, at most 8192 bytes.

Use the following operations (no schema refresh needed: operation remains a
string; parameters is the existing strict object):

- job.chain.start with parameters.scripts, an array of 2–6 bounded scripts.
- job.chain.status with task_id: current systemd state, count completed, size.
- job.chain.output with task_id and parameters.step (1-based integer):
  private capped stdout/stderr and receipt for that single step.
- job.list lists both ordinary and chained jobs.
- job.stop with task_id stops the fixed transient worker, including a chain.
- job.remove with task_id removes only a finished or safely aged job after
  checking every private artifact; running work cannot be deleted.
- job.output with task_id returns the final step's stdout/stderr on success.

Execution always uses a fixed, installed worker binary and a private
user-systemd unit. Each script is stored as 0600 private immutable input.
Each step gets its own 0600 stdout, stderr and JSON receipt, fsynced to
storage before the next step begins. A final receipt is also written.
A killed worker never silently resumes an ambiguous stage.

Security and limits:

- Existing local 0600 allow-workstation-development opt-in is required
  for job.chain.start, job.stop and job.remove; mutations are pre-audited.
- Maximum 6 steps, 2048 UTF-8 bytes/script, maximum 16 KiB total input.
- Maximum 64 KiB stdout and stderr per step; 8 KiB handoff.
- One chain runs for at most 3600 seconds, subject to the same global job
  capacity of 12 slots. This is a bounded pilot, not 8-hour execution yet.
- Failure and receipt output may include developer-selected script stdout:
  never print or pass secrets into these offline jobs.

**Important distinction:** a chain of offline jobs does not grant Codex or
ChatGPT autonomous internet access, access to GitHub APIs, credentials, or
the ability to create commits and PRs. It makes reliable step-to-step
background execution possible while preserving today's access boundary.
A production-grade overnight coding executor would need a separate,
explicitly authorized narrow GitHub/Codex capability and checkpoint/resume
policy; do not weaken the sandbox to get it.

No RDC or retired ru1 host is involved. Live installation, update of the
ThinkPad MCP binary and fault-injection testing require normal release
verification and permission checks. Source changes in a PR are not proof
that these operations are already available from the deployed plugin.
