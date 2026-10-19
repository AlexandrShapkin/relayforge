#!/usr/bin/env python3
"""One-shot, GitHub-hosted Codex executor. Never runs on an operator's device."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

ALLOWED = (
    "crates/relayforge-mcp/src/android.rs",
    "crates/relayforge-mcp/src/android_health.rs",
    "crates/relayforge-mcp/src/routeros.rs",
    "crates/relayforge-mcp/src/routeros_health.rs",
)
TASKS = (
    ("Android battery edge cases", "Add ONE offline regression test for a missing or malformed Android battery reading. Fix a proven bug only.", (ALLOWED[1],)),
    ("Android discovery", "Test ONE missing, unauthorized or malformed Android device status. Fix a proven bug only.", (ALLOWED[0],)),
    ("RouterOS health parsing", "Test ONE unexpected diagnostic field or corrupted output in read-only RouterOS health parsing.", (ALLOWED[3],)),
    ("RouterOS diagnostics", "Test ONE missing, duplicated or ill-formed field in RouterOS diagnostics.", (ALLOWED[2],)),
    ("Android state anomalies", "Test ONE contradictory charging/battery status case; fix only if verified.", (ALLOWED[1],)),
    ("Android authorization edge", "Test ONE unauthorized device edge case without enabling device writes.", (ALLOWED[0],)),
    ("RouterOS privacy edge", "Test ONE malformed RouterOS output that must not expose private fields.", (ALLOWED[3],)),
    ("RouterOS parser review", "Test ONE previously untested read-only RouterOS parser edge case.", (ALLOWED[2],)),
)
MAX_CHANGED_FILES = 1
MAX_CHANGED_LINES = 180


class Blocked(RuntimeError):
    pass


def run(argv, *, cwd, env=None, timeout=90, check=True):
    result = subprocess.run(argv, cwd=cwd, env=env, timeout=timeout,
                            text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode:
        raise Blocked(f"{argv[0]} failed (exit {result.returncode})")
    return result


def agent_env():
    """Never forward GitHub tokens, SSH agent access or cloud runtime credentials."""
    key = os.environ.get("OPENAI_API_KEY", "")
    if not key:
        raise Blocked("OPENAI_API_KEY is not configured")
    if not os.environ.get("GITHUB_ACTIONS") or not os.environ.get("RUNNER_TEMP"):
        raise Blocked("GitHub-hosted disposable runner required")
    return {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": os.environ["HOME"], "LANG": "C.UTF-8", "CI": "true",
            "OPENAI_API_KEY": key}


def safe_prompt(index):
    name, task, scope = TASKS[index]
    return (
        f"RelayForge offline small stage {index+1}/8 — {name}. Task: {task}\n"
        f"Edit ONLY this existing source file: {scope[0]}. At most 180 "
        "added+deleted lines. Add a small focused offline test and fix only "
        "a demonstrated defect. No network, SSH, ADB pairing, production "
        "services, deployment, secrets, remote device operations or config "
        "mutations. Do not modify any other files, Git metadata, hooks, "
        "Cargo manifests, workflows or policy files. Do not commit, push, "
        "create PRs, merge or deploy. If no valid fix exists, change nothing."
    )


def inspect_diff(repo, scope):
    """Validate EVERY dirty path; no rename, deletion, symlink or binary."""
    status = run(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"],
                 cwd=repo).stdout
    if not status:
        return ()
    fields = status.split("\0")
    if fields[-1] != "":
        raise Blocked("invalid status encoding")
    paths = []
    for line in fields[:-1]:
        code, sep, path = line[:2], line[2:3], line[3:]
        if sep != " " or code not in {" M", "M ", "MM", "??"}:
            raise Blocked("rename, deletion or staged mutation denied")
        if path not in scope or path not in ALLOWED or path in paths:
            raise Blocked("changed path outside fixed allowlist")
        if not (repo / path).is_file() or (repo / path).is_symlink():
            raise Blocked("unsafe source file")
        paths.append(path)
    if len(paths) > MAX_CHANGED_FILES:
        raise Blocked("too many changed files")
    numstat = run(["git", "diff", "--numstat", "HEAD", "--", *paths],
                  cwd=repo).stdout
    lines = 0
    for row in numstat.splitlines():
        cols = row.split("\t")
        if len(cols) != 3 or not cols[0].isdigit() or not cols[1].isdigit():
            raise Blocked("binary or malformed diff")
        lines += int(cols[0]) + int(cols[1])
    if lines < 1 or lines > MAX_CHANGED_LINES:
        raise Blocked("diff exceeds budget or is empty")
    return tuple(paths)


def stage(repo, index, run_id):
    name, _, scope = TASKS[index]
    branch = f"autodev/night-{run_id}-{index+1:02d}"
    base = run(["git", "rev-parse", "origin/main"], cwd=repo).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", base):
        raise Blocked("invalid main SHA")
    if run(["git", "status", "--porcelain=v1", "--untracked-files=all"],
           cwd=repo).stdout:
        raise Blocked("dirty checkout")
    run(["git", "switch", "-c", branch, "--no-track", "origin/main"], cwd=repo)
    print(f"Stage {index+1}: {name}, base={base[:12]}, branch={branch}",
          flush=True)
    # Codex receives a throwaway source COPY, never the Git checkout or .git.
    with tempfile.TemporaryDirectory(prefix="relayforge-stage-",
                                     dir=os.environ["RUNNER_TEMP"]) as tmp:
        scratch = Path(tmp) / "src"
        shutil.copytree(repo, scratch, symlinks=False,
                        ignore=shutil.ignore_patterns(".git", "target",
                                                      "__pycache__"))
        original = (repo / scope[0]).read_bytes()
        argv = ["codex", "--ask-for-approval", "never", "exec", "--sandbox",
                "workspace-write", "--skip-git-repo-check", safe_prompt(index)]
        result = run(argv, cwd=scratch, env=agent_env(), timeout=1200,
                     check=False)
        if result.returncode:
            raise Blocked("Codex failed")
        candidate = scratch / scope[0]
        if not candidate.is_file() or candidate.is_symlink():
            raise Blocked("source candidate missing or linked")
        if candidate.stat().st_size > 150000:
            raise Blocked("source file too large")
        data = candidate.read_bytes()
        data.decode("utf-8")
        if data != original:
            (repo / scope[0]).write_bytes(data)
    files = inspect_diff(repo, scope)
    if not files:
        print(f"Stage {index+1}: unchanged, no branch published", flush=True)
        return
    # Host-local, offline checks before push; Codex cannot run gh.
    for command in (
        ["cargo", "fmt", "--all", "--", "--check"],
        ["cargo", "test", "--workspace", "--locked", "-q"],
        ["cargo", "clippy", "--workspace", "--all-targets", "--locked",
         "--", "-D", "warnings"],
    ):
        run(command, cwd=repo, timeout=900)
    inspect_diff(repo, scope)
    run(["git", "add", "--", *files], cwd=repo)
    run(["git", "commit", "-m", f"test: nightly read-only regression {index+1}"],
        cwd=repo)
    run(["gh", "auth", "setup-git"], cwd=repo)
    run(["git", "push", "--set-upstream", "origin", branch], cwd=repo,
        timeout=120)
    description = (
        f"Unreviewed autonomous source-only change, stage {index+1}/8.\n\n"
        f"Task: {name}\nPath: {files[0]}\nBase SHA: {base}\n\n"
        "Offline checks: fmt, tests, Clippy.\n"
        "Human review required. Never automatically merge or deploy.\n"
        "GITHUB_TOKEN-authored PRs may not trigger downstream CI; run "
        "independent exact-SHA checks manually."
    )
    pr = run(["gh", "pr", "create", "--draft", "--base", "main", "--head",
              branch, "--title", f"test: nightly regression stage {index+1}",
              "--body", description], cwd=repo, timeout=120, check=False)
    if pr.returncode:
        print(f"Stage {index+1}: pushed {branch}; PR creation restricted",
              flush=True)
    else:
        print(f"Stage {index+1}: {pr.stdout.strip()}", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true")
    parser.add_argument("--start", type=int, default=1)
    parser.add_argument("--count", type=int, default=4)
    parser.add_argument("--interval-seconds", type=int, default=2700)
    args = parser.parse_args(argv)
    if args.plan:
        for i, (name, _, scope) in enumerate(TASKS, 1):
            print(f"{i}. {name}: {scope[0]}")
        return 0
    if not (1 <= args.start <= 8 and 1 <= args.count <= 4
            and args.start + args.count <= 9
            and 1800 <= args.interval_seconds <= 3300):
        parser.error("unsafe stage count or interval")
    repo = Path.cwd().resolve()
    if repo.name != "relayforge" or not (repo / ".git").is_dir():
        raise Blocked("not a disposable relayforge checkout")
    agent_env()
    run(["git", "fetch", "--no-tags", "origin", "main"], cwd=repo, timeout=120)
    run(["git", "config", "user.name", "relayforge-nightly[bot]"], cwd=repo)
    run(["git", "config", "user.email",
         "relayforge-nightly@users.noreply.github.com"], cwd=repo)
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[0-9]{1,16}", run_id):
        raise Blocked("invalid GitHub run ID")
    blocked = 0
    for index in range(args.start-1, args.start-1+args.count):
        start = time.monotonic()
        try:
            if index > args.start-1:
                run(["git", "switch", "--detach", "origin/main"], cwd=repo)
                run(["git", "clean", "-fd", "--", *ALLOWED], cwd=repo)
                run(["git", "reset", "--hard", "origin/main"], cwd=repo)
            stage(repo, index, run_id)
        except (Blocked, subprocess.TimeoutExpired, UnicodeDecodeError) as exc:
            blocked += 1
            print(f"Stage {index+1}: blocked ({type(exc).__name__}): {exc}",
                  flush=True)
        if index < args.start + args.count - 2:
            time.sleep(max(0, args.interval_seconds
                           - (time.monotonic() - start)))
    print(f"Batch finished: {args.count} stages; {blocked} blocked")
    return 1 if blocked else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Blocked, subprocess.TimeoutExpired) as exc:
        print(f"Executor blocked: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        sys.exit(1)
