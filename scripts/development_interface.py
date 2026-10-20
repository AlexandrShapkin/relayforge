"""Offline developer interface. Fixed project profiles, never a project-policy executor.

This is a manually invoked convenience tool. It provides neither Git
provenance attestation nor permission to execute arbitrary source metadata.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).absolute().parent.parent
DOCS = {
    "relayforge": (
        "README.md", "AGENTS.md", "docs/development-without-rdc.md",
        "docs/roadmap.md", "docs/security.md",
        ".github/DEVELOPMENT_INTERFACE.md",
        ".github/ISSUE_TEMPLATE/task.yml", ".github/pull_request_template.md",
        ".github/workflows/tests.yml", ".github/workflows/rdc-independent.yml",
    ),
    "assistant-hub": (
        "README.md", "AGENTS.md", "docs/architecture.md",
        "docs/workflow.md", "docs/roadmap.md", "docs/security.md",
        ".github/DEVELOPMENT_INTERFACE.md",
        ".github/ISSUE_TEMPLATE/task.yml", ".github/pull_request_template.md",
        ".github/workflows/ci.yml",
    ),
}
TOOLS = {
    "relayforge": ("git", "python3", "cargo", "rustc", "bash", "just"),
    "assistant-hub": ("git", "python3", "node", "just"),
}

def run_git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        text=True, capture_output=True, check=True,
        timeout=12,
    )
    return result.stdout.strip()

def safe_file(raw: str) -> Path:
    if not raw or raw.startswith("/") or any(x in ("", ".", "..", ".git") for x in raw.split("/")):
        raise ValueError("invalid bounded repository path")
    target = ROOT / raw
    for part in (target, *target.parents):
        if part == ROOT.parent:
            break
        if part.is_symlink():
            raise ValueError("symlink in repository document path")
    if not target.is_file() or not stat.S_ISREG(target.lstat().st_mode):
        raise ValueError("missing or non-regular required document")
    if target.stat().st_size > 131_072:
        raise ValueError("document exceeds read budget")
    return target

def docs_check(project: str) -> None:
    for name in DOCS[project]:
        try:
            safe_file(name)
        except (OSError, ValueError) as exc:
            raise ValueError("required document unavailable: " + name) from exc
    print("Required entrypoints and CI references: PASS (offline existence check only)")
    print("Markdown links, Git provenance, full native tests and device evidence: not checked")

def status(project: str) -> None:
    root = run_git("rev-parse", "--show-toplevel")
    if Path(root) != ROOT:
        raise ValueError("unexpected repository checkout root")
    head = run_git("rev-parse", "--verify", "HEAD")
    branch = run_git("symbolic-ref", "--quiet", "--short", "HEAD") if run_git("rev-parse", "--abbrev-ref", "HEAD") != "HEAD" else "(detached)"
    dirty = bool(run_git("status", "--porcelain=v1", "--untracked-files=all"))
    print(f"project: {project}")
    print(f"root: {root}")
    print(f"branch: {branch}")
    print(f"head: {head}")
    print(f"working_tree_clean: {str(not dirty).lower()}")
    print("remote origin/authenticity/current main: NOT VERIFIED")

def context(project: str) -> None:
    docs_check(project)
    text = ["Project: " + project, "GitHub Issues own current task state.",
            "Task form: .github/ISSUE_TEMPLATE/task.yml",
            "Development policy: .github/DEVELOPMENT_INTERFACE.md",
            "Read only task-relevant documents; bounded pointers:"]
    text.extend(" - " + p for p in DOCS[project])
    output = "\n".join(text) + "\n"
    if len(output.encode("utf-8")) > 8192:
        raise ValueError("context pointer budget exceeded")
    print(output, end="")
    print("No tracked metadata grants execution, merge, deploy or device permission")

def doctor(project: str) -> None:
    missing = [name for name in TOOLS[project] if shutil.which(name) is None]
    if missing:
        raise ValueError("required developer tools unavailable: " + ", ".join(missing))
    print("Baseline developer executables found (versions/trust NOT attested)")
    docs_check(project)

def ui_check(project: str) -> None:
    if project != "assistant-hub":
        raise ValueError("UI checks not applicable to this project")
    source = list((ROOT / "web").glob("*.mjs"))
    source += list((ROOT / "web/tests").glob("*.mjs"))
    source += list((ROOT / "src/assistant_hub/local_web").glob("*.mjs"))
    cases = list((ROOT / "web/tests").glob("*.test.mjs"))
    if not source or not cases:
        raise ValueError("offline UI source/tests missing")
    for path in sorted(set(source)):
        if path.is_symlink() or not path.is_file():
            raise ValueError("unsafe UI test input")
        subprocess.run(["node", "--check", str(path)], check=True, timeout=40, cwd=ROOT)
    subprocess.run(["node", "--test", *(str(p) for p in sorted(cases))],
                   check=True, timeout=120, cwd=ROOT)
    print("Offline UI syntax and tests: PASS")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", choices=sorted(DOCS))
    parser.add_argument("action", choices=("status", "context", "doctor", "docs-check", "ui-check"))
    args = parser.parse_args()
    try:
        {"status": status, "context": context, "doctor": doctor,
         "docs-check": docs_check, "ui-check": ui_check}[args.action](args.project)
        return 0
    except (ValueError, OSError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as error:
        print(f"developer interface refused: {type(error).__name__}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
