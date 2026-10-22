"""Full verification in a fixed disposable build tree, never deployment."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / ".build/verification"


def commands(root=ROOT):
    target = root / ".build/verification"
    return [
        ["bash", "-n", "deploy/relayforge-hot-activate.sh"],
        ["bash", "-n", "deploy/install-local-recovery.sh"],
        ["python3", "-B", "-m", "unittest", "discover", "-s", "scripts", "-p", "test_*.py"],
        ["cargo", "fmt", "--all", "--", "--check"],
        ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--target-dir", str(target), "--", "-D", "warnings"],
        ["cargo", "test", "--workspace", "--locked", "--target-dir", str(target)],
        ["cargo", "build", "--release", "--locked", "--target-dir", str(target), "-p", "relayforge-agent", "-p", "relayforge-mcp"],
        ["python3", "-B", "scripts/offline_mcp_smoke.py", str(target / "release/relayforge-mcp")],
        ["python3", "-B", "scripts/offline_artifact_acceptance.py", str(target / "release/relayforge-mcp")],
    ]


def main():
    # Fail closed on redirects instead of accidentally targeting the legacy live tree.
    for path in [ROOT / ".build", TARGET]:
        if path.is_symlink():
            raise SystemExit("isolated build directory must not be a symlink")
    env = dict(os.environ, CARGO_TARGET_DIR=str(TARGET))
    for command in commands():
        subprocess.run(command, cwd=ROOT, env=env, check=True)


if __name__ == "__main__":
    main()
