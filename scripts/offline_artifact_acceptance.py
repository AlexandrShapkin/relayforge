#!/usr/bin/env python3
"""Disposable-home read-only MCP acceptance; never reads the operator's files."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile


def main():
    binary = str(pathlib.Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="relayforge-artifact-acceptance-") as tmp:
        home = pathlib.Path(tmp)
        root = home / "Projects/relayforge/.build/issue77-development-activation-20261022"
        root.mkdir(parents=True)
        (home / "Projects/relayforge/.git").mkdir()
        config = home / ".config/relayforge/artifact-roots.json"
        config.parent.mkdir(parents=True)
        audit = home / ".local/state/relayforge"
        audit.mkdir(parents=True, mode=0o700)
        report = root / "AUTHORIZATION.md"
        report.write_text("Fixture only: attended authorization report.\n")
        (root / "secret.md").write_text("NEVER_RETURN_THIS")
        os.mkfifo(root / "pipe.txt", mode=0o600)
        (root / "binary.txt").write_bytes(b"binary\x00data")
        (root / "large.txt").write_bytes(b"x" * (49152 + 1))
        (root / "escape.md").symlink_to(home / "outside.md")
        (home / "outside.md").write_text("NEVER_RETURN_THIS")
        env = {"HOME": tmp, "PATH": "/usr/bin:/bin", "LC_ALL": "C",
               "XDG_RUNTIME_DIR": tmp + "/run"}

        def call(operation, path=None):
            args = {"operation": operation}
            if path is not None:
                args["path"] = path
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": "relayforge_workstation_develop", "arguments": args}}
            run = subprocess.run([binary, "--readonly-stdio"], env=env,
                                 input=json.dumps(request) + "\n", capture_output=True,
                                 text=True, check=True, timeout=10)
            assert "NEVER_RETURN_THIS" not in run.stdout
            return json.loads(run.stdout)["result"]

        assert call("artifact.read", "activation/AUTHORIZATION.md")["isError"]
        # Only this disposable fixture receives a config, never the owner's HOME.
        config.write_text(json.dumps({"roots": {"activation": str(root)}}))
        config.chmod(0o600)
        caps = json.loads(call("capabilities")["content"][0]["text"])
        assert caps["api_revision"] == 9
        assert caps["artifacts"]["configured"] is True
        assert caps["artifacts"]["read_only"] is True
        assert caps["arbitrary_host_shell"] is False
        assert caps["write_grants"]["source_edit"] is False
        assert {"artifact.list", "artifact.read"} <= set(caps["operations"])
        before = report.stat(), report.read_bytes(), config.read_bytes()
        result = call("artifact.read", "activation/AUTHORIZATION.md")
        assert result["isError"] is False, result
        assert json.loads(result["content"][0]["text"])["utf8_text"] == report.read_text()
        for path in ["unknown/AUTHORIZATION.md", "activation/../outside.md", str(report),
                     "activation/secret.md", "activation/escape.md", "activation/binary.txt",
                     "activation/large.txt", "activation/pipe.txt"]:
            assert call("artifact.read", path)["isError"], path
        # Listing fails closed on unsafe eligible entries; ordinary siblings list.
        assert call("artifact.list", "activation")["isError"]
        for name in ["escape.md", "binary.txt", "large.txt", "pipe.txt"]:
            (root / name).unlink()
        result = call("artifact.list", "activation")
        assert result["isError"] is False, result
        assert json.loads(result["content"][0]["text"])["files"] == ["AUTHORIZATION.md"]
        assert before[0].st_mtime_ns == report.stat().st_mtime_ns
        assert before[1:] == (report.read_bytes(), config.read_bytes())
        log = (audit / "workstation-dev-audit.jsonl").read_text()
        assert "artifact.read" in log and "artifact.list" in log
        assert "Fixture only" not in log and str(root) not in log
        config.unlink()
        assert call("artifact.read", "activation/AUTHORIZATION.md")["isError"]
    print("Offline artifact MCP: approved read/list, discovery, default deny, escapes, secrets, binary, size, metadata-only audit: PASS")


if __name__ == "__main__":
    main()
