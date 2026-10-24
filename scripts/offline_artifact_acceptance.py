#!/usr/bin/env python3
"""Disposable-home read-only MCP acceptance; never reads the operator's files."""
import json
import os
import pty
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
        for stage in ("prepared", "approved", "claimed", "done"):
            (audit / stage).mkdir(mode=0o700)
        report = root / "AUTHORIZATION.md"
        report.write_text("Fixture only: attended authorization report.\n")
        receipt = root / "operation-1792634926759214000.jsonl"
        receipt.write_text('{"time":1792634926.759214,"event":"started activate"}\n'
                           '{"time":1792634927.0,"event":"candidate staged and verified"}\n')
        (root / "secret.md").write_text("NEVER_RETURN_THIS")
        os.mkfifo(root / "pipe.txt", mode=0o600)
        (root / "binary.txt").write_bytes(b"binary\x00data")
        (root / "large.txt").write_bytes(b"x" * (49152 + 1))
        (root / "escape.md").symlink_to(home / "outside.md")
        (home / "outside.md").write_text("NEVER_RETURN_THIS")
        env = {"HOME": tmp, "PATH": "/usr/bin:/bin", "LC_ALL": "C",
               "XDG_RUNTIME_DIR": tmp + "/run"}

        def call(operation=None, path=None, *, parameters=None, tool="relayforge_workstation_develop", arguments=None):
            args = {"operation": operation} if arguments is None else arguments
            if path is not None:
                args["path"] = path
            if parameters is not None:
                args["parameters"] = parameters
            request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": tool, "arguments": args}}
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
        # New scope is not accessible before local approval, and malformed
        # generic-MCP parameters must not create pending grants.
        assert call("artifact.read", "issue77/AUTHORIZATION.md")["isError"]
        assert call("artifact.root.inspect", parameters={"name":"issue77"})["isError"] is False
        assert json.loads(call("artifact.root.inspect", parameters={"name":"issue77"})["content"][0]["text"])["currently_accessible"] is False
        for bad in [{"name":"issue77","directory":"../.ssh"},
                    {"name":"issue77","directory":"issue77-development-activation-20261022","unexpected":1},
                    {"name":"issue77"}, {"name":"/etc","directory":"bad"}]:
            assert call("artifact.root.prepare", parameters=bad)["isError"]
        grant = call("artifact.root.prepare", parameters={
            "name":"issue77","directory":"issue77-development-activation-20261022"})
        assert grant["isError"] is False, grant
        approval = json.loads(grant["content"][0]["text"])["approval_id"]
        def commit(approval_id):
            return call(tool="relayforge_change_commit", arguments={"approval_id":approval_id})
        assert commit(approval)["isError"], "no remote self-approval"
        assert call("artifact.read", "issue77/AUTHORIZATION.md")["isError"]
        def approve_on_disposable_pty(approval_id):
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen(
                    [binary, "--approve-change", approval_id], env=env,
                    stdin=slave, stdout=slave, stderr=subprocess.PIPE)
                os.close(slave)
                slave = -1
                os.write(master, ("APPROVE " + approval_id + "\\n").encode())
                _, errors = process.communicate(timeout=10)
                assert process.returncode == 0, errors
            finally:
                os.close(master)
                if slave >= 0:
                    os.close(slave)
        # Test-only PTY simulates a *real local approval*, not an MCP approval.
        approve_on_disposable_pty(approval)
        committed = commit(approval)
        assert committed["isError"] is False, committed
        assert json.loads(committed["content"][0]["text"])["status"] == "succeeded"
        assert commit(approval)["isError"], "single-use approval replay denied"
        assert call("artifact.read", "issue77/AUTHORIZATION.md")["isError"] is False
        assert json.loads(call("artifact.root.inspect", parameters={"name":"issue77"})["content"][0]["text"])["currently_accessible"] is True

        before = report.stat(), report.read_bytes(), config.read_bytes()
        result = call("artifact.read", "activation/AUTHORIZATION.md")
        assert result["isError"] is False, result
        assert json.loads(result["content"][0]["text"])["utf8_text"] == report.read_text()
        result = call("artifact.read", "activation/" + receipt.name)
        assert result["isError"] is False, result
        payload = json.loads(result["content"][0]["text"])
        assert payload["utf8_text"] == receipt.read_text()
        assert payload["byte_length"] == len(receipt.read_bytes())
        for path in ["unknown/AUTHORIZATION.md", "activation/../outside.md", str(report),
                     "activation/secret.md", "activation/escape.md", "activation/binary.txt",
                     "activation/large.txt", "activation/pipe.txt"]:
            assert call("artifact.read", path)["isError"], path
        # Listing fails closed on unsafe eligible entries; ordinary siblings list.
        assert call("artifact.list", "activation")["isError"]
        for name in ["escape.md", "binary.txt", "large.txt", "pipe.txt"]:
            (root / name).unlink()
        original = receipt.read_bytes()
        for forbidden in [b'{"event":"access_token: NEVER_RETURN_THIS"}\n',
                          b'{"event":"bad\x00text"}\n', b'\xff', b'x' * 49153]:
            receipt.write_bytes(forbidden)
            assert call("artifact.read", "activation/" + receipt.name)["isError"]
            assert call("artifact.list", "activation")["isError"]
        receipt.write_bytes(original)
        result = call("artifact.list", "activation")
        assert result["isError"] is False, result
        assert json.loads(result["content"][0]["text"])["files"] == ["AUTHORIZATION.md", receipt.name]
        assert before[0].st_mtime_ns == report.stat().st_mtime_ns
        assert before[1:] == (report.read_bytes(), config.read_bytes())
        log = (audit / "workstation-dev-audit.jsonl").read_text()
        assert "artifact.read" in log and "artifact.list" in log
        assert "Fixture only" not in log and str(root) not in log
        removal = call("artifact.root.revoke.prepare", parameters={"name":"issue77"})
        assert removal["isError"] is False, removal
        revocation_id = json.loads(removal["content"][0]["text"])["approval_id"]
        assert call("artifact.read", "issue77/AUTHORIZATION.md")["isError"] is False
        approve_on_disposable_pty(revocation_id)
        revoked = commit(revocation_id)
        assert revoked["isError"] is False, revoked
        assert json.loads(revoked["content"][0]["text"])["status"] == "succeeded"
        assert call("artifact.read", "issue77/AUTHORIZATION.md")["isError"]
        assert commit(revocation_id)["isError"], "revocation replay denied"
        assert json.loads(call("artifact.root.inspect", parameters={"name":"issue77"})["content"][0]["text"])["currently_accessible"] is False
        config.unlink()
        assert call("artifact.read", "activation/AUTHORIZATION.md")["isError"]
    print("Offline artifact MCP: approved read/list, discovery, default deny, escapes, secrets, binary, size, metadata-only audit: PASS")


if __name__ == "__main__":
    main()
