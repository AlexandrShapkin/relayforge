#!/usr/bin/env python3
"""Offline MCP smoke test for GitHub-hosted runners; no device or network access."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile

def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: offline_mcp_smoke.py <local-relayforge-mcp-binary>")

    requests = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                    "clientInfo": {"name": "offline-ci", "version": "1"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "relayforge_status", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
         "params": {"name": "relayforge_agent_probe_restart",
                    "arguments": {"host": "ru0"}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
         "params": {"name": "relayforge_workstation_status",
                    "arguments": {"command": "id"}}},
        {"jsonrpc": "2.0", "id": 6, "method": "tools/call",
         "params": {"name": "relayforge_workstation_status", "arguments": {}}},
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "repo.write",
                                  "path": "crates/relayforge-mcp/src/main.rs",
                                  "content": "malicious"}}},
        {"jsonrpc": "2.0", "id": 8, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "capabilities"}}},
        {"jsonrpc": "2.0", "id": 9, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "capabilities",
                                  "parameters": {"shell": "id"}}}},
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "task.list"}}},
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "tunnel.inspect"}}},
        {"jsonrpc": "2.0", "id": 12, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "workspace.put",
                                  "path": "test.md", "content": "denied"}}},
        {"jsonrpc": "2.0", "id": 13, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "job.start",
                                  "script": "printf 'unexpected'"}}},
        {"jsonrpc": "2.0", "id": 14, "method": "tools/call",
         "params": {"name": "relayforge_workstation_develop",
                    "arguments": {"operation": "job.stop",
                                  "task_id": "systemd.service"}}},
    ]
    serialized = "".join(json.dumps(item) + "\n" for item in requests)
    completed = subprocess.run(
        [sys.argv[1], "--readonly-stdio"],
        input=serialized, text=True, capture_output=True, timeout=20,
        check=True,
    )
    responses = [json.loads(line) for line in completed.stdout.splitlines()
                 if line.strip()]
    by_id = {r["id"]: r for r in responses}
    assert set(by_id) == set(range(1, 15)), "MCP responses missing or malformed"
    assert by_id[1]["result"]["protocolVersion"] == "2025-11-25"
    names = {tool["name"] for tool in by_id[2]["result"]["tools"]}
    expected = {"relayforge_status", "relayforge_routeros_health",
                "relayforge_android_health", "relayforge_fleet_health",
                "relayforge_workstation_status",
                "relayforge_workstation_develop"}
    assert expected <= names, f"missing read-only tools: {expected - names}"
    forbidden = {"relayforge_agent_file", "relayforge_agent_probe_restart"}
    assert not (forbidden & names), "unrestricted tools exposed via private stdio"
    assert by_id[3]["result"]["isError"] is False
    blocked = by_id[4]
    assert ("error" in blocked or
            blocked.get("result", {}).get("isError") is True), (
            "unsafe tool invocation was not denied")
    assert by_id[5]["result"]["isError"] is True, (
        "workstation tool accepted arbitrary command arguments")
    assert by_id[6]["result"]["isError"] is False, (
        "workstation read-only inventory failed on offline runner")
    inventory = json.loads(by_id[6]["result"]["content"][0]["text"])
    assert inventory["scope"] == "local_workstation_only"
    assert inventory["permissions"] == {
        "shell": False, "arbitrary_files": False, "service_mutation": False}
    assert "untracked_clean" in inventory["repository"]
    assert by_id[7]["result"]["isError"] is True, (
        "workstation write succeeded without local operator opt-in")
    assert by_id[8]["result"]["isError"] is False
    capabilities = json.loads(by_id[8]["result"]["content"][0]["text"])
    assert capabilities["api_revision"] == 8
    assert "repo.sync" in capabilities["operations"]
    assert "task.list" in capabilities["operations"]
    assert "tunnel.inspect" in capabilities["operations"]
    assert "recovery.inspect" in capabilities["operations"]
    assert "workspace.put" in capabilities["operations"]
    assert "job.start" in capabilities["operations"]
    assert "job.status" in capabilities["operations"]
    assert "job.stop" in capabilities["operations"]
    assert "job.chain.start" in capabilities["operations"]
    assert "job.chain.status" in capabilities["operations"]
    assert "job.chain.output" in capabilities["operations"]
    assert "dependency.audit" in capabilities["operations"]
    assert "ssh.retire.config" in capabilities["operations"]
    assert by_id[13]["result"]["isError"] is True, (
        "background job started without local development grant")
    assert by_id[14]["result"]["isError"] is True, (
        "job stop accepted arbitrary host unit")
    assert by_id[12]["result"]["isError"] is True, (
        "private workstation write succeeded without development grant")
    assert capabilities["arbitrary_host_shell"] is False
    assert by_id[9]["result"]["isError"] is True, (
        "capabilities operation accepted unrecognized nested parameters")
    # An invalid on-disk release must not kill the stable parent or cause
    # arbitrary command execution. The fallback invokes the already-running
    # parent executable via /proc/<parent-pid>/exe, never /proc/self/exe of
    # the child timeout process.
    with tempfile.TemporaryDirectory(prefix="relayforge-hot-smoke-") as home:
        fake_dir = pathlib.Path(home) / "Projects/relayforge/target/release"
        fake_dir.mkdir(parents=True)
        broken = fake_dir / "relayforge-mcp"
        broken.write_text("#!/bin/sh\nexit 7\n")
        broken.chmod(0o700)
        env = dict(os.environ, HOME=home)
        ping = {"jsonrpc": "2.0", "id": 51, "method": "ping"}
        fallback = subprocess.run(
            [sys.argv[1], "--readonly-stdio"],
            input=json.dumps(ping) + "\n", text=True,
            capture_output=True, timeout=20, check=True, env=env)
        response = json.loads(fallback.stdout.strip())
        assert response["id"] == 51
        assert response.get("result") == {}, (
            "hot stdio fallback failed when the on-disk worker crashed")
    # CI has no ThinkPad systemd user manager. Any result must remain
    # a bounded read-only diagnostic or fail closed, never a remote command.
    for ident in (10, 11):
        reply = by_id[ident]["result"]
        assert isinstance(reply["isError"], bool)
        assert all(item["type"] == "text" for item in reply["content"])
    print("Hot stdio: broken worker fallback to mapped parent: PASS")
    print("Offline MCP handshake/tool discovery/workstation/deny-by-default: PASS")
    print("No physical device, tunnel, remote shell or credentials were used.")

if __name__ == "__main__":
    main()
