#!/usr/bin/env python3
"""Offline MCP smoke test for GitHub-hosted runners; no device or network access."""
import json
import subprocess
import sys

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
    assert set(by_id) == {1, 2, 3, 4, 5, 6}, "MCP responses missing or malformed"
    assert by_id[1]["result"]["protocolVersion"] == "2025-11-25"
    names = {tool["name"] for tool in by_id[2]["result"]["tools"]}
    expected = {"relayforge_status", "relayforge_routeros_health",
                "relayforge_android_health", "relayforge_fleet_health",
                "relayforge_workstation_status"}
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
    print("Offline MCP handshake/tool discovery/workstation/deny-by-default: PASS")
    print("No physical device, tunnel, remote shell or credentials were used.")

if __name__ == "__main__":
    main()
