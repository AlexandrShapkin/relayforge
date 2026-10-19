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
    assert set(by_id) == {1, 2, 3, 4}, "MCP responses missing or malformed"
    assert by_id[1]["result"]["protocolVersion"] == "2025-11-25"
    names = {tool["name"] for tool in by_id[2]["result"]["tools"]}
    expected = {"relayforge_status", "relayforge_routeros_health",
                "relayforge_android_health", "relayforge_fleet_health"}
    assert expected <= names, f"missing read-only tools: {expected - names}"
    forbidden = {"relayforge_agent_file", "relayforge_agent_probe_restart"}
    assert not (forbidden & names), "unrestricted tools exposed via private stdio"
    assert by_id[3]["result"]["isError"] is False
    blocked = by_id[4]
    assert ("error" in blocked or
            blocked.get("result", {}).get("isError") is True), (
            "unsafe tool invocation was not denied")
    print("Offline MCP handshake/tool discovery/deny-by-default: PASS")
    print("No physical device, tunnel, remote shell or credentials were used.")

if __name__ == "__main__":
    main()
