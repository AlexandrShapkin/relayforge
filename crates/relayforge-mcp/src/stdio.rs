//! A local, read-only MCP JSON-RPC stdio transport.
//! No device is reachable from this implementation.
use crate::{agent, android, bridge, changes, routeros};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const MAX_LINE_BYTES: usize = 1024 * 1024;

// Handshake-era revisions only. The 2026-07-28 revision uses per-request
// metadata and server/discover, which this stdio adapter does NOT implement.
const LEGACY_MCP_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"];
const DEFAULT_LEGACY_VERSION: &str = "2025-11-25";

fn negotiate_version(requested: Option<&str>) -> &'static str {
    LEGACY_MCP_VERSIONS
        .iter()
        .copied()
        .find(|version| Some(*version) == requested)
        .unwrap_or(DEFAULT_LEGACY_VERSION)
}

fn error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

pub fn handle(input: &Value) -> Option<Value> {
    let id = input.get("id").cloned();
    let Some(method) = input.get("method").and_then(Value::as_str) else {
        return Some(error(id.unwrap_or(Value::Null), -32600, "Invalid Request"));
    };
    if input.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Some(error(id.unwrap_or(Value::Null), -32600, "Invalid Request"));
    }
    // JSON-RPC notifications must not be answered.
    let id = id?;
    if !(id.is_string() || id.as_i64().is_some() || id.as_u64().is_some()) {
        return Some(error(Value::Null, -32600, "Invalid Request"));
    }
    let result = match method {
        "initialize" => {
            let Some(requested) = input
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
            else {
                return Some(error(id, -32602, "Invalid initialize params"));
            };
            let version = negotiate_version(Some(requested));
            json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"relayforge","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":[{"name":"relayforge_status",
            "description":"Read the status of this local RelayForge MCP adapter. Device actions are restricted by tool and host.",
            "inputSchema":{"type":"object","properties":{},"additionalProperties":false}}, bridge::tool(), routeros::tool(), android::list_tool(), android::diagnostic_tool(), agent::tool(), agent::file_tool(), agent::probe_tool(), agent::file_inspect_tool(), changes::prepare_tool(), changes::commit_tool(), changes::status_tool(), changes::audit_tool()]}),
        "tools/call" => {
            let name = input.pointer("/params/name").and_then(Value::as_str);
            match name {
                Some("relayforge_status") => {
                    json!({"content":[{"type":"text","text":"RelayForge diagnostic bridge ready."}],"isError":false})
                }
                Some("relayforge_file_inspect") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match agent::file_inspect(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_change_prepare") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match changes::prepare(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_change_commit") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match changes::commit(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_change_audit") => {
                    let empty = json!({});
                    let args = input.pointer("/params/arguments").unwrap_or(&empty);
                    match changes::audit_recent(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_change_status") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match changes::status(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_agent_probe_restart") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match agent::restart_probe(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_agent_file") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match agent::file_query(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_agent_query") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match agent::query(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_android_devices") => {
                    let args = input
                        .pointer("/params/arguments")
                        .unwrap_or(&json!({}))
                        .clone();
                    match android::list(&args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_android_diagnostic") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match android::diagnostic(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_routeros_diagnostic") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match routeros::diagnostic(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                Some("relayforge_diagnostic") => {
                    let args = input.pointer("/params/arguments").unwrap_or(&Value::Null);
                    match bridge::diagnostic(args) {
                        Ok(value) => {
                            json!({"content":[{"type":"text","text":value}],"isError":false})
                        }
                        Err(message) => {
                            json!({"content":[{"type":"text","text":message}],"isError":true})
                        }
                    }
                }
                _ => return Some(error(id, -32602, "Unknown tool")),
            }
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

// A private ChatGPT tunnel still introduces a remote caller trust boundary.
// Do not let that boundary inherit local-only scratch writes or systemd
// restart probes. Enforce the policy at invocation, not just tools/list.
const TUNNEL_ALLOWED_TOOLS: &[&str] = &[
    "relayforge_status",
    "relayforge_diagnostic",
    "relayforge_routeros_diagnostic",
    "relayforge_android_devices",
    "relayforge_android_diagnostic",
    "relayforge_agent_query",
    "relayforge_file_inspect",
    "relayforge_change_prepare",
    "relayforge_change_commit",
    "relayforge_change_status",
    "relayforge_change_audit",
];

pub fn handle_tunnel(input: &Value) -> Option<Value> {
    let method = input.get("method").and_then(Value::as_str);
    if method == Some("tools/call") {
        let name = input.pointer("/params/name").and_then(Value::as_str);
        if !name.is_some_and(|value| TUNNEL_ALLOWED_TOOLS.contains(&value)) {
            // No untrusted operation may reach the local-only handlers.
            let id = input.get("id").cloned();
            return id.map(|id| error(id, -32602, "Tool denied by tunnel policy"));
        }
    }
    let mut response = handle(input)?;
    if method == Some("tools/list") {
        if let Some(tools) = response
            .pointer_mut("/result/tools")
            .and_then(Value::as_array_mut)
        {
            tools.retain(|tool| {
                tool.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|name| TUNNEL_ALLOWED_TOOLS.contains(&name))
            });
        }
    }
    Some(response)
}

pub fn serve_tunnel(reader: impl BufRead, writer: impl Write) -> io::Result<()> {
    serve_with_handler(reader, writer, handle_tunnel)
}

pub fn serve(reader: impl BufRead, writer: impl Write) -> io::Result<()> {
    serve_with_handler(reader, writer, handle)
}

fn serve_with_handler(
    mut reader: impl BufRead,
    mut writer: impl Write,
    handler: fn(&Value) -> Option<Value>,
) -> io::Result<()> {
    loop {
        // Bound memory use before allocating the full line. Drain oversize input
        // until newline so subsequent requests remain correctly framed.
        let mut line = Vec::new();
        let mut oversized = false;
        loop {
            let chunk = reader.fill_buf()?;
            if chunk.is_empty() {
                if line.is_empty() && !oversized {
                    return Ok(());
                }
                break;
            }
            let count = chunk
                .iter()
                .position(|b| *b == b'\n')
                .map_or(chunk.len(), |p| p + 1);
            if !oversized {
                let remaining = MAX_LINE_BYTES.saturating_add(1).saturating_sub(line.len());
                line.extend_from_slice(&chunk[..count.min(remaining)]);
                oversized = line.len() > MAX_LINE_BYTES;
            }
            let finished = chunk[count - 1] == b'\n';
            reader.consume(count);
            if finished {
                break;
            }
        }
        if oversized {
            let response = error(Value::Null, -32600, "Request too large");
            writeln!(writer, "{response}")?;
            writer.flush()?;
            continue;
        }
        let response = match serde_json::from_slice::<Value>(&line) {
            Ok(input) => handler(&input),
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            writeln!(writer, "{response}")?;
            writer.flush()?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tunnel_lists_only_read_only_tools() {
        let list = handle_tunnel(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"})).unwrap();
        let names: Vec<_> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .collect();
        assert_eq!(names.len(), TUNNEL_ALLOWED_TOOLS.len());
        assert!(!names.contains(&"relayforge_agent_file"));
        assert!(!names.contains(&"relayforge_agent_probe_restart"));
        for name in TUNNEL_ALLOWED_TOOLS {
            assert!(names.contains(name));
        }
    }

    #[test]
    fn tunnel_blocks_mutations_even_if_tool_name_is_known() {
        for name in [
            "relayforge_agent_file",
            "relayforge_agent_probe_restart",
            "process_execute",
            "relayforge_unknown",
        ] {
            let req = json!({"jsonrpc":"2.0","id":11,"method":"tools/call",
                "params":{"name":name,"arguments":{"host":"ru0","operation":"file.create",
                    "name":"should-not-be-created.txt","content":"no"}}});
            let result = handle_tunnel(&req).unwrap();
            assert_eq!(result["error"]["code"], -32602);
        }
        let mut output = Vec::new();
        serve_tunnel(
            b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n".as_slice(),
            &mut output,
        )
        .unwrap();
        let data: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(
            data["result"]["tools"].as_array().unwrap().len(),
            TUNNEL_ALLOWED_TOOLS.len()
        );
    }

    #[test]
    fn initialization_and_listing() {
        let init = handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}}))
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "relayforge");
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        let list = handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 13);
    }
    #[test]
    fn protocol_version_negotiation_does_not_echo_unknown_versions() {
        for version in LEGACY_MCP_VERSIONS {
            let response = handle(&json!({"jsonrpc":"2.0","id":4,
                "method":"initialize","params":{"protocolVersion":version}}))
            .unwrap();
            assert_eq!(response["result"]["protocolVersion"], *version);
        }
        for unsupported in ["2026-07-28", "2030-12-31", "attacker-controlled"] {
            let response = handle(&json!({"jsonrpc":"2.0","id":5,
                "method":"initialize","params":{"protocolVersion":unsupported}}))
            .unwrap();
            assert_eq!(response["result"]["protocolVersion"], "2025-11-25");
        }
        let missing = handle(&json!({"jsonrpc":"2.0","id":6,"method":"initialize"})).unwrap();
        assert_eq!(missing["error"]["code"], -32602);
    }

    #[test]
    fn rejects_non_scalar_request_ids() {
        for id in [json!({}), json!([]), Value::Null, json!(1.2)] {
            let response = handle(&json!({"jsonrpc":"2.0","id":id,"method":"ping"})).unwrap();
            assert_eq!(response["error"]["code"], -32600);
        }
    }

    #[test]
    fn no_remote_execution_or_unknown_tool() {
        let result = handle(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"process_execute","arguments":{"command":"id"}}}))
        .unwrap();
        assert_eq!(result["error"]["code"], -32602);
    }
    #[test]
    fn oversized_request_is_drained_without_losing_next_message() {
        let mut input = vec![b'x'; MAX_LINE_BYTES + 512];
        input.extend_from_slice(b"\n{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"ping\"}\n");
        let mut output = Vec::new();
        serve(input.as_slice(), &mut output).unwrap();
        let results: Vec<Value> = output
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["error"]["message"], "Request too large");
        assert_eq!(results[1]["id"], 4);
    }

    #[test]
    fn notifications_are_silent_and_malformed_is_rejected() {
        assert!(handle(&json!({"jsonrpc":"2.0","method":"notifications/initialized"})).is_none());
        let mut output = Vec::new();
        serve(
            "not json\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n".as_bytes(),
            &mut output,
        )
        .unwrap();
        let lines: Vec<Value> = output
            .split(|b| *b == b'\n')
            .filter(|s| !s.is_empty())
            .map(|s| serde_json::from_slice(s).unwrap())
            .collect();
        assert_eq!(lines[0]["error"]["code"], -32700);
        assert_eq!(lines[1]["result"], json!({}));
    }
}
