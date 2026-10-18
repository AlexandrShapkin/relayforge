//! A local, read-only MCP JSON-RPC stdio transport.
//! No device is reachable from this implementation.
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const MAX_LINE_BYTES: usize = 1024 * 1024;

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
    let result = match method {
        "initialize" => {
            let version = input
                .pointer("/params/protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or("2025-03-26");
            json!({"protocolVersion":version,"capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"relayforge","version":env!("CARGO_PKG_VERSION")}})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":[{"name":"relayforge_status",
            "description":"Read the status of this local RelayForge MCP adapter. No device operations are available.",
            "inputSchema":{"type":"object","properties":{},"additionalProperties":false}}]}),
        "tools/call" => {
            let name = input.pointer("/params/name").and_then(Value::as_str);
            if name != Some("relayforge_status") {
                return Some(error(id, -32602, "Unknown tool"));
            }
            json!({"content":[{"type":"text","text":"RelayForge local adapter ready; remote device access disabled."}],
                "isError":false})
        }
        _ => return Some(error(id, -32601, "Method not found")),
    };
    Some(json!({"jsonrpc":"2.0","id":id,"result":result}))
}

pub fn serve(reader: impl BufRead, mut writer: impl Write) -> io::Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.len() > MAX_LINE_BYTES {
            let response = error(Value::Null, -32600, "Request too large");
            writeln!(writer, "{response}")?;
            writer.flush()?;
            continue;
        }
        let response = match serde_json::from_str::<Value>(&line) {
            Ok(input) => handle(&input),
            Err(_) => Some(error(Value::Null, -32700, "Parse error")),
        };
        if let Some(response) = response {
            writeln!(writer, "{response}")?;
            writer.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn initialization_and_listing() {
        let init = handle(&json!({"jsonrpc":"2.0","id":1,"method":"initialize",
            "params":{"protocolVersion":"2025-03-26"}}))
        .unwrap();
        assert_eq!(init["result"]["serverInfo"]["name"], "relayforge");
        let list = handle(&json!({"jsonrpc":"2.0","id":2,"method":"tools/list"})).unwrap();
        assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 1);
    }
    #[test]
    fn no_remote_execution_or_unknown_tool() {
        let result = handle(&json!({"jsonrpc":"2.0","id":3,"method":"tools/call",
            "params":{"name":"process_execute","arguments":{"command":"id"}}}))
        .unwrap();
        assert_eq!(result["error"]["code"], -32602);
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
