//! Android diagnostic pilot via an already-authorized local ADB connection.
//! The transport is intentionally read-only and does not expose `adb shell`
//! or Android input / package-management commands to MCP callers.
use serde_json::{json, Value};
use std::process::{Command, Stdio};

const MAX_OUTPUT: usize = 16 * 1024;
const CHECKS: &[(&str, &[&str])] = &[
    ("model", &["shell", "getprop", "ro.product.model"]),
    (
        "android_version",
        &["shell", "getprop", "ro.build.version.release"],
    ),
    ("battery", &["shell", "dumpsys", "battery"]),
    ("uptime", &["shell", "uptime"]),
    ("storage", &["shell", "df", "/data"]),
];

pub fn list_tool() -> Value {
    json!({"name":"relayforge_android_devices",
        "description":"List currently authorized Android devices known to the local ADB server; no pairing or device modifications.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
}

pub fn diagnostic_tool() -> Value {
    json!({"name":"relayforge_android_diagnostic",
        "description":"Run a fixed read-only diagnostic on a currently authorized local Android ADB device.",
        "inputSchema":{"type":"object","properties":{
            "serial":{"type":"string","minLength":1,"maxLength":128},
            "check":{"type":"string","enum":["model","android_version","battery","uptime","storage"]}
        },"required":["serial","check"],"additionalProperties":false}})
}

fn valid_serial(serial: &str) -> bool {
    !serial.is_empty()
        && !serial.starts_with('-')
        && serial.len() <= 128
        && serial
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
}

fn parse_authorized_devices(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let serial = fields.next()?;
            if fields.next() == Some("device") && valid_serial(serial) {
                Some(serial.to_owned())
            } else {
                None
            }
        })
        .collect()
}

pub(crate) fn adb_devices() -> Result<Vec<String>, String> {
    let output = Command::new("timeout")
        .args(["6s", "adb", "devices"])
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "ADB is not available")?;
    if !output.status.success() {
        return Err("ADB device discovery failed".into());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_authorized_devices(&stdout))
}

pub fn list(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|obj| !obj.is_empty()) {
        return Err("unexpected arguments".into());
    }
    let devices = adb_devices()?;
    Ok(json!({"authorized_devices": devices}).to_string())
}

pub fn diagnostic(args: &Value) -> Result<String, String> {
    let obj = args.as_object().ok_or("arguments must be an object")?;
    if obj.len() != 2 {
        return Err("unexpected arguments".into());
    }
    let serial = obj
        .get("serial")
        .and_then(Value::as_str)
        .ok_or("missing serial")?;
    if !valid_serial(serial) {
        return Err("invalid serial".into());
    }
    let check = obj
        .get("check")
        .and_then(Value::as_str)
        .ok_or("missing check")?;
    let command = CHECKS
        .iter()
        .find(|(name, _)| *name == check)
        .map(|(_, command)| *command)
        .ok_or("check denied")?;
    if !adb_devices()?.iter().any(|item| item == serial) {
        return Err("Android device not authorized or offline".into());
    }
    let output = Command::new("timeout")
        .args(["8s", "adb", "-s", serial])
        .args(command)
        .stdin(Stdio::null())
        .output()
        .map_err(|_| "Android diagnostic unavailable")?;
    if !output.status.success() {
        return Err("Android diagnostic failed".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout[..output.stdout.len().min(MAX_OUTPUT)]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_authorized_devices() {
        let output = "List of devices attached\nserial-01 device product:abc\n192.168.1.3:4343 device\nunauthorized1 unauthorized\noffline1 offline\nbad;serial device\n";
        assert_eq!(
            parse_authorized_devices(output),
            ["serial-01", "192.168.1.3:4343"]
        );
    }

    #[test]
    fn rejects_option_like_serials() {
        for serial in ["-", "--help", "-s", "-device123"] {
            assert!(!valid_serial(serial));
            assert_eq!(
                diagnostic(&json!({"serial":serial,"check":"model"})),
                Err("invalid serial".into())
            );
            assert!(parse_authorized_devices(&format!("{serial} device\n")).is_empty());
        }
        assert!(valid_serial("device-123"));
        assert!(valid_serial("192.168.1.3:4343"));
    }

    #[test]
    fn rejects_untrusted_parameters_before_calling_adb() {
        for args in [
            json!({"serial":"any","check":"shell"}),
            json!({"serial":"any","check":"reboot"}),
            json!({"serial":"127.0.0.1;id","check":"model"}),
            json!({"serial":"--help","check":"model"}),
            json!({"serial":"any","check":"model","command":"input tap 0 0"}),
            json!({}),
        ] {
            assert!(diagnostic(&args).is_err());
        }
        assert!(list(&json!({"command":"devices"})).is_err());
    }

    #[test]
    fn command_table_is_fixed_and_read_only() {
        for (_, args) in CHECKS {
            assert_eq!(args.first(), Some(&"shell"));
            assert!(args
                .iter()
                .all(|arg| !arg.contains(';') && !arg.contains('|')));
        }
    }
}
