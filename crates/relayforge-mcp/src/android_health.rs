//! Privacy-filtered, bounded Android health from already-authorized ADB.
//! No pairing, input, app/file reads, setting changes or arbitrary shell.
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_DEVICES: usize = 4;
const PROBES: &[&str] = &["model", "android_version", "battery", "storage"];

pub fn tool() -> Value {
    json!({"name":"relayforge_android_health",
      "description":"Read-only health for up to four authorized Android ADB devices: model, version, battery, charging and free storage. No pairing or actions.",
      "inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
}

fn battery(raw: &str) -> Option<(u8, bool)> {
    if raw.len() > 16 * 1024 {
        return None;
    }
    let mut level = None;
    let mut status = None;
    let mut powered = false;
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        match k.trim() {
            "level" => level = v.trim().parse::<u8>().ok().filter(|x| *x <= 100),
            "status" => status = v.trim().parse::<u8>().ok(),
            "USB powered" | "AC powered" | "Wireless powered" => powered |= v.trim() == "true",
            _ => {}
        }
    }
    Some((level?, status.is_some_and(|s| s == 2 || s == 5) || powered))
}
fn storage_mib(raw: &str) -> Option<u64> {
    if raw.len() > 16 * 1024 {
        return None;
    }
    let mut lines = raw.lines().filter(|line| !line.trim().is_empty());
    let header: Vec<_> = lines.next()?.split_ascii_whitespace().collect();
    // Only these df layouts establish that Available is measured in KiB.
    if !matches!(
        header.as_slice(),
        [
            "Filesystem",
            "1K-blocks" | "1024-blocks",
            "Used",
            "Available" | "Avail",
            "Use%",
            "Mounted",
            "on"
        ]
    ) {
        return None;
    }
    lines.find_map(|line| {
        let columns: Vec<_> = line.split_ascii_whitespace().collect();
        if columns.len() != 6 || columns.last() != Some(&"/data") {
            return None;
        }
        columns[3].parse::<u64>().ok().map(|n| n / 1024)
    })
}
fn model_label(raw: &str) -> Option<String> {
    let name = raw.trim();
    if name.is_empty()
        || name.len() > 80
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " ._()+-/".contains(c))
    {
        return None;
    }
    Some(name.to_owned())
}
fn inspect<F>(serial: &str, read: &F) -> Value
where
    F: Fn(&str, &str) -> Result<String, String> + Sync,
{
    let model = read(serial, "model").ok().and_then(|s| model_label(&s));
    let version = read(serial, "android_version")
        .ok()
        .and_then(|s| model_label(&s));
    let battery = read(serial, "battery").ok().and_then(|s| battery(&s));
    let storage = read(serial, "storage").ok().and_then(|s| storage_mib(&s));
    let incomplete = model.is_none() || version.is_none() || battery.is_none() || storage.is_none();
    let mut findings = Vec::new();
    if incomplete {
        findings.push("adb_read_incomplete");
    }
    if battery.is_some_and(|(percent, _)| percent < 15) {
        findings.push("battery_low");
    }
    if storage.is_some_and(|mb| mb < 512) {
        findings.push("storage_low");
    }
    let status = if incomplete {
        "unverified"
    } else if findings.is_empty() {
        "healthy"
    } else {
        "attention"
    };
    json!({"serial":serial,"status":status,
        "model":model,"android_version":version,
        "battery_percent":battery.map(|x|x.0),"charging":battery.map(|x|x.1),
        "storage_free_mib":storage,"findings":findings})
}
fn aggregate<F>(serials: &[String], read: &F) -> Value
where
    F: Fn(&str, &str) -> Result<String, String> + Sync,
{
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if serials.len() > MAX_DEVICES {
        return json!({"status":"capacity_exceeded","authorized_device_count":serials.len(),
            "limit":MAX_DEVICES,"devices":[],"checked_at_unix":now});
    }
    if serials.is_empty() {
        return json!({"status":"no_authorized_devices","authorized_device_count":0,
            "limit":MAX_DEVICES,"devices":[],"checked_at_unix":now});
    }
    let devices = std::thread::scope(|scope| {
        let jobs: Vec<_> = serials
            .iter()
            .map(|serial| scope.spawn(move || inspect(serial, read)))
            .collect();
        jobs.into_iter()
            .map(|job| {
                job.join().unwrap_or_else(
                    |_| json!({"status":"unverified","reason":"device_query_failed"}),
                )
            })
            .collect::<Vec<_>>()
    });
    let status = if devices.iter().any(|d| d["status"] == "unverified") {
        "unverified"
    } else if devices.iter().any(|d| d["status"] == "attention") {
        "attention"
    } else {
        "healthy"
    };
    json!({"status":status,"authorized_device_count":serials.len(),
        "limit":MAX_DEVICES,"devices":devices,"checked_at_unix":now})
}
pub fn snapshot(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|o| !o.is_empty()) {
        return Err("unexpected Android health arguments".into());
    }
    let serials = crate::android::adb_devices()?;
    Ok(aggregate(&serials, &|serial, check| {
        if !PROBES.contains(&check) {
            return Err("Android probe not allowed".into());
        }
        crate::android::diagnostic(&json!({"serial":serial,"check":check}))
    })
    .to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn mock(_: &str, check: &str) -> Result<String, String> {
        Ok(match check{
            "model"=>"Pixel 9 Pro\n",
            "android_version"=>"16\n",
            "battery"=>"AC powered: false\nUSB powered: true\nstatus: 2\nlevel: 83\n",
            "storage"=>"Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/block/dm-8 100000000 40000000 60000000 40% /data\n",
            _=>return Err("unknown check".into()),
        }.to_owned())
    }
    #[test]
    fn no_device_never_reports_green() {
        let v = aggregate(&[], &mock);
        assert_eq!(v["status"], "no_authorized_devices");
        assert_eq!(v["authorized_device_count"], 0);
    }
    #[test]
    fn healthy_authorized_device_returns_metrics_only() {
        let v = aggregate(&["TEST123".to_owned()], &mock);
        assert_eq!(v["status"], "healthy");
        assert_eq!(v["devices"][0]["battery_percent"], 83);
        assert_eq!(v["devices"][0]["charging"], true);
        assert_eq!(v["devices"][0]["storage_free_mib"], 60000000 / 1024);
        assert_eq!(v["devices"][0].as_object().unwrap().len(), 8);
    }
    #[test]
    fn low_battery_attention_and_missing_probe_unverified() {
        let v = aggregate(&["TEST123".to_owned()], &|s, c| {
            if c == "battery" {
                Ok("level: 5\nstatus: 3".into())
            } else {
                mock(s, c)
            }
        });
        assert_eq!(v["status"], "attention");
        let v = aggregate(&["TEST123".to_owned()], &|s, c| {
            if c == "battery" {
                Err("offline".into())
            } else {
                mock(s, c)
            }
        });
        assert_eq!(v["status"], "unverified");
    }
    #[test]
    fn storage_requires_known_units_and_exact_data_mount() {
        for units in ["1K-blocks", "1024-blocks"] {
            let raw = format!(
                "\nFilesystem {units} Used Available Use% Mounted on\r\n\
                 /dev/other 9000000 1 8000000 1% /data/local\r\n\
                 /dev/data\t9000000\t1\t1048577\t1%\t/data\r\n"
            );
            assert_eq!(storage_mib(&raw), Some(1024));
        }
        for raw in [
            "",
            "/dev/data 9000000 1 1048576 1% /data",
            "Filesystem 512-blocks Used Available Use% Mounted on\n/dev/data 9000000 1 1048576 1% /data",
            "Filesystem Size Used Avail Use% Mounted on\n/dev/data 9G 1G 8G 1% /data",
            "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/data 9 1 -1 1% /data",
            "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/data 9 1 18446744073709551616 1% /data",
            "Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/data 9 1 8 1% /data/local",
        ] {
            assert_eq!(storage_mib(raw), None, "{raw:?}");
        }
        assert_eq!(storage_mib(&"x".repeat(16 * 1024 + 1)), None);
    }
    #[test]
    fn storage_threshold_controls_device_and_aggregate_health() {
        for (available, mib, status, findings) in [
            (0, 0, "attention", json!(["storage_low"])),
            (512 * 1024 - 1, 511, "attention", json!(["storage_low"])),
            (512 * 1024, 512, "healthy", json!([])),
            (512 * 1024 + 1024, 513, "healthy", json!([])),
        ] {
            let v = aggregate(&["TEST123".into()], &|s, c| {
                if c == "storage" {
                    Ok(format!("Filesystem 1K-blocks Used Available Use% Mounted on\n/dev/data 9000000 1 {available} 1% /data"))
                } else {
                    mock(s, c)
                }
            });
            assert_eq!(v["status"], status);
            assert_eq!(v["devices"][0]["status"], status);
            assert_eq!(v["devices"][0]["storage_free_mib"], mib);
            assert_eq!(v["devices"][0]["findings"], findings);
        }
    }
    #[test]
    fn missing_or_invalid_storage_is_unverified_not_low() {
        for result in [
            Err("offline".into()),
            Ok(String::new()),
            Ok("/data not mounted".into()),
        ] {
            let v = aggregate(&["TEST123".into()], &|s, c| {
                if c == "storage" {
                    result.clone()
                } else {
                    mock(s, c)
                }
            });
            assert_eq!(v["status"], "unverified");
            assert_eq!(v["devices"][0]["status"], "unverified");
            assert_eq!(v["devices"][0]["storage_free_mib"], Value::Null);
            assert_eq!(v["devices"][0]["findings"], json!(["adb_read_incomplete"]));
        }
    }
    #[test]
    fn rejects_malformed_data_and_untrusted_arguments() {
        assert!(model_label("Device; echo secret").is_none());
        assert!(storage_mib("/data not mounted").is_none());
        assert!(battery("level: 101\nstatus: 2").is_none());
        assert!(snapshot(&json!({"serial":"unexpected"})).is_err());
        assert!(snapshot(&json!({"command":"reboot"})).is_err());
        let many = (0..5).map(|i| format!("DEVICE{i}")).collect::<Vec<_>>();
        assert_eq!(aggregate(&many, &mock)["status"], "capacity_exceeded");
    }
}
