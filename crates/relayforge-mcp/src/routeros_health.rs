//! Fixed, bounded, read-only RouterOS posture: no configuration, scripts from
//! clients, wireless credentials, DHCP client addresses or raw firewall rules.
//! A single RouterOS SSH session obtains consistent sections using fixed
//! print-only commands. No RouterOS API or network listener is introduced.
use serde_json::{json, Value};

const SCRIPT: &str = concat!(
    ":put \"RF_RESOURCE\"; /system/resource/print; ",
    ":put \"RF_INTERFACES\"; /interface/print terse; ",
    ":put \"RF_ROUTES\"; /ip/route/print terse; ",
    ":put \"RF_DHCP\"; /ip/dhcp-server/print terse; ",
    ":put \"RF_WIFI\"; /interface/wifi/print terse; ",
    ":put \"RF_FILTER_COUNT\"; /ip/firewall/filter/print count-only; ",
    ":put \"RF_NAT_COUNT\"; /ip/firewall/nat/print count-only; ",
    ":put \"RF_WIFI_CLIENT_COUNT\"; /interface/wifi/registration-table/print count-only; ",
    ":put \"RF_LEASE_COUNT\"; /ip/dhcp-server/lease/print count-only; ",
    ":put \"RF_SERVICES\"; /ip/service/print terse"
);
const MARKERS: &[&str] = &[
    "RF_RESOURCE",
    "RF_INTERFACES",
    "RF_ROUTES",
    "RF_DHCP",
    "RF_WIFI",
    "RF_FILTER_COUNT",
    "RF_NAT_COUNT",
    "RF_WIFI_CLIENT_COUNT",
    "RF_LEASE_COUNT",
    "RF_SERVICES",
];

pub fn tool() -> Value {
    json!({"name":"relayforge_routeros_health",
        "description":"Read-only MikroTik RouterOS health and management-service posture without returning client addresses, Wi-Fi passwords or configuration. Checks uplink/default route, DHCP, Wi-Fi, firewall/NAT counts and management service source scoping.",
        "inputSchema":{"type":"object","properties":{},"additionalProperties":false}})
}

pub fn snapshot(args: &Value) -> Result<String, String> {
    if args.as_object().is_none_or(|obj| !obj.is_empty()) {
        return Err("unexpected RouterOS health arguments".into());
    }
    let raw = crate::routeros::health_snapshot_transport(SCRIPT)?;
    Ok(parse(&raw)?.to_string())
}

fn sections(raw: &str) -> Result<Vec<String>, String> {
    if raw.len() > 16 * 1024 || raw.contains('\0') {
        return Err("RouterOS health response oversized or invalid".into());
    }
    let mut outputs: Vec<String> = Vec::with_capacity(MARKERS.len());
    for line in raw.lines() {
        let value = line.trim();
        if let Some(index) = MARKERS.iter().position(|marker| *marker == value) {
            if index != outputs.len() {
                return Err("RouterOS health marker missing or reordered".into());
            }
            outputs.push(String::new());
        } else if let Some(last) = outputs.last_mut() {
            if line.len() > 2048 {
                return Err("RouterOS health line too large".into());
            }
            last.push_str(line);
            last.push('\n');
        } else if !value.is_empty() {
            return Err("RouterOS unexpected health prefix".into());
        }
    }
    if outputs.len() != MARKERS.len() {
        return Err("RouterOS health snapshot incomplete".into());
    }
    Ok(outputs)
}

fn property<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(&prefix))
}

fn flags<'a>(line: &'a str, property_name: &str) -> Vec<&'a str> {
    line.split(property_name)
        .next()
        .unwrap_or("")
        .split_ascii_whitespace()
        .filter(|token| token.len() <= 4)
        .collect()
}

fn disabled(line: &str, field: &str) -> bool {
    flags(line, field).iter().any(|flag| flag.contains('X'))
}

fn running(line: &str, field: &str) -> bool {
    flags(line, field).iter().any(|flag| flag.contains('R'))
}

fn default_route_active(line: &str) -> bool {
    property(line, "dst-address") == Some("0.0.0.0/0")
        && property(line, "routing-table") == Some("main")
        && flags(line, "dst-address=")
            .iter()
            .any(|flag| flag.contains('A'))
        && !disabled(line, "dst-address=")
}

fn numeric_section(section: &str) -> Result<u32, String> {
    let trimmed = section.trim();
    if trimmed.is_empty() || trimmed.len() > 7 || !trimmed.bytes().all(|c| c.is_ascii_digit()) {
        return Err("invalid RouterOS count response".into());
    }
    let count = trimmed
        .parse::<u32>()
        .map_err(|_| "invalid RouterOS count response")?;
    if count > 100_000 {
        return Err("RouterOS count exceeds limit".into());
    }
    Ok(count)
}

fn metadata(section: &str, key: &str) -> Option<String> {
    section.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name.trim() == key).then(|| value.trim().to_owned())
    })
}

fn parse(raw: &str) -> Result<Value, String> {
    let output = sections(raw)?;
    let board = metadata(&output[0], "board-name").ok_or("RouterOS board unknown")?;
    let version = metadata(&output[0], "version").ok_or("RouterOS version unknown")?;
    let uptime = metadata(&output[0], "uptime").ok_or("RouterOS uptime unknown")?;
    if board.is_empty() || board.len() > 64 || version.len() > 64 || uptime.len() > 64 {
        return Err("RouterOS resource fields invalid".into());
    }
    let cpu = metadata(&output[0], "cpu-load")
        .and_then(|s| s.trim_end_matches('%').parse::<u8>().ok())
        .filter(|v| *v <= 100)
        .ok_or("RouterOS CPU load missing")?;

    let interfaces: Vec<_> = output[1]
        .lines()
        .filter(|line| property(line, "name").is_some())
        .collect();
    if interfaces.is_empty() || interfaces.len() > 128 {
        return Err("RouterOS interface inventory unavailable".into());
    }
    let pppoe_up = interfaces.iter().any(|line| {
        property(line, "type") == Some("pppoe-out")
            && running(line, "name=")
            && !disabled(line, "name=")
    });
    let interfaces_disabled = interfaces
        .iter()
        .filter(|line| disabled(line, "name="))
        .count();
    let route_active = output[2].lines().any(default_route_active);
    let dhcp_servers_active = output[3]
        .lines()
        .filter(|line| property(line, "name").is_some() && !disabled(line, "name="))
        .count();
    let wifi_radios = output[4]
        .lines()
        .filter(|line| property(line, "name").is_some())
        .count();
    let wifi_radios_running = output[4]
        .lines()
        .filter(|line| property(line, "name").is_some() && running(line, "name="))
        .count();
    let firewall_filter = numeric_section(&output[5])?;
    let firewall_nat = numeric_section(&output[6])?;
    let wifi_clients = numeric_section(&output[7])?;
    let dhcp_leases = numeric_section(&output[8])?;

    let mut unscoped = Vec::new();
    let mut scoped = Vec::new();
    for line in output[9].lines() {
        let Some(name) = property(line, "name") else {
            continue;
        };
        if ![
            "ftp", "telnet", "www", "www-ssl", "ssh", "winbox", "api", "api-ssl",
        ]
        .contains(&name)
        {
            continue;
        }
        // Dynamic RouterOS service connection rows carry D c flags,
        // local=/remote= instead of the configured address= restriction.
        if disabled(line, "name=") || flags(line, "name=").iter().any(|flag| flag.contains('D')) {
            continue;
        }
        match property(line, "address") {
            Some("") => unscoped.push(name),
            Some(_) => scoped.push(name),
            None => return Err("RouterOS management service scope unknown".into()),
        }
    }
    if unscoped.len() + scoped.len() > 8 {
        return Err("RouterOS management inventory malformed".into());
    }
    let mut findings = Vec::new();
    if !pppoe_up {
        findings.push("pppoe_not_running");
    }
    if !route_active {
        findings.push("main_default_route_inactive");
    }
    if dhcp_servers_active == 0 {
        findings.push("dhcp_server_not_active");
    }
    if wifi_radios == 0 || wifi_radios_running == 0 {
        findings.push("wifi_radio_not_running");
    }
    if !unscoped.is_empty() {
        findings.push("management_service_source_scope_unrestricted");
    }
    let critical = !pppoe_up || !route_active || dhcp_servers_active == 0;
    Ok(json!({
        "status":if critical {"degraded"} else if findings.is_empty() {"healthy"} else {"attention"},
        "router":{"board":board,"version":version,"uptime":uptime,"cpu_load_percent":cpu},
        "interfaces":{"total":interfaces.len(),"disabled":interfaces_disabled,"pppoe_running":pppoe_up},
        "network":{"main_default_route_active":route_active,"dhcp_servers_active":dhcp_servers_active,
            "dhcp_lease_count":dhcp_leases,"wifi_radios":wifi_radios,
            "wifi_radios_running":wifi_radios_running,"wifi_client_count":wifi_clients},
        "firewall":{"filter_rule_count":firewall_filter,"nat_rule_count":firewall_nat},
        "management_services":{"source_unrestricted":unscoped,"source_restricted":scoped,
            "scope_note":"Service-level address restrictions only; firewall/WAN reachability not evaluated"},
        "findings":findings,
        "access":"read_only",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> String {
        [
            "RF_RESOURCE\n uptime: 2h\n version: 7.19.5 (stable)\n cpu-load: 2%\n board-name: hAP ax S\n",
            "RF_INTERFACES\n0 R name=ether1 type=ether\n1 R name=pppoe-out4 type=pppoe-out\n2 X name=sfp1 type=ether\n",
            "RF_ROUTES\nDAv dst-address=0.0.0.0/0 routing-table=main gateway=pppoe-out4\n0 As dst-address=0.0.0.0/0 routing-table=vpn-table gateway=wireguard1\n",
            "RF_DHCP\n0 name=defconf interface=bridge lease-time=30m\n",
            "RF_WIFI\n0 MBR name=wifi1 configuration.ssid=PRIVATE security.passphrase=SECRET\n",
            "RF_FILTER_COUNT\n11\n",
            "RF_NAT_COUNT\n8\n",
            "RF_WIFI_CLIENT_COUNT\n3\n",
            "RF_LEASE_COUNT\n5\n",
            "RF_SERVICES\n0 name=ftp port=21 address=\n1 X name=telnet port=23 address=\n2 name=ssh port=2224 address=192.0.2.15/32\n4 D c name=ssh local=192.0.2.1 remote=192.0.2.15:50000\n3 name=winbox port=8291 address=\n",
        ].concat()
    }
    #[test]
    fn strips_sensitive_text_and_identifies_unscoped_services() {
        let value = parse(&fixture()).unwrap();
        assert_eq!(value["status"], "attention");
        assert_eq!(value["interfaces"]["pppoe_running"], true);
        assert_eq!(value["network"]["main_default_route_active"], true);
        assert_eq!(value["network"]["wifi_client_count"], 3);
        assert_eq!(value["firewall"]["filter_rule_count"], 11);
        assert_eq!(
            value["management_services"]["source_unrestricted"],
            json!(["ftp", "winbox"])
        );
        let output = value.to_string();
        for secret in ["PRIVATE", "SECRET", "192.0.2.15", "pppoe-out4"] {
            assert!(!output.contains(secret));
        }
    }
    #[test]
    fn disconnected_primary_uplink_fails_degraded() {
        let raw = fixture().replace("1 R name=pppoe-out4", "1 name=pppoe-out4");
        assert_eq!(parse(&raw).unwrap()["status"], "degraded");
    }
    #[test]
    fn inactive_primary_route_fails_degraded() {
        let raw = fixture().replace("DAv dst-address=0.0.0.0/0", "D v dst-address=0.0.0.0/0");
        assert_eq!(parse(&raw).unwrap()["status"], "degraded");
    }
    #[test]
    fn refuses_partial_reordered_or_invalid_results() {
        for data in [
            fixture().replace("RF_NAT_COUNT", "RF_BAD_MARKER"),
            fixture().replace("RF_NAT_COUNT", "RF_FILTER_COUNT"),
            fixture().replace("RF_WIFI_CLIENT_COUNT\n3", "RF_WIFI_CLIENT_COUNT\n-1"),
            fixture().replace("RF_FILTER_COUNT\n11", "RF_FILTER_COUNT\n100000000"),
            fixture().replace("RF_SERVICES", "RF_NOT_SERVICES"),
            format!("{}\0", fixture()),
        ] {
            assert!(parse(&data).is_err());
        }
    }
    #[test]
    fn management_only_alert_remains_advisory() {
        let raw = fixture()
            .replace(
                "0 name=ftp port=21 address=",
                "0 X name=ftp port=21 address=",
            )
            .replace(
                "3 name=winbox port=8291 address=",
                "3 name=winbox port=8291 address=192.0.2.0/24",
            );
        let parsed = parse(&raw).unwrap();
        assert_eq!(parsed["status"], "healthy");
        assert_eq!(
            parsed["management_services"]["source_unrestricted"],
            json!([])
        );
    }

    #[test]
    fn wifi_and_dhcp_absence_are_visible() {
        let no_wifi = fixture().replace("0 MBR name=wifi1", "0 M B name=wifi1");
        let no_radio = parse(&no_wifi).unwrap();
        assert_eq!(no_radio["status"], "attention");
        assert_eq!(no_radio["network"]["wifi_radios_running"], 0);
        let no_dhcp = fixture().replace("0 name=defconf", "0 X name=defconf");
        let no_server = parse(&no_dhcp).unwrap();
        assert_eq!(no_server["status"], "degraded");
    }

    #[test]
    fn fixed_script_read_only_and_strict_args() {
        assert!(snapshot(&json!({"action":"reboot"})).is_err());
        assert!(snapshot(&json!({"host":"192.168.88.1"})).is_err());
        for banned in [
            "set ",
            "remove ",
            "add ",
            "disable ",
            "enable ",
            "export ",
            "password=",
        ] {
            assert!(!SCRIPT.contains(banned), "{banned}");
        }
        assert_eq!(MARKERS.len(), 10);
    }
}
