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
        if line.len() > 2048 || line.chars().any(|c| c.is_control() && c != '\t') {
            return Err("RouterOS health line oversized or invalid".into());
        }
        let value = line.trim();
        // Only exact standalone markers delimit sections. Reserve RF_ lines so
        // malformed or unknown markers cannot silently become section data.
        if let Some(index) = MARKERS.iter().position(|marker| *marker == line) {
            if index != outputs.len() {
                return Err("RouterOS health marker missing or reordered".into());
            }
            outputs.push(String::new());
        } else if value.starts_with("RF_") {
            return Err("RouterOS health marker invalid".into());
        } else if let Some(last) = outputs.last_mut() {
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

fn service_source_unrestricted(address: &str) -> Result<bool, String> {
    let invalid = || "RouterOS management service scope unknown".to_owned();
    let address = if let Some(quoted) = address.strip_prefix('"') {
        quoted.strip_suffix('"').ok_or_else(invalid)?
    } else {
        address
    };
    if address.is_empty() {
        return Ok(true);
    }
    let mut unrestricted = false;
    for entry in address.split(',') {
        let (ip, prefix) = match entry.split_once('/') {
            Some((ip, prefix)) => (ip, Some(prefix)),
            None => (entry, None),
        };
        let ip = ip.parse::<std::net::IpAddr>().map_err(|_| invalid())?;
        if let Some(prefix) = prefix {
            if prefix.is_empty() || !prefix.bytes().all(|c| c.is_ascii_digit()) {
                return Err(invalid());
            }
            let prefix = prefix.parse::<u8>().map_err(|_| invalid())?;
            if prefix > if ip.is_ipv4() { 32 } else { 128 } {
                return Err(invalid());
            }
            unrestricted |= prefix == 0;
        }
    }
    Ok(unrestricted)
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
        // Connection rows describe sessions, not configured source restrictions.
        if disabled(line, "name=")
            || flags(line, "name=")
                .iter()
                .any(|flag| flag.contains('D') || flag.contains('c'))
            || property(line, "local").is_some()
            || property(line, "remote").is_some()
        {
            continue;
        }
        let address =
            property(line, "address").ok_or("RouterOS management service scope unknown")?;
        if service_source_unrestricted(address)? {
            unscoped.push(name);
        } else {
            scoped.push(name);
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
    fn rejects_every_missing_or_duplicated_marker() {
        for marker in MARKERS {
            let line = format!("{marker}\n");
            assert!(parse(&fixture().replace(&line, "")).is_err(), "{marker}");
            assert!(
                parse(&fixture().replace(&line, &format!("{line}{line}"))).is_err(),
                "{marker}"
            );
            assert!(parse(&format!("{}{line}", fixture())).is_err(), "{marker}");
        }
    }

    #[test]
    fn rejects_reordered_markers() {
        for pair in MARKERS.windows(2) {
            let raw = fixture()
                .lines()
                .map(|line| {
                    if line == pair[0] {
                        pair[1]
                    } else if line == pair[1] {
                        pair[0]
                    } else {
                        line
                    }
                    .to_owned()
                })
                .collect::<Vec<_>>()
                .join("\n");
            assert!(parse(&raw).is_err(), "{pair:?}");
        }
    }

    #[test]
    fn rejects_malformed_markers_and_control_characters() {
        for payload in [
            "RF_UNKNOWN",
            " RF_SERVICES",
            "RF_SERVICES\t",
            "RF_SERVICES name=ssh address=",
            "RF_SERVICES; /system/reboot",
            "RF_SERVICES\u{200b}",
            "\u{1b}[2KRF_SERVICES",
            "RF_SERVICES\rhidden",
        ] {
            for marker in MARKERS {
                let raw = fixture().replace(marker, &format!("{marker}\n{payload}"));
                assert!(parse(&raw).is_err(), "{marker}: {payload:?}");
            }
        }
    }

    #[test]
    fn accepts_crlf_and_marker_names_inside_properties() {
        let raw = fixture().replace("name=ether1", "name=RF_SERVICES");
        assert_eq!(
            parse(&raw).unwrap(),
            parse(&raw.replace('\n', "\r\n")).unwrap()
        );
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
    fn service_allowlists_distinguish_hosts_subnets_and_unrestricted_ranges() {
        for (address, unrestricted) in [
            ("", true),
            ("\"\"", true),
            ("0.0.0.0/0", true),
            ("::/0", true),
            ("192.0.2.0/24,::/0", true),
            ("0.0.0.0/0,2001:db8::/32", true),
            ("\"192.0.2.0/24,::/0\"", true),
            ("192.0.2.15", false),
            ("2001:db8::1", false),
            ("192.0.2.15/32,2001:db8::1/128", false),
            ("\"192.0.2.0/24,2001:db8::/32\"", false),
            ("0.0.0.0/32,::/128", false),
        ] {
            let raw = fixture().replace(
                "2 name=ssh port=2224 address=192.0.2.15/32",
                &format!("2 name=ssh port=2224 address={address}"),
            );
            let value = parse(&raw).unwrap();
            let services = &value["management_services"];
            assert_eq!(
                services["source_unrestricted"],
                if unrestricted {
                    json!(["ftp", "ssh", "winbox"])
                } else {
                    json!(["ftp", "winbox"])
                },
                "{address}"
            );
            assert_eq!(
                services["source_restricted"],
                if unrestricted {
                    json!([])
                } else {
                    json!(["ssh"])
                },
                "{address}"
            );
            assert_eq!(
                services["scope_note"],
                "Service-level address restrictions only; firewall/WAN reachability not evaluated"
            );
            assert_eq!(value["status"], "attention");
        }
    }

    #[test]
    fn malformed_or_missing_service_allowlists_fail_closed() {
        for address in [
            "bad",
            "192.0.2.1/33",
            "::/129",
            "192.0.2.1/",
            "192.0.2.1/-1",
            "192.0.2.1,",
            "0.0.0.0/0,bad",
            "\"192.0.2.1",
            "192.0.2.1\"",
        ] {
            assert!(
                parse(&fixture().replace("address=192.0.2.15/32", &format!("address={address}")))
                    .is_err(),
                "{address}"
            );
        }
        assert!(parse(&fixture().replace(" address=192.0.2.15/32", "")).is_err());
    }

    #[test]
    fn connections_and_disabled_services_do_not_affect_configured_scope() {
        let baseline = parse(&fixture()).unwrap();
        for row in [
            "5 D c name=ssh local=192.0.2.1 remote=192.0.2.15:50000",
            "5 Dc name=ssh address=0.0.0.0/0",
            "5 c name=ssh address=",
            "5 name=ssh local=192.0.2.1 remote=192.0.2.15:50000",
            "5 X name=ssh address=0.0.0.0/0",
            "5 X name=ssh",
        ] {
            let raw = format!("{}{row}\n", fixture());
            assert_eq!(parse(&raw).unwrap(), baseline, "{row}");
        }
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
