//! Clash/mihomo YAML and sing-box JSON import.
//!
//! Every fixture is synthetic: fake UUIDs, keys and `example.com` hosts. Each
//! converted profile is run through the real parser, which is the contract
//! the importer promises.

#![cfg(feature = "import")]

use segue_config::import::{import_profile, ImportError, ImportFormat};
use serde_json::Value;

const CLASH: &str = include_str!("import/clash-full.yaml");
const SINGBOX: &str = include_str!("import/singbox-full.json");

fn convert(text: &str, format: ImportFormat) -> Value {
    let result = import_profile(text.as_bytes(), Some(format))
        .unwrap_or_else(|error| panic!("{format:?} import failed: {error}"));
    // The importer already parses its own output; parse again here so the
    // test fails if that contract ever regresses. A geodata file the fixture
    // references but that is not checked in is a deployment concern.
    let json = serde_json::to_string(&result.config).unwrap();
    let diagnostics = match segue_config::parse_xray_json(&json) {
        Ok(parsed) => parsed.diagnostics,
        Err(error) => error.diagnostics,
    };
    for diagnostic in diagnostics {
        assert!(
            diagnostic.message.contains("was not found"),
            "converted config rejected: {diagnostic:?}"
        );
    }
    result.config
}

fn outbound<'a>(config: &'a Value, tag: &str) -> &'a Value {
    config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|outbound| outbound["tag"] == tag)
        .unwrap_or_else(|| panic!("no outbound tagged {tag}"))
}

#[test]
fn clash_profile_converts_and_parses() {
    let config = convert(CLASH, ImportFormat::Clash);

    let vless = outbound(&config, "vless-reality");
    assert_eq!(vless["protocol"], "vless");
    assert_eq!(vless["settings"]["flow"], "xtls-rprx-vision");
    assert_eq!(vless["streamSettings"]["security"], "reality");
    assert_eq!(
        vless["streamSettings"]["realitySettings"]["serverName"],
        "www.example.com"
    );

    let vmess = outbound(&config, "vmess-ws");
    assert_eq!(vmess["protocol"], "vmess");
    assert_eq!(vmess["streamSettings"]["network"], "ws");
    assert_eq!(vmess["streamSettings"]["wsSettings"]["path"], "/ray");
    assert_eq!(vmess["streamSettings"]["wsSettings"]["host"], "ws.example.com");

    let trojan = outbound(&config, "trojan-grpc");
    assert_eq!(trojan["streamSettings"]["network"], "grpc");
    assert_eq!(
        trojan["streamSettings"]["grpcSettings"]["serviceName"],
        "GunService"
    );

    assert_eq!(outbound(&config, "ss-2022")["protocol"], "shadowsocks");

    let hy2 = outbound(&config, "hy2");
    assert_eq!(hy2["protocol"], "hysteria");
    assert_eq!(hy2["streamSettings"]["network"], "hysteria");
    let masks = hy2["streamSettings"]["finalmask"]["udp"].as_array().unwrap();
    assert_eq!(masks[0]["type"], "salamander");
    assert_eq!(masks[1]["type"], "udphop");

    assert_eq!(outbound(&config, "anytls")["protocol"], "anytls");
    assert_eq!(outbound(&config, "wg")["protocol"], "wireguard");
    assert_eq!(outbound(&config, "socks")["protocol"], "socks");
    assert_eq!(outbound(&config, "http-proxy")["protocol"], "http");

    // TUIC has no Segue equivalent and must not appear.
    assert!(config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .all(|outbound| outbound["tag"] != "tuic-unsupported"));
}

#[test]
fn clash_groups_become_balancers_and_observatory() {
    let config = convert(CLASH, ImportFormat::Clash);
    let balancers = config["routing"]["balancers"].as_array().unwrap();
    let auto = balancers
        .iter()
        .find(|balancer| balancer["tag"] == "auto")
        .unwrap();
    assert_eq!(auto["strategy"]["type"], "leastPing");
    let manual = balancers
        .iter()
        .find(|balancer| balancer["tag"] == "manual")
        .unwrap();
    assert_eq!(manual["strategy"]["type"], "random");
    let balance = balancers
        .iter()
        .find(|balancer| balancer["tag"] == "balance")
        .unwrap();
    assert_eq!(balance["strategy"]["type"], "roundRobin");

    assert_eq!(
        config["observatory"]["probeURL"],
        "https://www.gstatic.com/generate_204"
    );
    assert_eq!(config["observatory"]["probeInterval"], "300s");
}

#[test]
fn clash_rules_map_to_xray_conditions() {
    let config = convert(CLASH, ImportFormat::Clash);
    let rules = config["routing"]["rules"].as_array().unwrap();

    let suffix = rules
        .iter()
        .find(|rule| rule["domain"][0] == "domain:example.com")
        .unwrap();
    assert_eq!(suffix["balancerTag"], "auto");

    let exact = rules
        .iter()
        .find(|rule| rule["domain"][0] == "full:exact.example.org")
        .unwrap();
    assert_eq!(exact["balancerTag"], "manual");

    let keyword = rules
        .iter()
        .find(|rule| rule["domain"][0] == "keyword:ads")
        .unwrap();
    assert_eq!(keyword["outboundTag"], "REJECT");

    let cidr = rules
        .iter()
        .find(|rule| rule["ip"][0] == "192.0.2.0/24")
        .unwrap();
    assert_eq!(cidr["outboundTag"], "DIRECT");

    let geoip = rules
        .iter()
        .find(|rule| rule["ip"][0] == "geoip:CN")
        .unwrap();
    assert_eq!(geoip["outboundTag"], "DIRECT");

    let geosite = rules
        .iter()
        .find(|rule| rule["domain"][0] == "geosite:cn")
        .unwrap();
    assert_eq!(geosite["outboundTag"], "DIRECT");

    // PROCESS-NAME and RULE-SET cannot be expressed and are dropped.
    assert!(rules
        .iter()
        .all(|rule| rule["domain"][0] != "keyword:curl"));

    // MATCH is the last rule and always holds.
    let last = rules.last().unwrap();
    assert_eq!(last["balancerTag"], "auto");
    assert_eq!(last["network"], serde_json::json!(["tcp", "udp"]));
}

#[test]
fn clash_dns_fake_ip_and_exemptions() {
    let config = convert(CLASH, ImportFormat::Clash);
    let dns = &config["dns"];
    assert_eq!(dns["fakeIp"]["enabled"], true);
    assert_eq!(dns["fakeIp"]["ipv4Pool"], "198.18.0.1/16");
    let exempt = dns["fakeIp"]["exemptDomains"].as_array().unwrap();
    assert!(exempt.iter().any(|rule| rule == "domain:lan"));
    assert!(exempt.iter().any(|rule| rule == "domain:local"));
    // `*.example.com` becomes a suffix; a regex would be dropped.
    assert!(exempt.iter().any(|rule| rule == "domain:example.com"));
    // `system` is dropped, the DoH URL is kept.
    let servers = dns["servers"].as_array().unwrap();
    assert!(servers.iter().any(|server| server == "1.1.1.1"));
    assert!(servers
        .iter()
        .any(|server| server == "https://dns.example.com/dns-query"));
}

#[test]
fn singbox_profile_converts_and_parses() {
    let config = convert(SINGBOX, ImportFormat::Singbox);

    let vless = outbound(&config, "vless-reality");
    assert_eq!(vless["protocol"], "vless");
    assert_eq!(vless["settings"]["flow"], "xtls-rprx-vision");
    assert_eq!(vless["streamSettings"]["security"], "reality");
    assert_eq!(
        vless["streamSettings"]["realitySettings"]["fingerprint"],
        "chrome"
    );

    let vmess = outbound(&config, "vmess-ws");
    assert_eq!(vmess["streamSettings"]["network"], "ws");
    assert_eq!(vmess["streamSettings"]["wsSettings"]["host"], "ws.example.com");

    assert_eq!(
        outbound(&config, "trojan-grpc")["streamSettings"]["grpcSettings"]["serviceName"],
        "GunService"
    );
    assert_eq!(outbound(&config, "ss-2022")["protocol"], "shadowsocks");

    let hy2 = outbound(&config, "hy2");
    let masks = hy2["streamSettings"]["finalmask"]["udp"].as_array().unwrap();
    assert_eq!(masks[0]["type"], "salamander");
    assert_eq!(masks[1]["settings"]["remotePorts"], "443,8443-8445");

    assert_eq!(outbound(&config, "anytls")["protocol"], "anytls");
    assert_eq!(outbound(&config, "wg")["protocol"], "wireguard");
    assert_eq!(outbound(&config, "direct")["protocol"], "freedom");
    assert_eq!(outbound(&config, "block")["protocol"], "blackhole");
}

#[test]
fn singbox_groups_and_rules() {
    let config = convert(SINGBOX, ImportFormat::Singbox);
    let balancers = config["routing"]["balancers"].as_array().unwrap();
    let auto = balancers
        .iter()
        .find(|balancer| balancer["tag"] == "auto")
        .unwrap();
    assert_eq!(auto["strategy"]["type"], "leastPing");
    assert_eq!(config["observatory"]["probeInterval"], "300s");

    let rules = config["routing"]["rules"].as_array().unwrap();
    assert!(rules
        .iter()
        .any(|rule| rule["domain"][0] == "domain:example.com" && rule["balancerTag"] == "auto"));
    assert!(rules
        .iter()
        .any(|rule| rule["domain"][0] == "full:exact.example.org"));
    assert!(rules
        .iter()
        .any(|rule| rule["ip"][0] == "geoip:cn" && rule["outboundTag"] == "direct"));
    assert!(rules
        .iter()
        .any(|rule| rule["domain"][0] == "ext-srs:rules/ads.srs"));
    assert!(rules.iter().any(|rule| rule["port"] == "8443"));
    // process_name has no Xray equivalent; the rule is dropped.
    assert!(rules
        .iter()
        .all(|rule| rule.get("process_name").is_none()));
    // `route.final` is the last rule.
    assert_eq!(rules.last().unwrap()["balancerTag"], "auto");
}

#[test]
fn singbox_dns_fake_ip() {
    let config = convert(SINGBOX, ImportFormat::Singbox);
    let dns = &config["dns"];
    assert_eq!(dns["fakeIp"]["ipv4Pool"], "198.18.0.0/15");
    let servers = dns["servers"].as_array().unwrap();
    assert!(servers.iter().any(|server| server == "1.1.1.1"));
    assert!(servers
        .iter()
        .any(|server| server == "https://dns.example.com:443"));
}

#[test]
fn format_is_sniffed_without_a_hint() {
    let clash = import_profile(CLASH.as_bytes(), None).unwrap();
    assert_eq!(clash.format, ImportFormat::Clash);
    let singbox = import_profile(SINGBOX.as_bytes(), None).unwrap();
    assert_eq!(singbox.format, ImportFormat::Singbox);
}

#[test]
fn unsupported_fields_become_warnings() {
    let result = import_profile(CLASH.as_bytes(), Some(ImportFormat::Clash)).unwrap();
    let paths: Vec<&str> = result
        .warnings
        .iter()
        .map(|warning| warning.path.as_str())
        .collect();
    assert!(paths.iter().any(|path| path.starts_with("proxies[9]")));
    assert!(paths.iter().any(|path| path.starts_with("rule-providers.")));
    assert!(paths.iter().any(|path| path.starts_with("dns.fallback")));
    // No warning may repeat a credential.
    for warning in &result.warnings {
        assert!(!warning.message.contains("synthetic-"));
    }
}

#[test]
fn empty_profiles_are_refused() {
    let error = import_profile(b"proxies: []\n", Some(ImportFormat::Clash)).unwrap_err();
    assert!(matches!(error, ImportError::Empty));
    let error = import_profile(b"{\"outbounds\": []}", Some(ImportFormat::Singbox)).unwrap_err();
    assert!(matches!(error, ImportError::Empty));
}

#[test]
fn malformed_profiles_are_refused() {
    assert!(matches!(
        import_profile(b"proxies: [", Some(ImportFormat::Clash)).unwrap_err(),
        ImportError::Syntax(_)
    ));
    assert!(matches!(
        import_profile(b"{", Some(ImportFormat::Singbox)).unwrap_err(),
        ImportError::Syntax(_)
    ));
}

#[test]
fn plaintext_vless_to_a_public_server_is_dropped() {
    let profile = r#"
proxies:
  - name: plain
    type: vless
    server: edge.example.com
    port: 443
    uuid: 00000000-0000-4000-8000-000000000001
  - name: local
    type: vless
    server: 192.168.1.10
    port: 443
    uuid: 00000000-0000-4000-8000-000000000002
"#;
    let config = convert(profile, ImportFormat::Clash);
    let tags: Vec<&str> = config["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|outbound| outbound["tag"].as_str().unwrap())
        .collect();
    assert!(!tags.contains(&"plain"));
    assert!(tags.contains(&"local"));
}
