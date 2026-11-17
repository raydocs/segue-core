use segue_config::{parse_xray_json, AnyTlsOutboundSettings, OutboundSettings};
use serde_json::{json, Value};
use std::time::Duration;

fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"protocol":"anytls","settings":settings,"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.test"}}}]})
}
fn server() -> Value {
    json!({"address":"example.test","port":443,"password":"synthetic-anytls-test-secret"})
}

fn settings_of(config: &Value) -> AnyTlsOutboundSettings {
    // Own the settings. A reference would borrow `parsed`, which dies with this
    // function, and the callers pass a temporary profile.
    let parsed = parse_xray_json(&config.to_string()).unwrap();
    let outbound = parsed.config.outbounds.into_iter().next().expect("outbound");
    let OutboundSettings::AnyTls(settings) = outbound.settings else {
        panic!("AnyTLS")
    };
    settings
}

#[test]
fn defaults_and_redaction() {
    let parsed = parse_xray_json(&profile(server()).to_string()).unwrap();
    let OutboundSettings::AnyTls(settings) = &parsed.config.outbounds[0].settings else {
        panic!("AnyTLS")
    };
    assert_eq!(settings.port, 443);
    assert_eq!(settings.level, 0);
    assert_eq!(settings.min_idle_session, 0);
    assert_eq!(settings.client_metadata, None);
    // Zero means "take the reference's floor" at runtime.
    assert_eq!(settings.idle_session_check_interval, Duration::ZERO);
    assert_eq!(settings.idle_session_timeout, Duration::ZERO);
    assert_eq!(settings.password.as_str(), "synthetic-anytls-test-secret");
    assert!(!format!("{:?}", parsed.config).contains(settings.password.as_str()));
}

#[test]
fn every_field_is_read() {
    let mut settings = server();
    settings["idle_session_check_interval"] = json!("45s");
    settings["idle_session_timeout"] = json!("2m");
    settings["min_idle_session"] = json!(3);
    settings["client_metadata"] = json!("sing-anytls/0.0.13");
    settings["level"] = json!(7);
    let parsed = settings_of(&profile(settings));
    assert_eq!(parsed.idle_session_check_interval, Duration::from_secs(45));
    assert_eq!(parsed.idle_session_timeout, Duration::from_secs(120));
    assert_eq!(parsed.min_idle_session, 3);
    assert_eq!(
        parsed.client_metadata.as_deref(),
        Some("sing-anytls/0.0.13")
    );
    assert_eq!(parsed.level, 7);
}

#[test]
fn a_bare_number_is_nanoseconds_as_go_reads_it() {
    let mut settings = server();
    settings["idle_session_timeout"] = json!(30_000_000_000u64);
    assert_eq!(
        settings_of(&profile(settings)).idle_session_timeout,
        Duration::from_secs(30)
    );
}

#[test]
fn invalid_shapes_are_rejected_without_echoing_the_password() {
    let mut cases = vec![json!(null), json!([]), json!({})];
    for (key, value) in [
        ("address", json!("")),
        ("address", json!("a".repeat(256))),
        ("address", json!("bad host")),
        ("address", json!(1)),
        ("port", json!(0)),
        ("port", json!(65536)),
        ("port", json!("443")),
        ("password", json!("")),
        ("password", json!(1)),
        ("level", json!(256)),
        ("min_idle_session", json!(9)),
        ("min_idle_session", json!(-1)),
        ("idle_session_timeout", json!("soon")),
        ("idle_session_timeout", json!("0s")),
        ("idle_session_timeout", json!(0)),
        ("idle_session_check_interval", json!(true)),
        ("client_metadata", json!("a\nb")),
        ("client_metadata", json!("a=b")),
        ("client_metadata", json!(1)),
        ("unknownField", json!(1)),
    ] {
        let mut settings = server();
        settings[key] = value;
        cases.push(settings);
    }
    for case in cases {
        let raw = profile(case).to_string();
        let error = parse_xray_json(&raw).unwrap_err();
        assert!(
            !format!("{error:?}").contains("synthetic-anytls-test-secret"),
            "{error:?}"
        );
    }
}

#[test]
fn plaintext_and_insecure_tls_are_refused() {
    let plaintext = json!({"outbounds":[{"protocol":"anytls","settings":server()}]});
    assert!(parse_xray_json(&plaintext.to_string()).is_err());
    let insecure = json!({"outbounds":[{"protocol":"anytls","settings":server(),
        "streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.test","allowInsecure":true}}}]});
    assert!(parse_xray_json(&insecure.to_string()).is_err());
    // REALITY is accepted, as it is for Trojan.
    let reality = json!({"outbounds":[{"protocol":"anytls","settings":server(),
        "streamSettings":{"security":"reality","realitySettings":{
            "serverName":"example.test","fingerprint":"chrome",
            "publicKey":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
            "shortId":"02030405"}}}]});
    assert!(parse_xray_json(&reality.to_string()).is_ok());
}

#[test]
fn the_protocol_name_is_reported() {
    let parsed = parse_xray_json(&profile(server()).to_string()).unwrap();
    assert_eq!(
        parsed.config.outbounds[0].settings.protocol(),
        segue_config::OutboundProtocol::AnyTls
    );
}
