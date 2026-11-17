use segue_config::{
    parse_xray_json, OutboundProtocol, OutboundSettings, StreamSecurity, TuicCongestionControl,
    TuicUdpRelayMode,
};
use serde_json::{json, Value};
use std::time::Duration;

const UUID: &str = "00010203-0405-0607-0809-0a0b0c0d0e0f";
const PASSWORD: &str = "synthetic-tuic-test-password";

fn settings() -> Value {
    json!({
        "server": "tuic.example",
        "port": 443,
        "uuid": UUID,
        "password": PASSWORD,
    })
}

fn profile(settings: Value) -> Value {
    json!({"outbounds":[{"protocol":"tuic","settings":settings,
        "streamSettings":{"network":"udp","security":"tls",
            "tlsSettings":{"serverName":"tuic.example"}}}]})
}

#[test]
fn defaults_and_explicit_values_parse_without_leaking_credentials() {
    let outbounds = parse_xray_json(&profile(settings()).to_string())
        .unwrap()
        .config
        .outbounds;
    let OutboundSettings::Tuic(settings) = &outbounds[0].settings else {
        panic!("TUIC")
    };
    assert_eq!(outbounds[0].settings.protocol(), OutboundProtocol::Tuic);
    assert_eq!(settings.congestion_control, TuicCongestionControl::NewReno);
    assert_eq!(settings.udp_relay_mode, TuicUdpRelayMode::Native);
    assert!(!settings.zero_rtt_handshake);
    assert_eq!(settings.heartbeat, Duration::from_secs(10));
    assert_eq!(settings.uuid.as_bytes()[0], 0);
    assert!(!format!("{:?}", outbounds).contains(PASSWORD));
    assert!(!format!("{:?}", outbounds).contains(UUID));
}

#[test]
fn all_options_and_tls_insecure_are_parsed() {
    let mut settings = settings();
    settings["congestion_control"] = json!("bbr");
    settings["udp_relay_mode"] = json!("quic");
    settings["zero_rtt_handshake"] = json!(true);
    settings["heartbeat"] = json!("3s");
    let mut config = profile(settings);
    config["outbounds"][0]["streamSettings"]["tlsSettings"]["allowInsecure"] = json!(true);
    config["outbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = json!(["tuic"]);
    let parsed = parse_xray_json(&config.to_string()).unwrap();
    let OutboundSettings::Tuic(tuic) = &parsed.config.outbounds[0].settings else {
        panic!("TUIC")
    };
    assert_eq!(tuic.congestion_control, TuicCongestionControl::Bbr);
    assert_eq!(tuic.udp_relay_mode, TuicUdpRelayMode::Quic);
    assert!(tuic.zero_rtt_handshake);
    assert_eq!(tuic.heartbeat, Duration::from_secs(3));
    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("TLS")
    };
    assert!(tls.allow_insecure);
    assert_eq!(tls.alpn, ["tuic"]);
}

#[test]
fn heartbeat_accepts_nanoseconds_as_a_go_duration() {
    let mut settings = settings();
    settings["heartbeat"] = json!(2_000_000_000u64);
    let parsed = parse_xray_json(&profile(settings).to_string()).unwrap();
    let OutboundSettings::Tuic(tuic) = &parsed.config.outbounds[0].settings else {
        panic!("TUIC")
    };
    assert_eq!(tuic.heartbeat, Duration::from_secs(2));
}

#[test]
fn bad_settings_unknown_fields_and_the_wrong_transport_are_rejected() {
    let mut cases = vec![json!(null), json!([]), json!({})];
    for (key, bad) in [
        ("server", json!("bad host")),
        ("server", json!(1)),
        ("port", json!(0)),
        ("port", json!(65536)),
        ("uuid", json!("not-a-uuid")),
        ("uuid", json!(1)),
        ("password", json!("")),
        ("password", json!(1)),
        ("congestion_control", json!("reno")),
        ("congestion_control", json!(1)),
        ("udp_relay_mode", json!("stream")),
        ("udp_relay_mode", json!(1)),
        ("zero_rtt_handshake", json!(1)),
        ("heartbeat", json!("0s")),
        ("heartbeat", json!(0)),
        ("heartbeat", json!(true)),
        ("extra", json!(true)),
    ] {
        let mut value = settings();
        value[key] = bad;
        cases.push(value);
    }
    for case in cases {
        let raw = profile(case).to_string();
        let error = parse_xray_json(&raw).unwrap_err();
        assert!(!format!("{error:?}").contains(PASSWORD));
    }
    for (security, network) in [(json!("none"), json!("udp")), (json!("tls"), json!("tcp"))] {
        let mut config = profile(settings());
        config["outbounds"][0]["streamSettings"]["security"] = security;
        config["outbounds"][0]["streamSettings"]["network"] = network;
        assert!(parse_xray_json(&config.to_string()).is_err());
    }
    let insecure = json!({"outbounds":[{"protocol":"anytls","settings":{
        "address":"example.test","port":443,"password":PASSWORD},
        "streamSettings":{"security":"tls","tlsSettings":{"allowInsecure":true}}}]});
    assert!(parse_xray_json(&insecure.to_string()).is_err());
}
