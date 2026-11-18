//! `tlsSettings.echConfigList` and `echForceQuery`, as Xray-core v26.11.9's
//! `TLSConfig` reads them.
//!
//! The base64 vector is a synthetic ECHConfigList: one V18 config with an
//! X25519 HPKE key, HKDF-SHA256 and AES-128-GCM, and the public name
//! `public.example`. Its key is filler, so no server would accept the sealed
//! hello, but the list is well-formed and rustls accepts it.
use segue_config::{parse_xray_json, DiagnosticSeverity, StreamSecurity};
use serde_json::{json, Value};

const ECH_CONFIG_LIST_BASE64: &str =
    "AEH+DQA9BwAgACAREREREREREREREREREREREREREREREREREREREREREQAEAAEAAQAOcHVibGljLmV4YW1wbGUAAA==";

fn config(tls_settings: Value) -> String {
    json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":{"network":"raw","security":"tls","tlsSettings":tls_settings}}]})
    .to_string()
}

fn tls_settings(raw: &str) -> segue_config::TlsSettings {
    let parsed = parse_xray_json(raw).expect("config should parse");
    let StreamSecurity::Tls(tls) = &parsed.config.outbounds[0].stream.security else {
        panic!("expected TLS security");
    };
    tls.clone()
}

fn errors(raw: &str) -> Vec<(Option<String>, String)> {
    parse_xray_json(raw)
        .expect_err("config must be rejected")
        .diagnostics
        .into_iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| (diagnostic.path, diagnostic.message))
        .collect()
}

fn assert_error_at(raw: &str, path: &str, needle: &str) {
    let errors = errors(raw);
    assert!(
        errors.iter().any(|(error_path, message)| {
            error_path.as_deref() == Some(path) && message.contains(needle)
        }),
        "expected an error at {path} mentioning {needle:?}, got {errors:?}"
    );
}

#[test]
fn static_base64_ech_config_list_is_decoded() {
    let tls = tls_settings(&config(json!({
        "serverName": "server.example",
        "fingerprint": "unsafe",
        "echConfigList": ECH_CONFIG_LIST_BASE64,
    })));
    let decoded = tls.ech_config_list.expect("ECH config list is decoded");
    assert_eq!(decoded.len(), 67);
    assert_eq!(decoded[..2], [0x00, 0x41], "the list length prefix");
    assert_eq!(decoded[2..4], [0xfe, 0x0d], "the V18 config version");
}

#[test]
fn absent_null_and_empty_ech_config_list_mean_no_ech() {
    for settings in [
        json!({"serverName": "server.example"}),
        json!({"serverName": "server.example", "echConfigList": null}),
        json!({"serverName": "server.example", "echConfigList": ""}),
    ] {
        let tls = tls_settings(&config(settings));
        assert!(tls.ech_config_list.is_none());
    }
}

#[test]
fn invalid_base64_ech_config_list_is_rejected() {
    assert_error_at(
        &config(json!({"echConfigList": "not base64!"})),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "standard padded base64",
    );
}

#[test]
fn ech_config_list_with_a_wrong_length_prefix_is_rejected() {
    // `AAE=` is `00 01`: a one-byte body that is not there.
    assert_error_at(
        &config(json!({"echConfigList": "AAE="})),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "length prefix",
    );
    // A well-formed but empty list.
    assert_error_at(
        &config(json!({"echConfigList": "AAA="})),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "carries no ECH config",
    );
    // A single byte is too short for the list's own length prefix.
    assert_error_at(
        &config(json!({"echConfigList": "AA=="})),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "fewer than 2 bytes",
    );
}

#[test]
fn ech_config_list_must_be_a_string() {
    assert_error_at(
        &config(json!({"echConfigList": 42})),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "must be a string or null",
    );
}

#[test]
fn dns_resolver_forms_of_ech_config_list_are_refused() {
    for value in [
        "udp://1.1.1.1",
        "https://1.1.1.1/dns-query",
        "encryptedsni.com+udp://1.1.1.1",
    ] {
        assert_error_at(
            &config(json!({"echConfigList": value})),
            "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
            "DNS resolver forms",
        );
    }
}

#[test]
fn ech_config_list_is_refused_with_a_shaping_fingerprint() {
    // An absent fingerprint normalizes to chrome, which shapes.
    assert_error_at(
        &config(json!({"echConfigList": ECH_CONFIG_LIST_BASE64})),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "shaping fingerprint",
    );
    assert_error_at(
        &config(json!({
            "fingerprint": "firefox",
            "echConfigList": ECH_CONFIG_LIST_BASE64,
        })),
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "shaping fingerprint",
    );
}

#[test]
fn ech_config_list_is_refused_on_a_quic_carrier() {
    let raw = json!({"outbounds":[{"tag":"proxy","protocol":"vless",
        "settings":{"vnext":[{"address":"server.example","port":443,
            "users":[{"id":"00010203-0405-0607-0809-0a0b0c0d0e0f","encryption":"none"}]}]},
        "streamSettings":{"network":"xhttp","security":"tls",
            "tlsSettings":{"fingerprint":"unsafe","alpn":["h3"],
                "echConfigList": ECH_CONFIG_LIST_BASE64}}}]})
    .to_string();
    assert_error_at(
        &raw,
        "$.outbounds[0].streamSettings.tlsSettings.echConfigList",
        "QUIC carrier",
    );
}

#[test]
fn ech_force_query_was_removed_by_xray() {
    for value in [json!("full"), json!("none"), json!("half")] {
        assert_error_at(
            &config(json!({"echForceQuery": value})),
            "$.outbounds[0].streamSettings.tlsSettings.echForceQuery",
            "was removed by Xray",
        );
    }
    // Null is Go's zero value and is accepted, as for every other string field.
    let tls = tls_settings(&config(json!({"echForceQuery": null})));
    assert!(tls.ech_config_list.is_none());
}
