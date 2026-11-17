//! Import of Clash/mihomo YAML and sing-box JSON profiles into Segue's
//! Xray-style JSON configuration.
//!
//! The converters are deliberately lossy in one direction only: every field
//! they cannot express becomes an [`ImportWarning`] naming the source path,
//! never a silent drop. The produced [`ImportResult::config`] is ordinary
//! Xray JSON and is expected to pass [`crate::parse_xray_json`] (geodata
//! references such as `geoip:` need the usual `geoip.dat` beside it).

mod clash;
mod singbox;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

/// Largest profile accepted, matching the bounded parsers elsewhere.
pub const MAX_IMPORT_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ImportFormat {
    Clash,
    Singbox,
}

impl ImportFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Clash => "clash",
            Self::Singbox => "singbox",
        }
    }
}

/// One source field the converter could not carry, with the path it came
/// from. Messages never repeat credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImportWarning {
    pub path: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ImportResult {
    pub format: ImportFormat,
    pub config: Value,
    pub warnings: Vec<ImportWarning>,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ImportError {
    #[error("profile exceeds the import size limit")]
    TooLarge,
    #[error("profile is not valid {0} syntax")]
    Syntax(&'static str),
    #[error("profile contains no outbound Segue can use")]
    Empty,
    #[error("profile format is unknown; pass --format clash or --format singbox")]
    UnknownFormat,
    /// The converted config failed Segue's own parser at `path`.
    #[error("converted config is rejected at `{0}`: {1}")]
    Invalid(String, String),
}

/// Converts a Clash/mihomo YAML or sing-box JSON profile into Xray JSON.
///
/// `hint` selects the reader; without one the first non-space byte decides:
/// `{` is sing-box JSON, anything else is Clash YAML.
pub fn import_profile(
    bytes: &[u8],
    hint: Option<ImportFormat>,
) -> Result<ImportResult, ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let format = match hint {
        Some(format) => format,
        None => sniff(bytes).ok_or(ImportError::UnknownFormat)?,
    };
    let mut ctx = Ctx::default();
    let config = match format {
        ImportFormat::Clash => clash::convert(bytes, &mut ctx)?,
        ImportFormat::Singbox => singbox::convert(bytes, &mut ctx)?,
    };
    if config
        .get("outbounds")
        .and_then(Value::as_array)
        .is_none_or(Vec::is_empty)
    {
        return Err(ImportError::Empty);
    }
    // The result must be a config Segue itself accepts. A geodata file the
    // profile references but that is not beside it is a deployment concern,
    // not a conversion error, so it becomes a warning.
    let json = serde_json::to_string(&config).map_err(|_| ImportError::Syntax(format.name()))?;
    let diagnostics = match crate::parse_xray_json(&json) {
        Ok(parsed) => parsed.diagnostics,
        Err(error) => error.diagnostics,
    };
    for diagnostic in diagnostics {
        let path = diagnostic.path.unwrap_or_else(|| "$".to_owned());
        if diagnostic.message.contains("was not found") {
            ctx.warn(path, diagnostic.message);
        } else if diagnostic.severity == crate::DiagnosticSeverity::Error {
            return Err(ImportError::Invalid(path, diagnostic.message));
        } else {
            ctx.warn(path, diagnostic.message);
        }
    }
    Ok(ImportResult {
        format,
        config,
        warnings: ctx.warnings,
    })
}

fn sniff(bytes: &[u8]) -> Option<ImportFormat> {
    let first = bytes.iter().find(|byte| !byte.is_ascii_whitespace())?;
    Some(if *first == b'{' {
        ImportFormat::Singbox
    } else {
        ImportFormat::Clash
    })
}

/// Warnings collected while converting one profile.
#[derive(Default)]
pub(crate) struct Ctx {
    pub(crate) warnings: Vec<ImportWarning>,
}

impl Ctx {
    pub(crate) fn warn(&mut self, path: impl Into<String>, message: impl Into<String>) {
        self.warnings.push(ImportWarning {
            path: path.into(),
            message: message.into(),
        });
    }
}

/// The skeleton every converted profile starts from: a TUN inbound, the
/// outbounds the converter built, and empty routing and DNS.
pub(crate) fn base_config(outbounds: Vec<Value>) -> Value {
    json!({
        "inbounds": [{"tag": "tun-in", "protocol": "tun", "settings": {}}],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": []},
    })
}

/// A `freedom` outbound, the target of Clash's `DIRECT` and sing-box's
/// `direct`.
pub(crate) fn direct_outbound(tag: &str) -> Value {
    json!({"tag": tag, "protocol": "freedom", "settings": {}})
}

/// A `blackhole` outbound, the target of Clash's `REJECT` and sing-box's
/// `block`.
pub(crate) fn block_outbound(tag: &str) -> Value {
    json!({"tag": tag, "protocol": "blackhole", "settings": {}})
}

/// Whether Segue's parser exempts this server address from its plaintext
/// VLESS/Trojan refusal. Mirrors `TargetAddr::is_xray_plaintext_server_exempt`
/// so the converter can drop a profile the parser would reject.
pub(crate) fn plaintext_server_exempt(host: &str) -> bool {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
            std::net::IpAddr::V6(ip) => {
                ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local()
            }
        };
    }
    let normalized = host.to_lowercase();
    let normalized = normalized.strip_suffix('.').unwrap_or(&normalized);
    const SUFFIXES: [&str; 9] = [
        "lan",
        "localdomain",
        "example",
        "invalid",
        "localhost",
        "test",
        "local",
        "home.arpa",
        "internal",
    ];
    if SUFFIXES
        .iter()
        .any(|suffix| normalized == *suffix || normalized.ends_with(&format!(".{suffix}")))
    {
        return true;
    }
    // Xray's dotless-name exemption: a single lowercase label.
    let bytes = normalized.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 || !bytes[0].is_ascii_lowercase() {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    bytes[1..bytes.len() - 1]
        .iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && bytes[bytes.len() - 1].is_ascii_alphanumeric()
}

/// A string field, or `None` when absent or not a string.
pub(crate) fn string<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

/// A boolean field, defaulting to `false` when absent or not a boolean.
pub(crate) fn boolean(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A port from a JSON number or a decimal string.
pub(crate) fn port(value: Option<&Value>) -> Option<u16> {
    match value? {
        Value::Number(number) => number.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(text) => text.parse::<u16>().ok(),
        _ => None,
    }
}

/// A list of strings from a JSON array, a single string, or nothing.
pub(crate) fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(text)) => vec![text.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// A JSON object field, or `None`.
pub(crate) fn object<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Map<String, Value>> {
    map.get(key).and_then(Value::as_object)
}

/// The `streamSettings` object for a converted outbound, or `None` when the
/// transport is plain raw TCP without TLS.
pub(crate) fn stream_settings(
    network: &str,
    security: Option<Value>,
    transport: Option<(&str, Value)>,
) -> Option<Value> {
    let mut stream = Map::new();
    if network != "raw" {
        stream.insert("network".into(), json!(network));
    }
    if let Some(security) = security {
        let kind = security
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("tls")
            .to_owned();
        stream.insert("security".into(), json!(kind));
        let key = if kind == "reality" {
            "realitySettings"
        } else {
            "tlsSettings"
        };
        let mut settings = security;
        if let Some(object) = settings.as_object_mut() {
            object.remove("kind");
        }
        stream.insert(key.into(), settings);
    }
    if let Some((key, value)) = transport {
        stream.insert(key.into(), value);
    }
    if stream.is_empty() {
        None
    } else {
        Some(Value::Object(stream))
    }
}

/// Builds one outbound object, omitting an empty `streamSettings`.
pub(crate) fn outbound(tag: &str, protocol: &str, settings: Value, stream: Option<Value>) -> Value {
    let mut outbound = Map::new();
    outbound.insert("tag".into(), json!(tag));
    outbound.insert("protocol".into(), json!(protocol));
    outbound.insert("settings".into(), settings);
    if let Some(stream) = stream {
        outbound.insert("streamSettings".into(), stream);
    }
    Value::Object(outbound)
}

/// A TLS settings object from the fields both formats share.
pub(crate) fn tls_object(
    server_name: Option<&str>,
    alpn: &[String],
    fingerprint: Option<&str>,
    insecure: bool,
    ctx: &mut Ctx,
    path: &str,
) -> Value {
    let mut tls = Map::new();
    if let Some(server_name) = server_name.filter(|name| !name.is_empty()) {
        tls.insert("serverName".into(), json!(server_name));
    }
    if !alpn.is_empty() {
        tls.insert("alpn".into(), json!(alpn));
    }
    if let Some(fingerprint) = fingerprint.filter(|value| !value.is_empty()) {
        tls.insert("fingerprint".into(), json!(fingerprint));
    }
    if insecure {
        // Segue refuses `allowInsecure=true` outright; keeping verification on
        // is the only conversion that still parses.
        ctx.warn(
            path,
            "skip-cert-verify/insecure is unsupported; certificate verification stays enabled",
        );
    }
    Value::Object(tls)
}

/// A REALITY settings object from the fields both formats share.
pub(crate) fn reality_object(
    server_name: Option<&str>,
    public_key: &str,
    short_id: &str,
    fingerprint: Option<&str>,
    ctx: &mut Ctx,
    path: &str,
) -> Value {
    let mut reality = Map::new();
    if let Some(server_name) = server_name.filter(|name| !name.is_empty()) {
        reality.insert("serverName".into(), json!(server_name));
    }
    reality.insert("publicKey".into(), json!(public_key));
    reality.insert("shortId".into(), json!(short_id));
    // REALITY needs a fingerprint with an X25519 key share; chrome is the
    // default the parser itself applies to an empty name.
    reality.insert(
        "fingerprint".into(),
        json!(fingerprint
            .filter(|value| !value.is_empty())
            .unwrap_or("chrome")),
    );
    if public_key.is_empty() {
        ctx.warn(
            path,
            "REALITY public key is missing; the outbound will be rejected",
        );
    }
    Value::Object(reality)
}

/// A `wsSettings` object.
pub(crate) fn ws_settings(path: &str, host: Option<&str>, headers: &[(String, String)]) -> Value {
    let mut ws = Map::new();
    if !path.is_empty() {
        ws.insert("path".into(), json!(path));
    }
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        ws.insert("host".into(), json!(host));
    }
    if !headers.is_empty() {
        let mut map = Map::new();
        for (name, value) in headers {
            map.insert(name.clone(), json!(value));
        }
        ws.insert("headers".into(), Value::Object(map));
    }
    Value::Object(ws)
}

/// A `grpcSettings` object.
pub(crate) fn grpc_settings(service_name: &str) -> Value {
    json!({"serviceName": service_name})
}

/// An `httpupgradeSettings` object.
pub(crate) fn httpupgrade_settings(path: &str, host: Option<&str>) -> Value {
    let mut settings = Map::new();
    if !path.is_empty() {
        settings.insert("path".into(), json!(path));
    }
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        settings.insert("host".into(), json!(host));
    }
    Value::Object(settings)
}

/// An `xhttpSettings` object. Only the modes Segue knows are carried; any
/// other reads as `auto`, so one odd field cannot sink the whole profile.
pub(crate) fn xhttp_settings(path: &str, host: Option<&str>, mode: Option<&str>) -> Value {
    let mut settings = Map::new();
    if !path.is_empty() {
        settings.insert("path".into(), json!(path));
    }
    if let Some(host) = host.filter(|host| !host.is_empty()) {
        settings.insert("host".into(), json!(host));
    }
    if let Some(mode) =
        mode.filter(|mode| matches!(*mode, "auto" | "packet-up" | "stream-up" | "stream-one"))
    {
        settings.insert("mode".into(), json!(mode));
    }
    Value::Object(settings)
}

/// A `headers` map as `(name, value)` pairs, from a JSON object of strings.
pub(crate) fn header_pairs(value: Option<&Value>) -> Vec<(String, String)> {
    let Some(Value::Object(headers)) = value else {
        return Vec::new();
    };
    headers
        .iter()
        .filter_map(|(name, value)| value.as_str().map(|value| (name.clone(), value.to_owned())))
        .collect()
}

/// The `Host` header of a header list, if any.
pub(crate) fn host_header(headers: &[(String, String)]) -> Option<&str> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.as_str())
}

/// A DNS server string Segue's parser accepts, or `None` with a warning.
pub(crate) fn dns_server_string(raw: &str, ctx: &mut Ctx, path: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    // Clash appends `#h3=true`-style parameters; Segue's parser takes none.
    let (address, params) = raw.split_once('#').map_or((raw, ""), |(a, b)| (a, b));
    if !params.is_empty() {
        ctx.warn(
            path,
            format!("DNS server parameters `#{params}` are unsupported and were dropped"),
        );
    }
    let lower = address.to_ascii_lowercase();
    if lower == "system" || lower == "localhost" || lower == "fakedns" {
        ctx.warn(
            path,
            format!("DNS server `{address}` is unsupported and was dropped"),
        );
        return None;
    }
    if lower.starts_with("dhcp://") {
        ctx.warn(path, "DHCP DNS servers are unsupported and were dropped");
        return None;
    }
    if let Some(rest) = address.strip_prefix("udp://") {
        return Some(rest.to_owned());
    }
    if lower.starts_with("https://")
        || lower.starts_with("https+local://")
        || lower.starts_with("tls://")
        || lower.starts_with("tcp://")
        || lower.starts_with("tcp+local://")
        || lower.starts_with("quic+local://")
    {
        return Some(address.to_owned());
    }
    if address.contains("://") {
        ctx.warn(
            path,
            format!("DNS server scheme in `{address}` is unsupported and was dropped"),
        );
        return None;
    }
    Some(address.to_owned())
}

/// A fake-IP pool from a CIDR string, or `None` when it is not IPv4.
pub(crate) fn fake_ip_pool(range: &str) -> Option<String> {
    let (ip, prefix) = range.split_once('/')?;
    let ip = ip.parse::<std::net::Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    Some(format!("{ip}/{prefix}"))
}

/// The `dns` object for a converted profile, or `None` when it has none.
/// Segue accepts at most eight servers, so a longer list is truncated.
pub(crate) fn dns_object(
    mut servers: Vec<String>,
    fake_ip: Option<Value>,
    exempt_domains: Option<Vec<String>>,
    ctx: &mut Ctx,
) -> Option<Value> {
    if servers.len() > 8 {
        ctx.warn(
            "dns.servers",
            format!(
                "{} DNS servers were listed; Segue accepts at most 8, so the rest were dropped",
                servers.len()
            ),
        );
        servers.truncate(8);
    }
    if servers.is_empty() && fake_ip.is_none() {
        return None;
    }
    let mut dns = Map::new();
    if !servers.is_empty() {
        dns.insert("servers".into(), json!(servers));
    }
    if let Some(mut fake_ip) = fake_ip {
        if let Some(exempt) = exempt_domains {
            fake_ip["exemptDomains"] = json!(exempt);
        }
        dns.insert("fakeIp".into(), fake_ip);
    }
    Some(Value::Object(dns))
}

/// A fake-IP object with Segue's bounded defaults, or `None` when the pool
/// has no usable address. `poolSize` is clamped to the pool's usable
/// addresses, which the parser checks.
pub(crate) fn fake_ip_object(pool: &str, ttl: u32) -> Option<Value> {
    let prefix = pool.split_once('/')?.1.parse::<u8>().ok()?;
    if prefix > 32 {
        return None;
    }
    let addresses = 1_u64 << u32::from(32 - prefix);
    // The network and broadcast addresses, plus Segue's two reserved tunnel
    // addresses, are not usable.
    let usable = addresses.saturating_sub(4);
    if usable == 0 {
        return None;
    }
    Some(json!({
        "enabled": true,
        "ipv4Pool": pool,
        "poolSize": usable.min(32_768),
        "ttl": if ttl == 0 { 60 } else { ttl },
    }))
}
