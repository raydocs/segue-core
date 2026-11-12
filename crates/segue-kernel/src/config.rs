//! Kernel config file.
//!
//! ```json
//! {
//!   "listen": "127.0.0.1:1080",
//!   "outbounds": { "proxy": { ...one Xray-style outbound object... } },
//!   "rules": [ {"domain_suffix": "openai.com", "action": {"type": "proxy", "outbound": "proxy"}} ],
//!   "default": {"type": "direct"},
//!   "sniff": { "timeout_ms": 300, "max_bytes": 16384 },
//!   "dns": {
//!     "listen": "127.0.0.1:5353",
//!     "domestic": ["223.5.5.5:53", "119.29.29.29:53"],
//!     "chnroute": ["1.0.1.0/24"], "chnroute_file": "chnroute.txt",
//!     "foreign": {"type": "proxy", "outbound": "proxy"},
//!     "fake_ip_range": "198.18.0.0/15", "fake_ip_ttl_secs": 60, "fake_ip_grace_secs": 600,
//!     "query_timeout_ms": 2000, "cache_size": 4096
//!   }
//! }
//! ```
//!
//! Each outbound is parsed by the engine's own config parser, so anything the
//! engine accepts as an outbound (REALITY, Hysteria 2, ...) works here.
//!
//! `sniff` absent: bare-IP CONNECTs are routed by IP rules only. `dns`
//! absent: no DNS listener and no fake-IP range.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::dns::DnsSettings;
use crate::rules::{Action, Cidr, CidrTable, RuleSet, RuleSpec};
use crate::socks::SniffSettings;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: SocketAddr,
    #[serde(default)]
    outbounds: BTreeMap<String, Value>,
    #[serde(default)]
    rules: Vec<RuleSpec>,
    default: Action,
    #[serde(default)]
    sniff: Option<RawSniff>,
    #[serde(default)]
    dns: Option<RawDns>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSniff {
    #[serde(default = "default_sniff_timeout")]
    timeout_ms: u64,
    #[serde(default = "default_sniff_bytes")]
    max_bytes: usize,
}

fn default_sniff_timeout() -> u64 {
    300
}
fn default_sniff_bytes() -> usize {
    16 * 1024
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDns {
    listen: SocketAddr,
    domestic: Vec<SocketAddr>,
    #[serde(default)]
    chnroute: Vec<String>,
    #[serde(default)]
    chnroute_file: Option<PathBuf>,
    foreign: Action,
    #[serde(default = "default_fake_range")]
    fake_ip_range: String,
    #[serde(default = "default_fake_ttl")]
    fake_ip_ttl_secs: u64,
    #[serde(default = "default_fake_grace")]
    fake_ip_grace_secs: u64,
    #[serde(default = "default_query_timeout")]
    query_timeout_ms: u64,
    #[serde(default = "default_cache_size")]
    cache_size: usize,
}

fn default_fake_range() -> String {
    "198.18.0.0/15".into()
}
fn default_fake_ttl() -> u64 {
    60
}
fn default_fake_grace() -> u64 {
    600
}
fn default_query_timeout() -> u64 {
    2000
}
fn default_cache_size() -> usize {
    4096
}

/// Validated `dns` section.
pub struct DnsConfig {
    pub listen: SocketAddr,
    pub settings: DnsSettings,
    pub fake_ip_base: std::net::Ipv4Addr,
    pub fake_ip_prefix: u8,
    pub fake_ip_ttl: Duration,
    pub fake_ip_grace: Duration,
}

pub struct KernelConfig {
    pub listen: SocketAddr,
    pub outbounds: BTreeMap<String, Value>,
    pub rules: RuleSet,
    pub sniff: Option<SniffSettings>,
    pub dns: Option<DnsConfig>,
}

impl KernelConfig {
    /// Parse; relative `chnroute_file` paths resolve against the current
    /// directory.
    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_in(text, Path::new("."))
    }

    /// Parse; relative `chnroute_file` paths resolve against `base`.
    pub fn parse_in(text: &str, base: &Path) -> Result<Self, String> {
        let raw: RawConfig = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        if !raw.listen.ip().is_loopback() {
            // The SOCKS entry point has no authentication; exposing it beyond
            // this host would make it an open proxy.
            return Err(format!(
                "listen must be a loopback address, got {}",
                raw.listen
            ));
        }
        let rules = raw
            .rules
            .into_iter()
            .enumerate()
            .map(|(i, r)| r.into_rule().map_err(|e| format!("rules[{i}]: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let rules = RuleSet::new(rules, raw.default);
        for tag in rules.proxy_tags() {
            if !raw.outbounds.contains_key(tag) {
                return Err(format!("rule refers to unknown outbound {tag:?}"));
            }
        }
        let sniff = match raw.sniff {
            None => None,
            Some(s) => {
                if s.timeout_ms == 0 || s.timeout_ms > 10_000 {
                    return Err("sniff.timeout_ms must be 1..=10000".into());
                }
                if !(64..=65536).contains(&s.max_bytes) {
                    return Err("sniff.max_bytes must be 64..=65536".into());
                }
                Some(SniffSettings {
                    timeout: Duration::from_millis(s.timeout_ms),
                    max_bytes: s.max_bytes,
                })
            }
        };
        let dns = raw
            .dns
            .map(|d| dns_config(d, &raw.outbounds, base))
            .transpose()?;
        Ok(Self {
            listen: raw.listen,
            outbounds: raw.outbounds,
            rules,
            sniff,
            dns,
        })
    }
}

fn dns_config(
    d: RawDns,
    outbounds: &BTreeMap<String, Value>,
    base: &Path,
) -> Result<DnsConfig, String> {
    if !d.listen.ip().is_loopback() {
        // An open resolver on the LAN would answer anyone and hand out
        // fake-IPs that route through this device.
        return Err(format!(
            "dns.listen must be a loopback address, got {}",
            d.listen
        ));
    }
    if d.domestic.is_empty() {
        return Err("dns.domestic must list at least one resolver".into());
    }
    if d.domestic.contains(&d.listen) {
        return Err("dns.domestic must not include dns.listen (query loop)".into());
    }
    match &d.foreign {
        // Names judged foreign / polluted must not go out from this device.
        Action::Direct => return Err("dns.foreign must be proxy or reject, not direct".into()),
        Action::Proxy(tag) if !outbounds.contains_key(tag) => {
            return Err(format!("dns.foreign refers to unknown outbound {tag:?}"))
        }
        _ => {}
    }
    let mut cidrs = Vec::new();
    for (i, c) in d.chnroute.iter().enumerate() {
        cidrs.push(Cidr::parse(c).map_err(|e| format!("dns.chnroute[{i}]: {e}"))?);
    }
    if let Some(file) = &d.chnroute_file {
        let path = if file.is_absolute() {
            file.clone()
        } else {
            base.join(file)
        };
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("dns.chnroute_file {}: {e}", path.display()))?;
        for (n, line) in text.lines().enumerate() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            cidrs
                .push(Cidr::parse(line).map_err(|e| format!("{}:{}: {e}", path.display(), n + 1))?);
        }
    }
    let (base_ip, prefix) = d
        .fake_ip_range
        .split_once('/')
        .ok_or("dns.fake_ip_range must be a v4 CIDR")?;
    let fake_ip_base: std::net::Ipv4Addr = base_ip
        .parse()
        .map_err(|_| "dns.fake_ip_range must be a v4 CIDR")?;
    let fake_ip_prefix: u8 = prefix
        .parse()
        .map_err(|_| "dns.fake_ip_range: bad prefix")?;
    if !(8..=30).contains(&fake_ip_prefix) {
        return Err("dns.fake_ip_range prefix must be 8..=30".into());
    }
    let fake = Cidr::parse(&d.fake_ip_range)?;
    for r in &d.domestic {
        if fake.contains(r.ip()) {
            return Err(format!("dns.domestic {r} lies inside fake_ip_range"));
        }
    }
    if d.query_timeout_ms == 0 || d.cache_size == 0 || d.fake_ip_ttl_secs == 0 {
        return Err("dns: query_timeout_ms, cache_size and fake_ip_ttl_secs must be > 0".into());
    }
    Ok(DnsConfig {
        listen: d.listen,
        settings: DnsSettings {
            domestic: d.domestic,
            chnroute: CidrTable::new(&cidrs),
            foreign: d.foreign,
            query_timeout: Duration::from_millis(d.query_timeout_ms),
            cache_size: d.cache_size,
        },
        fake_ip_base,
        fake_ip_prefix,
        fake_ip_ttl: Duration::from_secs(d.fake_ip_ttl_secs),
        fake_ip_grace: Duration::from_secs(d.fake_ip_grace_secs),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_listen() {
        let err = KernelConfig::parse(r#"{"listen":"0.0.0.0:1080","default":{"type":"direct"}}"#)
            .err()
            .unwrap();
        assert!(err.contains("loopback"), "{err}");
    }

    #[test]
    fn rejects_unknown_outbound_reference() {
        let err = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","rules":[{"domain":"a.com","action":{"type":"proxy","outbound":"x"}}],"default":{"type":"direct"}}"#,
        )
        .err()
        .unwrap();
        assert!(err.contains("unknown outbound"), "{err}");
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},"bogus":{}}"#
        )
        .is_err());
        assert!(KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},"sniff":{"x":1}}"#
        )
        .is_err());
        let err = KernelConfig::parse(&dns_doc(r#""foreign":{"type":"reject"},"fakeip":"x""#))
            .err()
            .unwrap();
        assert!(err.contains("unknown field"), "{err}");
    }

    fn dns_doc(extra: &str) -> String {
        format!(
            r#"{{"listen":"127.0.0.1:1080","outbounds":{{"p":{{}}}},"default":{{"type":"direct"}},
               "dns":{{"listen":"127.0.0.1:5353","domestic":["223.5.5.5:53"],{extra}}}}}"#
        )
    }

    #[test]
    fn dns_and_sniff_defaults() {
        let c = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","outbounds":{"p":{}},"default":{"type":"direct"},"sniff":{},
                "dns":{"listen":"127.0.0.1:5353","domestic":["223.5.5.5:53"],"chnroute":["1.0.1.0/24"],
                       "foreign":{"type":"proxy","outbound":"p"}}}"#,
        )
        .unwrap();
        let s = c.sniff.unwrap();
        assert_eq!(s.timeout, Duration::from_millis(300));
        let d = c.dns.unwrap();
        assert_eq!(
            (d.fake_ip_base, d.fake_ip_prefix),
            ("198.18.0.0".parse().unwrap(), 15)
        );
        assert!(d.settings.chnroute.contains("1.0.1.9".parse().unwrap()));
        assert_eq!(d.settings.foreign, Action::Proxy("p".into()));
    }

    #[test]
    fn dns_validation() {
        let cases = [
            (r#""foreign":{"type":"direct"}"#, "not direct"),
            (
                r#""foreign":{"type":"proxy","outbound":"nope"}"#,
                "unknown outbound",
            ),
            (
                r#""foreign":{"type":"reject"},"chnroute":["bad"]"#,
                "chnroute[0]",
            ),
            (
                r#""foreign":{"type":"reject"},"fake_ip_range":"10.0.0.0/31""#,
                "8..=30",
            ),
            (
                r#""foreign":{"type":"reject"},"fake_ip_range":"223.5.5.0/24""#,
                "inside fake_ip_range",
            ),
            (
                r#""foreign":{"type":"reject"},"chnroute_file":"/nonexistent/x""#,
                "chnroute_file",
            ),
        ];
        for (extra, want) in cases {
            let err = KernelConfig::parse(&dns_doc(extra))
                .err()
                .unwrap_or_default();
            assert!(err.contains(want), "{extra}: {err}");
        }
        let err = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},
                "dns":{"listen":"0.0.0.0:53","domestic":["223.5.5.5:53"],"foreign":{"type":"reject"}}}"#,
        )
        .err()
        .unwrap();
        assert!(err.contains("loopback"), "{err}");
    }

    #[test]
    fn chnroute_file_relative_to_base() {
        let dir = std::env::temp_dir().join(format!("segue-kernel-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("cn.txt"),
            "# comment\n36.0.0.0/8\n\n240e::/20 # v6\n",
        )
        .unwrap();
        let c = KernelConfig::parse_in(
            &dns_doc(r#""foreign":{"type":"reject"},"chnroute_file":"cn.txt""#),
            &dir,
        )
        .unwrap();
        let t = &c.dns.unwrap().settings.chnroute;
        assert!(t.contains("36.1.2.3".parse().unwrap()));
        assert!(t.contains("240e::1".parse().unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
