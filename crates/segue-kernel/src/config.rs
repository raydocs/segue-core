//! Kernel config file.
//!
//! ```json
//! {
//!   "listen": "127.0.0.1:1080",
//!   "outbounds": { "proxy": { ...one Xray-style outbound object... } },
//!   "rules": [ {"domain_suffix": "openai.com", "action": {"type": "proxy", "outbound": "proxy"}} ],
//!   "default": {"type": "direct"}
//! }
//! ```
//!
//! Each outbound is parsed by the engine's own config parser, so anything the
//! engine accepts as an outbound (REALITY, Hysteria 2, ...) works here.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use serde::Deserialize;
use serde_json::Value;

use crate::rules::{Action, RuleSet, RuleSpec};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: SocketAddr,
    #[serde(default)]
    outbounds: BTreeMap<String, Value>,
    #[serde(default)]
    rules: Vec<RuleSpec>,
    default: Action,
}

pub struct KernelConfig {
    pub listen: SocketAddr,
    pub outbounds: BTreeMap<String, Value>,
    pub rules: RuleSet,
}

impl KernelConfig {
    pub fn parse(text: &str) -> Result<Self, String> {
        let raw: RawConfig = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        if !raw.listen.ip().is_loopback() {
            // The SOCKS entry point has no authentication; exposing it beyond
            // this host would make it an open proxy.
            return Err(format!("listen must be a loopback address, got {}", raw.listen));
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
        Ok(Self { listen: raw.listen, outbounds: raw.outbounds, rules })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_loopback_listen() {
        let err = KernelConfig::parse(r#"{"listen":"0.0.0.0:1080","default":{"type":"direct"}}"#).err().unwrap();
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
        assert!(KernelConfig::parse(r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},"dns":{}}"#).is_err());
    }
}
