//! Home (AI) target whitelist (KERNEL_SPEC §5.5 items 3, 7). Same source as
//! the CompiledPolicy AI set; until the control plane ships it, it comes
//! from the config file.

use std::net::IpAddr;

use crate::cidr::{any_contains, Cidr};

#[derive(Clone, Debug, Default)]
pub struct AiSet {
    suffixes: Vec<String>,
    cidrs: Vec<Cidr>,
}

/// Lowercase, no trailing dot; `None` if not a plausible DNS name.
pub fn normalize_domain(name: &str) -> Option<String> {
    let n = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then_some(n)
}

impl AiSet {
    pub fn new(domains: &[String], cidrs: &[String]) -> Result<Self, String> {
        let mut suffixes = Vec::new();
        for d in domains {
            let d = d.trim().trim_start_matches('.');
            suffixes.push(normalize_domain(d).ok_or_else(|| format!("bad AI domain {d:?}"))?);
        }
        let cidrs = cidrs
            .iter()
            .map(|c| Cidr::parse(c))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { suffixes, cidrs })
    }

    /// `name` must already be normalized.
    pub fn is_ai_domain(&self, name: &str) -> bool {
        self.suffixes.iter().any(|s| {
            name == s
                || (name.len() > s.len()
                    && name.ends_with(s.as_str())
                    && name.as_bytes()[name.len() - s.len() - 1] == b'.')
        })
    }

    pub fn is_ai_ip(&self, ip: IpAddr) -> bool {
        any_contains(&self.cidrs, ip)
    }
}
