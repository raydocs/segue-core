//! Route table: first matching rule wins, otherwise the default action.
//!
//! Domain rules match only domain targets and CIDR rules only IP targets.
//! The kernel never resolves a domain locally just to evaluate a CIDR rule:
//! that lookup would leak the name to the local resolver before the route
//! is known.

use std::net::IpAddr;

use segue_routing::TargetAddr;
use serde::Deserialize;

/// What to do with a flow.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type", content = "outbound")]
pub enum Action {
    /// Send through the named outer outbound. If that dial fails the flow is
    /// refused; it is never retried as direct.
    Proxy(String),
    /// Connect from this device.
    Direct,
    /// Refuse without dialling anything.
    Reject,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Matcher {
    /// `example.com` matches `example.com` and `a.example.com`.
    DomainSuffix(String),
    DomainExact(String),
    /// `domain_keyword`: substring of the name.
    DomainKeyword(String),
    Cidr(Cidr),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub matcher: Matcher,
    pub action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
    default: Action,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>, default: Action) -> Self {
        Self { rules, default }
    }

    pub fn decide(&self, target: &TargetAddr) -> &Action {
        let lowered;
        let domain = match target {
            TargetAddr::Domain(name) => {
                lowered = normalize(name);
                Some(lowered.as_str())
            }
            TargetAddr::Ip(_) => None,
        };
        for rule in &self.rules {
            let hit = match (&rule.matcher, target, domain) {
                (Matcher::DomainSuffix(s), _, Some(d)) => {
                    d == s || (d.len() > s.len() && d.ends_with(s.as_str()) && d.as_bytes()[d.len() - s.len() - 1] == b'.')
                }
                (Matcher::DomainExact(s), _, Some(d)) => d == s,
                (Matcher::DomainKeyword(s), _, Some(d)) => d.contains(s.as_str()),
                (Matcher::Cidr(c), TargetAddr::Ip(ip), _) => c.contains(*ip),
                _ => false,
            };
            if hit {
                return &rule.action;
            }
        }
        &self.default
    }

    /// Every outbound tag a rule or the default refers to.
    pub fn proxy_tags(&self) -> impl Iterator<Item = &str> {
        self.rules
            .iter()
            .map(|r| &r.action)
            .chain(std::iter::once(&self.default))
            .filter_map(|a| match a {
                Action::Proxy(tag) => Some(tag.as_str()),
                _ => None,
            })
    }
}

fn normalize(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// IPv4 or IPv6 prefix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| format!("bad CIDR address: {text}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p.parse::<u8>().map_err(|_| format!("bad CIDR prefix: {text}"))?,
            None => max,
        };
        if prefix > max {
            return Err(format!("CIDR prefix too long: {text}"));
        }
        Ok(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        // Treat IPv4-mapped IPv6 addresses as IPv4 so `::ffff:10.0.0.1`
        // cannot slip past a 10.0.0.0/8 rule.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(u32::from(net) as u128, u32::from(ip) as u128, self.prefix, 32)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => prefix_eq(u128::from(net), u128::from(ip), self.prefix, 128),
            _ => false,
        }
    }
}

fn prefix_eq(net: u128, ip: u128, prefix: u8, bits: u32) -> bool {
    if prefix == 0 {
        return true;
    }
    let shift = bits - u32::from(prefix);
    (net >> shift) == (ip >> shift)
}

/// JSON form of one rule: `{"domain_suffix": "openai.com", "action": {...}}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    #[serde(default)]
    pub domain_suffix: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub domain_keyword: Option<String>,
    #[serde(default)]
    pub ip_cidr: Option<String>,
    pub action: Action,
}

impl RuleSpec {
    pub fn into_rule(self) -> Result<Rule, String> {
        let mut matchers = Vec::new();
        if let Some(s) = self.domain_suffix {
            matchers.push(Matcher::DomainSuffix(normalize(&s)));
        }
        if let Some(s) = self.domain {
            matchers.push(Matcher::DomainExact(normalize(&s)));
        }
        if let Some(s) = self.domain_keyword {
            matchers.push(Matcher::DomainKeyword(s.to_ascii_lowercase()));
        }
        if let Some(s) = self.ip_cidr {
            matchers.push(Matcher::Cidr(Cidr::parse(&s)?));
        }
        match matchers.len() {
            1 => Ok(Rule { matcher: matchers.pop().expect("one matcher"), action: self.action }),
            0 => Err("rule has no matcher".into()),
            _ => Err("rule has more than one matcher; split it into separate rules".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set() -> RuleSet {
        RuleSet::new(
            vec![
                Rule { matcher: Matcher::DomainSuffix("openai.com".into()), action: Action::Proxy("home".into()) },
                Rule { matcher: Matcher::DomainExact("ads.example".into()), action: Action::Reject },
                Rule { matcher: Matcher::Cidr(Cidr::parse("10.0.0.0/8").unwrap()), action: Action::Direct },
                Rule { matcher: Matcher::Cidr(Cidr::parse("fd00::/8").unwrap()), action: Action::Direct },
            ],
            Action::Proxy("proxy".into()),
        )
    }

    fn d(name: &str) -> TargetAddr {
        TargetAddr::Domain(name.into())
    }

    fn ip(text: &str) -> TargetAddr {
        TargetAddr::Ip(text.parse().unwrap())
    }

    #[test]
    fn domain_suffix_matches_label_boundary_only() {
        let s = set();
        assert_eq!(s.decide(&d("openai.com")), &Action::Proxy("home".into()));
        assert_eq!(s.decide(&d("chat.OpenAI.com.")), &Action::Proxy("home".into()));
        assert_eq!(s.decide(&d("notopenai.com")), &Action::Proxy("proxy".into()));
    }

    #[test]
    fn exact_and_default() {
        let s = set();
        assert_eq!(s.decide(&d("ads.example")), &Action::Reject);
        assert_eq!(s.decide(&d("x.ads.example")), &Action::Proxy("proxy".into()));
    }

    #[test]
    fn cidr_v4_v6_and_mapped() {
        let s = set();
        assert_eq!(s.decide(&ip("10.1.2.3")), &Action::Direct);
        assert_eq!(s.decide(&ip("11.0.0.1")), &Action::Proxy("proxy".into()));
        assert_eq!(s.decide(&ip("::ffff:10.0.0.1")), &Action::Direct);
        assert_eq!(s.decide(&ip("fd12::1")), &Action::Direct);
        assert_eq!(s.decide(&ip("2001:db8::1")), &Action::Proxy("proxy".into()));
    }

    #[test]
    fn cidr_rule_never_applies_to_domain() {
        let s = set();
        // "10.0.0.1" given as a hostname string is still a domain target here;
        // the SOCKS layer turns literal IPs into Ip targets before routing.
        assert_eq!(s.decide(&d("intranet.local")), &Action::Proxy("proxy".into()));
    }

    #[test]
    fn cidr_parse_edges() {
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4").unwrap().contains("1.2.3.4".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.0/33").is_err());
        assert!(Cidr::parse("nope/8").is_err());
    }

    #[test]
    fn spec_requires_exactly_one_matcher() {
        let ok: RuleSpec = serde_json::from_str(r#"{"domain_suffix":"a.com","action":{"type":"reject"}}"#).unwrap();
        assert_eq!(ok.into_rule().unwrap().action, Action::Reject);
        let two: RuleSpec = serde_json::from_str(
            r#"{"domain_suffix":"a.com","ip_cidr":"1.0.0.0/8","action":{"type":"direct"}}"#,
        )
        .unwrap();
        assert!(two.into_rule().is_err());
        let proxy: RuleSpec = serde_json::from_str(r#"{"domain":"b.com","action":{"type":"proxy","outbound":"hk"}}"#).unwrap();
        assert_eq!(proxy.into_rule().unwrap().action, Action::Proxy("hk".into()));
    }
}
