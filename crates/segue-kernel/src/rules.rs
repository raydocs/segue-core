//! Route table: first matching rule wins, otherwise the default action.
//!
//! Domain rules match only domain targets and CIDR rules only IP targets.
//! The kernel never resolves a domain locally just to evaluate a CIDR rule:
//! that lookup would leak the name to the local resolver before the route
//! is known.
//!
//! An optional AI tier sits in front of the user rules ([`RuleSet::with_ai`]).
//! A destination it matches is the AI action, except when a user rule that
//! matches is an explicit [`Action::Reject`]: a block still blocks. A user
//! Direct or Proxy rule cannot pull an AI destination off the AI exit.
//! The same precedence applies to a process match ([`RuleSet::with_processes`]):
//! it is consulted only when the destination tier missed and the tier lists
//! a `name` or `path`.

use std::net::{IpAddr, SocketAddr};

use segue_routing::TargetAddr;
use serde::Deserialize;

use crate::owner::{AiProcessSet, OwnerResolver};

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

/// Index [`RuleSet::lookup`] returns when the AI tier matched and no user
/// rule rejected the target. Not an index into the user rules.
pub const AI_TIER_INDEX: usize = usize::MAX;

/// Why the AI tier claimed a flow. [`AiReason::label`] is the per-flow
/// diagnostic: `domain`, `cidr`, or `process:<name>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AiReason {
    Domain,
    Cidr,
    /// The matched `name` pattern, or the executable name on a path hit.
    Process(String),
}

impl AiReason {
    pub fn label(&self) -> String {
        match self {
            Self::Domain => "domain".to_owned(),
            Self::Cidr => "cidr".to_owned(),
            Self::Process(name) => format!("process:{name}"),
        }
    }
}

/// What [`RuleSet::explain`] decided. `matched` is None only for the default.
pub struct Decision<'a> {
    pub action: &'a Action,
    pub matched: Option<usize>,
    pub ai_reason: Option<AiReason>,
}

/// Local end of a flow, plus who can name its owner. Passed only when the
/// caller has a socket to ask about.
#[derive(Clone, Copy)]
pub struct FlowQuery<'a> {
    pub proto: crate::owner::Proto,
    pub local: SocketAddr,
    pub resolver: &'a dyn OwnerResolver,
}

/// Destinations, and optionally processes, that must use the AI exit.
/// Destinations come from `data/ai-lock.txt` plus the bundle's `ai_domains`
/// / `ai_cidrs`. Processes come from `data/ai-processes.txt` plus
/// `ai_processes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiTier {
    suffixes: Vec<String>,
    cidrs: CidrTable,
    processes: AiProcessSet,
    action: Action,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleSet {
    rules: Vec<Rule>,
    default: Action,
    ai: Option<AiTier>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>, default: Action) -> Self {
        Self {
            rules,
            default,
            ai: None,
        }
    }

    /// Install the AI tier. `suffixes` are already canonical; `cidrs` may
    /// be empty. The built-in file ships only Anthropic's published inbound
    /// ranges (see `data/ai-lock.txt`).
    pub fn with_ai(mut self, suffixes: Vec<String>, cidrs: &[Cidr], action: Action) -> Self {
        self.ai = Some(AiTier {
            suffixes,
            cidrs: CidrTable::new(cidrs),
            processes: AiProcessSet::default(),
            action,
        });
        self
    }

    /// Install process patterns on the AI tier. No effect without
    /// [`Self::with_ai`]: the tier owns the action a process match returns.
    /// An empty or bundle-only set never calls the resolver.
    pub fn with_processes(mut self, processes: AiProcessSet) -> Self {
        if let Some(ai) = self.ai.as_mut() {
            ai.processes = processes;
        }
        self
    }

    /// The AI tier matched `target` by destination (a block rule may still
    /// win in [`Self::lookup`]). Process matches are not a property of the
    /// destination; see [`Self::explain`].
    pub fn is_ai(&self, target: &TargetAddr) -> bool {
        self.destination_reason(target).is_some()
    }

    /// The action the AI tier routes to, when one is installed.
    pub fn ai_action(&self) -> Option<&Action> {
        self.ai.as_ref().map(|ai| &ai.action)
    }

    pub fn decide(&self, target: &TargetAddr) -> &Action {
        self.explain(target, None).action
    }

    /// The first rule that matches `target`, with its index, or None when
    /// only the default applies. Callers that combine two views of one flow
    /// (DNS classification, SNI vs IP) need to know "explicit match" apart
    /// from "fell through to the default".
    ///
    /// When the AI tier matches, an explicit [`Action::Reject`] user rule
    /// still wins (a block is a block). Every other user rule loses: the
    /// tier's action is returned with [`AI_TIER_INDEX`]. This is the
    /// destination-only view: a process match needs [`Self::explain`].
    pub fn lookup(&self, target: &TargetAddr) -> Option<(usize, &Action)> {
        let decided = self.explain(target, None);
        decided.matched.map(|i| (i, decided.action))
    }

    /// Destination rules, then — only when those missed and the AI tier
    /// lists a process `name` or `path` — the owner of `flow`'s local
    /// socket. The resolver is not called when the process list cannot
    /// match, when the destination tier already matched, or when `flow` is
    /// None. A resolver `None` falls through to the user rules. A user
    /// [`Action::Reject`] still wins over a process match; a user Direct
    /// or Proxy does not.
    pub fn explain(&self, target: &TargetAddr, flow: Option<FlowQuery<'_>>) -> Decision<'_> {
        if let Some(reason) = self.destination_reason(target) {
            if let Some(i) = self.reject_index(target) {
                return Decision {
                    action: &self.rules[i].action,
                    matched: Some(i),
                    ai_reason: None,
                };
            }
            return Decision {
                action: &self
                    .ai
                    .as_ref()
                    .expect("destination reason implies a tier")
                    .action,
                matched: Some(AI_TIER_INDEX),
                ai_reason: Some(reason),
            };
        }
        if let Some(reason) = self.process_reason(flow) {
            if let Some(i) = self.reject_index(target) {
                return Decision {
                    action: &self.rules[i].action,
                    matched: Some(i),
                    ai_reason: None,
                };
            }
            return Decision {
                action: &self
                    .ai
                    .as_ref()
                    .expect("process reason implies a tier")
                    .action,
                matched: Some(AI_TIER_INDEX),
                ai_reason: Some(reason),
            };
        }
        if let Some(i) = self.user_index(target) {
            return Decision {
                action: &self.rules[i].action,
                matched: Some(i),
                ai_reason: None,
            };
        }
        Decision {
            action: &self.default,
            matched: None,
            ai_reason: None,
        }
    }

    fn destination_reason(&self, target: &TargetAddr) -> Option<AiReason> {
        let ai = self.ai.as_ref()?;
        match target {
            TargetAddr::Domain(name) => {
                let n = normalize(name);
                if ai
                    .suffixes
                    .iter()
                    .any(|s| segue_policy::suffix_match(&n, s))
                {
                    Some(AiReason::Domain)
                } else {
                    None
                }
            }
            TargetAddr::Ip(ip) => {
                if ai.cidrs.contains(*ip) {
                    Some(AiReason::Cidr)
                } else {
                    None
                }
            }
        }
    }

    /// Process hit, ignoring the destination. Does not call the resolver
    /// unless a `name` or `path` is listed.
    pub(crate) fn process_reason(&self, flow: Option<FlowQuery<'_>>) -> Option<AiReason> {
        let ai = self.ai.as_ref()?;
        if !ai.processes.matchable() {
            return None;
        }
        let flow = flow?;
        let info = flow.resolver.owner(flow.proto, flow.local)?;
        ai.processes.matched_label(&info).map(AiReason::Process)
    }

    fn user_index(&self, target: &TargetAddr) -> Option<usize> {
        let domain = domain_of(target);
        self.rules.iter().enumerate().find_map(|(i, rule)| {
            rule_matches(&rule.matcher, target, domain.as_deref()).then_some(i)
        })
    }

    /// First user rule that both matches and rejects. Used only after the
    /// AI tier has matched, so a block listed after a broader Direct still
    /// blocks an AI destination.
    fn reject_index(&self, target: &TargetAddr) -> Option<usize> {
        let domain = domain_of(target);
        self.rules.iter().enumerate().find_map(|(i, rule)| {
            (matches!(rule.action, Action::Reject)
                && rule_matches(&rule.matcher, target, domain.as_deref()))
            .then_some(i)
        })
    }

    pub fn default_action(&self) -> &Action {
        &self.default
    }

    /// Every outbound tag a rule, the AI tier or the default refers to.
    pub fn proxy_tags(&self) -> impl Iterator<Item = &str> {
        let ai = self.ai.as_ref().map(|t| &t.action);
        self.rules
            .iter()
            .map(|r| &r.action)
            .chain(ai)
            .chain(std::iter::once(&self.default))
            .filter_map(|a| match a {
                Action::Proxy(tag) => Some(tag.as_str()),
                _ => None,
            })
    }
}

fn domain_of(target: &TargetAddr) -> Option<String> {
    match target {
        TargetAddr::Domain(name) => Some(normalize(name)),
        TargetAddr::Ip(_) => None,
    }
}

fn rule_matches(matcher: &Matcher, target: &TargetAddr, domain: Option<&str>) -> bool {
    match (matcher, target, domain) {
        // Same suffix rule as the relay's AI set (segue-policy).
        (Matcher::DomainSuffix(s), _, Some(d)) => segue_policy::suffix_match(d, s),
        (Matcher::DomainExact(s), _, Some(d)) => d == s,
        (Matcher::DomainKeyword(s), _, Some(d)) => d.contains(s.as_str()),
        (Matcher::Cidr(c), TargetAddr::Ip(ip), _) => c.contains(*ip),
        _ => false,
    }
}

/// The built-in AI list (`data/ai-lock.txt`): canonical suffixes and any
/// cited CIDRs. The file is part of the crate; a bad line is a bug.
pub fn builtin_ai_list() -> (Vec<String>, Vec<Cidr>) {
    parse_ai_list(include_str!("../data/ai-lock.txt")).expect("builtin AI list")
}

/// `suffix name` and `cidr prefix` lines. `#` comments and blank lines skip.
pub fn parse_ai_list(text: &str) -> Result<(Vec<String>, Vec<Cidr>), String> {
    let mut suffixes = Vec::new();
    let mut cidrs = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split_whitespace();
        let kind = parts.next().unwrap_or("");
        let value = parts
            .next()
            .ok_or_else(|| format!("ai list line {}: missing value", n + 1))?;
        if parts.next().is_some() {
            return Err(format!("ai list line {}: extra token", n + 1));
        }
        match kind {
            "suffix" => {
                let d = segue_policy::canonical_domain(value)
                    .ok_or_else(|| format!("ai list line {}: bad domain {value:?}", n + 1))?;
                if !suffixes.iter().any(|s| s == &d) {
                    suffixes.push(d);
                }
            }
            "cidr" => {
                let cidr =
                    Cidr::parse(value).map_err(|e| format!("ai list line {}: {e}", n + 1))?;
                cidrs.push(cidr);
            }
            other => return Err(format!("ai list line {}: unknown kind {other:?}", n + 1)),
        }
    }
    Ok((suffixes, cidrs))
}

pub(crate) fn normalize(name: &str) -> String {
    segue_policy::normalize_domain(name)
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
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| format!("bad CIDR address: {text}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| format!("bad CIDR prefix: {text}"))?,
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
            (IpAddr::V4(net), IpAddr::V4(ip)) => prefix_eq(
                u32::from(net) as u128,
                u32::from(ip) as u128,
                self.prefix,
                32,
            ),
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(u128::from(net), u128::from(ip), self.prefix, 128)
            }
            _ => false,
        }
    }
}

impl Cidr {
    /// Inclusive address range, as (is_v4, first, last).
    fn range(&self) -> (bool, u128, u128) {
        let (v4, net, bits) = match self.addr {
            IpAddr::V4(a) => (true, u32::from(a) as u128, 32u32),
            IpAddr::V6(a) => (false, u128::from(a), 128u32),
        };
        let host = bits - u32::from(self.prefix);
        let mask = if host == 0 {
            0
        } else if host >= 128 {
            u128::MAX
        } else {
            (1u128 << host) - 1
        };
        let first = net & !mask;
        (v4, first, first | mask)
    }
}

/// Many prefixes (e.g. chnroute, thousands of entries) with O(log n)
/// membership tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CidrTable {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

impl CidrTable {
    pub fn new(cidrs: &[Cidr]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for c in cidrs {
            let (is4, a, b) = c.range();
            if is4 {
                v4.push((a, b))
            } else {
                v6.push((a, b))
            }
        }
        Self {
            v4: merge(v4),
            v6: merge(v6),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        let (table, x) = match ip {
            IpAddr::V4(a) => (&self.v4, u32::from(a) as u128),
            IpAddr::V6(a) => (&self.v6, u128::from(a)),
        };
        let i = table.partition_point(|&(start, _)| start <= x);
        i > 0 && table[i - 1].1 >= x
    }
}

fn merge(mut v: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    v.sort_unstable();
    let mut out: Vec<(u128, u128)> = Vec::with_capacity(v.len());
    for (a, b) in v {
        match out.last_mut() {
            Some(last) if a <= last.1.saturating_add(1) => last.1 = last.1.max(b),
            _ => out.push((a, b)),
        }
    }
    out
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
            1 => Ok(Rule {
                matcher: matchers.pop().expect("one matcher"),
                action: self.action,
            }),
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
                Rule {
                    matcher: Matcher::DomainSuffix("openai.com".into()),
                    action: Action::Proxy("home".into()),
                },
                Rule {
                    matcher: Matcher::DomainExact("ads.example".into()),
                    action: Action::Reject,
                },
                Rule {
                    matcher: Matcher::Cidr(Cidr::parse("10.0.0.0/8").unwrap()),
                    action: Action::Direct,
                },
                Rule {
                    matcher: Matcher::Cidr(Cidr::parse("fd00::/8").unwrap()),
                    action: Action::Direct,
                },
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
        assert_eq!(
            s.decide(&d("chat.OpenAI.com.")),
            &Action::Proxy("home".into())
        );
        assert_eq!(
            s.decide(&d("notopenai.com")),
            &Action::Proxy("proxy".into())
        );
    }

    #[test]
    fn lookup_tells_explicit_from_default() {
        let s = set();
        assert_eq!(
            s.lookup(&d("x.openai.com")),
            Some((0, &Action::Proxy("home".into())))
        );
        assert_eq!(s.lookup(&ip("10.0.0.1")), Some((2, &Action::Direct)));
        assert_eq!(s.lookup(&d("example.org")), None);
        assert_eq!(s.default_action(), &Action::Proxy("proxy".into()));
    }

    #[test]
    fn exact_and_default() {
        let s = set();
        assert_eq!(s.decide(&d("ads.example")), &Action::Reject);
        assert_eq!(
            s.decide(&d("x.ads.example")),
            &Action::Proxy("proxy".into())
        );
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
        assert_eq!(
            s.decide(&d("intranet.local")),
            &Action::Proxy("proxy".into())
        );
    }

    #[test]
    fn cidr_parse_edges() {
        assert!(Cidr::parse("0.0.0.0/0")
            .unwrap()
            .contains("8.8.8.8".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.4")
            .unwrap()
            .contains("1.2.3.4".parse().unwrap()));
        assert!(Cidr::parse("1.2.3.0/33").is_err());
        assert!(Cidr::parse("nope/8").is_err());
    }

    #[test]
    fn cidr_table() {
        let cs: Vec<Cidr> = [
            "1.0.1.0/24",
            "1.0.2.0/23",
            "36.0.0.0/8",
            "240e::/20",
            "0.0.0.0/32",
        ]
        .iter()
        .map(|c| Cidr::parse(c).unwrap())
        .collect();
        let t = CidrTable::new(&cs);
        for ip in [
            "1.0.1.0",
            "1.0.3.255",
            "36.255.255.255",
            "240e:fff::1",
            "::ffff:36.1.1.1",
            "0.0.0.0",
        ] {
            assert!(t.contains(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "1.0.0.255",
            "1.0.4.0",
            "37.0.0.0",
            "2400::1",
            "8.8.8.8",
            "0.0.0.1",
        ] {
            assert!(!t.contains(ip.parse().unwrap()), "{ip}");
        }
        assert!(!CidrTable::default().contains("1.1.1.1".parse().unwrap()));
        assert!(
            CidrTable::new(&[Cidr::parse("::/0").unwrap()]).contains("2001::1".parse().unwrap())
        );
    }

    #[test]
    fn spec_requires_exactly_one_matcher() {
        let ok: RuleSpec =
            serde_json::from_str(r#"{"domain_suffix":"a.com","action":{"type":"reject"}}"#)
                .unwrap();
        assert_eq!(ok.into_rule().unwrap().action, Action::Reject);
        let two: RuleSpec = serde_json::from_str(
            r#"{"domain_suffix":"a.com","ip_cidr":"1.0.0.0/8","action":{"type":"direct"}}"#,
        )
        .unwrap();
        assert!(two.into_rule().is_err());
        let proxy: RuleSpec =
            serde_json::from_str(r#"{"domain":"b.com","action":{"type":"proxy","outbound":"hk"}}"#)
                .unwrap();
        assert_eq!(
            proxy.into_rule().unwrap().action,
            Action::Proxy("hk".into())
        );
    }

    #[test]
    fn builtin_list_covers_the_named_vendors_and_only_published_anthropic_cidrs() {
        let (suffixes, cidrs) = builtin_ai_list();
        // Inbound ranges from platform.claude.com/docs/en/api/ip-addresses
        // (2026-11-17). Not the larger outbound blocks, and not a CDN.
        let published = ["160.79.104.0/23", "153.61.224.0/22", "2607:6bc0::/48"]
            .map(|s| Cidr::parse(s).unwrap());
        assert_eq!(cidrs.as_slice(), published.as_slice());
        let rules = RuleSet::new(Vec::new(), Action::Direct).with_ai(
            suffixes,
            &cidrs,
            Action::Proxy("ai".into()),
        );
        for name in [
            "api.anthropic.com",
            "console.anthropic.com",
            "statsig.anthropic.com",
            "claude.ai",
            "API.Claude.AI.",
            "claude.com",
            "platform.claude.com",
            "downloads.claude.ai",
            "bridge.claudeusercontent.com",
            "api.openai.com",
            "auth.openai.com",
            "chat.openai.com",
            "chatgpt.com",
            "ab.chatgpt.com",
            "cdn.oaistatic.com",
            "files.oaiusercontent.com",
            "o33249.ingest.us.sentry.io",
            "api2.cursor.sh",
            "accounts.spacexsi.com",
            "api.x.ai",
            "auth.grok.com",
            "api.githubcopilot.com",
            "copilot-proxy.githubusercontent.com",
            "gemini.google.com",
            "generativelanguage.googleapis.com",
            "cloudcode-pa.googleapis.com",
        ] {
            assert_eq!(
                rules.decide(&d(name)),
                &Action::Proxy("ai".into()),
                "{name}"
            );
        }
        for name in [
            "notopenai.com",
            "example.com",
            "statsigapi.net",
            "sentry.io",
            "browser-intake-us5-datadoghq.com",
            "challenges.cloudflare.com",
            "github.com",
            "accounts.google.com",
            "play.googleapis.com",
            "chatgpt-staging.com",
        ] {
            assert_eq!(rules.decide(&d(name)), &Action::Direct, "{name}");
        }
        let ai = Action::Proxy("ai".into());
        let direct = Action::Direct;
        assert_eq!(rules.decide(&ip("160.79.104.10")), &ai);
        assert_eq!(rules.decide(&ip("153.61.224.1")), &ai);
        assert_eq!(rules.decide(&ip("2607:6bc0::10")), &ai);
        // Outbound-only slice of 160.79.104.0/21, and a Cloudflare address
        // chatgpt.com resolved to on the retrieval day.
        assert_eq!(rules.decide(&ip("160.79.106.1")), &direct);
        assert_eq!(rules.decide(&ip("104.18.32.47")), &direct);
        // downloads.claude.ai was on Google, not the Anthropic ranges.
        // The name is locked; this address is not.
        assert_eq!(rules.decide(&ip("35.190.46.17")), &direct);
    }

    #[test]
    fn ai_tier_beats_user_rules_except_an_explicit_block() {
        let (suffixes, _) = builtin_ai_list();
        let cidr = Cidr::parse("203.0.113.0/24").unwrap();
        let rules = RuleSet::new(
            vec![
                // A user Direct, and a broad proxy keyword that also matches
                // the name, both lose to the tier.
                Rule {
                    matcher: Matcher::DomainSuffix("claude.ai".into()),
                    action: Action::Direct,
                },
                Rule {
                    matcher: Matcher::DomainKeyword("a".into()),
                    action: Action::Proxy("overseas".into()),
                },
                Rule {
                    matcher: Matcher::Cidr(cidr),
                    action: Action::Direct,
                },
                // Listed after the broader rules: still an explicit block.
                Rule {
                    matcher: Matcher::DomainExact("blocked.openai.com".into()),
                    action: Action::Reject,
                },
                Rule {
                    matcher: Matcher::Cidr(Cidr::parse("203.0.113.9/32").unwrap()),
                    action: Action::Reject,
                },
            ],
            Action::Proxy("overseas".into()),
        )
        .with_ai(suffixes, &[cidr], Action::Proxy("ai".into()));
        assert_eq!(rules.decide(&d("claude.ai")), &Action::Proxy("ai".into()));
        assert_eq!(
            rules.decide(&d("api.openai.com")),
            &Action::Proxy("ai".into())
        );
        assert_eq!(rules.decide(&d("blocked.openai.com")), &Action::Reject);
        assert_eq!(
            rules.decide(&ip("203.0.113.1")),
            &Action::Proxy("ai".into()),
            "a direct CIDR does not pull an AI address off the AI exit"
        );
        assert_eq!(rules.decide(&ip("203.0.113.9")), &Action::Reject);
        assert_eq!(
            rules.decide(&d("example.com")),
            &Action::Proxy("overseas".into())
        );
        assert_eq!(rules.lookup(&d("claude.ai")).unwrap().0, AI_TIER_INDEX);
    }

    #[test]
    fn ai_list_parser_rejects_a_bad_line() {
        assert!(parse_ai_list("suffix claude.ai\n").is_ok());
        assert!(parse_ai_list("cidr 203.0.113.0/24\n").is_ok());
        assert!(parse_ai_list("suffix .claude.ai\n").is_err());
        assert!(parse_ai_list("nope claude.ai\n").is_err());
        assert!(parse_ai_list("suffix\n").is_err());
    }

    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::owner::{AiProcessSet, OwnerResolver, ProcessInfo, Proto};

    struct Scripted {
        calls: AtomicUsize,
        info: Option<ProcessInfo>,
    }

    impl OwnerResolver for Scripted {
        fn owner(&self, _proto: Proto, _local: std::net::SocketAddr) -> Option<ProcessInfo> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.info.clone()
        }
    }

    fn claude() -> ProcessInfo {
        ProcessInfo {
            pid: 7,
            name: "claude".into(),
            path: "/usr/local/bin/claude".into(),
        }
    }

    fn flow<'a>(resolver: &'a Scripted) -> FlowQuery<'a> {
        FlowQuery {
            proto: Proto::Tcp,
            local: "127.0.0.1:9".parse().unwrap(),
            resolver,
        }
    }

    #[test]
    fn destination_reason_is_domain_or_cidr() {
        let cidr = Cidr::parse("203.0.113.0/24").unwrap();
        let rules = RuleSet::new(Vec::new(), Action::Direct).with_ai(
            vec!["claude.ai".into()],
            &[cidr],
            Action::Proxy("ai".into()),
        );
        let domain = rules.explain(&d("a.claude.ai"), None);
        assert_eq!(domain.ai_reason.unwrap().label(), "domain");
        assert_eq!(domain.action, &Action::Proxy("ai".into()));
        let ip = rules.explain(&ip("203.0.113.9"), None);
        assert_eq!(ip.ai_reason.unwrap().label(), "cidr");
    }

    #[test]
    fn no_process_entries_never_calls_the_resolver() {
        let resolver = Scripted {
            calls: AtomicUsize::new(0),
            info: Some(claude()),
        };
        let rules = RuleSet::new(Vec::new(), Action::Direct).with_ai(
            vec!["claude.ai".into()],
            &[],
            Action::Proxy("ai".into()),
        );
        let missed = rules.explain(&d("example.com"), Some(flow(&resolver)));
        assert_eq!(missed.action, &Action::Direct);
        assert!(missed.ai_reason.is_none());
        let hit = rules.explain(&d("claude.ai"), Some(flow(&resolver)));
        assert_eq!(hit.ai_reason.unwrap().label(), "domain");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);

        let bundle_only = rules.with_processes(
            AiProcessSet::parse("bundle com.anthropic.claude\ncmd claude\n").unwrap(),
        );
        let _ = bundle_only.explain(&d("example.com"), Some(flow(&resolver)));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn process_match_beats_user_direct_and_proxy_but_not_reject() {
        let resolver = Scripted {
            calls: AtomicUsize::new(0),
            info: Some(claude()),
        };
        let rules = RuleSet::new(
            vec![
                Rule {
                    matcher: Matcher::DomainSuffix("example.com".into()),
                    action: Action::Direct,
                },
                Rule {
                    matcher: Matcher::Cidr(Cidr::parse("198.51.100.0/24").unwrap()),
                    action: Action::Proxy("overseas".into()),
                },
                Rule {
                    matcher: Matcher::DomainExact("blocked.example".into()),
                    action: Action::Reject,
                },
            ],
            Action::Proxy("overseas".into()),
        )
        .with_ai(Vec::new(), &[], Action::Proxy("ai".into()))
        .with_processes(AiProcessSet::parse("name claude\n").unwrap());

        let direct = rules.explain(&d("www.example.com"), Some(flow(&resolver)));
        assert_eq!(direct.action, &Action::Proxy("ai".into()));
        assert_eq!(direct.matched, Some(AI_TIER_INDEX));
        assert_eq!(direct.ai_reason.unwrap().label(), "process:claude");

        let proxy = rules.explain(&ip("198.51.100.8"), Some(flow(&resolver)));
        assert_eq!(proxy.action, &Action::Proxy("ai".into()));
        assert_eq!(proxy.ai_reason.unwrap().label(), "process:claude");

        let blocked = rules.explain(&d("blocked.example"), Some(flow(&resolver)));
        assert_eq!(blocked.action, &Action::Reject);
        assert!(blocked.ai_reason.is_none());
        assert_ne!(blocked.matched, Some(AI_TIER_INDEX));

        let quiet = Scripted {
            calls: AtomicUsize::new(0),
            info: None,
        };
        let missed = rules.explain(&d("www.example.com"), Some(flow(&quiet)));
        assert_eq!(missed.action, &Action::Direct);
        assert!(missed.ai_reason.is_none());
        assert_eq!(quiet.calls.load(Ordering::SeqCst), 1);

        let other = Scripted {
            calls: AtomicUsize::new(0),
            info: Some(ProcessInfo {
                pid: 3,
                name: "curl".into(),
                path: "/usr/bin/curl".into(),
            }),
        };
        let curl = rules.explain(&d("www.example.com"), Some(flow(&other)));
        assert_eq!(curl.action, &Action::Direct);
        assert!(curl.ai_reason.is_none());
    }
}
