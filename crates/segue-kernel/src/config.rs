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
//!     "fake_ip_max_entries": 16384, "fake_ip_state": "fakeip.state",
//!     "query_timeout_ms": 2000, "cache_size": 4096
//!   }
//! }
//! ```
//!
//! Each outbound is parsed by the engine's own config parser, so anything the
//! engine accepts as an outbound (REALITY, Hysteria 2, ...) works here.
//!
//! `"udp": { "refuse": ["home"], "refuse_quic": ["proxy"], "idle_timeout_secs": 60 }`
//! turns on SOCKS5 UDP ASSOCIATE; outbounds in `refuse` never carry UDP.
//!
//! `sniff` absent: bare-IP CONNECTs are routed by IP rules only. `dns`
//! absent: no DNS listener and no fake-IP range.
//!
//! Roles: an outbound object may carry `"role": "home"` (the AI / Home
//! exit; stripped before the engine sees the object). A `segue` route with
//! `exit_class: "ai"` is home-role. Home-role tags never carry UDP: they
//! are always in the UDP refuse set, and listing one in `udp.refuse_quic`
//! (which would allow non-443 UDP) is a config error.
//!
//! Rules: in the product they come only from a signed bundle (`policy`
//! section, see [`crate::policy`]); then `rules`, `default`,
//! `dns.chnroute` and `dns.chnroute_file` must be absent. Inline rules
//! are for the lab and tests.
//!
//! ```json
//! "policy": {"public_keys": [{"key_id": 1, "public_key": "<b64>"}],
//!            "bundle": "policy.bundle", "installed": "policy.installed",
//!            "ai_route": "ai"},
//! "exits": [{"name": "la", "carrier": "reality-la", "relay": "10.0.0.1:7443", "node_id": 1},
//!           {"name": "ny", "carrier": "hy2-ny", "relay": "10.0.0.2:7443", "node_id": 2}],
//! "segue": {"ai": {"ticket_file": "device.ticket", "exit_class": "ai"}},
//! "control": {"listen": "127.0.0.1:0", "token_file": "control.json"},
//! "tun": { "mtu": 1500, "ipv4": "172.19.0.1/30", "ipv4_peer": "172.19.0.2" }
//! ```
//!
//! `tun` absent: SOCKS and DNS only. `tun` present (macOS): open a utun,
//! install split default routes and exclude exit addresses. An empty `tun`
//! object uses the defaults above, plus `fd00:5e9e::1/64` via `fd00:5e9e::2`
//! unless `"ipv6": false`.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use serde_json::Value;

use crate::dns::DnsSettings;
use crate::policy::{Policy, PolicyStore, Verifier};
use crate::rules::{Action, Cidr, CidrTable, RuleSet, RuleSpec};
use crate::session::{Exit, SegueRoute};
use crate::socks::SniffSettings;
use crate::tun_setup::TunAddress;
use crate::udp::UdpSettings;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    listen: SocketAddr,
    #[serde(default)]
    outbounds: BTreeMap<String, Value>,
    #[serde(default)]
    rules: Option<Vec<RuleSpec>>,
    #[serde(default)]
    default: Option<Action>,
    #[serde(default)]
    policy: Option<RawPolicy>,
    #[serde(default)]
    exits: Vec<RawExit>,
    #[serde(default)]
    control: Option<RawControl>,
    #[serde(default)]
    sniff: Option<RawSniff>,
    #[serde(default)]
    dns: Option<RawDns>,
    #[serde(default)]
    udp: Option<RawUdp>,
    /// Session-layer routes: tag → relay reached through an engine outbound.
    #[serde(default)]
    segue: BTreeMap<String, RawSegue>,
    /// macOS utun. Absent: do not open one.
    #[serde(default)]
    tun: Option<RawTun>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTun {
    #[serde(default = "default_tun_mtu")]
    mtu: u32,
    #[serde(default = "default_tun_ipv4")]
    ipv4: String,
    #[serde(default = "default_tun_peer")]
    ipv4_peer: String,
    /// `false` skips the v6 address and the `::/1` + `8000::/1` routes.
    #[serde(default = "default_tun_v6")]
    ipv6: bool,
    #[serde(default)]
    ipv6_address: Option<String>,
    #[serde(default)]
    ipv6_peer: Option<String>,
}

fn default_tun_mtu() -> u32 {
    crate::tun_setup::DEFAULT_MTU
}
fn default_tun_ipv4() -> String {
    crate::tun_setup::DEFAULT_IPV4.into()
}
fn default_tun_peer() -> String {
    crate::tun_setup::DEFAULT_IPV4_PEER.into()
}
fn default_tun_v6() -> bool {
    true
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawSegue {
    /// File holding the device ticket (until the control plane).
    ticket_file: PathBuf,
    /// `overseas` or `ai` (a hint; the relay classifies by itself).
    exit_class: String,
    /// Optional; must agree with `exit_class` (`ai` ⇔ `home`).
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExit {
    name: String,
    /// Engine outbound that carries sessions to this node (Reality / Hy2).
    carrier: String,
    /// The relay address as the carrier's server sees it.
    relay: SocketAddr,
    #[serde(default)]
    node_id: u64,
    /// Exits that share an egress identity. Absent: this exit is its own
    /// group, so an AI flow pinned here never moves to another exit.
    #[serde(default)]
    egress_group: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    public_keys: Vec<RawKey>,
    /// A freshly delivered bundle, tried at startup.
    #[serde(default)]
    bundle: Option<PathBuf>,
    /// Where the last good bundle is kept.
    #[serde(default)]
    installed: Option<PathBuf>,
    #[serde(default = "default_ai_route")]
    ai_route: String,
}

fn default_ai_route() -> String {
    "ai".into()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    key_id: u32,
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawControl {
    listen: SocketAddr,
    /// Written at start (mode 0600): `{"addr": ..., "token": ...}`.
    token_file: PathBuf,
}

/// Validated `control` section.
#[derive(Debug, Clone)]
pub struct ControlConfig {
    pub listen: SocketAddr,
    pub token_file: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUdp {
    /// Outbounds that never carry UDP (the Home / AI exit, §1.2.3).
    #[serde(default)]
    refuse: Vec<String>,
    /// Outbounds that refuse UDP/443 (QUIC over a Reality carrier, §4.3).
    #[serde(default)]
    refuse_quic: Vec<String>,
    #[serde(default = "default_udp_idle")]
    idle_timeout_secs: u64,
    #[serde(default = "default_udp_flows")]
    max_flows: usize,
    #[serde(default = "default_udp_queue")]
    queue: usize,
    #[serde(default = "default_udp_assoc")]
    max_associations: usize,
}

fn default_udp_idle() -> u64 {
    60
}
fn default_udp_flows() -> usize {
    128
}
fn default_udp_queue() -> usize {
    32
}
fn default_udp_assoc() -> usize {
    64
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
    /// Lab only (inline rules): route for unmatched names judged foreign.
    /// Defaults to `default`. With a signed policy it is the bundle's
    /// `default` and setting it here is an error.
    #[serde(default)]
    foreign: Option<Action>,
    /// Where the fake-IP key and bindings are kept across restarts
    /// (relative to the config file). Default `fakeip.state`; `null` (lab,
    /// inline rules only; refused with a signed policy) keeps them in
    /// memory only, so a restart may hand a cached address to another name.
    #[serde(default = "default_fake_state")]
    fake_ip_state: Option<PathBuf>,
    #[serde(default = "default_fake_max")]
    fake_ip_max_entries: usize,
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
fn default_fake_state() -> Option<PathBuf> {
    Some(PathBuf::from("fakeip.state"))
}
fn default_fake_max() -> usize {
    crate::fakeip::DEFAULT_MAX_ENTRIES
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
    pub fake_ip_max_entries: usize,
    /// Absolute path of the fake-IP state file.
    pub fake_ip_state: Option<PathBuf>,
    /// Inline policy only: `dns.foreign`.
    pub foreign: Option<Action>,
}

pub struct KernelConfig {
    pub listen: SocketAddr,
    /// Engine outbound objects (`role` stripped).
    pub outbounds: BTreeMap<String, Value>,
    /// Rules in force: a signed bundle store, or inline (lab) rules.
    pub policy: Arc<PolicyStore>,
    /// Startup policy messages (what was restored / rejected).
    pub policy_log: Vec<String>,
    pub sniff: Option<SniffSettings>,
    pub dns: Option<DnsConfig>,
    /// None: UDP ASSOCIATE is refused as unsupported.
    pub udp: Option<UdpSettings>,
    /// Session-layer routes (`segue` section), by tag.
    pub segue: BTreeMap<String, SegueRoute>,
    /// Session exits in preference order (Auto picks the first healthy).
    pub exits: Vec<Exit>,
    /// Home-role tags (outbounds and session routes): never carry UDP.
    pub home: BTreeSet<String>,
    pub control: Option<ControlConfig>,
    /// macOS utun address. `None`: SOCKS and DNS only.
    pub tun: Option<TunAddress>,
}

/// Remove and check the `role` key of an outbound object. True: home.
fn take_role(tag: &str, spec: &mut Value) -> Result<bool, String> {
    let role = match spec {
        Value::Object(map) => map.remove("role"),
        _ => None,
    };
    match role {
        None => Ok(false),
        Some(Value::String(r)) if r == "home" => Ok(true),
        Some(Value::String(r)) if r == "proxy" => Ok(false),
        Some(other) => Err(format!(
            "outbounds.{tag}.role must be \"home\" or \"proxy\", got {other}"
        )),
    }
}

impl KernelConfig {
    /// Parse; relative `chnroute_file` paths resolve against the current
    /// directory.
    pub fn parse(text: &str) -> Result<Self, String> {
        Self::parse_in(text, Path::new("."))
    }

    /// Parse; relative paths resolve against `base` (the config file's
    /// directory).
    pub fn parse_in(text: &str, base: &Path) -> Result<Self, String> {
        Self::parse_with(text, base, None)
    }

    /// Parse. Relative runtime paths (`control.token_file`,
    /// `dns.fake_ip_state`, `policy.installed`) resolve against `state_dir`
    /// when it is set, and against `base` otherwise. The delivered bundle,
    /// tickets and `chnroute_file` always stay next to the config.
    pub fn parse_with(text: &str, base: &Path, state_dir: Option<&Path>) -> Result<Self, String> {
        let state = state_dir.unwrap_or(base);
        let raw: RawConfig = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        if !raw.listen.ip().is_loopback() {
            // The SOCKS entry point has no authentication; exposing it beyond
            // this host would make it an open proxy.
            return Err(format!(
                "listen must be a loopback address, got {}",
                raw.listen
            ));
        }
        let mut outbounds = raw.outbounds;
        let mut home = BTreeSet::new();
        for (tag, spec) in outbounds.iter_mut() {
            if take_role(tag, spec)? {
                home.insert(tag.clone());
            }
        }
        let mut exits = Vec::new();
        for (i, e) in raw.exits.iter().enumerate() {
            let ok_name = !e.name.is_empty()
                && e.name.len() <= 32
                && e.name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !ok_name || e.name == "auto" {
                return Err(format!(
                    "exits[{i}].name must be [a-z0-9-]{{1,32}} and not \"auto\""
                ));
            }
            if exits.iter().any(|x: &Exit| x.name == e.name) {
                return Err(format!("exits[{i}]: duplicate name {:?}", e.name));
            }
            if !outbounds.contains_key(&e.carrier) {
                return Err(format!(
                    "exits[{i}]: unknown carrier outbound {:?}",
                    e.carrier
                ));
            }
            if home.contains(&e.carrier) {
                return Err(format!(
                    "exits[{i}]: carrier must not be a home-role outbound"
                ));
            }
            let egress_group = match &e.egress_group {
                None => String::new(),
                Some(g)
                    if !g.is_empty()
                        && g.len() <= 64
                        && g.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') =>
                {
                    g.clone()
                }
                Some(g) => {
                    return Err(format!(
                        "exits[{i}].egress_group {g:?} must be [A-Za-z0-9_-]{{1,64}}"
                    ));
                }
            };
            exits.push(Exit {
                name: e.name.clone(),
                carrier: e.carrier.clone(),
                relay: e.relay,
                node_id: e.node_id,
                egress_group,
            });
        }
        if !raw.segue.is_empty() && exits.is_empty() {
            return Err("segue routes need at least one entry in exits".into());
        }
        let mut segue = BTreeMap::new();
        for (tag, r) in &raw.segue {
            if outbounds.contains_key(tag) {
                return Err(format!("segue.{tag}: tag also used by an outbound"));
            }
            let exit_class = match r.exit_class.as_str() {
                "overseas" => crate::session::EXIT_OVERSEAS,
                "ai" => crate::session::EXIT_AI,
                _ => return Err(format!("segue.{tag}: exit_class must be overseas or ai")),
            };
            let is_home = exit_class == crate::session::EXIT_AI;
            match r.role.as_deref() {
                None => {}
                Some("home") if is_home => {}
                Some("proxy") if !is_home => {}
                Some(_) => {
                    return Err(format!(
                        "segue.{tag}: role must match exit_class (ai is home, overseas is proxy)"
                    ))
                }
            }
            if is_home {
                home.insert(tag.clone());
            }
            let path = if r.ticket_file.is_absolute() {
                r.ticket_file.clone()
            } else {
                base.join(&r.ticket_file)
            };
            // The error never carries the ticket.
            let ticket = std::fs::read_to_string(&path)
                .map_err(|e| format!("segue.{tag}: ticket_file {}: {e}", path.display()))?;
            let ticket = ticket.trim().as_bytes().to_vec();
            if ticket.is_empty() {
                return Err(format!("segue.{tag}: ticket_file is empty"));
            }
            segue.insert(tag.clone(), SegueRoute { ticket, exit_class });
        }
        // Tags a rule may name: engine outbounds and session routes.
        let mut known = outbounds.clone();
        for tag in segue.keys() {
            known.insert(tag.clone(), Value::Null);
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
        let signed = raw.policy.is_some();
        let (dns, chnroute) = match raw.dns {
            Some(d) => {
                if signed && (!d.chnroute.is_empty() || d.chnroute_file.is_some()) {
                    return Err(
                        "dns.chnroute / chnroute_file come from the policy bundle; remove them"
                            .into(),
                    );
                }
                if signed && d.foreign.is_some() {
                    // An unsigned local route must not override the bundle's
                    // decision for unknown names (the bundle `default`).
                    return Err(
                        "dns.foreign comes from the policy bundle (its default); remove it".into(),
                    );
                }
                if signed && d.fake_ip_state.is_none() {
                    // Without persisted bindings a restart can hand an
                    // address a client still caches to another name.
                    return Err(
                        "dns.fake_ip_state: null is lab only; with a signed policy the \
                         fake-IP bindings must be persisted (omit it or name a file)"
                            .into(),
                    );
                }
                let (c, cidrs) = dns_config(d, &known, base, state)?;
                (Some(c), cidrs)
            }
            None => (None, Vec::new()),
        };
        let udp = raw.udp.map(|u| udp_config(u, &known, &home)).transpose()?;
        let in_config = |p: PathBuf| if p.is_absolute() { p } else { base.join(p) };
        let in_state = |p: PathBuf| if p.is_absolute() { p } else { state.join(p) };
        let (policy, policy_log) = match raw.policy {
            Some(p) => {
                if raw.rules.is_some() || raw.default.is_some() {
                    // Zero-config product: rules only come signed.
                    return Err("rules / default come from the policy bundle; remove them".into());
                }
                let mut keys = BTreeMap::new();
                for k in &p.public_keys {
                    let key = crate::policy::parse_public_key(&k.public_key)
                        .map_err(|e| format!("policy.public_keys[{}]: {e}", k.key_id))?;
                    if keys.insert(k.key_id, key).is_some() {
                        return Err(format!("policy: duplicate key_id {}", k.key_id));
                    }
                }
                let verifier = Verifier::new(
                    keys,
                    p.ai_route.clone(),
                    known.keys().cloned().collect(),
                    home.clone(),
                )?;
                let store = PolicyStore::signed(verifier, p.installed.map(in_state));
                let log = store.load_startup(p.bundle.map(in_config).as_deref());
                (Arc::new(store), log)
            }
            None => {
                let rules = raw
                    .rules
                    .unwrap_or_default()
                    .into_iter()
                    .enumerate()
                    .map(|(i, r)| r.into_rule().map_err(|e| format!("rules[{i}]: {e}")))
                    .collect::<Result<Vec<_>, _>>()?;
                let default = raw
                    .default
                    .ok_or("default is required without a policy section")?;
                let rules = RuleSet::new(rules, default);
                for tag in rules.proxy_tags() {
                    if !known.contains_key(tag) {
                        return Err(format!("rule refers to unknown outbound {tag:?}"));
                    }
                }
                let mut policy = Policy::inline(rules, CidrTable::new(&chnroute));
                if let Some(f) = dns.as_ref().and_then(|d| d.foreign.clone()) {
                    policy = policy.with_foreign(f);
                }
                (PolicyStore::inline(policy), Vec::new())
            }
        };
        let control = match raw.control {
            None => None,
            Some(c) => {
                if !c.listen.ip().is_loopback() {
                    return Err(format!(
                        "control.listen must be a loopback address, got {}",
                        c.listen
                    ));
                }
                Some(ControlConfig {
                    listen: c.listen,
                    token_file: in_state(c.token_file),
                })
            }
        };
        let tun = match raw.tun {
            None => None,
            Some(t) => {
                let addr = TunAddress::from_parts(
                    t.mtu,
                    &t.ipv4,
                    &t.ipv4_peer,
                    t.ipv6,
                    t.ipv6_address.as_deref(),
                    t.ipv6_peer.as_deref(),
                )?;
                if let Some(d) = &dns {
                    if addr.overlaps_fake(d.fake_ip_base, d.fake_ip_prefix) {
                        return Err(
                            "tun.ipv4 overlaps dns.fake_ip_range; the pool could hand out the utun address"
                                .into(),
                        );
                    }
                }
                Some(addr)
            }
        };
        Ok(Self {
            listen: raw.listen,
            outbounds,
            policy,
            policy_log,
            sniff,
            dns,
            udp,
            segue,
            exits,
            home,
            control,
            tun,
        })
    }
}

fn udp_config(
    u: RawUdp,
    outbounds: &BTreeMap<String, Value>,
    home: &BTreeSet<String>,
) -> Result<UdpSettings, String> {
    for tag in u.refuse.iter().chain(&u.refuse_quic) {
        if !outbounds.contains_key(tag) {
            return Err(format!("udp refers to unknown outbound {tag:?}"));
        }
    }
    for tag in &u.refuse_quic {
        if home.contains(tag) {
            // refuse_quic means "UDP allowed except 443": not for Home.
            return Err(format!(
                "udp.refuse_quic: {tag:?} is a home-role outbound; UDP to Home is always refused"
            ));
        }
    }
    // Home-role tags are refused whatever `refuse` lists.
    let mut refuse: BTreeSet<String> = u.refuse.into_iter().collect();
    refuse.extend(home.iter().cloned());
    if u.idle_timeout_secs == 0
        || !(1..=4096).contains(&u.max_flows)
        || !(1..=1024).contains(&u.queue)
        || !(1..=4096).contains(&u.max_associations)
    {
        return Err(
            "udp: idle_timeout_secs > 0, max_flows 1..=4096, queue 1..=1024, max_associations 1..=4096"
                .into(),
        );
    }
    Ok(UdpSettings {
        refuse,
        refuse_quic: u.refuse_quic.into_iter().collect(),
        idle_timeout: Duration::from_secs(u.idle_timeout_secs),
        max_flows: u.max_flows,
        queue: u.queue,
        max_associations: u.max_associations,
        queue_bytes: crate::udp::ASSOCIATION_QUEUE_BYTES,
    })
}

fn dns_config(
    d: RawDns,
    outbounds: &BTreeMap<String, Value>,
    config_base: &Path,
    state_base: &Path,
) -> Result<(DnsConfig, Vec<Cidr>), String> {
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
        Some(Action::Direct) => {
            return Err("dns.foreign must be proxy or reject, not direct".into())
        }
        Some(Action::Proxy(tag)) if !outbounds.contains_key(tag) => {
            return Err(format!("dns.foreign refers to unknown outbound {tag:?}"))
        }
        _ => {}
    }
    if d.fake_ip_max_entries == 0 {
        return Err("dns.fake_ip_max_entries must be > 0".into());
    }
    let mut cidrs = Vec::new();
    for (i, c) in d.chnroute.iter().enumerate() {
        cidrs.push(Cidr::parse(c).map_err(|e| format!("dns.chnroute[{i}]: {e}"))?);
    }
    if let Some(file) = &d.chnroute_file {
        let path = if file.is_absolute() {
            file.clone()
        } else {
            config_base.join(file)
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
    let cfg = DnsConfig {
        listen: d.listen,
        settings: DnsSettings {
            domestic: d.domestic,
            query_timeout: Duration::from_millis(d.query_timeout_ms),
            cache_size: d.cache_size,
        },
        fake_ip_base,
        fake_ip_prefix,
        fake_ip_ttl: Duration::from_secs(d.fake_ip_ttl_secs),
        fake_ip_grace: Duration::from_secs(d.fake_ip_grace_secs),
        fake_ip_max_entries: d.fake_ip_max_entries,
        fake_ip_state: d.fake_ip_state.map(|f| {
            if f.is_absolute() {
                f
            } else {
                state_base.join(f)
            }
        }),
        foreign: d.foreign,
    };
    Ok((cfg, cidrs))
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
        assert!(c
            .policy
            .current()
            .chnroute
            .contains("1.0.1.9".parse().unwrap()));
        assert_eq!(d.foreign, Some(Action::Proxy("p".into())));
        assert_eq!(
            c.policy.current().foreign,
            Action::Proxy("p".into()),
            "inline lab: dns.foreign overrides the default for foreign names"
        );
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
        let p = c.policy.current();
        let t = &p.chnroute;
        assert!(t.contains("36.1.2.3".parse().unwrap()));
        assert!(t.contains("240e::1".parse().unwrap()));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    const OUT: &str = r#""outbounds":{"home":{"role":"home","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1}]}},
                        "p":{"protocol":"freedom"}}"#;

    fn doc(rest: &str) -> String {
        format!(r#"{{"listen":"127.0.0.1:1080",{OUT},{rest}}}"#)
    }

    #[test]
    fn home_role_always_refuses_udp() {
        // Not in udp.refuse, still refused; role stripped for the engine.
        let c = KernelConfig::parse(&doc(r#""default":{"type":"direct"},"udp":{"refuse":[]}"#))
            .unwrap();
        let u = c.udp.unwrap();
        assert!(u.refuse.contains("home"));
        assert!(!u.refuse.contains("p"));
        assert!(c.home.contains("home"));
        assert!(c.outbounds["home"].get("role").is_none());
        assert_eq!(c.outbounds["home"]["protocol"], "socks");
    }

    #[test]
    fn config_cannot_allow_udp_to_home() {
        let err = KernelConfig::parse(&doc(
            r#""default":{"type":"direct"},"udp":{"refuse_quic":["home"]}"#,
        ))
        .err()
        .unwrap();
        assert!(err.contains("always refused"), "{err}");
        let err = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","outbounds":{"h":{"role":"exit"}},"default":{"type":"direct"}}"#,
        )
        .err()
        .unwrap();
        assert!(err.contains("role"), "{err}");
        let err = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","outbounds":{"h":{"role":true}},"default":{"type":"direct"}}"#,
        )
        .err()
        .unwrap();
        assert!(err.contains("role"), "{err}");
    }

    fn segue_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("segue-cfg-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("t"), "dGlja2V0").unwrap();
        dir
    }

    #[test]
    fn segue_ai_route_is_home_and_role_must_match() {
        let dir = segue_dir("role");
        let ok = doc(
            r#""exits":[{"name":"la","carrier":"p","relay":"127.0.0.1:7443","node_id":1}],
               "segue":{"ai":{"ticket_file":"t","exit_class":"ai"},
                        "ov":{"ticket_file":"t","exit_class":"overseas","role":"proxy"}},
               "default":{"type":"direct"},"udp":{}"#,
        );
        let c = KernelConfig::parse_in(&ok, &dir).unwrap();
        assert!(c.home.contains("ai") && !c.home.contains("ov"));
        assert!(c.udp.unwrap().refuse.contains("ai"));
        assert_eq!(c.exits[0].name, "la");
        assert_eq!(c.exits[0].group(), "la", "absent egress_group is its own");
        let grouped = ok.replace(r#""node_id":1}]"#, r#""node_id":1,"egress_group":"iad"}]"#);
        let c = KernelConfig::parse_in(&grouped, &dir).unwrap();
        assert_eq!(c.exits[0].group(), "iad");
        let bad_group = ok.replace(r#""node_id":1}]"#, r#""node_id":1,"egress_group":""}]"#);
        assert!(KernelConfig::parse_in(&bad_group, &dir).is_err());
        let bad = ok.replace(
            r#""exit_class":"ai"}"#,
            r#""exit_class":"ai","role":"proxy"}"#,
        );
        let err = KernelConfig::parse_in(&bad, &dir).err().unwrap();
        assert!(err.contains("role must match"), "{err}");
        // A home outbound cannot carry sessions.
        let bad = ok.replace(r#""carrier":"p""#, r#""carrier":"home""#);
        let err = KernelConfig::parse_in(&bad, &dir).err().unwrap();
        assert!(err.contains("home-role"), "{err}");
        for bad_name in ["auto", "LA", ""] {
            let bad = ok.replace(r#""name":"la""#, &format!(r#""name":"{bad_name}""#));
            assert!(KernelConfig::parse_in(&bad, &dir).is_err(), "{bad_name}");
        }
        let no_exits = ok.replace(
            r#""exits":[{"name":"la","carrier":"p","relay":"127.0.0.1:7443","node_id":1}],"#,
            "",
        );
        assert!(KernelConfig::parse_in(&no_exits, &dir).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn policy_section_forbids_inline_rules_and_fails_closed() {
        let dir = segue_dir("pol");
        let (key, public) = crate::policy::generate_key();
        let pol = format!(
            r#""policy":{{"public_keys":[{{"key_id":1,"public_key":"{public}"}}],"bundle":"b","installed":"i"}},
               "exits":[{{"name":"la","carrier":"p","relay":"127.0.0.1:7443"}}],
               "segue":{{"ai":{{"ticket_file":"t","exit_class":"ai"}}}}"#
        );
        // No bundle yet: valid config, fail-closed policy.
        let c = KernelConfig::parse_in(&doc(&pol), &dir).unwrap();
        assert!(!c.policy.status().valid);
        assert!(c.policy.current().refuse_all);
        // Inline rules next to a policy are rejected (zero-config product).
        let err = KernelConfig::parse_in(
            &doc(&format!(r#"{pol},"default":{{"type":"direct"}}"#)),
            &dir,
        )
        .err()
        .unwrap();
        assert!(err.contains("policy bundle"), "{err}");
        let err = KernelConfig::parse_in(
            &doc(&format!(
                r#"{pol},"dns":{{"listen":"127.0.0.1:5353","domestic":["223.5.5.5:53"],"chnroute":["1.0.0.0/8"],"foreign":{{"type":"reject"}}}}"#
            )),
            &dir,
        )
        .err()
        .unwrap();
        assert!(err.contains("policy bundle"), "{err}");
        // So is a local foreign route: unknown names follow the bundle.
        let err = KernelConfig::parse_in(
            &doc(&format!(
                r#"{pol},"dns":{{"listen":"127.0.0.1:5353","domestic":["223.5.5.5:53"],"foreign":{{"type":"proxy","outbound":"p"}}}}"#
            )),
            &dir,
        )
        .err()
        .unwrap();
        assert!(
            err.contains("dns.foreign comes from the policy bundle"),
            "{err}"
        );
        // In-memory fake-IP bindings are lab only: a signed config must
        // persist them (omitting the key keeps the default file).
        let err = KernelConfig::parse_in(
            &doc(&format!(
                r#"{pol},"dns":{{"listen":"127.0.0.1:5353","domestic":["223.5.5.5:53"],"fake_ip_state":null}}"#
            )),
            &dir,
        )
        .err()
        .unwrap();
        assert!(err.contains("fake_ip_state"), "{err}");
        let c = KernelConfig::parse_in(
            &doc(&format!(
                r#"{pol},"dns":{{"listen":"127.0.0.1:5353","domestic":["223.5.5.5:53"]}}"#
            )),
            &dir,
        )
        .unwrap();
        assert!(c.dns.unwrap().fake_ip_state.is_some());
        // A signed bundle in place installs at startup and is persisted.
        let body = br#"{"version":2,"expires_at":4000000000,"ai_domains":["openai.com"],"default":{"type":"direct"}}"#;
        std::fs::write(dir.join("b"), crate::policy::sign(&key, 1, body).unwrap()).unwrap();
        let c = KernelConfig::parse_in(&doc(&pol), &dir).unwrap();
        assert_eq!(c.policy.status().version, Some(2), "{:?}", c.policy_log);
        assert!(dir.join("i").exists());
        assert_eq!(
            c.policy
                .current()
                .rules
                .decide(&segue_routing::TargetAddr::Domain("x.openai.com".into())),
            &Action::Proxy("ai".into())
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn control_must_be_loopback() {
        let c = KernelConfig::parse(&doc(
            r#""default":{"type":"direct"},"control":{"listen":"127.0.0.1:0","token_file":"/tmp/x"}"#,
        ))
        .unwrap();
        assert!(c.control.is_some());
        let err = KernelConfig::parse(&doc(
            r#""default":{"type":"direct"},"control":{"listen":"0.0.0.0:9","token_file":"x"}"#,
        ))
        .err()
        .unwrap();
        assert!(err.contains("loopback"), "{err}");
    }

    #[test]
    fn state_dir_keeps_runtime_files_off_the_config_directory() {
        let dir = std::env::temp_dir().join(format!("segue-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        let text = r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},
            "control":{"listen":"127.0.0.1:0","token_file":"control.json"},
            "dns":{"listen":"127.0.0.1:5353","domestic":["1.1.1.1:53"],"fake_ip_state":"fakeip.state"}}"#;
        let state = dir.join("state");
        let c = KernelConfig::parse_with(text, &dir, Some(&state)).unwrap();
        assert_eq!(
            c.control.as_ref().unwrap().token_file,
            state.join("control.json")
        );
        assert_eq!(
            c.dns.as_ref().unwrap().fake_ip_state.as_ref().unwrap(),
            &state.join("fakeip.state")
        );
        let abs = r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},
            "control":{"listen":"127.0.0.1:0","token_file":"/tmp/keep.json"}}"#;
        let c = KernelConfig::parse_with(abs, &dir, Some(&state)).unwrap();
        assert_eq!(
            c.control.unwrap().token_file,
            PathBuf::from("/tmp/keep.json")
        );
        let c = KernelConfig::parse_in(text, &dir).unwrap();
        assert_eq!(c.control.unwrap().token_file, dir.join("control.json"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn tun_section_uses_defaults_and_rejects_the_fake_ip_range() {
        let off = KernelConfig::parse(r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"}}"#)
            .unwrap();
        assert!(off.tun.is_none());
        let on = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},"tun":{}}"#,
        )
        .unwrap();
        let tun = on.tun.unwrap();
        assert_eq!(tun.mtu, 1500);
        assert_eq!(tun.v4, std::net::Ipv4Addr::new(172, 19, 0, 1));
        assert!(tun.v6.is_some());
        let no_v6 = KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},"tun":{"ipv6":false}}"#,
        )
        .unwrap();
        assert!(no_v6.tun.unwrap().v6.is_none());
        let err = match KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},"tun":{"mtu":100}}"#,
        ) {
            Err(e) => e,
            Ok(_) => panic!("mtu 100 was accepted"),
        };
        assert!(err.contains("mtu"), "{err}");
        let err = match KernelConfig::parse(
            r#"{"listen":"127.0.0.1:1080","default":{"type":"direct"},
                "dns":{"listen":"127.0.0.1:5353","domestic":["1.1.1.1:53"],"fake_ip_range":"172.19.0.0/16"},
                "tun":{}}"#,
        ) {
            Err(e) => e,
            Ok(_) => panic!("utun address inside the fake-ip range was accepted"),
        };
        assert!(err.contains("fake_ip"), "{err}");
    }
}
