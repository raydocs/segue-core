//! Signed rule bundle (KERNEL_SPEC §5.3, §5.4; CONTROL_PLANE_SPEC §6).
//!
//! The routing rules are not user configuration: the control plane compiles
//! them into a bundle and signs it with Ed25519 (a key separate from the
//! ticket key). The kernel only loads and verifies.
//!
//! Envelope (JSON): `{"key_id": 1, "body": "<base64 body>", "sig": "<base64>"}`.
//! The signature covers [`SIG_CONTEXT`] followed by the raw body bytes, so a
//! signature made for anything else (a ticket, an older format) never
//! verifies as a policy.
//!
//! Body (JSON):
//!
//! ```json
//! {"version": 7, "expires_at": 1767225600,
//!  "ai_domains": ["openai.com"],
//!  "rules": [{"ip_cidr": "1.2.3.0/24", "action": {"type": "proxy", "outbound": "overseas"}}],
//!  "default": {"type": "proxy", "outbound": "overseas"},
//!  "chnroute": ["1.0.1.0/24"]}
//! ```
//!
//! `ai_domains` and `ai_cidrs` are the bundle's AI list (the same fields the
//! relay reads). The kernel merges them with the built-in list
//! ([`crate::rules::builtin_ai_list`]) into a first-tier match that beats
//! every user rule except an explicit reject. There is no separate `ai`
//! object and no version gate: those two fields have been in the body since
//! the signed format, and skipping the built-in list on an older `version`
//! would leave that bundle able to send Claude or ChatGPT direct. A bundle
//! that omits a built-in name still locks it. `chnroute` is the domestic IP
//! set the smart DNS uses to tell polluted answers apart.
//!
//! A bundle is installed only if its signature verifies under a configured
//! key, its `version` is above every version seen so far (no rollback; the
//! control plane rolls back by publishing a newer version), it has not
//! expired and every route it names exists. Anything else is rejected and
//! the last good bundle stays. When there is no good bundle (none yet, or
//! the installed one expired) the policy is fail-closed: every flow is
//! refused, AI included (§5.4 "策略未加载 / 验签失败 → 全部 REFUSE").

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::rules::{Action, Cidr, CidrTable, RuleSet, RuleSpec};

// Envelope format and signature check are shared with the relay, which
// reads its AI set from the same signed bundle (KERNEL_SPEC §5.5 item 7).
pub use segue_policy::{generate_key, parse_public_key, Envelope, MAX_BUNDLE_BYTES, SIG_CONTEXT};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub version: u64,
    /// Unix seconds; the bundle is invalid at and after this time.
    pub expires_at: u64,
    #[serde(default)]
    pub ai_domains: Vec<String>,
    /// AI IP ranges (the relay's AI set reads the same list).
    #[serde(default)]
    pub ai_cidrs: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    pub default: Action,
    #[serde(default)]
    pub chnroute: Vec<String>,
    /// ECH client-facing (public) names, as domain suffixes: a ClientHello
    /// with an ECH extension whose SNI is one of these hides its real
    /// name (KERNEL_SPEC §5.2a.1, astra r10 N2). Absent: the built-in
    /// [`DEFAULT_ECH_PUBLIC_NAMES`]; `[]` turns the list off.
    #[serde(default = "default_ech_public_names")]
    pub ech_public_names: Vec<String>,
}

/// Known ECH public names when a bundle names none: Cloudflare's shared
/// client-facing server.
pub const DEFAULT_ECH_PUBLIC_NAMES: &[&str] = &["cloudflare-ech.com"];

fn default_ech_public_names() -> Vec<String> {
    DEFAULT_ECH_PUBLIC_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// The routing data every flow and DNS query reads.
#[derive(Debug)]
pub struct Policy {
    pub rules: RuleSet,
    pub chnroute: CidrTable,
    /// Route for a name with no domain rule whose domestic DNS answer falls
    /// outside chnroute (smart DNS "foreign"). From a signed bundle this is
    /// always the bundle's `default`, so a name reaches the same decision by
    /// DNS + fake-IP as by a direct domain CONNECT.
    pub foreign: Action,
    /// Route for a TLS flow to a real IP whose server name is hidden
    /// (ClientHello offers ECH, KERNEL_SPEC §5.2a.1): the AI route from a
    /// signed bundle, so a hidden name is handled as if it were AI and the
    /// relay's Home whitelist decides (§5.5 item 3). Never the outer SNI's
    /// route. Reject for the fail-closed policy and, unless set, inline.
    pub hidden_name: Action,
    /// The bundle's AI IP ranges: a hidden name to one of these takes
    /// [`Policy::hidden_name`]; to any other IP it is refused locally.
    pub ai_ips: CidrTable,
    /// ECH public names (canonical suffixes), see [`Body::ech_public_names`].
    pub ech_public_names: Vec<String>,
    /// 0 for an inline (dev) policy and for the fail-closed policy.
    pub version: u64,
    /// None: does not expire (inline dev rules).
    pub expires_at: Option<u64>,
    /// No valid policy: every flow is refused, fake-IP entries included.
    pub refuse_all: bool,
}

impl Policy {
    /// No bundle: refuse everything.
    pub fn fail_closed() -> Self {
        Self {
            rules: RuleSet::new(Vec::new(), Action::Reject),
            chnroute: CidrTable::default(),
            foreign: Action::Reject,
            hidden_name: Action::Reject,
            ai_ips: CidrTable::default(),
            ech_public_names: default_ech_public_names(),
            version: 0,
            expires_at: None,
            refuse_all: true,
        }
    }

    /// Rules given in the kernel config (lab / tests only).
    pub fn inline(rules: RuleSet, chnroute: CidrTable) -> Self {
        Self {
            foreign: rules.default_action().clone(),
            hidden_name: Action::Reject,
            ai_ips: CidrTable::default(),
            ech_public_names: default_ech_public_names(),
            rules,
            chnroute,
            version: 0,
            expires_at: None,
            refuse_all: false,
        }
    }

    /// Lab only: a `dns.foreign` route different from the default.
    pub fn with_foreign(mut self, foreign: Action) -> Self {
        self.foreign = foreign;
        self
    }

    /// Lab / tests: the route for a hidden (ECH) name; see
    /// [`Policy::hidden_name`].
    pub fn with_hidden_name(mut self, route: Action) -> Self {
        self.hidden_name = route;
        self
    }

    /// Lab / tests: the AI IP ranges a hidden name may go to.
    pub fn with_ai_ips(mut self, cidrs: &[Cidr]) -> Self {
        self.ai_ips = CidrTable::new(cidrs);
        self
    }

    /// `sni` (normalized) is, or is under, a known ECH public name.
    pub fn is_ech_public_name(&self, sni: &str) -> bool {
        self.ech_public_names
            .iter()
            .any(|s| segue_policy::suffix_match(sni, s))
    }

    /// Decision for a fake-IP flow to `domain` (re-authorized per flow): an
    /// explicit domain rule, else the foreign route (fake-IPs for unmatched
    /// names are only handed out to names judged foreign).
    pub fn decide_fake(&self, domain: &str) -> &Action {
        match self
            .rules
            .lookup(&segue_routing::TargetAddr::Domain(domain.to_owned()))
        {
            Some((_, a)) => a,
            None => &self.foreign,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    Malformed(String),
    UnknownKey(u32),
    BadSignature,
    NotNewer {
        installed: u64,
        got: u64,
    },
    Expired {
        expires_at: u64,
        now: u64,
    },
    /// Names a route this kernel does not have, or breaks a rule invariant.
    Incompatible(String),
    /// The kernel runs on inline rules; bundles cannot be installed.
    Fixed,
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "policy bundle malformed: {e}"),
            Self::UnknownKey(k) => write!(f, "policy bundle signed with unknown key_id {k}"),
            Self::BadSignature => f.write_str("policy bundle signature invalid"),
            Self::NotNewer { installed, got } => write!(
                f,
                "policy bundle version {got} is not newer than installed {installed}"
            ),
            Self::Expired { expires_at, now } => {
                write!(f, "policy bundle expired at {expires_at} (now {now})")
            }
            Self::Incompatible(e) => write!(f, "policy bundle incompatible: {e}"),
            Self::Fixed => f.write_str("kernel runs on inline rules; bundles are not accepted"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Checks bundles against the configured keys and this kernel's routes.
pub struct Verifier {
    keys: BTreeMap<u32, Vec<u8>>,
    /// Route the AI domain list goes to.
    ai_route: String,
    /// Every outbound / session route tag a rule may name.
    known: BTreeSet<String>,
    /// Home-role tags: the AI route must be one, the default must not.
    home: BTreeSet<String>,
}

impl Verifier {
    pub fn new(
        keys: BTreeMap<u32, Vec<u8>>,
        ai_route: String,
        known: BTreeSet<String>,
        home: BTreeSet<String>,
    ) -> Result<Self, String> {
        if keys.is_empty() {
            return Err("policy.public_keys must list at least one key".into());
        }
        for (id, k) in &keys {
            if k.len() != 32 {
                return Err(format!(
                    "policy key {id}: Ed25519 public key must be 32 bytes"
                ));
            }
        }
        if !known.contains(&ai_route) {
            return Err(format!("policy.ai_route {ai_route:?} is not a known route"));
        }
        if !home.contains(&ai_route) {
            // AI traffic always uses the Home exit (D8).
            return Err(format!(
                "policy.ai_route {ai_route:?} must be a home-role route"
            ));
        }
        Ok(Self {
            keys,
            ai_route,
            known,
            home,
        })
    }

    /// Signature + body checks that do not depend on what is installed.
    /// Returns the body (version / expiry still to be judged).
    pub fn open(&self, bytes: &[u8]) -> Result<(Body, Policy), PolicyError> {
        let body = segue_policy::open(&self.keys, bytes).map_err(|e| match e {
            segue_policy::EnvelopeError::Malformed(m) => PolicyError::Malformed(m),
            segue_policy::EnvelopeError::UnknownKey(k) => PolicyError::UnknownKey(k),
            segue_policy::EnvelopeError::BadSignature => PolicyError::BadSignature,
        })?;
        // Only signed bytes are parsed past this point.
        let parsed: Body = serde_json::from_slice(&body)
            .map_err(|e| PolicyError::Malformed(format!("body: {e}")))?;
        let policy = self.compile(&parsed)?;
        Ok((parsed, policy))
    }

    fn compile(&self, b: &Body) -> Result<Policy, PolicyError> {
        let bad = PolicyError::Incompatible;
        // The signed AI set is accepted or refused by the same function the
        // relay uses (review r5 N3). The kernel then adds its built-in list,
        // which the relay does not see: a name only the kernel locks is sent
        // to the AI exit, and the relay's home whitelist may refuse it. That
        // is a failed dial, not a direct connection.
        segue_policy::AiSet::parse(&b.ai_domains, &b.ai_cidrs).map_err(bad)?;
        let (mut suffixes, mut ai_ips) = crate::rules::builtin_ai_list();
        for d in &b.ai_domains {
            let d = segue_policy::canonical_domain(d).expect("checked by AiSet::parse");
            if !suffixes.iter().any(|s| s == &d) {
                suffixes.push(d);
            }
        }
        for (i, c) in b.ai_cidrs.iter().enumerate() {
            let cidr = Cidr::parse(c).map_err(|e| bad(format!("ai_cidrs[{i}]: {e}")))?;
            ai_ips.push(cidr);
        }
        let mut rules = Vec::with_capacity(b.rules.len());
        let ech_public_names = b
            .ech_public_names
            .iter()
            .enumerate()
            .map(|(i, d)| {
                segue_policy::canonical_domain(d)
                    .ok_or_else(|| bad(format!("ech_public_names[{i}]: bad domain {d:?}")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (i, r) in b.rules.iter().enumerate() {
            let r = RuleSpec {
                domain_suffix: r.domain_suffix.clone(),
                domain: r.domain.clone(),
                domain_keyword: r.domain_keyword.clone(),
                ip_cidr: r.ip_cidr.clone(),
                action: r.action.clone(),
            };
            rules.push(r.into_rule().map_err(|e| bad(format!("rules[{i}]: {e}")))?);
        }
        let set = RuleSet::new(rules, b.default.clone()).with_ai(
            suffixes,
            &ai_ips,
            Action::Proxy(self.ai_route.clone()),
        );
        for tag in set.proxy_tags() {
            if !self.known.contains(tag) {
                return Err(bad(format!("refers to unknown route {tag:?}")));
            }
        }
        if let Action::Proxy(t) = &b.default {
            if self.home.contains(t) {
                // Sending everything unmatched to home broadband would make
                // the Home exit a general-purpose proxy.
                return Err(bad(format!("default must not be the home route {t:?}")));
            }
        }
        let mut cidrs = Vec::with_capacity(b.chnroute.len());
        for (i, c) in b.chnroute.iter().enumerate() {
            cidrs.push(Cidr::parse(c).map_err(|e| bad(format!("chnroute[{i}]: {e}")))?);
        }
        Ok(Policy {
            foreign: b.default.clone(),
            hidden_name: Action::Proxy(self.ai_route.clone()),
            ai_ips: CidrTable::new(&ai_ips),
            ech_public_names,
            rules: set,
            chnroute: CidrTable::new(&cidrs),
            version: b.version,
            expires_at: Some(b.expires_at),
            refuse_all: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyStatus {
    /// "signed" or "inline".
    pub source: &'static str,
    /// True when flows are routed by a bundle (or inline rules); false
    /// means fail-closed.
    pub valid: bool,
    /// Version in force (None: no valid bundle).
    pub version: Option<u64>,
    pub expires_at: Option<u64>,
    /// Highest version ever verified (rollback floor).
    pub high_water: u64,
}

enum Source {
    Inline(Arc<Policy>),
    Signed {
        verifier: Verifier,
        /// Where the last good bundle is kept across restarts.
        installed_path: Option<PathBuf>,
    },
}

#[derive(Default)]
struct Installed {
    current: Option<Arc<Policy>>,
    high_water: u64,
}

/// The policy in force. Reads are cheap (`Arc` clone under a read lock).
pub struct PolicyStore {
    source: Source,
    state: RwLock<Installed>,
    fail_closed: Arc<Policy>,
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl PolicyStore {
    /// Inline rules (lab, tests): always valid, never replaced.
    pub fn inline(policy: Policy) -> Arc<Self> {
        Arc::new(Self {
            source: Source::Inline(Arc::new(policy)),
            state: RwLock::new(Installed::default()),
            fail_closed: Arc::new(Policy::fail_closed()),
        })
    }

    /// Bundle-driven store, empty (fail-closed) until a bundle installs.
    pub fn signed(verifier: Verifier, installed_path: Option<PathBuf>) -> Self {
        Self {
            source: Source::Signed {
                verifier,
                installed_path,
            },
            state: RwLock::new(Installed::default()),
            fail_closed: Arc::new(Policy::fail_closed()),
        }
    }

    pub fn current(&self) -> Arc<Policy> {
        self.current_at(unix_now())
    }

    pub fn current_at(&self, now: u64) -> Arc<Policy> {
        match &self.source {
            Source::Inline(p) => p.clone(),
            Source::Signed { .. } => {
                let st = self.state.read().unwrap();
                match &st.current {
                    Some(p) if p.expires_at.is_some_and(|e| now < e) => p.clone(),
                    _ => self.fail_closed.clone(),
                }
            }
        }
    }

    pub fn status(&self) -> PolicyStatus {
        self.status_at(unix_now())
    }

    pub fn status_at(&self, now: u64) -> PolicyStatus {
        match &self.source {
            Source::Inline(_) => PolicyStatus {
                source: "inline",
                valid: true,
                version: None,
                expires_at: None,
                high_water: 0,
            },
            Source::Signed { .. } => {
                let st = self.state.read().unwrap();
                let live = st
                    .current
                    .as_ref()
                    .filter(|p| p.expires_at.is_some_and(|e| now < e));
                PolicyStatus {
                    source: "signed",
                    valid: live.is_some(),
                    version: live.map(|p| p.version),
                    expires_at: live.and_then(|p| p.expires_at),
                    high_water: st.high_water,
                }
            }
        }
    }

    /// Verify and install a bundle; on success it is also written to the
    /// installed path. Returns the new version.
    pub fn install(&self, bytes: &[u8]) -> Result<u64, PolicyError> {
        self.install_at(bytes, unix_now(), true)
    }

    pub fn install_at(&self, bytes: &[u8], now: u64, persist: bool) -> Result<u64, PolicyError> {
        let Source::Signed {
            verifier,
            installed_path,
        } = &self.source
        else {
            return Err(PolicyError::Fixed);
        };
        let (body, policy) = verifier.open(bytes)?;
        let mut st = self.state.write().unwrap();
        if body.version <= st.high_water {
            return Err(PolicyError::NotNewer {
                installed: st.high_water,
                got: body.version,
            });
        }
        if now >= body.expires_at {
            return Err(PolicyError::Expired {
                expires_at: body.expires_at,
                now,
            });
        }
        if persist {
            if let Some(path) = installed_path {
                write_atomic(path, bytes).map_err(|e| {
                    PolicyError::Malformed(format!("persist {}: {e}", path.display()))
                })?;
            }
        }
        st.high_water = body.version;
        st.current = Some(Arc::new(policy));
        Ok(body.version)
    }

    /// Startup: restore the last good bundle from the installed path, then
    /// try `candidate` (a freshly delivered bundle). Returns log lines.
    pub fn load_startup(&self, candidate: Option<&Path>) -> Vec<String> {
        self.load_startup_at(candidate, unix_now())
    }

    pub fn load_startup_at(&self, candidate: Option<&Path>, now: u64) -> Vec<String> {
        let mut log = Vec::new();
        let Source::Signed {
            verifier,
            installed_path,
        } = &self.source
        else {
            return log;
        };
        if let Some(path) = installed_path {
            match std::fs::read(path) {
                Ok(bytes) => match verifier.open(&bytes) {
                    Ok((body, policy)) => {
                        let mut st = self.state.write().unwrap();
                        // A genuine but expired bundle still sets the
                        // rollback floor.
                        st.high_water = body.version;
                        if now < body.expires_at {
                            st.current = Some(Arc::new(policy));
                            log.push(format!("policy: restored version {}", body.version));
                        } else {
                            log.push(format!(
                                "policy: installed version {} expired; fail-closed until a newer bundle",
                                body.version
                            ));
                        }
                    }
                    Err(e) => log.push(format!("policy: installed bundle rejected: {e}")),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => log.push(format!("policy: read {}: {e}", path.display())),
            }
        }
        if let Some(path) = candidate {
            match std::fs::read(path) {
                Ok(bytes) => match self.install_at(&bytes, now, true) {
                    Ok(v) => log.push(format!("policy: installed version {v}")),
                    // The same bundle as installed is the normal restart case.
                    Err(PolicyError::NotNewer { installed, got }) if installed == got => {}
                    Err(e) => log.push(format!("policy: {e}; keeping last good")),
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => log.push(format!("policy: read {}: {e}", path.display())),
            }
        }
        if !self.status_at(now).valid {
            log.push("policy: no valid bundle; refusing all flows".into());
        }
        log
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// Sign `body` (the body JSON) into an envelope (dev signing tool; the
/// control plane does this in production).
pub fn sign(key_b64: &str, key_id: u32, body: &[u8]) -> Result<String, String> {
    let parsed: Body =
        serde_json::from_slice(body).map_err(|e| format!("body does not parse: {e}"))?;
    let _ = parsed;
    segue_policy::sign(key_b64, key_id, body)
}

/// Read a private key file, refusing one readable by group / others.
pub fn read_private_key(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{}: key file must not be readable by group/others (chmod 600)",
                path.display()
            ));
        }
    }
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Create a new private key file with mode 0600 (never overwrites).
pub fn write_private_key(path: &Path, text: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        o.mode(0o600);
    }
    o.open(path)?.write_all(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use ring::signature;

    fn b64() -> base64::engine::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }
    use segue_routing::TargetAddr;

    const NOW: u64 = 1_800_000_000;

    fn body(version: u64, expires_at: u64) -> Vec<u8> {
        format!(
            r#"{{"version":{version},"expires_at":{expires_at},"ai_domains":["openai.com"],
                "rules":[{{"ip_cidr":"9.9.9.0/24","action":{{"type":"proxy","outbound":"overseas"}}}}],
                "default":{{"type":"proxy","outbound":"overseas"}},"chnroute":["36.0.0.0/8"]}}"#
        )
        .into_bytes()
    }

    struct Keys {
        key: String,
        pubkey: Vec<u8>,
    }

    fn keys() -> Keys {
        let (key, pubkey) = generate_key();
        Keys {
            key,
            pubkey: parse_public_key(&pubkey).unwrap(),
        }
    }

    fn verifier(k: &Keys) -> Verifier {
        let known: BTreeSet<String> = ["ai", "overseas"].map(String::from).into();
        let home: BTreeSet<String> = ["ai".to_string()].into();
        Verifier::new([(1, k.pubkey.clone())].into(), "ai".into(), known, home).unwrap()
    }

    fn signed(k: &Keys, version: u64, expires: u64) -> Vec<u8> {
        sign(&k.key, 1, &body(version, expires))
            .unwrap()
            .into_bytes()
    }

    fn dom(d: &str) -> TargetAddr {
        TargetAddr::Domain(d.into())
    }

    /// r9 F4: a hidden (ECH) name goes the signed bundle's AI route;
    /// fail-closed and inline policies refuse it.
    #[test]
    fn hidden_name_takes_the_ai_route() {
        let k = keys();
        let (_, p) = verifier(&k).open(&signed(&k, 1, NOW + 100)).unwrap();
        assert_eq!(p.hidden_name, Action::Proxy("ai".into()));
        assert_eq!(Policy::fail_closed().hidden_name, Action::Reject);
        let inline = Policy::inline(RuleSet::new(vec![], Action::Direct), CidrTable::default());
        assert_eq!(inline.hidden_name, Action::Reject);
    }

    /// r10 N2: the bundle's AI CIDRs are the IPs a hidden name may go to;
    /// `ech_public_names` defaults to `cloudflare-ech.com`, can be set or
    /// emptied, matches by suffix, and a bad entry refuses the bundle.
    #[test]
    fn ech_public_names_and_ai_ips_from_the_bundle() {
        let k = keys();
        let with = |extra: &str| {
            let b = format!(
                r#"{{"version":1,"expires_at":{},"ai_domains":[],"ai_cidrs":["203.0.113.0/24"],
                    "default":{{"type":"proxy","outbound":"overseas"}}{extra}}}"#,
                NOW + 100
            );
            verifier(&k).open(sign(&k.key, 1, b.as_bytes()).unwrap().as_bytes())
        };
        let (_, p) = with("").unwrap();
        assert!(p.ai_ips.contains("203.0.113.9".parse().unwrap()));
        assert!(!p.ai_ips.contains("9.9.9.9".parse().unwrap()));
        assert!(p.is_ech_public_name("cloudflare-ech.com"));
        assert!(p.is_ech_public_name("x.cloudflare-ech.com"));
        assert!(!p.is_ech_public_name("notcloudflare-ech.com"));
        let (_, p) = with(r#","ech_public_names":["Ech.Example."]"#).unwrap();
        assert!(p.is_ech_public_name("ech.example"));
        assert!(!p.is_ech_public_name("cloudflare-ech.com"));
        let (_, p) = with(r#","ech_public_names":[]"#).unwrap();
        assert!(!p.is_ech_public_name("cloudflare-ech.com"));
        assert!(with(r#","ech_public_names":["bad name"]"#).is_err());
    }

    /// Review r5 N3: the kernel and the relay read the same signed bytes
    /// the same way: both refuse a non-canonical AI entry, and for accepted
    /// bundles every name is AI to both or to neither.
    #[test]
    fn ai_classification_matches_relay() {
        let k = keys();
        let v = verifier(&k);
        let names = [
            "openai.com",
            "api.openai.com",
            "API.OpenAI.com.",
            "notopenai.com",
            "openai.com.evil",
            "x.ai.test",
            "test",
        ];
        for domains in [
            r#"[".openai.com"]"#,
            r#"[" openai.com"]"#,
            r#"["openai.com "]"#,
            r#"["a..b"]"#,
            r#"["OpenAI.com.", "ai.test"]"#,
            r#"["openai.com"]"#,
        ] {
            let body = format!(
                r#"{{"version":1,"expires_at":{},"ai_domains":{domains},"ai_cidrs":["203.0.113.0/24"],
                    "default":{{"type":"proxy","outbound":"overseas"}}}}"#,
                NOW + 100
            );
            let bytes = sign(&k.key, 1, body.as_bytes()).unwrap().into_bytes();
            let kernel = v.open(&bytes);
            let relay = segue_policy::open(&v.keys, &bytes)
                .map_err(|e| e.to_string())
                .and_then(|b| segue_policy::AiView::parse(&b).map_err(|e| e.to_string()))
                .and_then(|view| segue_policy::AiSet::from_view(&view));
            assert_eq!(kernel.is_ok(), relay.is_ok(), "{domains}: accept differs");
            let (Ok((_, pol)), Ok(set)) = (kernel, relay) else {
                continue;
            };
            for n in names {
                let k_ai = pol.rules.decide(&dom(n)) == &Action::Proxy("ai".into());
                assert_eq!(k_ai, set.is_ai_domain(n), "{domains}: {n} differs");
            }
            let ip = "203.0.113.7".parse().unwrap();
            assert_eq!(
                pol.rules.decide(&TargetAddr::Ip(ip)) == &Action::Proxy("ai".into()),
                set.is_ai_ip(ip)
            );
        }
    }

    #[test]
    fn empty_store_is_fail_closed() {
        let k = keys();
        let s = PolicyStore::signed(verifier(&k), None);
        let p = s.current_at(NOW);
        assert_eq!(p.rules.decide(&dom("chat.openai.com")), &Action::Reject);
        assert_eq!(p.rules.decide(&dom("example.com")), &Action::Reject);
        assert!(p.refuse_all);
        assert!(!s.status_at(NOW).valid);
    }

    #[test]
    fn valid_bundle_installs_and_routes_ai_to_home() {
        let k = keys();
        let s = PolicyStore::signed(verifier(&k), None);
        assert_eq!(s.install_at(&signed(&k, 3, NOW + 100), NOW, false), Ok(3));
        let p = s.current_at(NOW);
        assert_eq!(
            p.rules.decide(&dom("api.openai.com")),
            &Action::Proxy("ai".into())
        );
        assert_eq!(
            p.rules.decide(&TargetAddr::Ip("9.9.9.9".parse().unwrap())),
            &Action::Proxy("overseas".into())
        );
        assert!(p.chnroute.contains("36.1.1.1".parse().unwrap()));
        // Built-in names are AI even though this bundle only lists openai.com.
        assert_eq!(
            p.rules.decide(&dom("api.anthropic.com")),
            &Action::Proxy("ai".into())
        );
        let st = s.status_at(NOW);
        assert_eq!((st.valid, st.version, st.high_water), (true, Some(3), 3));
    }

    /// A user Direct for an AI name loses. An explicit Reject still blocks.
    #[test]
    fn ai_tier_beats_a_direct_rule_and_loses_to_reject() {
        let k = keys();
        let v = verifier(&k);
        let open = |rules: &str| {
            let body = format!(
                r#"{{"version":1,"expires_at":{},"ai_domains":[],"rules":{rules},
                    "default":{{"type":"proxy","outbound":"overseas"}}}}"#,
                NOW + 100
            );
            v.open(sign(&k.key, 1, body.as_bytes()).unwrap().as_bytes())
                .unwrap()
                .1
        };
        let direct = open(r#"[{"domain_suffix":"claude.ai","action":{"type":"direct"}}]"#);
        assert_eq!(
            direct.rules.decide(&dom("api.claude.ai")),
            &Action::Proxy("ai".into())
        );
        let blocked = open(r#"[{"domain_suffix":"openai.com","action":{"type":"reject"}}]"#);
        assert_eq!(
            blocked.rules.decide(&dom("api.openai.com")),
            &Action::Reject
        );
        assert_eq!(
            blocked.rules.decide(&dom("claude.ai")),
            &Action::Proxy("ai".into())
        );
    }

    #[test]
    fn forged_bundles_rejected_last_good_kept() {
        let k = keys();
        let s = PolicyStore::signed(verifier(&k), None);
        s.install_at(&signed(&k, 3, NOW + 100), NOW, false).unwrap();

        // Signed by a different key under the trusted key_id.
        let other = keys();
        let forged = sign(&other.key, 1, &body(9, NOW + 100)).unwrap();
        assert_eq!(
            s.install_at(forged.as_bytes(), NOW, false),
            Err(PolicyError::BadSignature)
        );
        // Body swapped after signing.
        let mut env: Envelope = serde_json::from_slice(&signed(&k, 9, NOW + 100)).unwrap();
        let mut b = body(9, NOW + 100);
        b.extend_from_slice(b" ");
        env.body = b64().encode(&b);
        let tampered = serde_json::to_vec(&env).unwrap();
        assert_eq!(
            s.install_at(&tampered, NOW, false),
            Err(PolicyError::BadSignature)
        );
        // A signature without the policy context (e.g. raw body signed).
        let der = b64().decode(&k.key).unwrap();
        let pair = signature::Ed25519KeyPair::from_pkcs8(&der).unwrap();
        let raw = body(9, NOW + 100);
        let env = Envelope {
            key_id: 1,
            body: b64().encode(&raw),
            sig: b64().encode(pair.sign(&raw).as_ref()),
        };
        assert_eq!(
            s.install_at(&serde_json::to_vec(&env).unwrap(), NOW, false),
            Err(PolicyError::BadSignature)
        );
        // Unknown key id.
        let unk = sign(&k.key, 2, &body(9, NOW + 100)).unwrap();
        assert_eq!(
            s.install_at(unk.as_bytes(), NOW, false),
            Err(PolicyError::UnknownKey(2))
        );
        assert!(matches!(
            s.install_at(b"not json", NOW, false),
            Err(PolicyError::Malformed(_))
        ));
        assert_eq!(s.status_at(NOW).version, Some(3), "last good kept");
    }

    #[test]
    fn older_or_equal_version_rejected() {
        let k = keys();
        let s = PolicyStore::signed(verifier(&k), None);
        s.install_at(&signed(&k, 5, NOW + 100), NOW, false).unwrap();
        assert_eq!(
            s.install_at(&signed(&k, 4, NOW + 1000), NOW, false),
            Err(PolicyError::NotNewer {
                installed: 5,
                got: 4
            })
        );
        assert!(s
            .install_at(&signed(&k, 5, NOW + 1000), NOW, false)
            .is_err());
        assert_eq!(s.install_at(&signed(&k, 6, NOW + 1000), NOW, false), Ok(6));
    }

    #[test]
    fn expired_rejected_and_installed_expiry_fails_closed() {
        let k = keys();
        let s = PolicyStore::signed(verifier(&k), None);
        assert_eq!(
            s.install_at(&signed(&k, 2, NOW), NOW, false),
            Err(PolicyError::Expired {
                expires_at: NOW,
                now: NOW
            })
        );
        s.install_at(&signed(&k, 3, NOW + 10), NOW, false).unwrap();
        assert_eq!(
            s.current_at(NOW + 9).rules.decide(&dom("openai.com")),
            &Action::Proxy("ai".into())
        );
        // Past expiry: refuse, AI included.
        let p = s.current_at(NOW + 10);
        assert_eq!(p.rules.decide(&dom("openai.com")), &Action::Reject);
        assert_eq!(p.rules.decide(&dom("example.com")), &Action::Reject);
        assert!(!s.status_at(NOW + 10).valid);
        // Rollback floor stays even though nothing is in force.
        assert!(matches!(
            s.install_at(&signed(&k, 3, NOW + 100), NOW + 10, false),
            Err(PolicyError::NotNewer { .. })
        ));
    }

    #[test]
    fn incompatible_bundles_rejected() {
        let k = keys();
        let s = PolicyStore::signed(verifier(&k), None);
        let cases = [
            (
                r#"{"version":1,"expires_at":1900000000,"default":{"type":"proxy","outbound":"nope"}}"#,
                "unknown route",
            ),
            (
                r#"{"version":1,"expires_at":1900000000,"default":{"type":"proxy","outbound":"ai"}}"#,
                "home route",
            ),
            (
                r#"{"version":1,"expires_at":1900000000,"default":{"type":"reject"},"chnroute":["x"]}"#,
                "chnroute[0]",
            ),
            (
                r#"{"version":1,"expires_at":1900000000,"default":{"type":"reject"},"extra":1}"#,
                "unknown field",
            ),
        ];
        for (b, want) in cases {
            let e = sign(&k.key, 1, b.as_bytes())
                .map(|env| s.install_at(env.as_bytes(), NOW, false))
                .map_err(PolicyError::Malformed);
            let msg = match e {
                Ok(Err(e)) | Err(e) => e.to_string(),
                Ok(Ok(_)) => panic!("{b} installed"),
            };
            assert!(msg.contains(want), "{b}: {msg}");
        }
        assert!(!s.status_at(NOW).valid);
    }

    #[test]
    fn ai_route_must_be_home() {
        let k = keys();
        let known: BTreeSet<String> = ["ai", "overseas"].map(String::from).into();
        let e = Verifier::new(
            [(1, k.pubkey.clone())].into(),
            "overseas".into(),
            known,
            ["ai".to_string()].into(),
        )
        .err()
        .unwrap();
        assert!(e.contains("home-role"), "{e}");
    }

    #[test]
    fn startup_restores_last_good_and_persists_new() {
        let k = keys();
        let dir = std::env::temp_dir().join(format!("segue-policy-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let installed = dir.join("installed.bundle");
        let cand = dir.join("candidate.bundle");
        let _ = std::fs::remove_file(&installed);
        std::fs::write(&cand, signed(&k, 4, NOW + 100)).unwrap();

        let s = PolicyStore::signed(verifier(&k), Some(installed.clone()));
        let log = s.load_startup_at(Some(&cand), NOW);
        assert_eq!(s.status_at(NOW).version, Some(4), "{log:?}");
        assert!(installed.exists(), "persisted");

        // Next start: an older candidate is rejected, the persisted v4 kept.
        std::fs::write(&cand, signed(&k, 2, NOW + 100)).unwrap();
        let s = PolicyStore::signed(verifier(&k), Some(installed.clone()));
        let log = s.load_startup_at(Some(&cand), NOW);
        assert_eq!(s.status_at(NOW).version, Some(4));
        assert!(log.iter().any(|l| l.contains("not newer")), "{log:?}");

        // A forged installed file does not count; nothing valid → refuse.
        std::fs::write(&installed, b"{}").unwrap();
        std::fs::remove_file(&cand).unwrap();
        let s = PolicyStore::signed(verifier(&k), Some(installed.clone()));
        let log = s.load_startup_at(Some(&cand), NOW);
        assert!(!s.status_at(NOW).valid);
        assert!(log.iter().any(|l| l.contains("refusing all")), "{log:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn private_key_file_is_0600_and_checked() {
        let dir = std::env::temp_dir().join(format!("segue-policy-key-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("k");
        let _ = std::fs::remove_file(&p);
        let (key, _) = generate_key();
        write_private_key(&p, &key).unwrap();
        assert!(write_private_key(&p, &key).is_err(), "never overwrites");
        assert_eq!(read_private_key(&p).unwrap(), key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(read_private_key(&p).unwrap_err().contains("chmod 600"));
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
