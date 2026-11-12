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
//! `ai_domains` become domain-suffix rules to the kernel's AI route (which
//! must be a `home` role route), ahead of `rules`. `chnroute` is the
//! domestic IP set the smart DNS uses to tell polluted answers apart.
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

use base64::Engine as _;
use ring::signature::{self, KeyPair as _};
use serde::{Deserialize, Serialize};

use crate::rules::{Action, Cidr, CidrTable, Matcher, Rule, RuleSet, RuleSpec};

/// Domain separation for policy signatures.
pub const SIG_CONTEXT: &[u8] = b"segue-policy-v1\0";
/// Largest envelope accepted (the AI / chnroute lists are a few thousand
/// entries; this leaves room without letting a bad file eat memory).
pub const MAX_BUNDLE_BYTES: usize = 8 << 20;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub key_id: u32,
    /// Base64 of the body JSON.
    pub body: String,
    /// Base64 Ed25519 signature over `SIG_CONTEXT || body bytes`.
    pub sig: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Body {
    pub version: u64,
    /// Unix seconds; the bundle is invalid at and after this time.
    pub expires_at: u64,
    #[serde(default)]
    pub ai_domains: Vec<String>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
    pub default: Action,
    #[serde(default)]
    pub chnroute: Vec<String>,
}

/// The routing data every flow and DNS query reads.
#[derive(Debug)]
pub struct Policy {
    pub rules: RuleSet,
    pub chnroute: CidrTable,
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
            version: 0,
            expires_at: None,
            refuse_all: true,
        }
    }

    /// Rules given in the kernel config (lab / tests only).
    pub fn inline(rules: RuleSet, chnroute: CidrTable) -> Self {
        Self {
            rules,
            chnroute,
            version: 0,
            expires_at: None,
            refuse_all: false,
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
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(PolicyError::Malformed(format!(
                "{} bytes > {MAX_BUNDLE_BYTES}",
                bytes.len()
            )));
        }
        let env: Envelope =
            serde_json::from_slice(bytes).map_err(|e| PolicyError::Malformed(e.to_string()))?;
        let key = self
            .keys
            .get(&env.key_id)
            .ok_or(PolicyError::UnknownKey(env.key_id))?;
        let body = b64()
            .decode(env.body.trim())
            .map_err(|_| PolicyError::Malformed("body: bad base64".into()))?;
        let sig = b64()
            .decode(env.sig.trim())
            .map_err(|_| PolicyError::Malformed("sig: bad base64".into()))?;
        let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + body.len());
        msg.extend_from_slice(SIG_CONTEXT);
        msg.extend_from_slice(&body);
        signature::UnparsedPublicKey::new(&signature::ED25519, key)
            .verify(&msg, &sig)
            .map_err(|_| PolicyError::BadSignature)?;
        // Only signed bytes are parsed past this point.
        let parsed: Body = serde_json::from_slice(&body)
            .map_err(|e| PolicyError::Malformed(format!("body: {e}")))?;
        let policy = self.compile(&parsed)?;
        Ok((parsed, policy))
    }

    fn compile(&self, b: &Body) -> Result<Policy, PolicyError> {
        let bad = PolicyError::Incompatible;
        let mut rules = Vec::with_capacity(b.ai_domains.len() + b.rules.len());
        for (i, d) in b.ai_domains.iter().enumerate() {
            let d = crate::rules::normalize(d);
            if d.is_empty() || d.contains('/') {
                return Err(bad(format!("ai_domains[{i}]: bad domain")));
            }
            rules.push(Rule {
                matcher: Matcher::DomainSuffix(d),
                action: Action::Proxy(self.ai_route.clone()),
            });
        }
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
        let set = RuleSet::new(rules, b.default.clone());
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

/// Parse a base64 Ed25519 public key.
pub fn parse_public_key(text: &str) -> Result<Vec<u8>, String> {
    let k = b64()
        .decode(text.trim())
        .map_err(|_| "public key: bad base64".to_string())?;
    if k.len() != 32 {
        return Err("public key: must be 32 bytes".into());
    }
    Ok(k)
}

/// A fresh Ed25519 key as base64 PKCS#8 (dev signing tool).
pub fn generate_key() -> (String, String) {
    let rng = ring::rand::SystemRandom::new();
    let der = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("ed25519 keygen");
    let pair = signature::Ed25519KeyPair::from_pkcs8(der.as_ref()).expect("fresh key");
    (
        b64().encode(der.as_ref()),
        b64().encode(pair.public_key().as_ref()),
    )
}

/// Sign `body` (the body JSON) into an envelope (dev signing tool; the
/// control plane does this in production).
pub fn sign(key_b64: &str, key_id: u32, body: &[u8]) -> Result<String, String> {
    let der = b64()
        .decode(key_b64.trim())
        .map_err(|_| "key: bad base64".to_string())?;
    let pair = signature::Ed25519KeyPair::from_pkcs8(&der).map_err(|_| "key: bad PKCS#8")?;
    let parsed: Body =
        serde_json::from_slice(body).map_err(|e| format!("body does not parse: {e}"))?;
    let _ = parsed;
    let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + body.len());
    msg.extend_from_slice(SIG_CONTEXT);
    msg.extend_from_slice(body);
    let sig = pair.sign(&msg);
    let env = Envelope {
        key_id,
        body: b64().encode(body),
        sig: b64().encode(sig.as_ref()),
    };
    Ok(serde_json::to_string(&env).expect("envelope"))
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
        let st = s.status_at(NOW);
        assert_eq!((st.valid, st.version, st.high_water), (true, Some(3), 3));
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
