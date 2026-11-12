//! Home (AI) target whitelist (KERNEL_SPEC §5.5 items 3, 7;
//! CONTROL_PLANE_SPEC §6.2). It is read from the same signed policy bundle
//! the client installs (envelope and signature check shared through
//! `segue-policy`), so both ends judge with the same version of the AI set.
//!
//! The relay keeps the newest bundle and the one before it: a target is AI
//! when either set lists it, so a client one version behind is neither
//! wrongly refused nor able to send an AI target out of the data centre.
//! Versions only go up. With no unexpired bundle the relay cannot classify
//! and refuses every target.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use crate::cidr::{any_contains, Cidr};

#[derive(Clone, Debug, Default)]
pub struct AiSet {
    suffixes: Vec<String>,
    cidrs: Vec<Cidr>,
}

/// Lowercase, no trailing dot; `None` if not a plausible DNS name.
pub fn normalize_domain(name: &str) -> Option<String> {
    let n = segue_policy::normalize_domain(name);
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
            // Same normalization and acceptance as the kernel's compile.
            let n = segue_policy::normalize_domain(d.trim().trim_start_matches('.'));
            if n.is_empty() || n.contains('/') {
                return Err(format!("bad AI domain {d:?}"));
            }
            suffixes.push(n);
        }
        let cidrs = cidrs
            .iter()
            .map(|c| Cidr::parse(c))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { suffixes, cidrs })
    }

    /// `name` must already be normalized.
    pub fn is_ai_domain(&self, name: &str) -> bool {
        self.suffixes
            .iter()
            .any(|s| segue_policy::suffix_match(name, s))
    }

    pub fn is_ai_ip(&self, ip: IpAddr) -> bool {
        any_contains(&self.cidrs, ip)
    }
}

#[derive(Debug)]
struct Loaded {
    version: u64,
    expires_at: u64,
    set: AiSet,
}

/// The AI sets in force at one instant (current and, if still valid, the
/// previous version).
#[derive(Clone, Debug)]
pub struct AiCheck {
    sets: Vec<Arc<Loaded>>,
}

impl AiCheck {
    pub fn version(&self) -> u64 {
        self.sets[0].version
    }
    pub fn is_ai_domain(&self, name: &str) -> bool {
        self.sets.iter().any(|l| l.set.is_ai_domain(name))
    }
    pub fn is_ai_ip(&self, ip: IpAddr) -> bool {
        self.sets.iter().any(|l| l.set.is_ai_ip(ip))
    }
}

#[derive(Default)]
struct State {
    current: Option<Arc<Loaded>>,
    previous: Option<Arc<Loaded>>,
    high_water: u64,
}

/// Signed AI whitelist, reloaded from the bundle file.
pub struct AiPolicy {
    keys: BTreeMap<u32, Vec<u8>>,
    path: Option<PathBuf>,
    state: RwLock<State>,
    file: Mutex<Option<(SystemTime, u64)>>,
}

impl AiPolicy {
    pub fn new(keys: BTreeMap<u32, Vec<u8>>, path: Option<PathBuf>) -> Self {
        Self {
            keys,
            path,
            state: RwLock::new(State::default()),
            file: Mutex::new(None),
        }
    }

    /// Verify and install a bundle. `Ok(Some(v))`: version `v` is now
    /// current; `Ok(None)`: the same version as current (no change).
    pub fn install(&self, bytes: &[u8], now: u64) -> Result<Option<u64>, String> {
        let body = segue_policy::open(&self.keys, bytes).map_err(|e| e.to_string())?;
        let v = segue_policy::AiView::parse(&body).map_err(|e| e.to_string())?;
        let set = AiSet::new(&v.ai_domains, &v.ai_cidrs)?;
        let mut st = self.state.write().unwrap();
        if v.version <= st.high_water {
            if st.current.as_ref().is_some_and(|c| c.version == v.version) {
                return Ok(None);
            }
            return Err(format!(
                "policy version {} not above {} (no rollback)",
                v.version, st.high_water
            ));
        }
        if now >= v.expires_at {
            return Err(format!("policy version {} expired", v.version));
        }
        st.high_water = v.version;
        st.previous = st.current.take();
        st.current = Some(Arc::new(Loaded {
            version: v.version,
            expires_at: v.expires_at,
            set,
        }));
        Ok(Some(v.version))
    }

    /// Re-read the bundle file if it changed.
    pub fn reload(&self, now: u64) -> Result<Option<u64>, String> {
        let Some(path) = &self.path else {
            return Ok(None);
        };
        let meta = std::fs::metadata(path).map_err(|e| format!("policy bundle: {e}"))?;
        let stamp = (
            meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
            meta.len(),
        );
        if *self.file.lock().unwrap() == Some(stamp) {
            return Ok(None);
        }
        if meta.len() > segue_policy::MAX_BUNDLE_BYTES as u64 {
            return Err("policy bundle: too large".into());
        }
        let bytes = std::fs::read(path).map_err(|e| format!("policy bundle: {e}"))?;
        let r = self.install(&bytes, now);
        *self.file.lock().unwrap() = Some(stamp);
        r
    }

    /// The AI sets valid at `now`; `None` when no unexpired bundle exists
    /// (fail closed: nothing can be classified).
    pub fn check(&self, now: u64) -> Option<AiCheck> {
        let st = self.state.read().unwrap();
        let cur = st.current.as_ref().filter(|c| now < c.expires_at)?.clone();
        let mut sets = vec![cur];
        if let Some(p) = st.previous.as_ref().filter(|p| now < p.expires_at) {
            sets.push(p.clone());
        }
        Some(AiCheck { sets })
    }

    pub fn version(&self) -> Option<u64> {
        self.state
            .read()
            .unwrap()
            .current
            .as_ref()
            .map(|c| c.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle(k: &str, version: u64, expires: u64, domains: &[&str]) -> Vec<u8> {
        let body = serde_json::json!({
            "version": version, "expires_at": expires, "ai_domains": domains,
            "ai_cidrs": ["203.0.113.0/24"], "default": {"type": "proxy", "outbound": "overseas"}
        });
        segue_policy::sign(k, 1, body.to_string().as_bytes())
            .unwrap()
            .into_bytes()
    }

    #[test]
    fn versions_previous_expiry_rollback() {
        let (k, p) = segue_policy::generate_key();
        let keys = [(1, segue_policy::parse_public_key(&p).unwrap())].into();
        let pol = AiPolicy::new(keys, None);
        assert!(pol.check(100).is_none(), "fail closed before any bundle");
        assert_eq!(
            pol.install(&bundle(&k, 1, 1000, &["a.com"]), 100),
            Ok(Some(1))
        );
        assert_eq!(pol.install(&bundle(&k, 1, 1000, &["a.com"]), 100), Ok(None));
        assert_eq!(
            pol.install(&bundle(&k, 2, 2000, &["b.com"]), 100),
            Ok(Some(2))
        );
        let c = pol.check(100).unwrap();
        assert_eq!(c.version(), 2);
        assert!(c.is_ai_domain("x.a.com") && c.is_ai_domain("b.com"));
        assert!(c.is_ai_ip("203.0.113.9".parse().unwrap()));
        assert!(pol.install(&bundle(&k, 1, 3000, &["a.com"]), 100).is_err());
        // Previous dropped once expired; current expiry fails closed.
        assert!(!pol.check(1500).unwrap().is_ai_domain("a.com"));
        assert!(pol.check(2000).is_none());
        // Forged bundle.
        let (other, _) = segue_policy::generate_key();
        assert!(pol
            .install(&bundle(&other, 9, 9000, &["c.com"]), 100)
            .is_err());
        assert_eq!(pol.version(), Some(2));
    }
}
