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
//!
//! The rollback floor and the accepted bundles are persisted (review r5
//! N2), so a restart never accepts a bundle older than one it had taken.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

pub use segue_policy::AiSet;

/// Canonical target name, `None` if not a DNS name (the same check the
/// bundle's AI domains pass, `segue_policy::canonical_domain`).
pub fn normalize_domain(name: &str) -> Option<String> {
    segue_policy::canonical_domain(name)
}

#[derive(Debug)]
struct Loaded {
    version: u64,
    expires_at: u64,
    set: AiSet,
    /// The signed envelope, kept so it can be persisted and re-verified.
    bytes: Vec<u8>,
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

/// On-disk form of [`State`] (review r5 N2): the rollback floor and the
/// accepted envelopes survive a restart. The envelopes are re-verified on
/// load; the file itself is not trusted for anything but the floor.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Persisted {
    high_water: u64,
    #[serde(default)]
    current: Option<String>,
    #[serde(default)]
    previous: Option<String>,
}

/// Signed AI whitelist, reloaded from the bundle file.
pub struct AiPolicy {
    keys: BTreeMap<u32, Vec<u8>>,
    path: Option<PathBuf>,
    state_path: Option<PathBuf>,
    state: RwLock<State>,
    file: Mutex<Option<(SystemTime, u64)>>,
}

impl AiPolicy {
    pub fn new(keys: BTreeMap<u32, Vec<u8>>, path: Option<PathBuf>) -> Self {
        Self::with_state(keys, path, None)
    }

    /// Like [`new`](Self::new), persisting accepted bundles to `state_path`.
    /// Call [`restore`](Self::restore) before the first reload.
    pub fn with_state(
        keys: BTreeMap<u32, Vec<u8>>,
        path: Option<PathBuf>,
        state_path: Option<PathBuf>,
    ) -> Self {
        Self {
            keys,
            path,
            state_path,
            state: RwLock::new(State::default()),
            file: Mutex::new(None),
        }
    }

    fn verify(&self, bytes: &[u8]) -> Result<Loaded, String> {
        let body = segue_policy::open(&self.keys, bytes).map_err(|e| e.to_string())?;
        let v = segue_policy::AiView::parse(&body).map_err(|e| e.to_string())?;
        let set = AiSet::from_view(&v)?;
        Ok(Loaded {
            version: v.version,
            expires_at: v.expires_at,
            set,
            bytes: bytes.to_vec(),
        })
    }

    /// Restore the accepted state written by an earlier run: the rollback
    /// floor and the bundles in force (re-verified). A missing file is a
    /// first start. An unreadable or invalid file fails closed: no bundle
    /// is accepted until an operator removes or repairs it, because the
    /// floor it held is unknown.
    pub fn restore(&self) -> Result<Option<u64>, String> {
        let Some(sp) = &self.state_path else {
            return Ok(None);
        };
        let text = match std::fs::read(sp) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(self.poison(format!("policy state {}: {e}", sp.display()))),
        };
        let p: Persisted = serde_json::from_slice(&text)
            .map_err(|e| self.poison(format!("policy state {}: {e}", sp.display())))?;
        let load = |b: &Option<String>| -> Result<Option<Arc<Loaded>>, String> {
            b.as_ref()
                .map(|b| self.verify(b.as_bytes()).map(Arc::new))
                .transpose()
        };
        let (current, previous) = match (load(&p.current), load(&p.previous)) {
            (Ok(c), Ok(pr)) => (c, pr),
            (Err(e), _) | (_, Err(e)) => {
                return Err(self.poison(format!("policy state {}: {e}", sp.display())))
            }
        };
        let mut st = self.state.write().unwrap();
        st.high_water = p.high_water.max(current.as_ref().map_or(0, |c| c.version));
        st.current = current;
        st.previous = previous;
        Ok(Some(st.high_water))
    }

    fn poison(&self, e: String) -> String {
        self.state.write().unwrap().high_water = u64::MAX;
        e
    }

    fn persist(&self, st: &State) -> Result<(), String> {
        let Some(sp) = &self.state_path else {
            return Ok(());
        };
        let env = |l: &Option<Arc<Loaded>>| {
            l.as_ref()
                .map(|l| String::from_utf8_lossy(&l.bytes).into_owned())
        };
        let p = Persisted {
            high_water: st.high_water,
            current: env(&st.current),
            previous: env(&st.previous),
        };
        write_atomic(sp, serde_json::to_string(&p).expect("state").as_bytes())
            .map_err(|e| format!("policy state {}: {e}", sp.display()))
    }

    /// Verify and install a bundle. `Ok(Some(v))`: version `v` is now
    /// current; `Ok(None)`: the same version as current (no change).
    pub fn install(&self, bytes: &[u8], now: u64) -> Result<Option<u64>, String> {
        let l = self.verify(bytes)?;
        let mut st = self.state.write().unwrap();
        if l.version <= st.high_water {
            if st.current.as_ref().is_some_and(|c| c.version == l.version) {
                return Ok(None);
            }
            return Err(format!(
                "policy version {} not above {} (no rollback)",
                l.version, st.high_water
            ));
        }
        if now >= l.expires_at {
            return Err(format!("policy version {} expired", l.version));
        }
        let v = l.version;
        st.high_water = v;
        st.previous = st.current.take();
        st.current = Some(Arc::new(l));
        if let Err(e) = self.persist(&st) {
            // In force in memory; a restart before the next good write
            // could fall back to the older floor, so say so loudly.
            crate::log!("error", "policy state not persisted", "error" = e);
        }
        Ok(Some(v))
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

/// Write via a temporary file and rename, so a crash leaves the old or the
/// new content, never a torn file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
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

    /// Review r5 N2: after accepting v2, the bundle file is replaced by a
    /// still-valid v1 and the relay restarts. The restarted relay keeps v2
    /// (its AI set too) and refuses v1.
    #[test]
    fn rollback_floor_survives_restart() {
        let (k, p) = segue_policy::generate_key();
        let keys: BTreeMap<u32, Vec<u8>> =
            [(1, segue_policy::parse_public_key(&p).unwrap())].into();
        let dir = std::env::temp_dir().join(format!("segue-relay-pol-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("policy.bundle");
        let state = dir.join("policy.bundle.accepted");
        let _ = std::fs::remove_file(&state);
        let start = || {
            let pol = AiPolicy::with_state(keys.clone(), Some(file.clone()), Some(state.clone()));
            pol.restore().unwrap();
            let _ = pol.reload(100);
            pol
        };
        std::fs::write(&file, bundle(&k, 1, 1000, &["a.com"])).unwrap();
        assert_eq!(start().version(), Some(1));
        std::fs::write(&file, bundle(&k, 2, 2000, &["b.com"])).unwrap();
        let pol = start();
        assert_eq!(pol.version(), Some(2));
        drop(pol);
        // Rolled back while down.
        std::fs::write(&file, bundle(&k, 1, 3000, &["a.com"])).unwrap();
        let pol = start();
        assert_eq!(pol.version(), Some(2), "restart accepted a rollback");
        let c = pol.check(100).unwrap();
        assert!(c.is_ai_domain("x.b.com"), "v2 AI set lost on restart");
        assert!(c.is_ai_domain("x.a.com"), "previous kept too");
        // A corrupt state file fails closed rather than forgetting the floor.
        std::fs::write(&state, "{not json").unwrap();
        let pol = AiPolicy::with_state(keys.clone(), Some(file.clone()), Some(state.clone()));
        assert!(pol.restore().is_err());
        std::fs::write(&file, bundle(&k, 3, 3000, &["c.com"])).unwrap();
        assert!(pol.reload(100).is_err());
        assert!(pol.check(100).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review r5 N3: an AI entry the kernel would read differently (leading
    /// dot, whitespace) refuses the bundle, as the kernel does.
    #[test]
    fn non_canonical_ai_domain_refuses_bundle() {
        let (k, p) = segue_policy::generate_key();
        let keys = [(1, segue_policy::parse_public_key(&p).unwrap())].into();
        let pol = AiPolicy::new(keys, None);
        for bad in [".openai.com", " openai.com"] {
            assert!(
                pol.install(&bundle(&k, 1, 1000, &[bad]), 100).is_err(),
                "{bad:?}"
            );
        }
        assert!(pol.check(100).is_none());
    }
}
