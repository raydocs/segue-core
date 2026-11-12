//! Local revocation list (stand-in for the control plane feed,
//! CONTROL_PLANE_SPEC §4). One device id per line, `#` comments, plus two
//! header lines written by the sync process:
//!
//! ```text
//! seq 1234            # control-plane revocation seq this list is at
//! synced_at 1767225600 # unix time of the last successful sync
//! 42
//! ```
//!
//! Freshness (RESUME grace, SESSION_PROTOCOL §6) comes only from
//! `synced_at` inside the file: a sync process that stops leaves an old
//! `synced_at`, and the list goes stale 5 min later however often the relay
//! re-reads it. A file without `synced_at` is never fresh. `seq` must not
//! go backwards. When the content changes, newly listed devices are
//! returned so their sessions can be reset. A missing, unreadable or
//! invalid file keeps the last good list.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;

/// List older than this is stale (SESSION_PROTOCOL §6: 5 min).
pub const FRESH_FOR_SECS: u64 = 300;
const MAX_FILE: u64 = 16 << 20;

pub struct Revocations {
    path: Option<PathBuf>,
    set: RwLock<HashSet<u64>>,
    state: Mutex<FileState>,
}

#[derive(Default)]
struct FileState {
    /// Last sync time and seq stated by the accepted file.
    synced_at: Option<u64>,
    seq: Option<u64>,
    stamp: Option<(SystemTime, u64)>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct List {
    pub devices: HashSet<u64>,
    pub seq: Option<u64>,
    pub synced_at: Option<u64>,
}

pub fn parse(text: &str) -> Result<List, String> {
    let mut out = List::default();
    for (i, line) in text.lines().enumerate() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let num = |v: &str| {
            v.trim()
                .parse::<u64>()
                .map_err(|_| format!("revocation line {}: bad number", i + 1))
        };
        if let Some(v) = l.strip_prefix("synced_at ") {
            out.synced_at = Some(num(v)?);
        } else if let Some(v) = l.strip_prefix("seq ") {
            out.seq = Some(num(v)?);
        } else {
            let d = l
                .parse::<u64>()
                .map_err(|_| format!("revocation line {}: not a device id", i + 1))?;
            out.devices.insert(d);
        }
    }
    Ok(out)
}

impl Revocations {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            set: RwLock::new(HashSet::new()),
            state: Mutex::new(FileState::default()),
        }
    }

    pub fn contains(&self, device: u64) -> bool {
        self.set.read().unwrap().contains(&device)
    }

    pub fn len(&self) -> usize {
        self.set.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The last sync the list states is within [`FRESH_FOR_SECS`] of `now`
    /// (unix seconds). Reading the same file again never refreshes it. A
    /// `synced_at` far in the future (clock skew, bad writer) is not fresh.
    pub fn is_fresh_at(&self, now: u64) -> bool {
        self.state.lock().unwrap().synced_at.is_some_and(|t| {
            now < t.saturating_add(FRESH_FOR_SECS) && t <= now.saturating_add(FRESH_FOR_SECS)
        })
    }

    /// Re-read the file if it changed. Returns devices newly revoked.
    pub fn reload(&self) -> Result<Vec<u64>, String> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        let meta = std::fs::metadata(path).map_err(|e| format!("revocation file: {e}"))?;
        if meta.len() > MAX_FILE {
            return Err("revocation file too large".into());
        }
        let stamp = meta.modified().ok().map(|m| (m, meta.len()));
        if stamp.is_some() && self.state.lock().unwrap().stamp == stamp {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("revocation file: {e}"))?;
        let new = parse(&text)?;
        let added = self.install(new)?;
        self.state.lock().unwrap().stamp = stamp;
        Ok(added)
    }

    /// Install a parsed list (file reload, tests, future control-plane
    /// feed). Refused if its `seq` is below the current one or it moves
    /// `synced_at` backwards.
    pub fn install(&self, new: List) -> Result<Vec<u64>, String> {
        let mut st = self.state.lock().unwrap();
        if let (Some(have), Some(got)) = (st.seq, new.seq) {
            if got < have {
                return Err(format!("revocation seq {got} below {have}"));
            }
        }
        if let (Some(have), Some(got)) = (st.synced_at, new.synced_at) {
            if got < have {
                return Err(format!("revocation synced_at {got} before {have}"));
            }
        }
        let added = {
            let mut cur = self.set.write().unwrap();
            let added = new.devices.difference(&cur).copied().collect();
            *cur = new.devices;
            added
        };
        st.seq = new.seq.or(st.seq);
        st.synced_at = new.synced_at;
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_reload() {
        let l = parse("seq 3\nsynced_at 1000\n1\n# x\n 2 # y\n\n").unwrap();
        assert_eq!(l.devices, HashSet::from([1, 2]));
        assert_eq!((l.seq, l.synced_at), (Some(3), Some(1000)));
        assert!(parse("abc").is_err());
        assert!(parse("synced_at x").is_err());
        let dir = std::env::temp_dir().join(format!("segue-relay-rev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("revoked.txt");
        std::fs::write(&p, "synced_at 1000\n5\n").unwrap();
        let r = Revocations::new(Some(p.clone()));
        assert!(!r.is_fresh_at(1000));
        assert_eq!(r.reload().unwrap(), vec![5]);
        assert!(r.is_fresh_at(1000) && r.contains(5));
        assert_eq!(r.reload().unwrap(), Vec::<u64>::new());
        std::fs::write(&p, "synced_at 1001\n5\n6\n7\n").unwrap();
        let mut a = r.reload().unwrap();
        a.sort();
        assert_eq!(a, vec![6, 7]);
        std::fs::write(&p, "bad\n").unwrap();
        assert!(r.reload().is_err());
        assert!(r.contains(7), "last good list kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sync process stops; the file stays readable and is re-read
    /// every poll. Freshness still runs out 5 min after its `synced_at`.
    #[test]
    fn file_stops_updating_but_stays_readable() {
        let dir =
            std::env::temp_dir().join(format!("segue-relay-rev-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("revoked.txt");
        std::fs::write(&p, "seq 9\nsynced_at 10000\n").unwrap();
        let r = Revocations::new(Some(p.clone()));
        r.reload().unwrap();
        for t in [10_000, 10_100, 10_299] {
            r.reload().unwrap();
            assert!(r.is_fresh_at(t), "fresh at {t}");
        }
        for t in [10_300, 10_301, 20_000] {
            // Re-reading (even forcing a full re-read) does not refresh it.
            r.state.lock().unwrap().stamp = None;
            r.reload().unwrap();
            assert!(!r.is_fresh_at(t), "stale at {t}");
        }
        // No synced_at: never fresh. Older seq / synced_at: refused.
        std::fs::write(&p, "seq 9\n").unwrap();
        r.reload().unwrap();
        assert!(!r.is_fresh_at(10_000));
        std::fs::write(&p, "seq 8\nsynced_at 30000\n").unwrap();
        assert!(r.reload().is_err());
        // Future synced_at beyond the skew bound is not fresh.
        let f = Revocations::new(None);
        f.install(parse("synced_at 50000\n").unwrap()).unwrap();
        assert!(!f.is_fresh_at(40_000));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
