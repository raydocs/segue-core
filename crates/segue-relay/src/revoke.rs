//! Local revocation list (stand-in for the control plane feed,
//! CONTROL_PLANE_SPEC §4). One device id per line, `#` comments. The file is
//! polled; when its content changes, newly listed devices are returned so
//! their sessions can be reset. A missing or unreadable file keeps the last
//! good list and makes the list stale (no RESUME grace, §6).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};

/// List older than this is stale (SESSION_PROTOCOL §6: 5 min).
pub const FRESH_FOR: Duration = Duration::from_secs(300);
const MAX_FILE: u64 = 16 << 20;

pub struct Revocations {
    path: Option<PathBuf>,
    set: RwLock<HashSet<u64>>,
    state: Mutex<FileState>,
}

#[derive(Default)]
struct FileState {
    last_ok: Option<Instant>,
    mtime: Option<SystemTime>,
    len: u64,
}

pub fn parse(text: &str) -> Result<HashSet<u64>, String> {
    let mut s = HashSet::new();
    for (i, line) in text.lines().enumerate() {
        let l = line.split('#').next().unwrap_or("").trim();
        if l.is_empty() {
            continue;
        }
        let d = l
            .parse::<u64>()
            .map_err(|_| format!("revocation line {}: not a device id", i + 1))?;
        s.insert(d);
    }
    Ok(s)
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

    /// The list was read successfully within [`FRESH_FOR`]. Without a file
    /// the list is never fresh.
    pub fn is_fresh(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .last_ok
            .is_some_and(|t| t.elapsed() <= FRESH_FOR)
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
        let mtime = meta.modified().ok();
        {
            let mut st = self.state.lock().unwrap();
            if st.last_ok.is_some() && st.mtime == mtime && st.len == meta.len() && mtime.is_some()
            {
                st.last_ok = Some(Instant::now());
                return Ok(Vec::new());
            }
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("revocation file: {e}"))?;
        let new = parse(&text)?;
        let added: Vec<u64> = {
            let mut cur = self.set.write().unwrap();
            let added = new.difference(&cur).copied().collect();
            *cur = new;
            added
        };
        let mut st = self.state.lock().unwrap();
        st.last_ok = Some(Instant::now());
        st.mtime = mtime;
        st.len = meta.len();
        Ok(added)
    }

    /// Replace the list directly (tests, future control-plane feed).
    pub fn set_all(&self, devices: HashSet<u64>) -> Vec<u64> {
        let mut cur = self.set.write().unwrap();
        let added = devices.difference(&cur).copied().collect();
        *cur = devices;
        self.state.lock().unwrap().last_ok = Some(Instant::now());
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_reload() {
        assert_eq!(parse("1\n# x\n 2 # y\n\n").unwrap(), HashSet::from([1, 2]));
        assert!(parse("abc").is_err());
        let dir = std::env::temp_dir().join(format!("segue-relay-rev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("revoked.txt");
        std::fs::write(&p, "5\n").unwrap();
        let r = Revocations::new(Some(p.clone()));
        assert!(!r.is_fresh());
        assert_eq!(r.reload().unwrap(), vec![5]);
        assert!(r.is_fresh() && r.contains(5));
        assert_eq!(r.reload().unwrap(), Vec::<u64>::new());
        std::fs::write(&p, "5\n6\n7\n").unwrap();
        let mut a = r.reload().unwrap();
        a.sort();
        assert_eq!(a, vec![6, 7]);
        std::fs::write(&p, "bad\n").unwrap();
        assert!(r.reload().is_err());
        assert!(r.contains(7), "last good list kept");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
