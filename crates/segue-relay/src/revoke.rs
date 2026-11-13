//! Local revocation list (stand-in for the control plane feed,
//! CONTROL_PLANE_SPEC §4). A complete snapshot written by the sync process:
//! two header lines, one device id per line, `#` comments, and an `end`
//! trailer with the number of device lines:
//!
//! ```text
//! seq 1234             # control-plane revocation seq this list is at
//! synced_at 1767225600 # unix time of the last successful sync
//! 42
//! end 1
//! ```
//!
//! Only complete snapshots are taken (review r5 N4): `seq`, `synced_at` and
//! a matching `end` are required, so an empty, truncated or half-written
//! file is refused and the last good list stays. `seq` never goes back, and
//! one `seq` names one device set: the same `seq` with other devices is
//! refused. The time floor (`synced_at`) is kept on its own and never moves
//! back. Freshness (RESUME grace, SESSION_PROTOCOL §6) comes only from that
//! `synced_at`: a sync process that stops leaves an old one, and the list
//! goes stale 5 min later however often the relay re-reads it.
//!
//! The accepted snapshot is persisted next to the file (atomic rename) and
//! restored first on start, so a restart never replays an older list.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Mutex, RwLock};
use std::time::SystemTime;

/// List older than this is stale (SESSION_PROTOCOL §6: 5 min).
pub const FRESH_FOR_SECS: u64 = 300;
const MAX_FILE: u64 = 16 << 20;

/// A snapshot that was not committed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeError {
    pub message: String,
    /// Devices newly enforced although the snapshot was not committed (its
    /// state could not be written, review r6 R2): their live sessions
    /// must still be reset.
    pub newly_revoked: Vec<u64>,
    /// Only the durable write failed; the same file is retried.
    persist: bool,
}

impl RevokeError {
    fn list(message: String) -> Self {
        Self {
            message,
            newly_revoked: Vec::new(),
            persist: false,
        }
    }
}

impl std::fmt::Display for RevokeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<RevokeError> for String {
    fn from(e: RevokeError) -> String {
        e.message
    }
}

pub struct Revocations {
    path: Option<PathBuf>,
    state_path: Option<PathBuf>,
    set: RwLock<HashSet<u64>>,
    state: Mutex<FileState>,
}

#[derive(Default)]
struct FileState {
    /// Seq and sync time of the accepted snapshot (`None` before one).
    seq: Option<u64>,
    synced_at: Option<u64>,
    stamp: Option<(SystemTime, u64)>,
    /// Devices enforced in memory from a snapshot that could not be
    /// written durably (review r6 R2). Not part of the committed floor.
    unsaved: HashSet<u64>,
    /// The state of an earlier run could not be read (review r6 R3): its
    /// floor is unknown, so no snapshot is accepted.
    poisoned: bool,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct List {
    pub devices: HashSet<u64>,
    pub seq: u64,
    pub synced_at: u64,
}

impl List {
    /// The file form ([`parse`] reads it back).
    pub fn to_text(&self) -> String {
        let mut d: Vec<u64> = self.devices.iter().copied().collect();
        d.sort_unstable();
        let mut s = format!("seq {}\nsynced_at {}\n", self.seq, self.synced_at);
        for x in &d {
            s += &format!("{x}\n");
        }
        s += &format!("end {}\n", d.len());
        s
    }
}

pub fn parse(text: &str) -> Result<List, String> {
    let (mut seq, mut synced_at, mut end) = (None, None, None);
    let mut devices = HashSet::new();
    let mut lines = 0u64;
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
        if end.is_some() {
            return Err(format!("revocation line {}: content after end", i + 1));
        }
        let once = |slot: &mut Option<u64>, v: &str, what: &str| {
            if slot.replace(num(v)?).is_some() {
                return Err(format!("revocation line {}: duplicate {what}", i + 1));
            }
            Ok(())
        };
        if let Some(v) = l.strip_prefix("synced_at ") {
            once(&mut synced_at, v, "synced_at")?;
        } else if let Some(v) = l.strip_prefix("seq ") {
            once(&mut seq, v, "seq")?;
        } else if let Some(v) = l.strip_prefix("end ") {
            end = Some(num(v)?);
        } else {
            let d = l
                .parse::<u64>()
                .map_err(|_| format!("revocation line {}: not a device id", i + 1))?;
            devices.insert(d);
            lines += 1;
        }
    }
    let seq = seq.ok_or("revocation list: no seq (incomplete snapshot)")?;
    let synced_at = synced_at.ok_or("revocation list: no synced_at (incomplete snapshot)")?;
    match end {
        Some(n) if n == lines => {}
        Some(n) => return Err(format!("revocation list: end {n} but {lines} device lines")),
        None => return Err("revocation list: no end line (truncated)".into()),
    }
    Ok(List {
        devices,
        seq,
        synced_at,
    })
}

impl Revocations {
    pub fn new(path: Option<PathBuf>) -> Self {
        Self::with_state(path, None)
    }

    /// Like [`new`](Self::new), persisting each accepted snapshot to
    /// `state_path`; call [`restore`](Self::restore) before the first
    /// reload.
    pub fn with_state(path: Option<PathBuf>, state_path: Option<PathBuf>) -> Self {
        Self {
            path,
            state_path,
            set: RwLock::new(HashSet::new()),
            state: Mutex::new(FileState::default()),
        }
    }

    /// Install the snapshot an earlier run accepted. A missing state file
    /// is a first start. A state file that exists but cannot be read or
    /// parsed fails closed (review r6 R3): the floor it held is unknown,
    /// so every later snapshot is refused until an operator repairs it.
    pub fn restore(&self) -> Result<(), String> {
        let Some(sp) = &self.state_path else {
            return Ok(());
        };
        let r = match std::fs::read_to_string(sp) {
            Ok(t) => parse(&t).and_then(|l| self.apply(l, false).map(|_| ()).map_err(String::from)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => Err(e.to_string()),
        };
        r.map_err(|e| {
            self.state.lock().unwrap().poisoned = true;
            format!("revocation state {}: {e}", sp.display())
        })
    }

    /// Devices are enforced from a snapshot whose state is not yet durable
    /// (the restart floor is behind what is in force); retried each reload.
    pub fn storage_fault(&self) -> bool {
        !self.state.lock().unwrap().unsaved.is_empty()
    }

    /// Seq of the accepted snapshot.
    pub fn seq(&self) -> Option<u64> {
        self.state.lock().unwrap().seq
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
    pub fn reload(&self) -> Result<Vec<u64>, RevokeError> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        let meta = std::fs::metadata(path)
            .map_err(|e| RevokeError::list(format!("revocation file: {e}")))?;
        if meta.len() > MAX_FILE {
            return Err(RevokeError::list("revocation file too large".into()));
        }
        let stamp = meta.modified().ok().map(|m| (m, meta.len()));
        if stamp.is_some() && self.state.lock().unwrap().stamp == stamp {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(path)
            .map_err(|e| RevokeError::list(format!("revocation file: {e}")))?;
        // A refused file is not re-parsed until it changes again; one that
        // could not be persisted is retried on the next poll.
        let r = parse(&text)
            .map_err(RevokeError::list)
            .and_then(|l| self.apply(l, true));
        if !matches!(&r, Err(e) if e.persist) {
            self.state.lock().unwrap().stamp = stamp;
        }
        r
    }

    /// Install a complete snapshot (file reload, tests, future
    /// control-plane feed). Refused if its `seq` is below the current one,
    /// it moves `synced_at` back, or it changes the devices without a new
    /// `seq`. On refusal nothing changes, except as below.
    ///
    /// The snapshot is committed (seq, `synced_at` and the device set move
    /// forward) only once it is durably written (review r6 R2). If it
    /// cannot be written, its newly revoked devices are still enforced in
    /// memory (revocation only gets stricter), but nothing is lifted, the
    /// floor and freshness stay where they were, [`storage_fault`] is set
    /// and an error is returned; the next reload tries again.
    ///
    /// [`storage_fault`]: Self::storage_fault
    pub fn install(&self, new: List) -> Result<Vec<u64>, RevokeError> {
        self.apply(new, true)
    }

    fn apply(&self, new: List, persist: bool) -> Result<Vec<u64>, RevokeError> {
        let mut st = self.state.lock().unwrap();
        let mut cur = self.set.write().unwrap();
        if st.poisoned {
            return Err(RevokeError::list(
                "revocation state unreadable; refusing snapshots until repaired".into(),
            ));
        }
        if let Some(have) = st.seq {
            if new.seq < have {
                return Err(RevokeError::list(format!(
                    "revocation seq {} below {have}",
                    new.seq
                )));
            }
            // Compare with the committed set (what is in force minus what
            // a failed write added on top).
            let same = new.devices.len() + st.unsaved.len() == cur.len()
                && new
                    .devices
                    .iter()
                    .all(|d| cur.contains(d) && !st.unsaved.contains(d));
            if new.seq == have && !same {
                return Err(RevokeError::list(format!(
                    "revocation seq {have} restated with a different device set"
                )));
            }
        }
        if let Some(have) = st.synced_at {
            if new.synced_at < have {
                return Err(RevokeError::list(format!(
                    "revocation synced_at {} before {have}",
                    new.synced_at
                )));
            }
        }
        let added: Vec<u64> = new.devices.difference(&cur).copied().collect();
        if persist {
            if let Some(sp) = &self.state_path {
                if let Err(e) = crate::write_atomic(sp, new.to_text().as_bytes()) {
                    let e = format!("revocation state {} not persisted: {e}", sp.display());
                    crate::log!(
                        "error",
                        "revocation state not persisted; enforcing new revocations, floor unchanged",
                        "seq" = new.seq,
                        "error" = e.clone()
                    );
                    for &d in &added {
                        cur.insert(d);
                        st.unsaved.insert(d);
                    }
                    return Err(RevokeError {
                        message: e,
                        newly_revoked: added,
                        persist: true,
                    });
                }
            }
        }
        st.seq = Some(new.seq);
        st.synced_at = Some(new.synced_at);
        st.unsaved.clear();
        *cur = new.devices;
        Ok(added)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("segue-relay-rev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_and_reload() {
        let l = parse("seq 3\nsynced_at 1000\n1\n# x\n 2 # y\n\nend 2\n").unwrap();
        assert_eq!(l.devices, HashSet::from([1, 2]));
        assert_eq!((l.seq, l.synced_at), (3, 1000));
        assert_eq!(parse(&l.to_text()).unwrap(), l);
        assert!(parse("abc").is_err());
        assert!(parse("synced_at x").is_err());
        let dir = tmp("reload");
        let p = dir.join("revoked.txt");
        std::fs::write(&p, "seq 1\nsynced_at 1000\n5\nend 1\n").unwrap();
        let r = Revocations::new(Some(p.clone()));
        assert!(!r.is_fresh_at(1000));
        assert_eq!(r.reload().unwrap(), vec![5]);
        assert!(r.is_fresh_at(1000) && r.contains(5));
        assert_eq!(r.reload().unwrap(), Vec::<u64>::new());
        std::fs::write(&p, "seq 2\nsynced_at 1001\n5\n6\n7\nend 3\n").unwrap();
        let mut a = r.reload().unwrap();
        a.sort();
        assert_eq!(a, vec![6, 7]);
        std::fs::write(&p, "bad\n").unwrap();
        assert!(r.reload().is_err());
        assert!(r.contains(7), "last good list kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review r5 N4: with `seq 10, {42}` accepted, nothing short of a
    /// complete, newer snapshot removes 42: not an empty file, a truncated
    /// one, one without seq or synced_at, nor the same seq with another
    /// set. The time floor stays. A restart restores 42 even if the file
    /// was replaced by an older list.
    #[test]
    fn incomplete_or_restated_snapshot_keeps_revocation() {
        let dir = tmp("n4");
        let p = dir.join("revoked.txt");
        let sp = dir.join("revoked.txt.accepted");
        let r = Revocations::with_state(Some(p.clone()), Some(sp.clone()));
        r.restore().unwrap();
        std::fs::write(&p, "seq 10\nsynced_at 5000\n42\n43\nend 2\n").unwrap();
        r.reload().unwrap();
        for (i, bad) in [
            "",
            "seq 10\nsynced_at 5000\n42\n",        // truncated: no end
            "seq 10\nsynced_at 5000\n4",           // torn mid-line
            "seq 10\nsynced_at 5000\n43\nend 2\n", // count mismatch
            "synced_at 6000\nend 0\n",             // no seq
            "seq 11\nend 0\n",                     // no synced_at
            "seq 10\nsynced_at 6000\n43\nend 1\n", // same seq, other set
            "seq 9\nsynced_at 6000\nend 0\n",      // older seq
            "seq 11\nsynced_at 4000\nend 0\n",     // synced_at back
        ]
        .iter()
        .enumerate()
        {
            std::fs::write(&p, format!("{bad}{}", "#".repeat(i + 1))).unwrap();
            assert!(r.reload().is_err(), "{bad:?} accepted");
            assert!(r.contains(42), "{bad:?} cleared 42");
            assert!(r.is_fresh_at(5000), "{bad:?} lost the time floor");
        }
        // Same seq, same set: a re-sync, advances synced_at.
        std::fs::write(&p, "seq 10\nsynced_at 5100\n43\n42\nend 2\n").unwrap();
        r.reload().unwrap();
        assert!(r.is_fresh_at(5350));
        // Restart with the file replaced by an older list.
        std::fs::write(&p, "seq 3\nsynced_at 100\nend 0\n").unwrap();
        let r2 = Revocations::with_state(Some(p.clone()), Some(sp.clone()));
        r2.restore().unwrap();
        assert!(r2.reload().is_err());
        assert!(r2.contains(42) && r2.seq() == Some(10));
        // A newer complete snapshot does lift it.
        std::fs::write(&p, "seq 11\nsynced_at 5200\n43\nend 1\n").unwrap();
        r2.reload().unwrap();
        assert!(!r2.contains(42) && r2.contains(43));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sync process stops; the file stays readable and is re-read
    /// every poll. Freshness still runs out 5 min after its `synced_at`.
    /// Review r6 R2: a snapshot whose state cannot be written durably is
    /// not committed. Its new revocations are enforced at once, nothing is
    /// lifted, seq / freshness stay, and a restart still holds the last
    /// durable floor. The same file is retried once storage is back.
    #[test]
    fn unpersisted_snapshot_is_not_committed() {
        let dir = tmp("r2");
        let p = dir.join("revoked.txt");
        let sdir = dir.join("state");
        std::fs::create_dir_all(&sdir).unwrap();
        let sp = sdir.join("revoked.accepted");
        let r = Revocations::with_state(Some(p.clone()), Some(sp.clone()));
        r.restore().unwrap();
        std::fs::write(&p, "seq 9\nsynced_at 1000\n7\nend 1\n").unwrap();
        r.reload().unwrap();
        std::fs::remove_dir_all(&sdir).unwrap();
        std::fs::write(&p, "seq 10\nsynced_at 2000\n42\nend 1\n").unwrap();
        let e = r.reload().unwrap_err();
        assert_eq!(e.newly_revoked, vec![42]);
        assert!(r.contains(42), "new revocation not enforced");
        assert!(r.contains(7), "revocation lifted without a durable commit");
        assert_eq!(r.seq(), Some(9), "floor moved without a durable commit");
        assert!(!r.is_fresh_at(2100), "freshness moved without a commit");
        assert!(r.storage_fault());
        // A restart now only knows seq 9 (what was durable).
        let r2 = Revocations::with_state(Some(p.clone()), None);
        r2.install(parse("seq 9\nsynced_at 1000\n7\nend 1\n").unwrap())
            .unwrap();
        // Storage back: the unchanged file is retried and commits.
        std::fs::create_dir_all(&sdir).unwrap();
        assert_eq!(r.reload().unwrap(), Vec::<u64>::new());
        assert_eq!(r.seq(), Some(10));
        assert!(r.contains(42) && !r.contains(7) && !r.storage_fault());
        let r3 = Revocations::with_state(Some(p.clone()), Some(sp.clone()));
        r3.restore().unwrap();
        assert_eq!(r3.seq(), Some(10));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Review r6 R3: an accepted-state file that exists but is corrupt
    /// fails closed; it never lets an older snapshot in.
    #[test]
    fn corrupt_state_refuses_snapshots() {
        let dir = tmp("r3");
        let p = dir.join("revoked.txt");
        let sp = dir.join("revoked.accepted");
        std::fs::write(&sp, "seq 10\nsynced_at 2000\n42\nen").unwrap();
        std::fs::write(&p, "seq 9\nsynced_at 1000\nend 0\n").unwrap();
        let r = Revocations::with_state(Some(p.clone()), Some(sp.clone()));
        assert!(r.restore().is_err());
        assert!(
            r.reload().is_err(),
            "old snapshot accepted over corrupt state"
        );
        assert_eq!(r.seq(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_stops_updating_but_stays_readable() {
        let dir = tmp("stale");
        let p = dir.join("revoked.txt");
        std::fs::write(&p, "seq 9\nsynced_at 10000\nend 0\n").unwrap();
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
        // Older seq / synced_at: refused.
        std::fs::write(&p, "seq 8\nsynced_at 30000\nend 0\n").unwrap();
        assert!(r.reload().is_err());
        // Future synced_at beyond the skew bound is not fresh.
        let f = Revocations::new(None);
        f.install(parse("seq 1\nsynced_at 50000\nend 0\n").unwrap())
            .unwrap();
        assert!(!f.is_fresh_at(40_000));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
