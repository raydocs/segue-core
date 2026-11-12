//! Process counters. Exposed as text on the optional loopback metrics port
//! and logged at shutdown. No labels carrying secrets or targets.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

macro_rules! counters {
    ($($name:ident),* $(,)?) => {
        #[derive(Default)]
        pub struct Metrics {
            $(pub $name: AtomicU64,)*
            /// Per-device reclassification counts (R2-1), bounded.
            reclass: Mutex<BTreeMap<u64, u64>>,
            /// Home bytes per line id (§5.6 item 7).
            home_bytes: Mutex<BTreeMap<String, u64>>,
        }

        impl Metrics {
            pub fn render(&self) -> String {
                let mut s = String::new();
                $(let _ = writeln!(s, "segue_relay_{} {}", stringify!($name), self.$name.load(Ordering::Relaxed));)*
                for (line, b) in self.home_bytes.lock().unwrap().iter() {
                    let _ = writeln!(s, "segue_relay_home_line_bytes{{line=\"{line}\"}} {b}");
                }
                s
            }
        }
    };
}

counters!(
    carriers_accepted,
    carriers_rejected_limit,
    carriers_first_frame_timeout,
    tickets_ok,
    tickets_bad,
    tickets_expired,
    tickets_revoked,
    tickets_wrong_device,
    exit_denied,
    target_denied,
    ssrf_blocked,
    session_limit,
    reclassified,
    dns_failures,
    connects_overseas,
    connects_home,
    connect_failures,
    home_unavailable,
    home_line_failures,
    home_alerts,
    revocation_reloads,
    devices_reset,
    sessions_closed,
);

const MAX_RECLASS_DEVICES: usize = 4096;

impl Metrics {
    pub fn inc(c: &AtomicU64) {
        c.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }

    /// Returns the device's new count.
    pub fn reclass(&self, device: u64) -> u64 {
        Self::inc(&self.reclassified);
        let mut m = self.reclass.lock().unwrap();
        if m.len() >= MAX_RECLASS_DEVICES && !m.contains_key(&device) {
            return 0;
        }
        let n = m.entry(device).or_default();
        *n += 1;
        *n
    }

    pub fn add_home_bytes(&self, line: &str, n: u64) {
        let mut m = self.home_bytes.lock().unwrap();
        match m.get_mut(line) {
            Some(b) => *b += n,
            None => {
                m.insert(line.to_string(), n);
            }
        }
    }
}
