//! segue-relay: the node side of a Segue session (KERNEL_SPEC v1.2 §5.5,
//! §5.6, §5.7, §6.4, §6.5; SESSION_PROTOCOL v0.4 relay side).
//!
//! The node's outer servers (Xray Reality, sing-box / Hysteria Hy2) forward
//! their Segue inbound to this process on loopback. Each forwarded stream is
//! one session carrier for [`segue_session::driver::run_relay_ctl`].
//!
//! Layout:
//! - [`config`]: the config file (JSON) and limits.
//! - [`ticket`]: Ed25519 device tickets, offline verification, the
//!   [`segue_session::relay::Authorizer`] implementation.
//! - [`revoke`]: the local revocation list, reloaded when the file changes.
//! - [`cidr`], [`guard`]: address sets and the SSRF guard.
//! - [`policy`]: the Home (AI) target whitelist used for independent
//!   classification (R2-1).
//! - [`socks5`]: SOCKS5 client (RFC 1928 / RFC 1929) for Decodo lines.
//! - [`home`]: Home line pool, assignment (D2) and alert-only failover.
//! - [`dial`]: the site connector: classification, exit checks, dialing.
//! - [`metrics`], [`log`]: counters and secret-free structured logs.
//! - [`server`]: wiring, loopback listener, graceful shutdown.
//!
//! Not here (control plane deferred): ticket-key / revocation / line
//! credential sync, REFRESH proxying, CTRL_HELLO / control stream, line
//! reports upstream, cross-node forwarding (M9+), UDP sessions.

pub mod cidr;
pub mod config;
pub mod dial;
pub mod guard;
pub mod home;
pub mod log;
pub mod metrics;
pub mod policy;
pub mod revoke;
pub mod server;
pub mod socks5;
pub mod ticket;

/// `exit_class` hint values a client puts in OPEN. The relay never routes by
/// the hint (R2-1); it only counts reclassifications.
pub mod hint {
    pub const OVERSEAS: u8 = 0;
    pub const AI: u8 = 1;
}

/// Unix time in seconds; injectable for tests.
pub type Clock = std::sync::Arc<dyn Fn() -> u64 + Send + Sync>;

pub fn system_clock() -> Clock {
    std::sync::Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    })
}

/// Write via a temporary file and rename, so a crash leaves the old or the
/// new content, never a torn file. Returns only once the new content is
/// durable (review r6 R2): the file is synced before the rename and the
/// directory after it, so a power loss cannot bring back the old entry.
pub fn write_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => std::path::Path::new("."),
    };
    std::fs::File::open(dir)?.sync_all()
}
