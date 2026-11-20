//! Relay config file (JSON). Secrets are never in this file: SOCKS
//! credentials come from a separate file or an environment variable, and the
//! ticket signing key never reaches a node (only public keys are listed).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::Engine as _;
use serde::Deserialize;

use crate::cidr::Cidr;
use crate::socks5::Credentials;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Raw {
    listen: SocketAddr,
    #[serde(default)]
    dgram_listen: Option<SocketAddr>,
    node_id: u64,
    #[serde(default)]
    metrics_listen: Option<SocketAddr>,
    ticket_keys: Vec<RawKey>,
    #[serde(default)]
    revocation_file: Option<PathBuf>,
    /// The signed policy bundle the AI whitelist is read from (the same
    /// bundle format and keys as the client, KERNEL_SPEC §5.5 item 7).
    policy: RawPolicy,
    #[serde(default)]
    home_lines: Vec<RawLine>,
    #[serde(default)]
    home_auto_failover: bool,
    /// Device id → line id, pinned assignments (until the control plane).
    #[serde(default)]
    home_assignments: BTreeMap<String, String>,
    /// The node's own public addresses, inter-node subnets.
    #[serde(default)]
    blocked_cidrs: Vec<String>,
    /// Lab only: ranges exempt from the SSRF guard (e.g. 127.0.0.1/32 for a
    /// loopback end-to-end test). Never set on a real node; a warning is
    /// logged at startup when it is non-empty.
    #[serde(default)]
    dev_allow_cidrs: Vec<String>,
    #[serde(default)]
    limits: RawLimits,
    #[serde(default)]
    redundancy: RawRedundancy,
    #[serde(default)]
    dgram: RawDgram,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawDgram {
    enabled: Option<bool>,
    ai_only: bool,
    max_frame_bytes: usize,
    flows: u8,
    piggyback_k2: usize,
    piggyback_k1: usize,
    max_bytes_per_sec: u32,
    max_packets_per_sec: u32,
}

impl Default for RawDgram {
    fn default() -> Self {
        let d = segue_session::DgramConfig::default();
        Self {
            enabled: None,
            ai_only: d.ai_only,
            max_frame_bytes: d.max_frame_bytes,
            flows: d.flows,
            piggyback_k2: d.piggyback_k2,
            piggyback_k1: d.piggyback_k1,
            max_bytes_per_sec: d.max_bytes_per_sec,
            max_packets_per_sec: d.max_packets_per_sec,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawRedundancy {
    mode: String,
    delay_ms: u64,
    max_frame_bytes: usize,
    ai_only: bool,
}

impl Default for RawRedundancy {
    fn default() -> Self {
        let d = segue_session::RedundancyConfig::default();
        let (mode, delay_ms) = match d.mode {
            segue_session::RedundancyMode::Off => ("off".into(), 0),
            segue_session::RedundancyMode::Dup { delay } => {
                ("dup".into(), delay.as_millis() as u64)
            }
            segue_session::RedundancyMode::Hedge { delay } => {
                ("hedge".into(), delay.as_millis() as u64)
            }
        };
        Self {
            mode,
            delay_ms,
            max_frame_bytes: d.max_frame_bytes,
            ai_only: d.ai_only,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawKey {
    key_id: u32,
    /// Raw 32-byte Ed25519 public key, standard base64.
    public_key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    public_keys: Vec<RawKey>,
    /// Bundle file, kept current by the sync process; re-read on change.
    bundle: PathBuf,
    /// Where the relay keeps the bundles it accepted (rollback floor across
    /// restarts). Default: `<bundle>.accepted`. Must be writable.
    #[serde(default)]
    state_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLine {
    id: String,
    /// SOCKS5 gateway `host:port`.
    server: String,
    #[serde(default)]
    isp: String,
    /// File holding `username:password` (one line).
    #[serde(default)]
    credentials_file: Option<PathBuf>,
    /// Environment variable holding `username:password`.
    #[serde(default)]
    credentials_env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RawLimits {
    pool_bytes: usize,
    window_cap: usize,
    replay_cap: usize,
    max_carriers: usize,
    max_sessions_per_device: usize,
    first_frame_timeout_ms: u64,
    connect_timeout_ms: u64,
    dns_timeout_ms: u64,
    line_units: usize,
    line_units_failover: usize,
    line_fail_threshold: u32,
    probe_interval_secs: u64,
    drain_secs: u64,
    site_flush_idle_secs: u64,
    site_flush_max_secs: u64,
}

impl Default for RawLimits {
    fn default() -> Self {
        let d = Limits::default();
        Self {
            pool_bytes: d.pool_bytes,
            window_cap: d.window_cap,
            replay_cap: d.replay_cap,
            max_carriers: d.max_carriers,
            max_sessions_per_device: d.max_sessions_per_device,
            first_frame_timeout_ms: d.first_frame_timeout.as_millis() as u64,
            connect_timeout_ms: d.connect_timeout.as_millis() as u64,
            dns_timeout_ms: d.dns_timeout.as_millis() as u64,
            line_units: d.line_units,
            line_units_failover: d.line_units_failover,
            line_fail_threshold: d.line_fail_threshold,
            probe_interval_secs: d.probe_interval.as_secs(),
            drain_secs: d.drain.as_secs(),
            site_flush_idle_secs: d.site_flush_idle.as_secs(),
            site_flush_max_secs: d.site_flush_max.as_secs(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Limits {
    /// Global session buffer pool (receive + replay), bytes.
    pub pool_bytes: usize,
    pub window_cap: usize,
    pub replay_cap: usize,
    /// Accepted carriers at once; more are closed on accept.
    pub max_carriers: usize,
    /// Live sessions per device; more → `REJECT(capacity)`.
    pub max_sessions_per_device: usize,
    /// A carrier must deliver its complete first frame (OPEN / RESUME,
    /// authenticated on arrival) within this.
    pub first_frame_timeout: Duration,
    pub connect_timeout: Duration,
    pub dns_timeout: Duration,
    /// D2: hard cap of billing units per line.
    pub line_units: usize,
    /// D2: temporary cap while failed over.
    pub line_units_failover: usize,
    /// Consecutive gateway failures before a line is DOWN.
    pub line_fail_threshold: u32,
    pub probe_interval: Duration,
    /// Graceful shutdown drain limit.
    pub drain: Duration,
    /// After a client's FIN: reset when the site accepts no upload byte
    /// for this long (segue-session `Timing::site_flush_idle`).
    pub site_flush_idle: Duration,
    /// After a client's FIN: overall bound on flushing the upload to the
    /// site (`Timing::site_flush_max`).
    pub site_flush_max: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            pool_bytes: 256 << 20,
            window_cap: 1024 * 1024,
            replay_cap: 2 * 1024 * 1024,
            max_carriers: 4096,
            max_sessions_per_device: 256,
            first_frame_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            dns_timeout: Duration::from_secs(5),
            line_units: 5,
            line_units_failover: 7,
            line_fail_threshold: 3,
            probe_interval: Duration::from_secs(60),
            drain: Duration::from_secs(30),
            site_flush_idle: segue_session::Timing::default().site_flush_idle,
            site_flush_max: segue_session::Timing::default().site_flush_max,
        }
    }
}

#[derive(Clone, Debug)]
pub struct LineConfig {
    pub id: String,
    pub server: String,
    pub isp: String,
    pub credentials: Option<Credentials>,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen: SocketAddr,
    pub dgram_listen: Option<SocketAddr>,
    pub node_id: u64,
    pub metrics_listen: Option<SocketAddr>,
    pub ticket_keys: Vec<(u32, [u8; 32])>,
    pub revocation_file: Option<PathBuf>,
    /// Last accepted revocation snapshot, `<revocation_file>.accepted`
    /// (review r5 N4: restored first on start).
    pub revocation_state: Option<PathBuf>,
    /// Policy bundle verification keys (key id → raw Ed25519 key).
    pub policy_keys: BTreeMap<u32, Vec<u8>>,
    pub policy_bundle: PathBuf,
    /// Accepted-bundle state (review r5 N2).
    pub policy_state: PathBuf,
    pub home_lines: Vec<LineConfig>,
    pub home_auto_failover: bool,
    pub home_assignments: Vec<(u64, String)>,
    pub blocked_cidrs: Vec<Cidr>,
    pub dev_allow_cidrs: Vec<Cidr>,
    pub limits: Limits,
    pub redundancy: segue_session::RedundancyConfig,
    pub dgram: segue_session::DgramConfig,
}

fn read_credentials(
    file: Option<&Path>,
    env: Option<&str>,
    base: &Path,
    id: &str,
) -> Result<Option<Credentials>, String> {
    let raw = match (file, env) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "line {id}: set credentials_file or credentials_env, not both"
            ))
        }
        (Some(f), None) => {
            let p = base.join(f);
            // The error never includes the content.
            std::fs::read_to_string(&p)
                .map_err(|e| format!("line {id}: cannot read credentials file: {e}"))?
        }
        (None, Some(v)) => {
            std::env::var(v).map_err(|_| format!("line {id}: credentials env var is not set"))?
        }
        (None, None) => return Ok(None),
    };
    Credentials::parse(raw.trim()).map(Some).ok_or_else(|| {
        format!("line {id}: credentials must be `username:password` (1..=255 bytes each)")
    })
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        Self::parse_in(&text, base)
    }

    /// Parse; relative paths resolve against `base`.
    pub fn parse_in(text: &str, base: &Path) -> Result<Self, String> {
        let raw: Raw = serde_json::from_str(text).map_err(|e| format!("config: {e}"))?;
        if !raw.listen.ip().is_loopback() {
            return Err(
                "listen must be a loopback address (the outer servers forward to it)".into(),
            );
        }
        if let Some(d) = raw.dgram_listen {
            if !d.ip().is_loopback() {
                return Err(
                    "dgram_listen must be a loopback address (the outer servers forward to it)"
                        .into(),
                );
            }
        }
        if let Some(m) = raw.metrics_listen {
            if !m.ip().is_loopback() {
                return Err("metrics_listen must be a loopback address".into());
            }
        }
        if raw.ticket_keys.is_empty() {
            return Err("ticket_keys must not be empty".into());
        }
        let mut ticket_keys = Vec::new();
        for k in &raw.ticket_keys {
            let b = base64::engine::general_purpose::STANDARD
                .decode(k.public_key.trim())
                .map_err(|_| format!("ticket key {}: bad base64", k.key_id))?;
            let b: [u8; 32] = b
                .try_into()
                .map_err(|_| format!("ticket key {}: must be 32 bytes", k.key_id))?;
            if ticket_keys.iter().any(|(id, _)| *id == k.key_id) {
                return Err(format!("duplicate ticket key_id {}", k.key_id));
            }
            ticket_keys.push((k.key_id, b));
        }
        if raw.policy.public_keys.is_empty() {
            return Err("policy.public_keys must not be empty".into());
        }
        let mut policy_keys = BTreeMap::new();
        for k in &raw.policy.public_keys {
            let b = segue_policy::parse_public_key(&k.public_key)
                .map_err(|e| format!("policy key {}: {e}", k.key_id))?;
            if policy_keys.insert(k.key_id, b).is_some() {
                return Err(format!("duplicate policy key_id {}", k.key_id));
            }
        }
        let mut home_lines: Vec<LineConfig> = Vec::new();
        for l in &raw.home_lines {
            if l.id.is_empty() || home_lines.iter().any(|x| x.id == l.id) {
                return Err(format!("home line id {:?} empty or duplicate", l.id));
            }
            if l.server
                .rsplit_once(':')
                .and_then(|(_, p)| p.parse::<u16>().ok())
                .is_none()
            {
                return Err(format!("home line {}: server must be host:port", l.id));
            }
            let credentials = read_credentials(
                l.credentials_file.as_deref(),
                l.credentials_env.as_deref(),
                base,
                &l.id,
            )?;
            home_lines.push(LineConfig {
                id: l.id.clone(),
                server: l.server.clone(),
                isp: l.isp.clone(),
                credentials,
            });
        }
        let mut home_assignments = Vec::new();
        for (d, line) in &raw.home_assignments {
            let d: u64 = d
                .parse()
                .map_err(|_| format!("home_assignments: bad device id {d:?}"))?;
            if !home_lines.iter().any(|l| &l.id == line) {
                return Err(format!("home_assignments: unknown line {line:?}"));
            }
            home_assignments.push((d, line.clone()));
        }
        let blocked_cidrs = raw
            .blocked_cidrs
            .iter()
            .map(|c| Cidr::parse(c.trim()))
            .collect::<Result<Vec<_>, _>>()?;
        let dev_allow_cidrs = raw
            .dev_allow_cidrs
            .iter()
            .map(|c| Cidr::parse(c.trim()))
            .collect::<Result<Vec<_>, _>>()?;
        let r = &raw.limits;
        let limits = Limits {
            pool_bytes: r.pool_bytes,
            window_cap: r.window_cap,
            replay_cap: r.replay_cap,
            max_carriers: r.max_carriers,
            max_sessions_per_device: r.max_sessions_per_device,
            first_frame_timeout: Duration::from_millis(r.first_frame_timeout_ms),
            connect_timeout: Duration::from_millis(r.connect_timeout_ms),
            dns_timeout: Duration::from_millis(r.dns_timeout_ms),
            line_units: r.line_units,
            line_units_failover: r.line_units_failover,
            line_fail_threshold: r.line_fail_threshold.max(1),
            probe_interval: Duration::from_secs(r.probe_interval_secs.max(1)),
            drain: Duration::from_secs(r.drain_secs),
            site_flush_idle: Duration::from_secs(r.site_flush_idle_secs),
            site_flush_max: Duration::from_secs(r.site_flush_max_secs),
        };
        if limits.site_flush_idle.is_zero() || limits.site_flush_max < limits.site_flush_idle {
            return Err(
                "limits: site_flush_idle_secs must be > 0 and <= site_flush_max_secs".into(),
            );
        }
        if limits.pool_bytes < 1 << 20
            || limits.window_cap < 16 * 1024
            || limits.replay_cap < 16 * 1024
        {
            return Err("limits: pool_bytes >= 1 MiB, window_cap / replay_cap >= 16 KiB".into());
        }
        if limits.max_carriers == 0 || limits.max_sessions_per_device == 0 {
            return Err("limits: max_carriers and max_sessions_per_device must be > 0".into());
        }
        // D2: 5 per line is a hard cap, 7 only while failed over.
        if limits.line_units == 0
            || limits.line_units > 5
            || limits.line_units_failover < limits.line_units
            || limits.line_units_failover > 7
        {
            return Err(
                "limits: 0 < line_units <= 5, line_units <= line_units_failover <= 7".into(),
            );
        }
        if limits.first_frame_timeout.is_zero()
            || limits.connect_timeout.is_zero()
            || limits.dns_timeout.is_zero()
        {
            return Err("limits: timeouts must be > 0".into());
        }
        let mode = match raw.redundancy.mode.as_str() {
            "off" => segue_session::RedundancyMode::Off,
            "dup" => segue_session::RedundancyMode::Dup {
                delay: Duration::from_millis(raw.redundancy.delay_ms),
            },
            "hedge" => segue_session::RedundancyMode::Hedge {
                delay: Duration::from_millis(raw.redundancy.delay_ms),
            },
            other => {
                return Err(format!(
                    "redundancy.mode: expected \"off\", \"dup\", or \"hedge\", got {other:?}"
                ))
            }
        };
        if !matches!(mode, segue_session::RedundancyMode::Off)
            && raw.redundancy.max_frame_bytes == 0
        {
            return Err("redundancy.max_frame_bytes must be > 0".into());
        }
        let redundancy = segue_session::RedundancyConfig {
            mode,
            max_frame_bytes: raw.redundancy.max_frame_bytes,
            ai_only: raw.redundancy.ai_only,
        };
        let dgram_enabled = raw.dgram.enabled.unwrap_or(raw.dgram_listen.is_some());
        if dgram_enabled && raw.dgram.max_frame_bytes == 0 {
            return Err("dgram.max_frame_bytes must be > 0".into());
        }
        if dgram_enabled && (raw.dgram.flows == 0 || raw.dgram.flows > 2) {
            return Err("dgram.flows must be 1 or 2".into());
        }
        let dgram_defaults = segue_session::DgramConfig::default();
        let dgram = segue_session::DgramConfig {
            enabled: dgram_enabled,
            ai_only: raw.dgram.ai_only,
            max_frame_bytes: raw.dgram.max_frame_bytes,
            flows: raw.dgram.flows,
            piggyback_k2: raw.dgram.piggyback_k2.max(1),
            piggyback_k1: raw.dgram.piggyback_k1.max(1),
            max_bytes_per_sec: raw.dgram.max_bytes_per_sec.max(1200),
            max_packets_per_sec: raw.dgram.max_packets_per_sec.max(1),
            ..dgram_defaults
        };
        Ok(Self {
            listen: raw.listen,
            dgram_listen: raw.dgram_listen,
            node_id: raw.node_id,
            metrics_listen: raw.metrics_listen,
            ticket_keys,
            revocation_state: raw.revocation_file.as_ref().map(|p| {
                let mut s = base.join(p).into_os_string();
                s.push(".accepted");
                PathBuf::from(s)
            }),
            revocation_file: raw.revocation_file.map(|p| base.join(p)),
            policy_keys,
            policy_bundle: base.join(&raw.policy.bundle),
            policy_state: match &raw.policy.state_file {
                Some(p) => base.join(p),
                None => {
                    let mut p = base.join(&raw.policy.bundle).into_os_string();
                    p.push(".accepted");
                    PathBuf::from(p)
                }
            },
            home_lines,
            home_auto_failover: raw.home_auto_failover,
            home_assignments,
            blocked_cidrs,
            dev_allow_cidrs,
            limits,
            redundancy,
            dgram,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use segue_session::{RedundancyConfig, RedundancyMode};

    fn parse_with_extra(extra: &str) -> Result<Config, String> {
        let pk = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let json = format!(
            r#"{{
                "listen": "127.0.0.1:8443",
                "node_id": 1,
                "ticket_keys": [{{"key_id": 1, "public_key": "{pk}"}}],
                "policy": {{
                    "public_keys": [{{"key_id": 1, "public_key": "{pk}"}}],
                    "bundle": "bundle.bin"
                }}{extra}
            }}"#
        );
        Config::parse_in(&json, Path::new("."))
    }

    #[test]
    fn redundancy_block_defaults_and_parses() {
        let cfg = parse_with_extra("").unwrap();
        assert_eq!(cfg.redundancy, RedundancyConfig::default());

        let cfg = parse_with_extra(r#", "redundancy": {"mode": "off"}"#).unwrap();
        assert_eq!(cfg.redundancy.mode, RedundancyMode::Off);

        let cfg = parse_with_extra(
            r#", "redundancy": {"mode": "hedge", "delay_ms": 45, "max_frame_bytes": 512, "ai_only": false}"#,
        )
        .unwrap();
        assert_eq!(
            cfg.redundancy,
            RedundancyConfig {
                mode: RedundancyMode::Hedge {
                    delay: Duration::from_millis(45),
                },
                max_frame_bytes: 512,
                ai_only: false,
            }
        );

        assert!(parse_with_extra(r#", "redundancy": {"mode": "bogus"}"#).is_err());
        assert!(parse_with_extra(r#", "redundancy": {"max_frame_bytes": 0}"#).is_err());
    }

    #[test]
    fn dgram_listen_requires_loopback_and_enables_accelerator() {
        let off = parse_with_extra("").unwrap();
        assert_eq!(off.dgram_listen, None);
        assert!(!off.dgram.enabled);

        let err = parse_with_extra(r#", "dgram_listen": "0.0.0.0:8444""#).unwrap_err();
        assert!(err.contains("loopback"), "{err}");

        let on = parse_with_extra(
            r#", "dgram_listen": "127.0.0.1:8444", "dgram": {"flows": 1, "max_bytes_per_sec": 65536}"#,
        )
        .unwrap();
        assert_eq!(on.dgram_listen, Some("127.0.0.1:8444".parse().unwrap()));
        assert!(on.dgram.enabled);
        assert_eq!(on.dgram.flows, 1);
        assert_eq!(on.dgram.max_bytes_per_sec, 65536);

        assert!(parse_with_extra(r#", "dgram": {"enabled": true, "flows": 3}"#).is_err());
    }
}
