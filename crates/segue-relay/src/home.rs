//! Home (Decodo ISP SOCKS5) line pool (KERNEL_SPEC §5.6, §5.7, D2).
//!
//! First phase: detect, attribute, alert; no automatic failover
//! (`home_auto_failover` defaults to off). A device's AI traffic uses its
//! primary line only; when that line is DOWN the device's AI connections are
//! refused (`home_unavailable`), never sent direct and never moved to
//! another line unless failover is switched on.
//!
//! Capacity counts billing units, approximated here by devices: at most
//! `line_units` (5) primaries per line; with failover on, a temporary
//! assignment may use seats up to `line_units_failover` (7).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;

use crate::config::{Limits, LineConfig};
use crate::metrics::Metrics;
use crate::socks5::{self, SocksError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineState {
    Active,
    Down,
}

#[derive(Debug)]
struct Line {
    cfg: LineConfig,
    state: LineState,
    fails: u32,
    /// Last gateway address that worked (Decodo DNS outage, §5.7).
    last_addr: Option<SocketAddr>,
    /// Live connections per device on this line. A device holds a seat
    /// here while it has any, even after it moved back to its primary.
    live: HashMap<u64, usize>,
}

#[derive(Debug, Default)]
struct Assign {
    primary: usize,
    /// Temporary line while failed over (only with failover on).
    current: Option<usize>,
}

#[derive(Debug)]
struct Inner {
    lines: Vec<Line>,
    devices: HashMap<u64, Assign>,
}

pub struct HomePool {
    inner: Arc<Mutex<Inner>>,
    limits: Limits,
    auto_failover: bool,
    metrics: Arc<Metrics>,
}

/// Why no Home path is available.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeError {
    /// No lines configured, or every line full.
    NoCapacity,
    /// Assigned line is DOWN (and failover is off or found no seat), or
    /// the gateway failed.
    LineDown,
    /// The gateway works but the target refused / was unreachable (SOCKS
    /// reply code): not a Home outage.
    TargetRefused,
}

const MAX_DEVICES: usize = 1 << 20;
/// Lines probed at once.
const PROBE_CONCURRENCY: usize = 16;

impl HomePool {
    pub fn new(
        lines: Vec<LineConfig>,
        pinned: &[(u64, String)],
        limits: Limits,
        auto_failover: bool,
        metrics: Arc<Metrics>,
    ) -> Result<Self, String> {
        let lines: Vec<Line> = lines
            .into_iter()
            .map(|cfg| Line {
                cfg,
                state: LineState::Active,
                fails: 0,
                last_addr: None,
                live: HashMap::new(),
            })
            .collect();
        let mut devices = HashMap::new();
        for (d, id) in pinned {
            let i = lines
                .iter()
                .position(|l| &l.cfg.id == id)
                .ok_or_else(|| format!("unknown line {id}"))?;
            devices.insert(
                *d,
                Assign {
                    primary: i,
                    current: None,
                },
            );
        }
        let p = Self {
            inner: Arc::new(Mutex::new(Inner { lines, devices })),
            limits,
            auto_failover,
            metrics,
        };
        let inner = p.inner.lock().unwrap();
        for i in 0..inner.lines.len() {
            if primaries(&inner, i) > p.limits.line_units {
                return Err(format!(
                    "home_assignments: line {} has more than {} devices",
                    inner.lines[i].cfg.id, p.limits.line_units
                ));
            }
        }
        drop(inner);
        Ok(p)
    }

    pub fn line_count(&self) -> usize {
        self.inner.lock().unwrap().lines.len()
    }

    pub fn state(&self, id: &str) -> Option<LineState> {
        let g = self.inner.lock().unwrap();
        g.lines.iter().find(|l| l.cfg.id == id).map(|l| l.state)
    }

    pub fn units(&self, id: &str) -> usize {
        let g = self.inner.lock().unwrap();
        g.lines
            .iter()
            .position(|l| l.cfg.id == id)
            .map_or(0, |i| seats(&g, i))
    }

    /// Line the device's AI traffic uses now (assigning a primary if it has
    /// none). Returns (index, config).
    pub fn line_for(&self, device: u64) -> Result<(usize, LineConfig), HomeError> {
        let mut g = self.inner.lock().unwrap();
        let i = self.pick(&mut g, device)?;
        Ok((i, g.lines[i].cfg.clone()))
    }

    /// [`Self::line_for`] plus a seat lease for one connection: the device
    /// keeps its seat on that line until the lease (the connection) ends.
    pub fn acquire(&self, device: u64) -> Result<(usize, LineConfig, Lease), HomeError> {
        let mut g = self.inner.lock().unwrap();
        let i = self.pick(&mut g, device)?;
        *g.lines[i].live.entry(device).or_default() += 1;
        let lease = Lease {
            inner: self.inner.clone(),
            line: i,
            device,
        };
        Ok((i, g.lines[i].cfg.clone(), lease))
    }

    fn pick(&self, g: &mut Inner, device: u64) -> Result<usize, HomeError> {
        if g.lines.is_empty() {
            return Err(HomeError::NoCapacity);
        }
        let primary = match g.devices.get(&device) {
            Some(a) => a.primary,
            None => {
                if g.devices.len() >= MAX_DEVICES {
                    return Err(HomeError::NoCapacity);
                }
                let i = pick_new(g, self.limits.line_units).ok_or(HomeError::NoCapacity)?;
                g.devices.insert(
                    device,
                    Assign {
                        primary: i,
                        current: None,
                    },
                );
                crate::log!(
                    "info",
                    "home line assigned",
                    "device" = device,
                    "line" = g.lines[i].cfg.id
                );
                i
            }
        };
        if g.lines[primary].state == LineState::Active {
            // Primary healthy again: new connections return to it. The
            // temporary seat stays held while old connections on that
            // line live (their leases), so it cannot be handed out twice.
            if let Some(a) = g.devices.get_mut(&device) {
                a.current = None;
            }
            return Ok(primary);
        }
        if !self.auto_failover {
            return Err(HomeError::LineDown);
        }
        if let Some(c) = g.devices.get(&device).and_then(|a| a.current) {
            if g.lines[c].state == LineState::Active {
                return Ok(c);
            }
        }
        let cap = self.limits.line_units_failover;
        let pisp = g.lines[primary].cfg.isp.clone();
        // Prefer another ISP, then fewest seats.
        let best = (0..g.lines.len())
            .filter(|&i| {
                i != primary
                    && g.lines[i].state == LineState::Active
                    && (seats(g, i) < cap || g.lines[i].live.contains_key(&device))
            })
            .min_by_key(|&i| (g.lines[i].cfg.isp == pisp, seats(g, i)));
        let Some(t) = best else {
            return Err(HomeError::LineDown);
        };
        g.devices.get_mut(&device).unwrap().current = Some(t);
        crate::log!(
            "warn",
            "home temporary failover",
            "device" = device,
            "from" = g.lines[primary].cfg.id,
            "to" = g.lines[t].cfg.id
        );
        Ok(t)
    }

    /// Gateway outcome for line `i` (sessions and probes).
    pub fn report(&self, i: usize, ok: bool, addr: Option<SocketAddr>) {
        let mut g = self.inner.lock().unwrap();
        let threshold = self.limits.line_fail_threshold;
        let Some(l) = g.lines.get_mut(i) else { return };
        if ok {
            l.fails = 0;
            if addr.is_some() {
                l.last_addr = addr;
            }
            if l.state == LineState::Down {
                l.state = LineState::Active;
                crate::log!("warn", "home line recovered", "line" = l.cfg.id);
            }
            return;
        }
        Metrics::inc(&self.metrics.home_line_failures);
        l.fails = l.fails.saturating_add(1);
        if l.state == LineState::Active && l.fails >= threshold {
            l.state = LineState::Down;
            let id = l.cfg.id.clone();
            let isp = l.cfg.isp.clone();
            let affected = seats(&g, i);
            Metrics::inc(&self.metrics.home_alerts);
            // Alert: fault domain, affected units, suggested action. Delivery
            // and acknowledgement belong to the control plane / ops console.
            crate::log!(
                "error",
                "ALERT home line down",
                "line" = id,
                "isp" = isp,
                "affected_units" = affected,
                "auto_failover" = self.auto_failover,
                "action" = if self.auto_failover {
                    "temporary reassignment"
                } else {
                    "manual failover required"
                }
            );
        }
    }

    fn last_addr(&self, i: usize) -> Option<SocketAddr> {
        self.inner
            .lock()
            .unwrap()
            .lines
            .get(i)
            .and_then(|l| l.last_addr)
    }

    /// TCP to the line's gateway (resolving its host, falling back to the
    /// last good address) and SOCKS greeting/auth.
    pub async fn open(
        &self,
        i: usize,
        line: &LineConfig,
        timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), SocksError> {
        Self::open_with(line, self.last_addr(i), timeout).await
    }

    async fn open_with(
        line: &LineConfig,
        last_addr: Option<SocketAddr>,
        timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), SocksError> {
        let addrs: Vec<SocketAddr> = match tokio::time::timeout(
            timeout,
            tokio::net::lookup_host(line.server.as_str()),
        )
        .await
        {
            Ok(Ok(a)) => a.collect(),
            _ => Vec::new(),
        };
        let addrs = if addrs.is_empty() {
            last_addr.into_iter().collect()
        } else {
            addrs
        };
        let mut last = SocksError::Io(std::io::Error::other("gateway unresolved"));
        for a in addrs {
            let r = tokio::time::timeout(timeout, async {
                let mut s = TcpStream::connect(a).await?;
                let _ = s.set_nodelay(true);
                socks5::handshake(&mut s, line.credentials.as_ref()).await?;
                Ok::<_, SocksError>(s)
            })
            .await;
            match r {
                Ok(Ok(s)) => return Ok((s, a)),
                Ok(Err(e)) => last = e,
                Err(_) => last = SocksError::Io(std::io::ErrorKind::TimedOut.into()),
            }
        }
        Err(last)
    }

    /// Full Home dial: gateway, auth, CONNECT to `target` (an IP).
    pub async fn dial(
        &self,
        device: u64,
        target: SocketAddr,
        timeout: Duration,
    ) -> Result<(TcpStream, String, Lease), HomeError> {
        let (i, line, lease) = self.acquire(device)?;
        let r = async {
            let (mut s, a) = self.open(i, &line, timeout).await?;
            tokio::time::timeout(timeout, socks5::connect(&mut s, target))
                .await
                .map_err(|_| SocksError::Io(std::io::ErrorKind::TimedOut.into()))??;
            Ok::<_, SocksError>((s, a))
        }
        .await;
        match r {
            Ok((s, a)) => {
                self.report(i, true, Some(a));
                Ok((s, line.id, lease))
            }
            Err(e) => {
                if e.is_line_fault() {
                    self.report(i, false, None);
                } else {
                    // Target refused through a working gateway.
                    self.report(i, true, None);
                }
                crate::log!(
                    "warn",
                    "home dial failed",
                    "line" = line.id,
                    "error" = e.to_string()
                );
                Err(if e.is_line_fault() {
                    HomeError::LineDown
                } else {
                    HomeError::TargetRefused
                })
            }
        }
    }

    /// Active probe of every line: gateway + auth (§5.7). Exit-IP echo needs
    /// a known echo target and is left to deployment config.
    pub async fn probe_all(&self, timeout: Duration) {
        let lines: Vec<(LineConfig, Option<SocketAddr>)> = self
            .inner
            .lock()
            .unwrap()
            .lines
            .iter()
            .map(|l| (l.cfg.clone(), l.last_addr))
            .collect();
        // Concurrently (bounded): one hung gateway must not stretch the
        // probe cycle to `lines × timeout`.
        let mut set = tokio::task::JoinSet::new();
        let mut it = lines.into_iter().enumerate();
        loop {
            while set.len() < PROBE_CONCURRENCY {
                let Some((i, (l, last))) = it.next() else {
                    break;
                };
                set.spawn(async move {
                    let r = Self::open_with(&l, last, timeout).await;
                    (i, r.map(|(_, a)| a))
                });
            }
            let Some(r) = set.join_next().await else {
                break;
            };
            if let Ok((i, r)) = r {
                match r {
                    Ok(a) => self.report(i, true, Some(a)),
                    Err(_) => self.report(i, false, None),
                }
            }
        }
    }
}

fn primaries(g: &Inner, i: usize) -> usize {
    g.devices.values().filter(|a| a.primary == i).count()
}

/// Seats used on line `i`: primaries (reserved even while failed over),
/// temporary occupants, and devices with live connections left here.
fn seats(g: &Inner, i: usize) -> usize {
    let assigned = g
        .devices
        .values()
        .filter(|a| a.primary == i || a.current == Some(i))
        .count();
    // Plus devices that moved away but still have connections here.
    let lingering = g.lines[i]
        .live
        .keys()
        .filter(|d| {
            g.devices
                .get(d)
                .is_none_or(|a| a.primary != i && a.current != Some(i))
        })
        .count();
    assigned + lingering
}

/// One Home connection's hold on its line's seat (D2). Dropped when the
/// connection ends; the last one on a line releases the device's seat
/// there (unless the line is its primary or current line).
#[derive(Debug)]
pub struct Lease {
    inner: Arc<Mutex<Inner>>,
    line: usize,
    device: u64,
}

impl Drop for Lease {
    fn drop(&mut self) {
        let mut g = self.inner.lock().unwrap();
        if let Some(l) = g.lines.get_mut(self.line) {
            if let Some(n) = l.live.get_mut(&self.device) {
                *n -= 1;
                if *n == 0 {
                    l.live.remove(&self.device);
                }
            }
        }
    }
}

/// New unit: ISP with the lowest share of units → its line with fewest
/// seats; only ACTIVE lines below the hard cap.
fn pick_new(g: &Inner, cap: usize) -> Option<usize> {
    let mut isp_units: HashMap<&str, usize> = HashMap::new();
    for a in g.devices.values() {
        *isp_units
            .entry(g.lines[a.primary].cfg.isp.as_str())
            .or_default() += 1;
    }
    (0..g.lines.len())
        .filter(|&i| g.lines[i].state == LineState::Active && seats(g, i) < cap)
        .min_by_key(|&i| {
            (
                isp_units
                    .get(g.lines[i].cfg.isp.as_str())
                    .copied()
                    .unwrap_or(0),
                seats(g, i),
                i,
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(id: &str, isp: &str) -> LineConfig {
        LineConfig {
            id: id.into(),
            server: "127.0.0.1:1".into(),
            isp: isp.into(),
            credentials: None,
        }
    }

    fn pool(failover: bool) -> HomePool {
        let limits = Limits {
            line_fail_threshold: 1,
            ..Limits::default()
        };
        HomePool::new(
            vec![line("a", "x"), line("b", "y")],
            &[],
            limits,
            failover,
            Arc::new(Metrics::default()),
        )
        .unwrap()
    }

    #[test]
    fn five_per_line_balanced_across_isps() {
        let p = pool(false);
        for d in 0..10 {
            p.line_for(d).unwrap();
        }
        assert_eq!((p.units("a"), p.units("b")), (5, 5));
        assert_eq!(p.line_for(10).unwrap_err(), HomeError::NoCapacity);
        // Sticky.
        let (i, _) = p.line_for(3).unwrap();
        assert_eq!(p.line_for(3).unwrap().0, i);
    }

    #[test]
    fn down_line_refuses_without_failover() {
        let p = pool(false);
        let (i, l) = p.line_for(1).unwrap();
        p.report(i, false, None);
        assert_eq!(p.state(&l.id), Some(LineState::Down));
        assert_eq!(p.line_for(1).unwrap_err(), HomeError::LineDown);
        p.report(i, true, None);
        assert_eq!(p.line_for(1).unwrap().0, i);
    }

    #[test]
    fn failover_uses_temp_seats_up_to_seven() {
        let p = pool(true);
        for d in 0..10 {
            p.line_for(d).unwrap();
        }
        let (ia, _) = p.line_for(0).unwrap();
        p.report(ia, false, None);
        // Two of a's five units fit on b (5 + 2 = 7), the rest are refused.
        let mut moved = 0;
        let mut refused = 0;
        for d in 0..10 {
            if p.line_for(d).is_ok() {
                continue;
            }
            refused += 1;
        }
        for d in 0..10 {
            if let Ok((i, _)) = p.line_for(d) {
                if i != ia {
                    moved += 0;
                }
            }
        }
        let _ = moved;
        assert_eq!(refused, 3);
        let ib = 1 - ia;
        assert_eq!(p.units(if ib == 0 { "a" } else { "b" }), 7);
    }

    /// Review r4 #9: B holds 5 primaries + 2 temporary devices from A. A
    /// recovers and the two open new connections on A while their old B
    /// connections live on; a third line then fails. B must still count
    /// the two lingering devices, so at most 7 devices ever hold live
    /// connections on B; the seats free only when the last old one ends.
    #[test]
    fn switch_back_keeps_seat_until_last_old_connection() {
        let limits = Limits {
            line_fail_threshold: 1,
            ..Limits::default()
        };
        let p = HomePool::new(
            vec![line("a", "x"), line("b", "y"), line("c", "x")],
            &[],
            limits,
            true,
            Arc::new(Metrics::default()),
        )
        .unwrap();
        let mut leases: Vec<(u64, usize, Lease)> = Vec::new();
        for d in 0..15 {
            let (i, _, l) = p.acquire(d).unwrap();
            leases.push((d, i, l));
        }
        let idx = |id: &str| {
            p.inner
                .lock()
                .unwrap()
                .lines
                .iter()
                .position(|l| l.cfg.id == id)
                .unwrap()
        };
        let (a, b, c) = (idx("a"), idx("b"), idx("c"));
        let on = |line: usize| -> Vec<u64> {
            let mut v: Vec<u64> = leases.iter().filter(|x| x.1 == line).map(|x| x.0).collect();
            v.sort();
            v.dedup();
            v
        };
        let a_devs = on(a);
        let c_devs = on(c);
        assert_eq!((a_devs.len(), on(b).len(), c_devs.len()), (5, 5, 5));
        let live_on_b = |p: &HomePool| p.inner.lock().unwrap().lines[b].live.len();

        // A fails: two of its devices take B's temporary seats (other ISP).
        p.report(a, false, None);
        let mut temps = Vec::new();
        for &d in &a_devs {
            if let Ok((i, _, l)) = p.acquire(d) {
                if i == b {
                    temps.push(d);
                    leases.push((d, i, l));
                }
            }
        }
        assert_eq!(temps.len(), 2);
        assert_eq!((p.units("b"), live_on_b(&p)), (7, 7));

        // A recovers: the temps' new connections go to A; old B ones live.
        p.report(a, true, None);
        for &d in &temps {
            let (i, _, l) = p.acquire(d).unwrap();
            assert_eq!(i, a);
            leases.push((d, i, l));
        }
        assert_eq!(p.units("b"), 7, "lingering old-line connections hold seats");

        // C fails: its devices may not squeeze onto B.
        p.report(c, false, None);
        for &d in &c_devs {
            if let Ok((i, _, l)) = p.acquire(d) {
                assert_ne!(i, b, "B is full while old connections live");
                leases.push((d, i, l));
            }
            assert!(live_on_b(&p) <= 7);
        }
        assert_eq!((p.units("b"), live_on_b(&p)), (7, 7));

        // One temp's old B connection ends: one seat frees, the other
        // temp still holds its seat.
        let first = temps[0];
        leases.retain(|x| !(x.0 == first && x.1 == b));
        assert_eq!(p.units("b"), 6);
        let moved = c_devs
            .iter()
            .filter_map(|&d| p.acquire(d).ok().filter(|x| x.0 == b).map(|x| (d, x)))
            .map(|(d, (i, _, l))| leases.push((d, i, l)))
            .count();
        assert!(moved >= 1);
        assert!(live_on_b(&p) <= 7 && p.units("b") <= 7);
    }

    #[test]
    fn pinned_over_cap_rejected() {
        let pins: Vec<(u64, String)> = (0..6).map(|d| (d, "a".to_string())).collect();
        assert!(HomePool::new(
            vec![line("a", "x")],
            &pins,
            Limits::default(),
            false,
            Arc::new(Metrics::default())
        )
        .is_err());
    }
}
