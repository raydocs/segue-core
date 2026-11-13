//! SOCKS5 UDP ASSOCIATE (KERNEL_SPEC §4.3, §5.4).
//!
//! One association = one loopback UDP socket for the client, alive while the
//! client keeps its TCP control connection open (and something is moving).
//! Each destination the client sends to is its own flow, routed on its own:
//!
//! - a fake-IP destination is routed by its recorded domain and dialled by
//!   name; an unknown or stale fake address is dropped;
//! - other targets go through the rule table;
//! - Reject, and Proxy through an outbound listed in `refuse` (the Home / AI
//!   exit: §1.2.3, UDP to home broadband is always refused), are dropped;
//!   `refuse_quic` outbounds (Reality carriers) refuse UDP/443 only (§4.3);
//! - a proxy flow whose dial fails stays refused until it goes idle. It is
//!   never retried direct: `dial_udp(None, ..)` is only reached from a
//!   Direct rule.
//!
//! "Refused" for UDP means the datagrams are dropped: SOCKS5 has no way to
//! signal a per-datagram error, and the app falls back to TCP (where the
//! same rules answer with a proper refusal).
//!
//! Memory is bounded per association (`max_flows` × `queue` datagrams, and
//! at most `queue_bytes` of queued payload) and globally
//! (`max_associations`). Datagrams over the path's payload limit,
//! over a full queue, or with FRAG ≠ 0 are dropped and counted.
//!
//! A bare-IP destination (not fake) is classified by its first datagrams
//! (§5.2a.2): a QUIC client Initial is decrypted for its SNI and the name
//! routed like a TCP sniff (the stricter of the IP and the name rule, so an
//! AI name is refused); QUIC whose name cannot be confirmed (ClientHello
//! not complete within [`crate::quic::MAX_DATAGRAMS`] datagrams, unknown
//! version, no SNI), and anything to UDP/443 that is not a readable QUIC
//! Initial, is refused so the app falls back to TCP. Other UDP goes by the
//! IP rules. Datagrams are held (counted in the association budget) while
//! the ClientHello is incomplete and released to the flow once routed.
//! Later datagrams of a sniffed flow pass its [`ConnGuard`]: a new QUIC
//! connection is classified on its own, and QUIC that belongs to no allowed
//! connection (unknown version, unknown connection ID) is dropped; replies
//! teach the guard the server's connection IDs.

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::{self, error::TrySendError};
use tokio::sync::Semaphore;
use tokio::time::Instant;

use crate::dial::{Dialer, UdpSession};
use crate::quic::{ConnGuard, InitialSniffer, Quic, QuicRoutes, ReplyWatch, Step};
use crate::rules::Action;
use crate::socks::{Kernel, REP_GENERAL, REP_OK};

const DIAL_TIMEOUT: Duration = Duration::from_secs(15);
/// Default for `UdpSettings::queue_bytes`.
pub const ASSOCIATION_QUEUE_BYTES: usize = 1 << 20;

#[derive(Clone, Debug)]
pub struct UdpSettings {
    /// Outbounds that never carry UDP (the Home / AI exit).
    pub refuse: BTreeSet<String>,
    /// Outbounds that refuse UDP to port 443 (QUIC over a Reality carrier),
    /// so the app falls back to TCP.
    pub refuse_quic: BTreeSet<String>,
    /// A flow with no datagram either way for this long is closed; an
    /// association with no flows and no client datagram for this long ends.
    pub idle_timeout: Duration,
    /// Live destinations per association.
    pub max_flows: usize,
    /// Datagrams queued towards one destination while its dial or send is
    /// pending.
    pub queue: usize,
    /// Concurrent associations.
    pub max_associations: usize,
    /// Payload bytes queued across all flows of one association. A datagram
    /// can be ~64 KiB, so the datagram-count `queue` alone would let one
    /// association hold `max_flows × queue × 64 KiB` (hundreds of MiB).
    pub queue_bytes: usize,
}

impl Default for UdpSettings {
    fn default() -> Self {
        Self {
            refuse: BTreeSet::new(),
            refuse_quic: BTreeSet::new(),
            idle_timeout: Duration::from_secs(60),
            max_flows: 128,
            queue: 32,
            max_associations: 64,
            queue_bytes: ASSOCIATION_QUEUE_BYTES,
        }
    }
}

/// UDP state shared by every association of one kernel.
pub struct Udp {
    pub settings: UdpSettings,
    /// Which outbounds carry QUIC to which servers, for every UDP flow of
    /// the kernel, SOCKS and TUN (see [`QuicRoutes`]).
    pub quic_routes: QuicRoutes,
    slots: Arc<Semaphore>,
    dropped: Arc<AtomicU64>,
}

impl Udp {
    pub fn new(settings: UdpSettings) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(settings.max_associations)),
            settings,
            quic_routes: QuicRoutes::default(),
            dropped: Arc::default(),
        }
    }

    /// Datagrams dropped so far: refused routes, oversize, full queues,
    /// fragments, malformed headers.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn drop_one(&self) {
        self.dropped.fetch_add(1, Ordering::Relaxed);
    }
}

type Key = (TargetAddr, u16);

/// A destination of one association.
enum Slot {
    Live {
        tx: mpsc::Sender<Vec<u8>>,
        /// For a flow routed by sniffing: every further QUIC connection on
        /// it is classified too (N7).
        guard: Option<Box<Guarded>>,
    },
    /// Waiting for the rest of a QUIC ClientHello.
    Held {
        sniffer: InitialSniffer,
        datagrams: Vec<Vec<u8>>,
        since: Instant,
    },
}

impl Slot {
    fn stale(&self, idle: Duration) -> bool {
        match self {
            Slot::Live { tx, .. } => tx.is_closed(),
            Slot::Held { since, .. } => since.elapsed() >= idle,
        }
    }
}

struct Guarded {
    guard: ConnGuard<Vec<u8>>,
    /// The flow's route; a new connection must route the same way.
    route: (Option<String>, TargetAddr),
}

fn release(queued: &AtomicUsize, slot: &Slot) {
    let held: &[Vec<u8>] = match slot {
        Slot::Held { datagrams, .. } => datagrams,
        Slot::Live { guard: Some(g), .. } => g.guard.held(),
        Slot::Live { .. } => &[],
    };
    let n: usize = held.iter().map(Vec::len).sum();
    queued.fetch_sub(n, Ordering::Relaxed);
}

fn drop_all(udp: &Udp, queued: &AtomicUsize, ds: &[Vec<u8>]) {
    let n: usize = ds.iter().map(Vec::len).sum();
    queued.fetch_sub(n, Ordering::Relaxed);
    for _ in ds {
        udp.drop_one();
    }
}

/// Serve one UDP ASSOCIATE request. `client_port` is the port the client
/// said it would send from (0: not known yet).
pub(crate) async fn associate(
    mut conn: TcpStream,
    kernel: &Kernel,
    udp: &Udp,
    client_port: u16,
) -> std::io::Result<()> {
    let Ok(_slot) = udp.slots.clone().try_acquire_owned() else {
        return reply_bound(&mut conn, REP_GENERAL, None).await;
    };
    let peer = conn.peer_addr()?;
    // The relay socket sits on the same loopback address the client reached
    // us on; it is never exposed beyond this host.
    let socket = Arc::new(UdpSocket::bind((conn.local_addr()?.ip(), 0)).await?);
    reply_bound(&mut conn, REP_OK, Some(socket.local_addr()?)).await?;

    let mut client = (client_port != 0).then(|| SocketAddr::new(peer.ip(), client_port));
    let mut flows: HashMap<Key, Slot> = HashMap::new();
    let queued = Arc::new(AtomicUsize::new(0));
    let mut buf = vec![0u8; 65_535];
    let mut ctl = [0u8; 64];
    let idle = udp.settings.idle_timeout;
    let mut last = Instant::now();
    loop {
        tokio::select! {
            r = conn.read(&mut ctl) => match r {
                // The association ends with its control connection.
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            },
            r = socket.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { continue };
                if from.ip() != peer.ip() {
                    continue;
                }
                match client {
                    None => client = Some(from),
                    Some(c) if c != from => continue,
                    Some(_) => {}
                }
                last = Instant::now();
                uplink(kernel, udp, &mut flows, &queued, &socket, from, &buf[..n]);
            }
            _ = tokio::time::sleep_until(last + idle) => {
                flows.retain(|_, f| {
                    let stale = f.stale(idle);
                    if stale {
                        release(&queued, f);
                    }
                    !stale
                });
                if flows.is_empty() {
                    break;
                }
                last = Instant::now();
            }
        }
    }
    // Dropping the senders ends every flow task.
    Ok(())
}

fn uplink(
    kernel: &Kernel,
    udp: &Udp,
    flows: &mut HashMap<Key, Slot>,
    queued: &Arc<AtomicUsize>,
    socket: &Arc<UdpSocket>,
    client: SocketAddr,
    pkt: &[u8],
) {
    let Some((addr, port, payload)) = parse_header(pkt) else {
        return udp.drop_one();
    };
    let key = (addr, port);
    // Reserve the payload's bytes in the association budget; whoever takes
    // the datagram off the queue (or drops it) gives them back.
    let budget = udp.settings.queue_bytes;
    let reserve = |q: &AtomicUsize| {
        q.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
            (used + payload.len() <= budget).then_some(used + payload.len())
        })
        .is_ok()
    };
    let mut held = None;
    match flows.get_mut(&key) {
        Some(Slot::Live { tx, guard }) => {
            if !reserve(queued) {
                return udp.drop_one();
            }
            let batch = match (guard, &key.0) {
                (Some(g), TargetAddr::Ip(ip)) => {
                    let Guarded { guard, route } = &mut **g;
                    let same = |q: &Quic| {
                        route_sniffed(kernel, &udp.settings, *ip, port, q).as_ref() == Some(route)
                    };
                    match guard.push(payload.to_vec(), payload, same) {
                        Step::Hold => return,
                        // SOCKS has no way to signal a refusal to the
                        // client: drop, as for any refused datagram.
                        Step::Drop(ds) | Step::Refuse(ds) => return drop_all(udp, queued, &ds),
                        Step::Forward(ds) => ds,
                    }
                }
                _ => vec![payload.to_vec()],
            };
            let single = batch.len() == 1;
            let mut batch = batch.into_iter();
            for d in batch.by_ref() {
                let n = d.len();
                match tx.try_send(d) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_)) => {
                        queued.fetch_sub(n, Ordering::Relaxed);
                        udp.drop_one();
                    }
                    Err(TrySendError::Closed(_)) => {
                        queued.fetch_sub(n, Ordering::Relaxed);
                        let rest: Vec<_> = batch.by_ref().collect();
                        drop_all(udp, queued, &rest);
                        if let Some(old) = flows.remove(&key) {
                            release(queued, &old);
                        }
                        if !single {
                            return udp.drop_one();
                        }
                        // Went idle (or broke): route afresh below.
                        break;
                    }
                }
            }
            if flows.contains_key(&key) {
                return;
            }
        }
        Some(Slot::Held { .. }) => held = flows.remove(&key),
        None => {}
    }
    if held.is_none() && flows.len() >= udp.settings.max_flows {
        flows.retain(|_, f| {
            let stale = f.stale(udp.settings.idle_timeout);
            if stale {
                release(queued, f);
            }
            !stale
        });
        if flows.len() >= udp.settings.max_flows {
            return udp.drop_one();
        }
    }
    if !reserve(queued) {
        if let Some(h) = &held {
            release(queued, h);
        }
        return udp.drop_one();
    }
    let decided = match (held, &key.0) {
        (
            Some(Slot::Held {
                mut sniffer,
                mut datagrams,
                since,
            }),
            TargetAddr::Ip(ip),
        ) => {
            datagrams.push(payload.to_vec());
            match sniffer.push(payload) {
                Quic::NeedMore => {
                    flows.insert(
                        key,
                        Slot::Held {
                            sniffer,
                            datagrams,
                            since,
                        },
                    );
                    return;
                }
                q => (
                    route_sniffed(kernel, &udp.settings, *ip, port, &q),
                    datagrams,
                    Some(guard_for(&sniffer, &q, port)),
                ),
            }
        }
        (_, TargetAddr::Ip(ip)) if sniffs(kernel, *ip) => {
            let mut sniffer = InitialSniffer::default();
            match sniffer.push(payload) {
                Quic::NeedMore => {
                    flows.insert(
                        key,
                        Slot::Held {
                            sniffer,
                            datagrams: vec![payload.to_vec()],
                            since: Instant::now(),
                        },
                    );
                    return;
                }
                q => (
                    route_sniffed(kernel, &udp.settings, *ip, port, &q),
                    vec![payload.to_vec()],
                    Some(guard_for(&sniffer, &q, port)),
                ),
            }
        }
        _ => (
            route(kernel, &udp.settings, &key.0, port),
            vec![payload.to_vec()],
            None,
        ),
    };
    let (route, datagrams, guard) = decided;
    let Some((tag, target)) = route.clone() else {
        let n: usize = datagrams.iter().map(Vec::len).sum();
        queued.fetch_sub(n, Ordering::Relaxed);
        for _ in &datagrams {
            udp.drop_one();
        }
        return;
    };
    let (tx, rx) = mpsc::channel(udp.settings.queue.max(datagrams.len()));
    for d in datagrams {
        let _ = tx.try_send(d);
    }
    tokio::spawn(flow(
        Flow {
            dialer: kernel.dialer.clone(),
            tag,
            // Replies name the address the client sent to (e.g. its fake IP).
            reply_as: key.0.clone(),
            target,
            port,
            socket: socket.clone(),
            client,
            idle: udp.settings.idle_timeout,
            dropped: udp.dropped.clone(),
            queued: queued.clone(),
            watch: guard.as_ref().map(ConnGuard::watch),
        },
        rx,
    ));
    let guard = guard.map(|guard| {
        let route = route.expect("routed");
        let guard = match &key.0 {
            TargetAddr::Ip(ip) => guard.with_route(
                udp.quic_routes.clone(),
                SocketAddr::new(*ip, port),
                route.0.clone(),
            ),
            TargetAddr::Domain(_) => guard,
        };
        Box::new(Guarded { guard, route })
    });
    flows.insert(key, Slot::Live { tx, guard });
}

/// The per-connection guard of a flow routed after `sniffer` said `q`.
fn guard_for(sniffer: &InitialSniffer, q: &Quic, port: u16) -> ConnGuard<Vec<u8>> {
    ConnGuard::new(
        matches!(q, Quic::Domain(_)).then_some(sniffer),
        port == QUIC_PORT,
    )
}

/// Whether a new flow to this bare IP is classified by its datagrams first
/// (not a fake address, and not already refused by an IP rule).
pub(crate) fn sniffs(kernel: &Kernel, ip: IpAddr) -> bool {
    if kernel.fake_ip.as_ref().is_some_and(|p| p.contains(ip)) {
        return false;
    }
    let policy = kernel.policy.current();
    !policy.refuse_all
        && !matches!(
            policy.rules.lookup(&TargetAddr::Ip(ip)),
            Some((_, Action::Reject))
        )
}

/// Route a bare-IP flow once its first datagrams are classified (§5.2a.2).
/// The policy current now applies.
pub(crate) fn route_sniffed(
    kernel: &Kernel,
    s: &UdpSettings,
    ip: IpAddr,
    port: u16,
    quic: &Quic,
) -> Option<(Option<String>, TargetAddr)> {
    let policy = kernel.policy.current();
    if policy.refuse_all {
        return None;
    }
    match quic {
        // UDP/443 is QUIC's port: anything there that is not a readable
        // client Initial (a short-header packet of a connection we never saw
        // start, a QUIC version we cannot read) cannot be confirmed non-AI.
        Quic::NotQuic if port != QUIC_PORT => route(kernel, s, &TargetAddr::Ip(ip), port),
        Quic::Domain(d) => {
            let rules = &policy.rules;
            let by_ip = rules.lookup(&TargetAddr::Ip(ip));
            let by_domain = rules.lookup(&TargetAddr::Domain(d.clone()));
            let action = crate::socks::stricter(by_ip, by_domain)
                .unwrap_or_else(|| rules.default_action())
                .clone();
            let target = match action {
                // Direct goes to the address the app asked for (resolving
                // the sniffed name locally would leak it).
                Action::Direct => TargetAddr::Ip(ip),
                _ => TargetAddr::Domain(d.clone()),
            };
            finish(s, action, target, port)
        }
        _ => None,
    }
}

const QUIC_PORT: u16 = 443;

/// The outbound (None: direct) and the address to dial, or None: refused.
pub(crate) fn route(
    kernel: &Kernel,
    s: &UdpSettings,
    addr: &TargetAddr,
    port: u16,
) -> Option<(Option<String>, TargetAddr)> {
    let policy = kernel.policy.current();
    if policy.refuse_all {
        return None;
    }
    let (action, target) = match addr {
        TargetAddr::Ip(ip) if kernel.fake_ip.as_ref().is_some_and(|p| p.contains(*ip)) => {
            // A fake address is never dialled as an IP.
            // Authorized against the policy in force now; the pool only
            // remembers the name.
            let entry = kernel.fake_ip.as_ref()?.lookup(*ip)?;
            (
                policy.decide_fake(&entry.domain).clone(),
                TargetAddr::Domain(entry.domain),
            )
        }
        _ => (policy.rules.decide(addr).clone(), addr.clone()),
    };
    finish(s, action, target, port)
}

fn finish(
    s: &UdpSettings,
    action: Action,
    target: TargetAddr,
    port: u16,
) -> Option<(Option<String>, TargetAddr)> {
    match action {
        Action::Reject => None,
        Action::Direct => Some((None, target)),
        Action::Proxy(tag) if s.refuse.contains(&tag) => None,
        Action::Proxy(tag) if port == QUIC_PORT && s.refuse_quic.contains(&tag) => None,
        Action::Proxy(tag) => Some((Some(tag), target)),
    }
}

struct Flow {
    dialer: Arc<dyn Dialer>,
    tag: Option<String>,
    reply_as: TargetAddr,
    target: TargetAddr,
    port: u16,
    socket: Arc<UdpSocket>,
    client: SocketAddr,
    idle: Duration,
    dropped: Arc<AtomicU64>,
    queued: Arc<AtomicUsize>,
    /// The flow's QUIC guard learns the server's connection IDs from
    /// replies (R7).
    watch: Option<ReplyWatch>,
}

async fn flow(f: Flow, mut rx: mpsc::Receiver<Vec<u8>>) {
    run_flow(&f, &mut rx).await;
    // Give back the budget of whatever is still queued.
    rx.close();
    while let Ok(p) = rx.try_recv() {
        f.queued.fetch_sub(p.len(), Ordering::Relaxed);
    }
}

/// Takes the next datagram off the queue and returns its budget.
async fn next(f: &Flow, rx: &mut mpsc::Receiver<Vec<u8>>) -> Result<Option<Vec<u8>>, ()> {
    let p = tokio::time::timeout(f.idle, rx.recv())
        .await
        .map_err(drop)?;
    if let Some(p) = &p {
        f.queued.fetch_sub(p.len(), Ordering::Relaxed);
    }
    Ok(p)
}

async fn run_flow(f: &Flow, rx: &mut mpsc::Receiver<Vec<u8>>) {
    let dial = f.dialer.dial_udp(f.tag.as_deref(), &f.target, f.port);
    let session: Arc<dyn UdpSession> = match tokio::time::timeout(DIAL_TIMEOUT, dial).await {
        Ok(Ok(s)) => Arc::from(s),
        _ => {
            // Refused, never retried direct. Swallow until idle so a chatty
            // app does not trigger a dial per datagram.
            while let Ok(Some(_)) = next(f, rx).await {
                f.dropped.fetch_add(1, Ordering::Relaxed);
            }
            return;
        }
    };
    let max = session.max_payload(&f.target, f.port);
    let start = Instant::now();
    let last_down = Arc::new(AtomicU64::new(0));
    // Downlink in its own task so `recv` is never cancelled mid-datagram.
    let down = tokio::spawn({
        let session = session.clone();
        let last_down = last_down.clone();
        let (socket, client, reply_as, port) =
            (f.socket.clone(), f.client, f.reply_as.clone(), f.port);
        let by_name = matches!(f.target, TargetAddr::Domain(_));
        let watch = f.watch.clone();
        async move {
            let mut buf = Vec::new();
            let mut out = Vec::new();
            while let Ok((src, sport)) = session.recv(&mut buf).await {
                last_down.store(start.elapsed().as_millis() as u64, Ordering::Relaxed);
                if let Some(w) = &watch {
                    w.observe(&buf);
                }
                let (src, sport) = if by_name {
                    (&reply_as, port)
                } else {
                    (&src, sport)
                };
                out.clear();
                put_header(&mut out, src, sport);
                out.extend_from_slice(&buf);
                let _ = socket.send_to(&out, client).await;
            }
        }
    });
    loop {
        match next(f, rx).await {
            Ok(Some(p)) => {
                if p.len() > max {
                    f.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if session.send(&f.target, f.port, &p).await.is_err() {
                    break;
                }
            }
            // Association gone.
            Ok(None) => break,
            Err(_) => {
                // The downlink may have stored a later instant than ours.
                let quiet = (start.elapsed().as_millis() as u64)
                    .saturating_sub(last_down.load(Ordering::Relaxed));
                if down.is_finished() || quiet >= f.idle.as_millis() as u64 {
                    break;
                }
            }
        }
        if down.is_finished() {
            break;
        }
    }
    down.abort();
}

/// `RSV RSV FRAG ATYP ADDR PORT DATA` → target and payload. Fragments and
/// malformed headers give None.
fn parse_header(p: &[u8]) -> Option<(TargetAddr, u16, &[u8])> {
    if p.len() < 4 || p[2] != 0 {
        return None;
    }
    let (addr, rest) = match p[3] {
        1 => {
            let b: [u8; 4] = p.get(4..8)?.try_into().ok()?;
            (TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(b))), &p[8..])
        }
        4 => {
            let b: [u8; 16] = p.get(4..20)?.try_into().ok()?;
            (TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b))), &p[20..])
        }
        3 => {
            let len = *p.get(4)? as usize;
            let name = std::str::from_utf8(p.get(5..5 + len)?).ok()?;
            let addr = match name.parse::<IpAddr>() {
                Ok(ip) => TargetAddr::Ip(ip),
                Err(_) if !name.is_empty() => TargetAddr::Domain(name.to_owned()),
                Err(_) => return None,
            };
            (addr, &p[5 + len..])
        }
        _ => return None,
    };
    let port = u16::from_be_bytes(rest.get(..2)?.try_into().ok()?);
    Some((addr, port, &rest[2..]))
}

fn put_header(out: &mut Vec<u8>, addr: &TargetAddr, port: u16) {
    out.extend_from_slice(&[0, 0, 0]);
    match addr {
        TargetAddr::Ip(IpAddr::V4(v4)) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        TargetAddr::Ip(IpAddr::V6(v6)) => {
            out.push(4);
            out.extend_from_slice(&v6.octets());
        }
        TargetAddr::Domain(name) => {
            let name = &name.as_bytes()[..name.len().min(255)];
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name);
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
}

async fn reply_bound(
    conn: &mut TcpStream,
    code: u8,
    bound: Option<SocketAddr>,
) -> std::io::Result<()> {
    let mut r = vec![5, code, 0];
    let bound = bound.unwrap_or_else(|| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
    put_header(&mut r, &TargetAddr::Ip(bound.ip()), bound.port());
    // Drop the RSV RSV FRAG put_header wrote: a reply has its own VER REP RSV.
    r.drain(3..6);
    conn.write_all(&r).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        for (addr, port) in [
            (TargetAddr::Ip("1.2.3.4".parse().unwrap()), 53),
            (TargetAddr::Ip("2001:db8::1".parse().unwrap()), 443),
            (TargetAddr::Domain("example.com".into()), 8443),
        ] {
            let mut p = Vec::new();
            put_header(&mut p, &addr, port);
            p.extend_from_slice(b"hi");
            assert_eq!(parse_header(&p), Some((addr, port, &b"hi"[..])));
        }
    }

    #[test]
    fn fragments_and_junk_are_rejected() {
        let mut p = Vec::new();
        put_header(&mut p, &TargetAddr::Ip("1.2.3.4".parse().unwrap()), 53);
        p[2] = 1;
        assert_eq!(parse_header(&p), None);
        assert_eq!(parse_header(&[0, 0, 0, 1, 1, 2]), None);
        assert_eq!(parse_header(&[0, 0, 0, 3, 9, b'a']), None);
        assert_eq!(parse_header(&[0, 0, 0, 9]), None);
    }
}
