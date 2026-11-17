//! Local SOCKS5 entry point (CONNECT and UDP ASSOCIATE, no authentication,
//! loopback only). UDP lives in `crate::udp`.
//!
//! Domain targets: the success reply is sent only after the outbound dial
//! succeeds, so a failed proxy route reaches the application as a SOCKS
//! error instead of a half-open connection.
//!
//! Fake-IP targets (handed out by the smart DNS): routed by the recorded
//! domain and dialled by name; an unknown or stale fake address is refused.
//!
//! Other bare-IP targets (KERNEL_SPEC §5.2a): when sniffing is on, the kernel
//! answers success first, waits a bounded time for the client's first bytes,
//! takes the TLS SNI or HTTP Host, and routes by both the IP and the domain
//! (Reject wins, then the sniffed domain's rule, D8). The sniffed bytes are
//! replayed to the upstream unchanged.
//! A flow refused after the early success is reset (RST), as in §5.2a.5.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dial::{Dialer, Stream};
use crate::fakeip::FakeIpPool;
use crate::killswitch::{self, Admission, FlowPosture, HoldGuard};
use crate::policy::{Policy, PolicyStore};
use crate::rules::{Action, CidrTable, RuleSet};
use crate::sniff::{sniff, Sniff};
use crate::udp::{associate, Udp};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIAL_TIMEOUT: Duration = Duration::from_secs(15);

pub const REP_OK: u8 = 0x00;
pub const REP_GENERAL: u8 = 0x01;
pub const REP_NOT_ALLOWED: u8 = 0x02;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CMD_UNSUPPORTED: u8 = 0x07;
pub const REP_ATYP_UNSUPPORTED: u8 = 0x08;

const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;

pub struct Kernel {
    /// Rules in force (signed bundle, or inline in the lab). Each flow reads
    /// the current policy once.
    pub policy: Arc<PolicyStore>,
    pub dialer: Arc<dyn Dialer>,
    /// Present when the smart DNS is on; CONNECTs into its range are
    /// resolved through it.
    pub fake_ip: Option<Arc<FakeIpPool>>,
    /// None turns sniffing off: bare IPs are routed by IP rules only.
    pub sniff: Option<SniffSettings>,
    /// None: UDP ASSOCIATE is answered "command not supported".
    pub udp: Option<Arc<Udp>>,
    /// Hidden-name (real ECH) flows refused locally, shared by the SOCKS
    /// and TUN front ends.
    pub hidden: HiddenRefusals,
    /// Session kill switch. `None`: admission does not consult posture
    /// (a lab dialer, or an engine with no session routes).
    pub flows: Option<Arc<dyn FlowPosture>>,
}

impl Kernel {
    /// Rules + dialer only: no fake-IP, no sniffing.
    pub fn new(rules: RuleSet, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            policy: PolicyStore::inline(Policy::inline(rules, CidrTable::default())),
            dialer,
            fake_ip: None,
            sniff: None,
            udp: None,
            hidden: Default::default(),
            flows: None,
        }
    }

    /// Kill-switch verdict for `action`. With no session kill switch wired,
    /// the answer is the one admission treats as proceed.
    pub(crate) fn verdict_of(&self, action: &Action) -> killswitch::Verdict {
        let Some(src) = self.flows.as_ref() else {
            return match action {
                Action::Reject => killswitch::Verdict::Refuse,
                Action::Direct => killswitch::Verdict::Direct,
                Action::Proxy(tag) => killswitch::Verdict::Proxy(tag.clone()),
            };
        };
        match action {
            Action::Proxy(tag) => match src.protection(tag) {
                Some(protection) => killswitch::decide(src.posture(), action, protection),
                // An engine outbound is not a session route. It is refused
                // only while the user has Segue off, matching the dialer.
                None => {
                    if src.posture() == killswitch::Posture::Disconnected {
                        killswitch::Verdict::Release
                    } else {
                        killswitch::Verdict::Proxy(tag.clone())
                    }
                }
            },
            other => killswitch::decide(src.posture(), other, killswitch::Protection::Wait),
        }
    }

    /// Admission for a new flow. No kill switch: always proceed, so lab
    /// kernels keep today's behaviour.
    pub(crate) fn preview(&self, action: &Action, udp: bool) -> Admission {
        if self.flows.is_none() {
            return Admission::Proceed;
        }
        killswitch::admission(self.verdict_of(action), action, udp)
    }

    pub(crate) fn try_hold(&self) -> Option<HoldGuard> {
        self.flows.as_ref().and_then(|src| src.try_hold())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SniffSettings {
    /// Total time to wait for the client's first bytes (spec: 300 ms, TBD).
    pub timeout: Duration,
    /// Most bytes held back while looking for a host name.
    pub max_bytes: usize,
}

impl Default for SniffSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(300),
            max_bytes: 16 * 1024,
        }
    }
}

pub async fn serve(listener: TcpListener, kernel: Arc<Kernel>) -> std::io::Result<()> {
    loop {
        let (conn, _) = listener.accept().await?;
        let kernel = kernel.clone();
        tokio::spawn(async move {
            let _ = handle(conn, &kernel).await;
        });
    }
}

#[derive(Debug)]
enum Fail {
    Io(#[allow(dead_code)] std::io::Error),
    Reply(u8),
}

impl From<std::io::Error> for Fail {
    fn from(e: std::io::Error) -> Self {
        Fail::Io(e)
    }
}

async fn handle(mut conn: TcpStream, kernel: &Kernel) -> Result<(), Fail> {
    let _ = conn.set_nodelay(true);
    let request = tokio::time::timeout(HANDSHAKE_TIMEOUT, read_request(&mut conn))
        .await
        .map_err(|_| Fail::Io(std::io::ErrorKind::TimedOut.into()))?;
    let (cmd, addr, port) = match request {
        Ok(target) => target,
        Err(Fail::Reply(code)) => {
            reply(&mut conn, code).await?;
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let policy = kernel.policy.current();
    if policy.refuse_all {
        // No valid policy: fail closed (KERNEL_SPEC §5.4).
        reply(&mut conn, REP_NOT_ALLOWED).await?;
        return Ok(());
    }
    if cmd == CMD_UDP_ASSOCIATE {
        let Some(udp) = kernel.udp.as_ref() else {
            reply(&mut conn, REP_CMD_UNSUPPORTED).await?;
            return Ok(());
        };
        // DST.ADDR/PORT name where the client will send from; only the port
        // is used (the address must be the TCP peer's anyway).
        associate(conn, kernel, udp, port).await?;
        return Ok(());
    }
    if let TargetAddr::Ip(ip) = addr {
        if let Some(pool) = kernel.fake_ip.as_ref().filter(|p| p.contains(ip)) {
            // A fake address is never dialled as an IP.
            // The pool only remembers the name; the flow is authorized
            // against the policy in force now.
            let Some(entry) = pool.lookup(ip) else {
                reply(&mut conn, REP_NOT_ALLOWED).await?;
                return Ok(());
            };
            let action = policy.decide_fake(&entry.domain).clone();
            return connect_then_reply(
                conn,
                kernel,
                &action,
                TargetAddr::Domain(entry.domain),
                port,
            )
            .await;
        }
        if let Some(settings) = kernel.sniff {
            return sniffed(conn, kernel, &policy, ip, port, settings).await;
        }
    }
    let action = policy.rules.decide(&addr).clone();
    drop(policy);
    connect_then_reply(conn, kernel, &action, addr, port).await
}

/// Dial first, then tell the client how it went.
async fn connect_then_reply(
    mut conn: TcpStream,
    kernel: &Kernel,
    action: &Action,
    addr: TargetAddr,
    port: u16,
) -> Result<(), Fail> {
    let tag = match action {
        Action::Reject => {
            reply(&mut conn, REP_NOT_ALLOWED).await?;
            return Ok(());
        }
        Action::Direct => None,
        Action::Proxy(tag) => Some(tag.as_str()),
    };
    // Held, not refused, while the kill switch says Wait. The SOCKS success
    // is still sent only after the dial, so a deadline is a normal refusal.
    if !kill_switch_allows(kernel, action).await {
        reply(&mut conn, REP_HOST_UNREACHABLE).await?;
        return Ok(());
    }
    let upstream = match dial(kernel, tag, &addr, port).await {
        Some(stream) => stream,
        None => {
            reply(&mut conn, REP_HOST_UNREACHABLE).await?;
            return Ok(());
        }
    };
    reply(&mut conn, REP_OK).await?;
    splice(conn, upstream).await
}

/// Relay both ways. An upstream that ends with an error (a session reset,
/// revoked, failed) is passed on as RST, never as FIN: the client must not
/// take a truncated response for a complete one.
async fn splice(mut conn: TcpStream, mut upstream: Stream) -> Result<(), Fail> {
    match tokio::io::copy_bidirectional(&mut conn, &mut upstream).await {
        Ok(_) => Ok(()),
        Err(e) => {
            drop(upstream);
            let _ = reset(conn);
            Err(e.into())
        }
    }
}

/// `false`: refuse the way a failed dial is refused. [`Admission::Hold`]
/// waits until the posture leaves Wait or the per-flow deadline passes,
/// then refuses if it is still not a dial.
async fn kill_switch_allows(kernel: &Kernel, action: &Action) -> bool {
    match kernel.preview(action, false) {
        Admission::Proceed => true,
        Admission::Refuse => false,
        Admission::Hold => {
            let Some(guard) = kernel.try_hold() else {
                return false;
            };
            let verdict = killswitch::wait_out(|| kernel.verdict_of(action)).await;
            drop(guard);
            matches!(
                verdict,
                killswitch::Verdict::Proxy(_) | killswitch::Verdict::Direct
            )
        }
    }
}

async fn dial(kernel: &Kernel, tag: Option<&str>, addr: &TargetAddr, port: u16) -> Option<Stream> {
    // A proxy route that fails is refused, never retried as direct.
    match tokio::time::timeout(DIAL_TIMEOUT, kernel.dialer.dial(tag, addr, port)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(e)) => {
            eprintln!(
                "segue-kernel: dial via {} failed: {e}",
                tag.unwrap_or("direct")
            );
            None
        }
        Err(_) => {
            eprintln!(
                "segue-kernel: dial via {} timed out",
                tag.unwrap_or("direct")
            );
            None
        }
    }
}

/// Bare-IP CONNECT with sniffing (§5.2a.1).
async fn sniffed(
    mut conn: TcpStream,
    kernel: &Kernel,
    policy: &Policy,
    ip: IpAddr,
    port: u16,
    s: SniffSettings,
) -> Result<(), Fail> {
    if let Some((_, Action::Reject)) = policy.rules.lookup(&TargetAddr::Ip(ip)) {
        // Nothing a sniffed name could do changes this; refuse before the
        // early success so the client gets a proper SOCKS error.
        reply(&mut conn, REP_NOT_ALLOWED).await?;
        return Ok(());
    }
    reply(&mut conn, REP_OK).await?;
    let (first, found) = peek_host(&mut conn, s).await?;
    let dst = SocketAddr::new(ip, port);
    let Some((tag, target)) = sniffed_route(policy, dst, &found, &kernel.hidden) else {
        return reset(conn);
    };
    let action = match &tag {
        Some(t) => Action::Proxy(t.clone()),
        None => Action::Direct,
    };
    // The success reply is already out (the handshake had to complete to
    // sniff). A wait holds the flow; a refusal or a deadline resets it,
    // the same as a dial that fails after the early success.
    if !kill_switch_allows(kernel, &action).await {
        return reset(conn);
    }
    let tag = tag.as_deref();
    let Some(mut upstream) = dial(kernel, tag, &target, port).await else {
        return reset(conn);
    };
    if !first.is_empty() && upstream.write_all(&first).await.is_err() {
        return reset(conn);
    }
    splice(conn, upstream).await
}

/// Combine the IP and the sniffed-domain verdicts (§5.2a.3/4, D8). Only
/// explicit rule matches have an opinion. Reject from either side wins.
/// Otherwise a matched sniffed domain decides the route (D8: an AI domain on
/// an IP that matched an ordinary proxy rule still goes to the AI exit), with
/// one exception: a domain saying Direct never downgrades an IP that matched a
/// proxy rule, so a forged or unrelated SNI cannot send AI/proxied IPs direct.
/// None: neither matched.
pub(crate) fn stricter<'a>(
    by_ip: Option<(usize, &'a Action)>,
    by_domain: Option<(usize, &'a Action)>,
) -> Option<&'a Action> {
    match (by_ip, by_domain) {
        (None, None) => None,
        (Some((_, x)), None) | (None, Some((_, x))) => Some(x),
        (Some((_, ip)), Some((_, dom))) => Some(match (ip, dom) {
            (Action::Reject, _) | (Action::Proxy(_), Action::Direct) => ip,
            _ => dom,
        }),
    }
}

/// Route of a bare-IP TCP flow to `dst` once sniffing is over (§5.2a.1),
/// None to refuse. `found` is final: [`Sniff::NeedMore`] (timeout,
/// `max_bytes`) counts as no name.
///
/// - A name: the stricter of its rule and the IP's ([`stricter`]); the
///   relay connects by that name unless the route is direct.
/// - No name (not TLS/HTTP, no SNI, server speaks first, sniff timeout):
///   the IP rules alone (an accepted boundary: such a flow to an AI
///   service's IP outside the AI CIDRs is routed as that IP says).
/// - An ECH extension (astra r10 N2) whose SNI is not a known ECH public
///   name ([`Policy::is_ech_public_name`]): treated as GREASE (RFC 9849
///   §6.2), the SNI routed like a real name. A heuristic (r11 R1): real
///   ECH behind an unlisted public name is routed by its outer name too,
///   so an AI inner name can leave by the overseas route; a broad listed
///   suffix refuses ordinary GREASE under it (KERNEL_SPEC §5.2a.1).
/// - A hidden name: ECH with a known public name as SNI, or with no SNI.
///   Rejected IP: refused. IP in the bundle's AI ranges:
///   [`Policy::hidden_name`] (the AI route) to the IP. Any other IP:
///   refused here, counted in `hidden` ([`HiddenRefusals`]), never sent to
///   the relay. The outer SNI is never looked up: it names the
///   client-facing server, which fronts AI and non-AI names alike.
pub(crate) fn sniffed_route(
    policy: &Policy,
    dst: SocketAddr,
    found: &Sniff,
    hidden: &HiddenRefusals,
) -> Option<(Option<String>, TargetAddr)> {
    let ip = dst.ip();
    let rules = &policy.rules;
    let by_ip = rules.lookup(&TargetAddr::Ip(ip));
    let named = match found {
        Sniff::Domain(d) => Some(d),
        Sniff::Ech { outer: Some(d) } if !policy.is_ech_public_name(d) => Some(d),
        _ => None,
    };
    let (action, name) = match (found, named) {
        (_, Some(d)) => {
            let by_domain = rules.lookup(&TargetAddr::Domain(d.clone()));
            let a = stricter(by_ip, by_domain).unwrap_or_else(|| rules.default_action());
            (a, Some(d))
        }
        (Sniff::Ech { .. }, None) => match by_ip {
            Some((_, Action::Reject)) => (&Action::Reject, None),
            _ if policy.ai_ips.contains(ip) => (&policy.hidden_name, None),
            _ => {
                hidden.refuse(dst, Instant::now());
                (&Action::Reject, None)
            }
        },
        _ => (by_ip.map_or(rules.default_action(), |(_, a)| a), None),
    };
    match action {
        Action::Reject => None,
        // Direct goes to the address the client asked for, never to a
        // locally resolved sniffed name (that lookup would leak the name).
        Action::Direct => Some((None, TargetAddr::Ip(ip))),
        // The relay connects by name when there is one, which sidesteps a
        // polluted or stale IP.
        Action::Proxy(tag) => Some((
            Some(tag.clone()),
            name.map_or(TargetAddr::Ip(ip), |d| TargetAddr::Domain(d.clone())),
        )),
    }
}

/// Hidden-name (real ECH) flows refused locally (astra r10 N2): a count,
/// and a token bucket per destination (IP, port) so that an app retrying
/// in a loop logs a few lines, not one per attempt. The refusal itself is
/// never rate limited: every such flow is refused, none reaches the relay.
/// Refusing new SYNs to a destination outright would also cut off the
/// GREASE and plain-TLS flows that share the IP (a CDN front), so the
/// limiter only decides what is reported.
#[derive(Debug, Default)]
pub struct HiddenRefusals {
    refused: AtomicU64,
    logged: AtomicU64,
    buckets: Mutex<HashMap<SocketAddr, (f64, Instant)>>,
}

impl HiddenRefusals {
    /// Reports per destination at once.
    pub const BURST: f64 = 3.0;
    /// Then one report per this long.
    pub const REFILL: Duration = Duration::from_secs(60);
    /// Most destinations tracked; beyond, new ones are not reported.
    pub const MAX_TRACKED: usize = 1024;

    /// Every hidden-name flow refused locally.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }

    /// Of those, how many were reported (passed the per-destination bucket).
    pub fn logged(&self) -> u64 {
        self.logged.load(Ordering::Relaxed)
    }

    /// Count one refusal to `dst` at `now`; true if it is reported.
    pub fn refuse(&self, dst: SocketAddr, now: Instant) -> bool {
        self.refused.fetch_add(1, Ordering::Relaxed);
        let refill = |(tokens, at): (f64, Instant)| {
            let t = tokens
                + now.saturating_duration_since(at).as_secs_f64() / Self::REFILL.as_secs_f64();
            t.min(Self::BURST)
        };
        let mut b = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if b.len() >= Self::MAX_TRACKED && !b.contains_key(&dst) {
            // Forget destinations whose bucket has refilled.
            b.retain(|_, v| refill(*v) < Self::BURST);
            if b.len() >= Self::MAX_TRACKED {
                return false;
            }
        }
        let e = b.entry(dst).or_insert((Self::BURST, now));
        let tokens = refill(*e);
        let report = tokens >= 1.0;
        *e = (if report { tokens - 1.0 } else { tokens }, now);
        drop(b);
        if report {
            self.logged.fetch_add(1, Ordering::Relaxed);
            eprintln!(
                "segue-kernel: refused {dst}: ECH hides the server name and the address is not in the AI ranges ({} so far)",
                self.refused()
            );
        }
        report
    }
}

/// Read the client's first bytes until a host name is found (or found
/// hidden), the data is clearly not TLS/HTTP, `max_bytes` is reached or
/// the deadline passes. The bytes are returned for replay; nothing is
/// lost. The result is final: never [`Sniff::NeedMore`].
async fn peek_host(conn: &mut TcpStream, s: SniffSettings) -> std::io::Result<(Vec<u8>, Sniff)> {
    let deadline = tokio::time::Instant::now() + s.timeout;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = vec![0u8; 4096];
    loop {
        let want = (s.max_bytes - buf.len()).min(chunk.len());
        if want == 0 {
            return Ok((buf, Sniff::None));
        }
        let n = match tokio::time::timeout_at(deadline, conn.read(&mut chunk[..want])).await {
            Ok(r) => r?,
            Err(_) => return Ok((buf, Sniff::None)), // server-speaks-first or slow client
        };
        if n == 0 {
            return Ok((buf, Sniff::None));
        }
        buf.extend_from_slice(&chunk[..n]);
        match sniff(&buf) {
            Sniff::NeedMore => {}
            found => return Ok((buf, found)),
        }
    }
}

/// Refuse a flow that has already been told "success": RST, not FIN.
fn reset(conn: TcpStream) -> Result<(), Fail> {
    let _ = conn.set_zero_linger();
    drop(conn);
    Ok(())
}

async fn read_request(conn: &mut TcpStream) -> Result<(u8, TargetAddr, u16), Fail> {
    let mut head = [0u8; 2];
    conn.read_exact(&mut head).await?;
    if head[0] != 5 {
        return Err(Fail::Io(std::io::ErrorKind::InvalidData.into()));
    }
    let mut methods = vec![0u8; head[1] as usize];
    conn.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        conn.write_all(&[5, 0xff]).await?;
        return Err(Fail::Io(std::io::ErrorKind::PermissionDenied.into()));
    }
    conn.write_all(&[5, 0]).await?;

    let mut req = [0u8; 4];
    conn.read_exact(&mut req).await?;
    if req[0] != 5 {
        return Err(Fail::Io(std::io::ErrorKind::InvalidData.into()));
    }
    let addr = match req[3] {
        1 => {
            let mut b = [0u8; 4];
            conn.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(b)))
        }
        4 => {
            let mut b = [0u8; 16];
            conn.read_exact(&mut b).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        3 => {
            let len = conn.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            conn.read_exact(&mut b).await?;
            let name = String::from_utf8(b).map_err(|_| Fail::Reply(REP_GENERAL))?;
            // A literal IP sent as a hostname is routed as an IP.
            match name.parse::<IpAddr>() {
                Ok(ip) => TargetAddr::Ip(ip),
                Err(_) if !name.is_empty() => TargetAddr::Domain(name),
                Err(_) => return Err(Fail::Reply(REP_GENERAL)),
            }
        }
        _ => return Err(Fail::Reply(REP_ATYP_UNSUPPORTED)),
    };
    let port = conn.read_u16().await?;
    if req[1] != CMD_CONNECT && req[1] != CMD_UDP_ASSOCIATE {
        return Err(Fail::Reply(REP_CMD_UNSUPPORTED));
    }
    Ok((req[1], addr, port))
}

async fn reply(conn: &mut TcpStream, code: u8) -> std::io::Result<()> {
    conn.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await
}
