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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::dial::{Dialer, Stream};
use crate::fakeip::FakeIpPool;
use crate::rules::{Action, RuleSet};
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
    pub rules: RuleSet,
    pub dialer: Arc<dyn Dialer>,
    /// Present when the smart DNS is on; CONNECTs into its range are
    /// resolved through it.
    pub fake_ip: Option<Arc<FakeIpPool>>,
    /// None turns sniffing off: bare IPs are routed by IP rules only.
    pub sniff: Option<SniffSettings>,
    /// None: UDP ASSOCIATE is answered "command not supported".
    pub udp: Option<Arc<Udp>>,
}

impl Kernel {
    /// Rules + dialer only: no fake-IP, no sniffing.
    pub fn new(rules: RuleSet, dialer: Arc<dyn Dialer>) -> Self {
        Self {
            rules,
            dialer,
            fake_ip: None,
            sniff: None,
            udp: None,
        }
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
            let Some(entry) = pool.lookup(ip) else {
                reply(&mut conn, REP_NOT_ALLOWED).await?;
                return Ok(());
            };
            return connect_then_reply(
                conn,
                kernel,
                &entry.action,
                TargetAddr::Domain(entry.domain),
                port,
            )
            .await;
        }
        if let Some(settings) = kernel.sniff {
            return sniffed(conn, kernel, ip, port, settings).await;
        }
    }
    let action = kernel.rules.decide(&addr).clone();
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
    let mut upstream = match dial(kernel, tag, &addr, port).await {
        Some(stream) => stream,
        None => {
            reply(&mut conn, REP_HOST_UNREACHABLE).await?;
            return Ok(());
        }
    };
    reply(&mut conn, REP_OK).await?;
    tokio::io::copy_bidirectional(&mut conn, &mut upstream).await?;
    Ok(())
}

async fn dial(kernel: &Kernel, tag: Option<&str>, addr: &TargetAddr, port: u16) -> Option<Stream> {
    // A proxy route that fails is refused, never retried as direct.
    match tokio::time::timeout(DIAL_TIMEOUT, kernel.dialer.dial(tag, addr, port)).await {
        Ok(Ok(stream)) => Some(stream),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Bare-IP CONNECT with sniffing (§5.2a.1).
async fn sniffed(
    mut conn: TcpStream,
    kernel: &Kernel,
    ip: IpAddr,
    port: u16,
    s: SniffSettings,
) -> Result<(), Fail> {
    let by_ip = kernel.rules.lookup(&TargetAddr::Ip(ip));
    if let Some((_, Action::Reject)) = by_ip {
        // Nothing a sniffed name could do changes this; refuse before the
        // early success so the client gets a proper SOCKS error.
        reply(&mut conn, REP_NOT_ALLOWED).await?;
        return Ok(());
    }
    reply(&mut conn, REP_OK).await?;
    let (first, domain) = peek_host(&mut conn, s).await?;
    let by_domain = domain
        .as_ref()
        .and_then(|d| kernel.rules.lookup(&TargetAddr::Domain(d.clone())));
    let action = stricter(by_ip, by_domain)
        .unwrap_or_else(|| kernel.rules.default_action())
        .clone();
    let (tag, target) = match &action {
        Action::Reject => return reset(conn),
        // Direct goes to the address the client asked for, never to a
        // locally resolved sniffed name (that lookup would leak the name).
        Action::Direct => (None, TargetAddr::Ip(ip)),
        // The relay connects by name when there is one, which sidesteps a
        // polluted or stale IP.
        Action::Proxy(tag) => (
            Some(tag.as_str()),
            domain.map(TargetAddr::Domain).unwrap_or(TargetAddr::Ip(ip)),
        ),
    };
    let Some(mut upstream) = dial(kernel, tag, &target, port).await else {
        return reset(conn);
    };
    if !first.is_empty() {
        upstream.write_all(&first).await?;
    }
    tokio::io::copy_bidirectional(&mut conn, &mut upstream).await?;
    Ok(())
}

/// Combine the IP and the sniffed-domain verdicts (§5.2a.3/4, D8). Only
/// explicit rule matches have an opinion. Reject from either side wins.
/// Otherwise a matched sniffed domain decides the route (D8: an AI domain on
/// an IP that matched an ordinary proxy rule still goes to the AI exit), with
/// one exception: a domain saying Direct never downgrades an IP that matched a
/// proxy rule, so a forged or unrelated SNI cannot send AI/proxied IPs direct.
/// None: neither matched.
fn stricter<'a>(
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

/// Read the client's first bytes until a host name is found, the data is
/// clearly not TLS/HTTP, `max_bytes` is reached or the deadline passes.
/// The bytes are returned for replay; nothing is lost.
async fn peek_host(
    conn: &mut TcpStream,
    s: SniffSettings,
) -> std::io::Result<(Vec<u8>, Option<String>)> {
    let deadline = tokio::time::Instant::now() + s.timeout;
    let mut buf = Vec::with_capacity(2048);
    let mut chunk = vec![0u8; 4096];
    loop {
        let want = (s.max_bytes - buf.len()).min(chunk.len());
        if want == 0 {
            return Ok((buf, None));
        }
        let n = match tokio::time::timeout_at(deadline, conn.read(&mut chunk[..want])).await {
            Ok(r) => r?,
            Err(_) => return Ok((buf, None)), // server-speaks-first or slow client
        };
        if n == 0 {
            return Ok((buf, None));
        }
        buf.extend_from_slice(&chunk[..n]);
        match sniff(&buf) {
            Sniff::Domain(d) => return Ok((buf, Some(d))),
            Sniff::None => return Ok((buf, None)),
            Sniff::NeedMore => {}
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
