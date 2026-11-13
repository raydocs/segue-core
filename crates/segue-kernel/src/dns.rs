//! Smart DNS (KERNEL_SPEC §5.2).
//!
//! A loopback DNS listener (UDP and TCP) that answers per the rule table:
//!
//! | name | answer |
//! |---|---|
//! | `use-application-dns.net` | NXDOMAIN (Firefox turns its own DoH off) |
//! | explicit `proxy` / `reject` domain rule | local fake-IP, no network request |
//! | explicit `direct` domain rule (the domestic list) | domestic resolvers, real IP |
//! | no domain rule | domestic resolvers only; every address inside chnroute → real IP, otherwise treated as polluted / foreign → fake-IP routed by the policy's foreign route (the bundle `default`) |
//!
//! No valid policy (no bundle yet, or it expired): every query is REFUSED,
//! with no cache read, no fake-IP and no upstream query.
//!
//! The fake-IP pool records only the name; a flow to a fake address is
//! authorized against the policy in force when the flow starts
//! ([`crate::policy::Policy::decide_fake`]).
//!
//! Foreign names are never resolved here: the relay resolves them at the exit
//! (§5.2.5), so there is no DoH/DoT client in the kernel. A fake-IP CONNECT
//! is dialled by domain.
//!
//! Domestic upstreams are queried in parallel; the first valid answer wins.
//! A/AAAA answers are cached by upstream TTL and served stale while a
//! background refresh runs (optimistic cache, §5.2.1).
//!
//! Not done: ECS, TCP fallback to upstreams on a truncated reply, binding
//! upstream sockets to a protected interface (the shell's job under TUN).

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use segue_routing::TargetAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinSet;

use crate::fakeip::FakeIpPool;
use crate::policy::{Policy, PolicyStore};
use crate::rules::{normalize, Action};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

pub const RCODE_OK: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_REFUSED: u8 = 5;

/// Negative answers (NXDOMAIN / NODATA) are cached this long.
const NEGATIVE_TTL: u32 = 30;
/// A cache entry this far past its expiry is no longer served stale.
const MAX_STALE: Duration = Duration::from_secs(3600);
const TCP_IDLE: Duration = Duration::from_secs(10);

pub struct DnsSettings {
    pub domestic: Vec<SocketAddr>,
    pub query_timeout: Duration,
    pub cache_size: usize,
}

/// What a domestic resolver said, independent of any policy. Classifying it
/// (real IP vs foreign → fake-IP) happens when answering, against the policy
/// in force then, so a cached answer never carries an old decision.
#[derive(Clone, Debug)]
struct Raw {
    rcode: u8,
    ips: Vec<IpAddr>,
}

struct CacheEntry {
    value: Raw,
    expires: Instant,
}

pub struct SmartDns {
    /// Rules, chnroute and the foreign route come from the policy in force.
    policy: Arc<PolicyStore>,
    pool: Arc<FakeIpPool>,
    s: DnsSettings,
    cache: Mutex<HashMap<(String, u16), CacheEntry>>,
    refreshing: Mutex<HashSet<(String, u16)>>,
    upstream_limit: tokio::sync::Semaphore,
    /// Upstream exchanges started (tests use it to check cache hits).
    pub upstream_queries: std::sync::atomic::AtomicUsize,
}

/// The parsed single question of a query.
struct Question<'a> {
    id: u16,
    rd: bool,
    /// Raw question bytes (name + type + class), echoed back verbatim.
    raw: &'a [u8],
    name: String,
    qtype: u16,
}

enum Class {
    /// Explicit proxy / reject domain rule: fake-IP, no network request.
    Fake,
    /// Explicit direct domain rule: real answer.
    Domestic,
    /// No domain rule: real answer if all in chnroute, else foreign.
    Unmatched,
}

fn classify(policy: &Policy, name: &str) -> Class {
    match policy.rules.lookup(&TargetAddr::Domain(name.to_owned())) {
        Some((_, Action::Direct)) => Class::Domestic,
        Some(_) => Class::Fake,
        None => Class::Unmatched,
    }
}

impl SmartDns {
    pub fn new(policy: Arc<PolicyStore>, pool: Arc<FakeIpPool>, s: DnsSettings) -> Self {
        Self {
            policy,
            pool,
            s,
            cache: Mutex::new(HashMap::new()),
            refreshing: Mutex::new(HashSet::new()),
            upstream_limit: tokio::sync::Semaphore::new(MAX_UPSTREAM_IN_FLIGHT),
            upstream_queries: Default::default(),
        }
    }

    /// Answer one DNS message. None means "drop it" (not even a header).
    ///
    /// Without a valid policy every query is answered REFUSED before the
    /// cache, the fake-IP pool or any upstream is touched (§5.4). The policy
    /// is read again after every upstream wait; an answer is always rendered
    /// under the policy in force when it is sent.
    pub async fn handle(self: &Arc<Self>, query: &[u8]) -> Option<Vec<u8>> {
        let q = match parse_question(query) {
            Ok(q) => q,
            Err(Some((id, rd))) => return Some(header_only(id, rd, RCODE_FORMERR)),
            Err(None) => return None,
        };
        let policy = self.policy.current();
        if policy.refuse_all {
            return Some(respond(&q, RCODE_REFUSED, &[], 0));
        }
        if q.name == "use-application-dns.net" {
            return Some(respond(&q, RCODE_NXDOMAIN, &[], 0));
        }
        if q.name.is_empty() {
            return self.passthrough(query, &q).await;
        }
        match (classify(&policy, &q.name), q.qtype) {
            (Class::Fake, TYPE_A) => Some(
                self.fake_answer(&q, &policy, |p| matches!(classify(p, &q.name), Class::Fake))
                    .await,
            ),
            // The pool is IPv4 only; AAAA for proxied names is NODATA so
            // clients use the fake A record (§5.2.6).
            (Class::Fake, _) => Some(respond(&q, RCODE_OK, &[], 0)),
            (_, TYPE_A | TYPE_AAAA) => Some(self.resolve_cached(&q).await),
            // Non-A/AAAA for domestic / unmatched names: straight through.
            (_, _) => self.passthrough(query, &q).await,
        }
    }

    /// A new binding is durable (persistence thread) before this answers;
    /// that wait is bounded ([`crate::fakeip::DURABLE_TIMEOUT`], SERVFAIL
    /// past it). The policy is read again after it (r7 #5): REFUSED if it
    /// went away, SERVFAIL (the client asks again and gets the new
    /// policy's answer) if the policy now in force no longer gives this
    /// name a fake address (`still_fake`).
    async fn fake_answer(
        &self,
        q: &Question<'_>,
        policy: &Policy,
        still_fake: impl Fn(&Policy) -> bool,
    ) -> Vec<u8> {
        let ip = self.pool.assign_durable(&q.name, policy.version).await;
        let now = self.policy.current();
        if now.refuse_all {
            return respond(q, RCODE_REFUSED, &[], 0);
        }
        match ip {
            Some(ip) if now.version == policy.version || still_fake(&now) => respond(
                q,
                RCODE_OK,
                &[IpAddr::V4(ip)],
                self.pool.ttl.as_secs().max(1) as u32,
            ),
            _ => respond(q, RCODE_SERVFAIL, &[], 0),
        }
    }

    async fn resolve_cached(self: &Arc<Self>, q: &Question<'_>) -> Vec<u8> {
        let key = (q.name.clone(), q.qtype);
        let now = Instant::now();
        let hit = {
            let cache = self.cache.lock().expect("dns cache");
            cache.get(&key).and_then(|e| {
                if now <= e.expires {
                    Some((
                        e.value.clone(),
                        (e.expires - now).as_secs().max(1) as u32,
                        false,
                    ))
                } else if now - e.expires <= MAX_STALE {
                    Some((e.value.clone(), 1, true))
                } else {
                    None
                }
            })
        };
        if let Some((value, ttl, stale)) = hit {
            if stale {
                self.spawn_refresh(key);
            }
            return self.render(q, value, ttl).await;
        }
        match self.resolve(&q.name, q.qtype).await {
            Some((value, ttl)) => {
                self.store(key, value.clone(), ttl);
                self.render(q, value, ttl.max(1)).await
            }
            None => self.after_wait(q, || respond(q, RCODE_SERVFAIL, &[], 0)),
        }
    }

    /// The answer for a name that needed (or once needed) the domestic
    /// resolvers, decided under the policy in force now.
    async fn render(&self, q: &Question<'_>, value: Raw, ttl: u32) -> Vec<u8> {
        let policy = self.policy.current();
        if policy.refuse_all {
            return respond(q, RCODE_REFUSED, &[], 0);
        }
        let foreign = |policy: &Policy| match classify(policy, &q.name) {
            // The policy changed while we waited and now proxies the name.
            Class::Fake => true,
            Class::Domestic => false,
            Class::Unmatched => {
                !value.ips.is_empty() && !value.ips.iter().all(|ip| policy.chnroute.contains(*ip))
            }
        };
        match (foreign(&policy), q.qtype) {
            (false, _) => respond(q, value.rcode, &value.ips, ttl),
            (true, TYPE_A) => self.fake_answer(q, &policy, foreign).await,
            (true, _) => respond(q, RCODE_OK, &[], 0),
        }
    }

    /// After an upstream wait that produced no answer: REFUSED if the
    /// policy went away meanwhile, else `other`.
    fn after_wait(&self, q: &Question<'_>, other: impl FnOnce() -> Vec<u8>) -> Vec<u8> {
        if self.policy.current().refuse_all {
            respond(q, RCODE_REFUSED, &[], 0)
        } else {
            other()
        }
    }

    fn spawn_refresh(self: &Arc<Self>, key: (String, u16)) {
        if !self
            .refreshing
            .lock()
            .expect("refreshing")
            .insert(key.clone())
        {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            // A refresh is an upstream query too: none without a policy.
            if !me.policy.current().refuse_all {
                if let Some((value, ttl)) = me.resolve(&key.0, key.1).await {
                    me.store(key.clone(), value, ttl);
                }
            }
            me.refreshing.lock().expect("refreshing").remove(&key);
        });
    }

    fn store(&self, key: (String, u16), value: Raw, ttl: u32) {
        let mut cache = self.cache.lock().expect("dns cache");
        if cache.len() >= self.s.cache_size && !cache.contains_key(&key) {
            let now = Instant::now();
            cache.retain(|_, e| e.expires > now);
            if cache.len() >= self.s.cache_size {
                cache.clear();
            }
        }
        cache.insert(
            key,
            CacheEntry {
                value,
                expires: Instant::now() + Duration::from_secs(u64::from(ttl)),
            },
        );
    }

    /// Ask the domestic resolvers. None on upstream failure.
    async fn resolve(&self, name: &str, qtype: u16) -> Option<(Raw, u32)> {
        let id: u16 = rand::random();
        let mut packet = Vec::with_capacity(32 + name.len());
        packet.extend_from_slice(&id.to_be_bytes());
        packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        encode_name(&mut packet, name)?;
        packet.extend_from_slice(&qtype.to_be_bytes());
        packet.extend_from_slice(&CLASS_IN.to_be_bytes());
        let reply = self.race(packet).await?;
        let (rcode, ips, ttl) = parse_answers(&reply, qtype)?;
        if rcode != RCODE_OK && rcode != RCODE_NXDOMAIN {
            return None;
        }
        let ttl = if ips.is_empty() { NEGATIVE_TTL } else { ttl };
        Some((Raw { rcode, ips }, ttl))
    }

    /// Forward the client's own message to the domestic resolvers.
    async fn passthrough(&self, query: &[u8], q: &Question<'_>) -> Option<Vec<u8>> {
        let id: u16 = rand::random();
        let mut packet = query.to_vec();
        packet[..2].copy_from_slice(&id.to_be_bytes());
        match self.race(packet).await {
            Some(_) if self.policy.current().refuse_all => Some(respond(q, RCODE_REFUSED, &[], 0)),
            Some(mut reply) => {
                reply[..2].copy_from_slice(&q.id.to_be_bytes());
                Some(reply)
            }
            None => Some(self.after_wait(q, || respond(q, RCODE_SERVFAIL, &[], 0))),
        }
    }

    /// Send `packet` to every domestic resolver at once; first valid reply.
    async fn race(&self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let _permit = self.upstream_limit.try_acquire().ok()?;
        self.upstream_queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let packet = Arc::new(packet);
        let mut set = JoinSet::new();
        for &server in &self.s.domestic {
            let packet = packet.clone();
            let timeout = self.s.query_timeout;
            set.spawn(
                async move { tokio::time::timeout(timeout, exchange(server, &packet)).await },
            );
        }
        // First definitive answer (NOERROR/NXDOMAIN) wins; a fast
        // SERVFAIL/REFUSED must not beat a good answer still in flight.
        let mut fallback = None;
        while let Some(done) = set.join_next().await {
            if let Ok(Ok(Ok(reply))) = done {
                let rcode = reply.get(3).map_or(RCODE_SERVFAIL, |b| b & 0x0f);
                if rcode == RCODE_OK || rcode == RCODE_NXDOMAIN {
                    return Some(reply);
                }
                fallback = Some(reply);
            }
        }
        fallback
    }
}

/// One UDP exchange. Replies with the wrong ID or question are ignored
/// (spoofed or late), not treated as the answer.
async fn exchange(server: SocketAddr, packet: &[u8]) -> std::io::Result<Vec<u8>> {
    let bind: SocketAddr = if server.is_ipv4() {
        (Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(server).await?;
    sock.send(packet).await?;
    let want_q = question_bytes(packet).ok_or(std::io::ErrorKind::InvalidInput)?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = sock.recv(&mut buf).await?;
        let r = &buf[..n];
        if n >= 12 && r[..2] == packet[..2] && r[2] & 0x80 != 0 {
            if let Some(got_q) = question_bytes(r) {
                if got_q.eq_ignore_ascii_case(want_q) {
                    return Ok(r.to_vec());
                }
            }
        }
    }
}

/// Bytes of the single question section, if the message has exactly one.
fn question_bytes(msg: &[u8]) -> Option<&[u8]> {
    if msg.len() < 12 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return None;
    }
    let end = skip_name(msg, 12)?.checked_add(4)?;
    msg.get(12..end)
}

/// Err(Some(id, rd)) = answer FORMERR; Err(None) = drop.
fn parse_question(msg: &[u8]) -> Result<Question<'_>, Option<(u16, bool)>> {
    if msg.len() < 12 {
        return Err(None);
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let rd = msg[2] & 0x01 != 0;
    if msg[2] & 0x80 != 0 {
        return Err(None); // a response, not a query
    }
    let opcode = (msg[2] >> 3) & 0x0f;
    if opcode != 0 || u16::from_be_bytes([msg[4], msg[5]]) != 1 {
        return Err(Some((id, rd)));
    }
    // Names in a question are never compressed; refusing pointers here
    // means no pointer chasing at all on client input.
    let mut p = 12;
    let mut labels: Vec<String> = Vec::new();
    let mut total = 0usize;
    loop {
        let len = *msg.get(p).ok_or(Some((id, rd)))? as usize;
        p += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err(Some((id, rd)));
        }
        let label = msg.get(p..p + len).ok_or(Some((id, rd)))?;
        total += len + 1;
        if total > 255 {
            return Err(Some((id, rd)));
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        p += len;
    }
    let tail = msg.get(p..p + 4).ok_or(Some((id, rd)))?;
    let qtype = u16::from_be_bytes([tail[0], tail[1]]);
    Ok(Question {
        id,
        rd,
        raw: &msg[12..p + 4],
        name: normalize(&labels.join(".")),
        qtype,
    })
}

/// Advance past a (possibly compressed) name without following pointers.
fn skip_name(msg: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let len = *msg.get(p)?;
        match len {
            0 => return Some(p + 1),
            l if l & 0xc0 == 0xc0 => {
                msg.get(p + 1)?;
                return Some(p + 2);
            }
            l if l > 63 => return None,
            l => p += 1 + l as usize,
        }
    }
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Option<()> {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        if label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Some(())
}

/// (rcode, addresses of `qtype`, min TTL over the answer section).
fn parse_answers(msg: &[u8], qtype: u16) -> Option<(u8, Vec<IpAddr>, u32)> {
    if msg.len() < 12 {
        return None;
    }
    let rcode = msg[3] & 0x0f;
    let qd = u16::from_be_bytes([msg[4], msg[5]]);
    let an = u16::from_be_bytes([msg[6], msg[7]]);
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(msg, p)?.checked_add(4)?;
    }
    let mut ips = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..an {
        p = skip_name(msg, p)?;
        let h = msg.get(p..p + 10)?;
        let rtype = u16::from_be_bytes([h[0], h[1]]);
        let class = u16::from_be_bytes([h[2], h[3]]);
        let rttl = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let rdlen = u16::from_be_bytes([h[8], h[9]]) as usize;
        let data = msg.get(p + 10..p + 10 + rdlen)?;
        p += 10 + rdlen;
        if class != CLASS_IN {
            continue;
        }
        ttl = ttl.min(rttl);
        match (rtype, qtype, data.len()) {
            (TYPE_A, TYPE_A, 4) => ips.push(IpAddr::V4(Ipv4Addr::new(
                data[0], data[1], data[2], data[3],
            ))),
            (TYPE_AAAA, TYPE_AAAA, 16) => {
                let mut b = [0u8; 16];
                b.copy_from_slice(data);
                ips.push(IpAddr::V6(Ipv6Addr::from(b)));
            }
            _ => {}
        }
    }
    if ttl == u32::MAX {
        ttl = NEGATIVE_TTL;
    }
    Some((rcode, ips, ttl))
}

fn header_only(id: u16, rd: bool, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.push(0x80 | u8::from(rd));
    out.push(0x80 | rcode);
    out.extend_from_slice(&[0; 8]);
    out
}

/// Response echoing the client's question, with `ips` that match its type.
fn respond(q: &Question<'_>, rcode: u8, ips: &[IpAddr], ttl: u32) -> Vec<u8> {
    let answers: Vec<&IpAddr> = ips
        .iter()
        .filter(|ip| {
            matches!(
                (ip, q.qtype),
                (IpAddr::V4(_), TYPE_A) | (IpAddr::V6(_), TYPE_AAAA)
            )
        })
        .collect();
    let mut out = Vec::with_capacity(12 + q.raw.len() + answers.len() * 28);
    out.extend_from_slice(&q.id.to_be_bytes());
    out.push(0x80 | u8::from(q.rd));
    out.push(0x80 | rcode);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(q.raw);
    for ip in answers {
        out.extend_from_slice(&[0xc0, 0x0c]);
        let (ty, data): (u16, Vec<u8>) = match ip {
            IpAddr::V4(a) => (TYPE_A, a.octets().to_vec()),
            IpAddr::V6(a) => (TYPE_AAAA, a.octets().to_vec()),
        };
        out.extend_from_slice(&ty.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
    }
    out
}

/// Most upstream exchanges in flight (client queries and background
/// refreshes). Each holds a 64 KiB receive buffer per domestic resolver, so
/// this bounds memory when resolvers hang; over the limit a query gets
/// SERVFAIL. Local answers (fake-IP, cache, canary) are never limited.
const MAX_UPSTREAM_IN_FLIGHT: usize = 256;
/// Most DNS-over-TCP connections at once; further accepts wait.
const MAX_TCP_CONNS: usize = 256;
/// Most UDP queries being answered at once (r7 #5). Each is bounded in time
/// (upstream timeout, fake-IP durable timeout); over this a query is
/// answered SERVFAIL at once instead of spawning another task.
pub const MAX_UDP_IN_FLIGHT: usize = 512;

/// Serve DNS over UDP on `sock`. Per-datagram errors (e.g. an ICMP
/// port-unreachable from a client that went away, which some platforms
/// report on the next receive) do not stop the listener.
pub async fn serve_udp(sock: UdpSocket, dns: Arc<SmartDns>) -> std::io::Result<()> {
    serve_udp_limited(sock, dns, MAX_UDP_IN_FLIGHT).await
}

async fn serve_udp_limited(
    sock: UdpSocket,
    dns: Arc<SmartDns>,
    limit: usize,
) -> std::io::Result<()> {
    let sock = Arc::new(sock);
    let limit = Arc::new(tokio::sync::Semaphore::new(limit));
    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(r) => r,
            Err(e) if transient(&e) => continue,
            Err(e) => return Err(e),
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            // Overloaded: a header-only SERVFAIL, never queued.
            let reply = match parse_question(&buf[..n]) {
                Ok(q) => respond(&q, RCODE_SERVFAIL, &[], 0),
                Err(Some((id, rd))) => header_only(id, rd, RCODE_FORMERR),
                Err(None) => continue,
            };
            let _ = sock.try_send_to(&reply, peer);
            continue;
        };
        let msg = buf[..n].to_vec();
        let (sock, dns) = (sock.clone(), dns.clone());
        tokio::spawn(async move {
            let _permit = permit;
            if let Some(reply) = dns.handle(&msg).await {
                let _ = sock.send_to(&reply, peer).await;
            }
        });
    }
}

fn transient(e: &std::io::Error) -> bool {
    use std::io::ErrorKind::*;
    matches!(
        e.kind(),
        ConnectionReset | ConnectionRefused | ConnectionAborted | Interrupted | WouldBlock
    )
}

/// Serve DNS over TCP (2-byte length framing, several queries per connection).
pub async fn serve_tcp(listener: TcpListener, dns: Arc<SmartDns>) -> std::io::Result<()> {
    let limit = Arc::new(tokio::sync::Semaphore::new(MAX_TCP_CONNS));
    loop {
        let permit = limit
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore never closed");
        let conn = match listener.accept().await {
            Ok((conn, _)) => conn,
            // Out of descriptors or an aborted handshake: keep serving.
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let dns = dns.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = tcp_conn(conn, &dns).await;
        });
    }
}

async fn tcp_conn(mut conn: TcpStream, dns: &Arc<SmartDns>) -> std::io::Result<()> {
    loop {
        let len = match tokio::time::timeout(TCP_IDLE, conn.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            _ => return Ok(()),
        };
        let mut msg = vec![0u8; len];
        tokio::time::timeout(TCP_IDLE, conn.read_exact(&mut msg))
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        let Some(reply) = dns.handle(&msg).await else {
            return Ok(());
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        conn.write_all(&framed).await?;
    }
}

/// Build a query message (tests and tools).
#[doc(hidden)]
pub fn query_for_test(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&mut p, name).expect("short labels");
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&CLASS_IN.to_be_bytes());
    p
}

/// Decode a response: (id, rcode, addresses).
#[doc(hidden)]
pub fn answers_for_test(msg: &[u8]) -> Option<(u16, u8, Vec<IpAddr>)> {
    let qtype = {
        let end = skip_name(msg, 12)?;
        u16::from_be_bytes([*msg.get(end)?, *msg.get(end + 1)?])
    };
    let (rcode, ips, _) = parse_answers(msg, qtype)?;
    Some((u16::from_be_bytes([msg[0], msg[1]]), rcode, ips))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{generate_key, parse_public_key, sign, unix_now, Verifier};

    struct Persisted {
        dir: std::path::PathBuf,
        pool: Arc<FakeIpPool>,
    }
    impl Drop for Persisted {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// A journaled pool whose every append takes `slow`.
    fn slow_pool(slow: Duration) -> Persisted {
        let dir = std::env::temp_dir().join(format!("dns-{:016x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let (pool, _) = FakeIpPool::open(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::from_secs(60),
            Duration::from_secs(60),
            1024,
            Some(&dir.join("fakeip.state")),
        )
        .unwrap();
        pool.set_slow_append(slow);
        Persisted {
            dir,
            pool: Arc::new(pool),
        }
    }

    fn signed() -> (impl Fn(u64, &str) -> Vec<u8>, Arc<PolicyStore>) {
        let (key, pubkey) = generate_key();
        let verifier = Verifier::new(
            [(1, parse_public_key(&pubkey).unwrap())].into(),
            "ai".into(),
            ["ai", "overseas"].map(String::from).into(),
            ["ai".to_string()].into(),
        )
        .unwrap();
        let bundle = move |v: u64, rules: &str| {
            let body = format!(
                r#"{{"version":{v},"expires_at":{},"ai_domains":[],
                    "rules":{rules},"default":{{"type":"proxy","outbound":"overseas"}},
                    "chnroute":[]}}"#,
                unix_now() + 3600
            );
            sign(&key, 1, body.as_bytes()).unwrap().into_bytes()
        };
        (bundle, Arc::new(PolicyStore::signed(verifier, None)))
    }

    const PROXY_X: &str =
        r#"[{"domain_suffix":"x.example","action":{"type":"proxy","outbound":"overseas"}}]"#;
    const DIRECT_X: &str = r#"[{"domain_suffix":"x.example","action":{"type":"direct"}}]"#;

    /// r7 #5: a fake-IP answer that waited on the disk is rendered under
    /// the policy in force when it is sent: a policy that now resolves the
    /// name for real gets no stale fake address, and an expired / removed
    /// one gets REFUSED.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fake_answer_rechecks_policy_after_durable_wait() {
        let (bundle, store) = signed();
        store.install(&bundle(1, PROXY_X)).unwrap();
        let p = slow_pool(Duration::from_millis(300));
        let settings = DnsSettings {
            domestic: vec![],
            query_timeout: Duration::from_millis(100),
            cache_size: 16,
        };
        let dns = Arc::new(SmartDns::new(store.clone(), p.pool.clone(), settings));
        let ask = |name: &'static str| {
            let dns = dns.clone();
            tokio::spawn(async move {
                let r = dns.handle(&query_for_test(1, name, TYPE_A)).await.unwrap();
                answers_for_test(&r).unwrap()
            })
        };
        // Unchanged policy: the address is answered after the wait.
        let (_, rc, ips) = ask("a.x.example").await.unwrap();
        assert_eq!((rc, ips.len()), (RCODE_OK, 1));
        // The policy turns the name direct while the binding is on disk.
        let pending = ask("b.x.example");
        tokio::time::sleep(Duration::from_millis(100)).await;
        store.install(&bundle(2, DIRECT_X)).unwrap();
        let (_, rc, ips) = pending.await.unwrap();
        assert_eq!(rc, RCODE_SERVFAIL, "stale fake answer: {ips:?}");
        // A new policy that still proxies it: answered.
        store.install(&bundle(3, PROXY_X)).unwrap();
        let pending = ask("c.x.example");
        tokio::time::sleep(Duration::from_millis(100)).await;
        store.install(&bundle(4, PROXY_X)).unwrap();
        let (_, rc, ips) = pending.await.unwrap();
        assert_eq!((rc, ips.len()), (RCODE_OK, 1));
    }

    /// r7 #5: queries over the UDP in-flight limit are answered SERVFAIL at
    /// once (no task, no job), and a stuck disk answers within its bound.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_overload_is_servfail_not_queued() {
        let (bundle, store) = signed();
        store.install(&bundle(1, PROXY_X)).unwrap();
        let p = slow_pool(Duration::from_secs(30));
        let settings = DnsSettings {
            domestic: vec![],
            query_timeout: Duration::from_millis(100),
            cache_size: 16,
        };
        let dns = Arc::new(SmartDns::new(store, p.pool.clone(), settings));
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(serve_udp_limited(sock, dns, 2));
        let c = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let start = Instant::now();
        for i in 0..6u16 {
            let name = format!("n{i}.x.example");
            c.send_to(&query_for_test(i, &name, TYPE_A), addr)
                .await
                .unwrap();
        }
        let mut got = Vec::new();
        let mut b = [0u8; 512];
        while got.len() < 6 {
            let n = tokio::time::timeout(Duration::from_secs(5), c.recv(&mut b))
                .await
                .expect("every query answered within the durable timeout")
                .unwrap();
            let (id, rc, _) = answers_for_test(&b[..n]).unwrap();
            got.push((id, rc, start.elapsed()));
        }
        assert!(
            got.iter().all(|&(_, rc, _)| rc == RCODE_SERVFAIL),
            "{got:?}"
        );
        let fast = got
            .iter()
            .filter(|&&(_, _, t)| t < Duration::from_millis(500))
            .count();
        assert_eq!(fast, 4, "over the limit answered at once: {got:?}");
        assert!(got
            .iter()
            .all(|&(_, _, t)| t < crate::fakeip::DURABLE_TIMEOUT + Duration::from_secs(1)));
    }

    #[test]
    fn question_parse_and_formerr() {
        let q = query_for_test(0x1234, "WWW.Example.COM", TYPE_A);
        let parsed = parse_question(&q).ok().unwrap();
        assert_eq!(parsed.name, "www.example.com");
        assert_eq!(parsed.qtype, TYPE_A);
        assert_eq!(parsed.raw, &q[12..]);
        assert!(matches!(parse_question(&q[..5]), Err(None)));
        // Truncated name → FORMERR with the same id.
        assert!(matches!(
            parse_question(&q[..15]),
            Err(Some((0x1234, true)))
        ));
        // Compression pointer in the question → FORMERR.
        let mut bad = q[..12].to_vec();
        bad.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        assert!(matches!(parse_question(&bad), Err(Some(_))));
    }

    #[test]
    fn respond_roundtrip_keeps_question_case() {
        let q = query_for_test(7, "MiXeD.cn", TYPE_A);
        let parsed = parse_question(&q).ok().unwrap();
        let ips = ["1.2.3.4".parse().unwrap(), "::1".parse().unwrap()];
        let r = respond(&parsed, RCODE_OK, &ips, 60);
        assert_eq!(&r[12..12 + parsed.raw.len()], parsed.raw);
        assert_eq!(
            answers_for_test(&r),
            Some((7, 0, vec!["1.2.3.4".parse().unwrap()]))
        );
    }

    #[test]
    fn parse_answers_bounds() {
        let q = query_for_test(1, "a.b", TYPE_A);
        let parsed = parse_question(&q).ok().unwrap();
        let r = respond(&parsed, RCODE_OK, &["9.9.9.9".parse().unwrap()], 5);
        for n in 0..r.len() {
            assert!(parse_answers(&r[..n], TYPE_A).is_none(), "prefix {n}");
        }
        let mut x: u32 = 12345;
        for _ in 0..5000 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let mut m = r.clone();
            let i = (x as usize >> 8) % m.len();
            m[i] = (x >> 16) as u8;
            let _ = parse_answers(&m, TYPE_A);
            let _ = parse_question(&m);
            let _ = question_bytes(&m);
        }
    }
}
