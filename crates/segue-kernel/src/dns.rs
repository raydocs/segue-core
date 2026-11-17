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
//! Passed-through answers lose the `ech` SvcParam of every HTTPS / SVCB
//! record ([`strip_ech`], astra r9 F4): a client that never learns an ECH
//! config sends its real server name in the clear, so the SNI sniffer
//! (§5.2a.1) can route by it.
//!
//! A reply is rebuilt only when it carries an `ech` to remove; otherwise
//! it is passed on byte for byte. A truncated upstream reply is fetched
//! again over TCP; replies to UDP clients are cut to their EDNS size.
//!
//! Not done: ECS, binding
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
pub const TYPE_SVCB: u16 = 64;
pub const TYPE_HTTPS: u16 = 65;
const TYPE_CNAME: u16 = 5;
const TYPE_OPT: u16 = 41;
const FLAG_TC: u8 = 0x02;
const FLAG_AD: u8 = 0x20;
const CLASS_IN: u16 = 1;
/// SvcParamKey `ech` (RFC 9460 §14.3.2; ECH config list, RFC 9848).
pub const SVC_KEY_ECH: u16 = 5;
const SVC_KEY_MANDATORY: u16 = 0;

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

/// How a reply goes back to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// UDP; the most payload the path carries (TUN: MTU less headers).
    Udp(usize),
    /// TCP (length-prefixed): no size limit but the 16-bit length.
    Tcp,
}

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

pub(crate) enum Class {
    /// Explicit proxy / reject domain rule: fake-IP, no network request.
    Fake,
    /// Explicit direct domain rule: real answer.
    Domestic,
    /// No domain rule: real answer if all in chnroute, else foreign.
    Unmatched,
}

pub(crate) fn classify(policy: &Policy, name: &str) -> Class {
    match policy.rules.lookup(&TargetAddr::Domain(name.to_owned())) {
        Some((_, Action::Direct)) => Class::Domestic,
        Some(_) => Class::Fake,
        None => Class::Unmatched,
    }
}

/// How a name that will not be resolved for real is answered.
///
/// A is a fake IPv4. AAAA would be a fake IPv6 if the pool had a v6 range;
/// it does not ([`crate::fakeip`] is IPv4 only), so AAAA is an empty NOERROR
/// and the client uses the v4 address through the tunnel. Every other type
/// is empty too: nothing is forwarded to a direct upstream.
pub(crate) enum ProxiedAnswer {
    FakeV4,
    Empty,
}

pub(crate) fn proxied_answer(qtype: u16) -> ProxiedAnswer {
    if qtype == TYPE_A {
        ProxiedAnswer::FakeV4
    } else {
        ProxiedAnswer::Empty
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
    ///
    /// Over UDP the reply is cut to the client's EDNS size (512 without
    /// OPT) and the path's `cap`: header, question and OPT with TC
    /// (`truncate_udp`); over TCP it is whole (r10 N8).
    pub async fn handle(self: &Arc<Self>, query: &[u8], via: Transport) -> Option<Vec<u8>> {
        let reply = self.answer(query).await?;
        Some(match via {
            Transport::Udp(cap) => truncate_udp(reply, udp_limit(query, cap)),
            Transport::Tcp => reply,
        })
    }

    async fn answer(self: &Arc<Self>, query: &[u8]) -> Option<Vec<u8>> {
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
        match (classify(&policy, &q.name), proxied_answer(q.qtype)) {
            (Class::Fake, ProxiedAnswer::FakeV4) => Some(
                self.fake_answer(&q, &policy, |p| matches!(classify(p, &q.name), Class::Fake))
                    .await,
            ),
            // AI names take this path too: lookup returns the AI tier, so
            // they are Fake, never Domestic or Unmatched, and `resolve`
            // (the direct upstream) is not called. AAAA is empty NOERROR.
            (Class::Fake, ProxiedAnswer::Empty) => Some(respond(&q, RCODE_OK, &[], 0)),
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
            Some(reply) => match strip_ech(&reply) {
                Some(mut reply) => {
                    reply[..2].copy_from_slice(&q.id.to_be_bytes());
                    Some(reply)
                }
                // A reply that cannot be walked might hide an ECH config
                // from us but not from the client: not passed on.
                None => Some(respond(q, RCODE_SERVFAIL, &[], 0)),
            },
            None => Some(self.after_wait(q, || respond(q, RCODE_SERVFAIL, &[], 0))),
        }
    }

    /// Send `packet` to every domestic resolver at once; first valid reply.
    ///
    /// Only complete replies count (r11 R2): a reply with TC is retried over
    /// TCP and dropped if that does not give a complete one, so a fast
    /// truncated reply never beats a slower complete one, never reaches the
    /// address cache and never goes to a client. With no complete reply
    /// from any resolver the caller answers SERVFAIL — over UDP too: we do
    /// not pass a truncated upstream reply on as our own TC, the client
    /// retries the query instead.
    async fn race(&self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let _permit = self.upstream_limit.try_acquire().ok()?;
        self.upstream_queries
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let packet = Arc::new(packet);
        let mut set: JoinSet<std::io::Result<Vec<u8>>> = JoinSet::new();
        for &server in &self.s.domestic {
            let packet = packet.clone();
            let deadline = tokio::time::Instant::now() + self.s.query_timeout;
            set.spawn(async move {
                let late = || std::io::Error::from(std::io::ErrorKind::TimedOut);
                let reply = tokio::time::timeout_at(deadline, exchange(server, &packet))
                    .await
                    .map_err(|_| late())??;
                if reply[2] & FLAG_TC == 0 {
                    return Ok(reply);
                }
                // Truncated upstream: ask the same server again over TCP
                // (RFC 7766). A truncated reply is never an answer (r11
                // R2): if TCP fails, times out, ends mid-frame or is
                // truncated too, this server gave nothing.
                let full = tokio::time::timeout_at(deadline, exchange_tcp(server, &packet))
                    .await
                    .map_err(|_| late())??;
                if full[2] & FLAG_TC != 0 {
                    return Err(std::io::ErrorKind::InvalidData.into());
                }
                Ok(full)
            });
        }
        // First definitive answer (NOERROR/NXDOMAIN) wins; a fast
        // SERVFAIL/REFUSED must not beat a good answer still in flight.
        let mut fallback = None;
        while let Some(done) = set.join_next().await {
            if let Ok(Ok(reply)) = done {
                if reply[2] & FLAG_TC != 0 {
                    continue;
                }
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
    question_bytes(packet).ok_or(std::io::ErrorKind::InvalidInput)?;
    let mut buf = vec![0u8; 65535];
    loop {
        let n = sock.recv(&mut buf).await?;
        if answers_query(packet, &buf[..n]) {
            return Ok(buf[..n].to_vec());
        }
    }
}

/// One exchange over TCP (after a truncated UDP reply).
async fn exchange_tcp(server: SocketAddr, packet: &[u8]) -> std::io::Result<Vec<u8>> {
    question_bytes(packet).ok_or(std::io::ErrorKind::InvalidInput)?;
    let len = u16::try_from(packet.len()).map_err(|_| std::io::ErrorKind::InvalidInput)?;
    let mut conn = TcpStream::connect(server).await?;
    let mut framed = Vec::with_capacity(packet.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(packet);
    conn.write_all(&framed).await?;
    loop {
        let n = usize::from(conn.read_u16().await?);
        let mut r = vec![0u8; n];
        conn.read_exact(&mut r).await?;
        if answers_query(packet, &r) {
            return Ok(r);
        }
    }
}

/// `r` is a response with the ID and question of `packet`.
fn answers_query(packet: &[u8], r: &[u8]) -> bool {
    r.len() >= 12
        && r[..2] == packet[..2]
        && r[2] & 0x80 != 0
        && matches!(
            (question_bytes(r), question_bytes(packet)),
            (Some(got), Some(want)) if got.eq_ignore_ascii_case(want)
        )
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
    // A truncated message is not an answer set (RFC 2181 §9; r11 R2).
    if msg[2] & FLAG_TC != 0 {
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

/// One resource record of a walked message (offsets into it).
struct RrAt {
    /// 0 answer, 1 authority, 2 additional.
    section: usize,
    name: usize,
    ty: u16,
    /// Offset of TYPE (the 10-byte fixed part).
    fixed: usize,
    data: std::ops::Range<usize>,
}

/// The layout of a message: where its questions end, every record.
struct Walk {
    qd: usize,
    question_end: usize,
    rrs: Vec<RrAt>,
}

/// Walk every section of `msg` without following pointers. None if a
/// count or length runs past the end.
fn walk(msg: &[u8]) -> Option<Walk> {
    if msg.len() < 12 {
        return None;
    }
    let count = |i: usize| usize::from(u16::from_be_bytes([msg[i], msg[i + 1]]));
    let (qd, an, ns, ar) = (count(4), count(6), count(8), count(10));
    let mut p = 12;
    for _ in 0..qd {
        p = skip_name(msg, p)?.checked_add(4)?;
        msg.get(..p)?;
    }
    let question_end = p;
    let mut rrs = Vec::with_capacity(an + ns + ar);
    for i in 0..an + ns + ar {
        let name = p;
        p = skip_name(msg, p)?;
        let h = msg.get(p..p + 10)?;
        let ty = u16::from_be_bytes([h[0], h[1]]);
        let rdlen = usize::from(u16::from_be_bytes([h[8], h[9]]));
        let data = p + 10..p + 10 + rdlen;
        msg.get(data.clone())?;
        rrs.push(RrAt {
            section: if i < an {
                0
            } else if i < an + ns {
                1
            } else {
                2
            },
            name,
            ty,
            fixed: p,
            data: data.clone(),
        });
        p = data.end;
    }
    Some(Walk {
        qd,
        question_end,
        rrs,
    })
}

/// The EDNS UDP payload size a query offers (its OPT record's class).
fn edns_size(msg: &[u8]) -> Option<u16> {
    let w = walk(msg)?;
    let opt = w.rrs.iter().find(|r| r.ty == TYPE_OPT)?;
    Some(u16::from_be_bytes([msg[opt.fixed + 2], msg[opt.fixed + 3]]))
}

/// Largest UDP reply to `query`: its EDNS size (never below 512, RFC 6891
/// §6.2.5), or 512 without OPT; and no more than the path carries (`cap`).
fn udp_limit(query: &[u8], cap: usize) -> usize {
    edns_size(query)
        .map_or(512, |s| usize::from(s).max(512))
        .min(cap)
}

/// `reply` if it fits in `limit` bytes; otherwise header and question with
/// TC set, and the reply's OPT record kept (RFC 6891 §7; its options
/// dropped only if even they do not fit), so the client retries over TCP.
fn truncate_udp(reply: Vec<u8>, limit: usize) -> Vec<u8> {
    if reply.len() <= limit {
        return reply;
    }
    let Some(w) = walk(&reply) else {
        // Unwalkable: the header alone, nothing claimed.
        let mut out = reply[..12.min(reply.len())].to_vec();
        if out.len() == 12 {
            out[2] |= FLAG_TC;
            out[4..12].fill(0);
        }
        return out;
    };
    // Header and question keep their offsets: any pointer inside the
    // question stays valid.
    let mut out = reply[..w.question_end].to_vec();
    out[2] |= FLAG_TC;
    out[6..12].fill(0);
    let opt = w.rrs.iter().find(|r| r.ty == TYPE_OPT && r.section == 2);
    if let Some(opt) = opt {
        let whole = &reply[opt.name..opt.data.end];
        if out.len() + whole.len() <= limit {
            out.extend_from_slice(whole);
        } else {
            out.extend_from_slice(&reply[opt.name..opt.fixed + 8]);
            out.extend_from_slice(&[0, 0]);
        }
        out[10..12].copy_from_slice(&1u16.to_be_bytes());
    }
    out
}

/// `name` at `p` written out in full, lowercase (RRset owner comparison).
fn lower_name(msg: &[u8], p: usize) -> Option<Vec<u8>> {
    let mut n = Vec::new();
    expand_name(msg, p, &mut n)?;
    n.make_ascii_lowercase();
    Some(n)
}

/// `msg` without the `ech` SvcParam in its HTTPS / SVCB records (r9 F4);
/// None if the message cannot be walked or safely rebuilt (the caller
/// answers SERVFAIL).
///
/// A message with no HTTPS / SVCB record carrying `ech` is returned byte
/// for byte (r10 N8). Otherwise it is decoded and encoded again (r10 N7,
/// N8), every section kept:
///
/// - header as it was but AD cleared: the rewritten RRsets are no longer
///   what was validated (RFC 4035 §3.2.3); CD, RD and the OPT record (DO
///   bit, options) untouched;
/// - every name written out in full, no compression: owners, the question
///   and the names inside the data of the types that may carry compressed
///   names (RFC 1035 NS, MD, MF, CNAME, SOA, MB, MG, MR, PTR, MINFO, MX;
///   RFC 3597 §4 RP, AFSDB, RT, PX, NAPTR, SRV), so no pointer can land on
///   a moved offset;
/// - HTTPS / SVCB data without `ech` (and without `ech` in `mandatory`,
///   which is dropped once empty);
/// - RRSIG records covering an HTTPS / SVCB RRset that was rewritten are
///   dropped: they no longer verify. Other signatures stay;
/// - data of the other known types verbatim (their names are never
///   compressed: `NO_COMPRESSED_NAMES`).
///
/// A record of any other (unknown) type makes it None: its data might hold
/// a compressed name we cannot find, and removing just the HTTPS / SVCB
/// records would move offsets just the same. SERVFAIL is the safe answer:
/// no ECH config and no corrupt message reaches the client. Size limits
/// are applied by the caller, per transport.
pub fn strip_ech(msg: &[u8]) -> Option<Vec<u8>> {
    let w = walk(msg)?;
    let mut rewritten: Vec<(Vec<u8>, u16)> = Vec::new();
    for rr in &w.rrs {
        if rr.ty == TYPE_HTTPS || rr.ty == TYPE_SVCB {
            let params = svc_params(&msg[rr.data.clone()])?;
            if params.iter().any(|&(k, _)| k == SVC_KEY_ECH) {
                rewritten.push((lower_name(msg, rr.name)?, rr.ty));
            }
        }
    }
    if rewritten.is_empty() {
        return Some(msg.to_vec());
    }
    let mut out = Vec::with_capacity(msg.len() + 128);
    out.extend_from_slice(&msg[..12]);
    out[3] &= !FLAG_AD;
    let mut p = 12;
    for _ in 0..w.qd {
        p = expand_name(msg, p, &mut out)?;
        out.extend_from_slice(msg.get(p..p + 4)?);
        p += 4;
    }
    let mut counts = [0u16; 3];
    for rr in &w.rrs {
        let rdata = &msg[rr.data.clone()];
        if rr.ty == TYPE_RRSIG && rdata.len() >= 2 {
            let covered = u16::from_be_bytes([rdata[0], rdata[1]]);
            if (covered == TYPE_HTTPS || covered == TYPE_SVCB)
                && rewritten.contains(&(lower_name(msg, rr.name)?, covered))
            {
                continue;
            }
        }
        expand_name(msg, rr.name, &mut out)?;
        out.extend_from_slice(&msg[rr.fixed..rr.fixed + 8]);
        let len_at = out.len();
        out.extend_from_slice(&[0, 0]);
        match rr.ty {
            TYPE_HTTPS | TYPE_SVCB => out.extend_from_slice(&svc_without_ech(rdata)?),
            ty => expand_rdata(msg, ty, rr.data.clone(), &mut out)?,
        }
        let len = u16::try_from(out.len() - len_at - 2).ok()?;
        out[len_at..len_at + 2].copy_from_slice(&len.to_be_bytes());
        counts[rr.section] += 1;
    }
    for (i, n) in counts.iter().enumerate() {
        out[6 + 2 * i..8 + 2 * i].copy_from_slice(&n.to_be_bytes());
    }
    (out.len() <= usize::from(u16::MAX)).then_some(out)
}

const TYPE_NS: u16 = 2;
const TYPE_MD: u16 = 3;
const TYPE_MF: u16 = 4;
const TYPE_SOA: u16 = 6;
const TYPE_MB: u16 = 7;
const TYPE_MG: u16 = 8;
const TYPE_MR: u16 = 9;
const TYPE_PTR: u16 = 12;
const TYPE_MINFO: u16 = 14;
const TYPE_MX: u16 = 15;
const TYPE_RP: u16 = 17;
const TYPE_AFSDB: u16 = 18;
const TYPE_RT: u16 = 21;
const TYPE_PX: u16 = 26;
const TYPE_SRV: u16 = 33;
const TYPE_NAPTR: u16 = 35;
const TYPE_RRSIG: u16 = 46;

/// Types whose data never holds a compressed name (no name at all, or one
/// its RFC forbids compressing: DNAME, RRSIG / NSEC signer and next name,
/// IPSECKEY gateway, HIP servers, SVCB / HTTPS TargetName).
const NO_COMPRESSED_NAMES: &[u16] = &[
    1, 10, 11, 13, 16, 19, 20, 22, 25, 27, 28, 29, 37, 39, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
    51, 52, 53, 55, 59, 60, 61, 62, 63, 64, 65, 99, 108, 109, 256, 257,
];

/// Append the data of a `ty` record at `range` of `msg` with every name in
/// it written out in full. None if malformed, or if `ty` is unknown.
fn expand_rdata(
    msg: &[u8],
    ty: u16,
    range: std::ops::Range<usize>,
    out: &mut Vec<u8>,
) -> Option<()> {
    let end = range.end;
    let name = |p: usize, out: &mut Vec<u8>| -> Option<usize> {
        let q = expand_name(msg, p, out)?;
        (q <= end).then_some(q)
    };
    let fixed = |p: usize, n: usize, out: &mut Vec<u8>| -> Option<usize> {
        let q = p.checked_add(n).filter(|&q| q <= end)?;
        out.extend_from_slice(&msg[p..q]);
        Some(q)
    };
    let p = range.start;
    let p = match ty {
        TYPE_NS | TYPE_MD | TYPE_MF | TYPE_CNAME | TYPE_MB | TYPE_MG | TYPE_MR | TYPE_PTR => {
            name(p, out)?
        }
        TYPE_SOA => {
            let p = name(p, out)?;
            let p = name(p, out)?;
            fixed(p, 20, out)?
        }
        TYPE_MINFO | TYPE_RP => {
            let p = name(p, out)?;
            name(p, out)?
        }
        TYPE_MX | TYPE_AFSDB | TYPE_RT => {
            let p = fixed(p, 2, out)?;
            name(p, out)?
        }
        TYPE_PX => {
            let p = fixed(p, 2, out)?;
            let p = name(p, out)?;
            name(p, out)?
        }
        TYPE_SRV => {
            let p = fixed(p, 6, out)?;
            name(p, out)?
        }
        TYPE_NAPTR => {
            // order, preference, then flags / services / regexp strings.
            let mut p = fixed(p, 4, out)?;
            for _ in 0..3 {
                let len = usize::from(*msg.get(p).filter(|_| p < end)?);
                p = fixed(p, 1 + len, out)?;
            }
            name(p, out)?
        }
        t if NO_COMPRESSED_NAMES.contains(&t) => fixed(p, end - p, out)?,
        _ => return None,
    };
    (p == end).then_some(())
}

/// The SvcParams of SVCB / HTTPS data: (key, value range). None if
/// malformed (RFC 9460 §2.2: keys strictly increasing).
fn svc_params(rdata: &[u8]) -> Option<Vec<(u16, std::ops::Range<usize>)>> {
    rdata.get(..2)?;
    // TargetName is never compressed (RFC 9460 §2.2).
    let mut p = 2;
    loop {
        let len = usize::from(*rdata.get(p)?);
        if len == 0 {
            p += 1;
            break;
        }
        if len > 63 {
            return None;
        }
        p += 1 + len;
    }
    let mut params = Vec::new();
    let mut last: Option<u16> = None;
    while p < rdata.len() {
        let h = rdata.get(p..p + 4)?;
        let key = u16::from_be_bytes([h[0], h[1]]);
        let len = usize::from(u16::from_be_bytes([h[2], h[3]]));
        if last.is_some_and(|l| key <= l) {
            return None;
        }
        last = Some(key);
        rdata.get(p + 4..p + 4 + len)?;
        params.push((key, p + 4..p + 4 + len));
        p += 4 + len;
    }
    Some(params)
}

/// SVCB / HTTPS data with `ech` removed (and from `mandatory`).
fn svc_without_ech(rdata: &[u8]) -> Option<Vec<u8>> {
    let params = svc_params(rdata)?;
    let head_end = params.first().map_or(rdata.len(), |(_, r)| r.start - 4);
    let mut out = rdata[..head_end].to_vec();
    for (key, range) in params {
        let value = &rdata[range];
        match key {
            SVC_KEY_ECH => {}
            SVC_KEY_MANDATORY => {
                if !value.len().is_multiple_of(2) {
                    return None;
                }
                let keys: Vec<u8> = value
                    .chunks(2)
                    .filter(|k| u16::from_be_bytes([k[0], k[1]]) != SVC_KEY_ECH)
                    .flatten()
                    .copied()
                    .collect();
                if !keys.is_empty() {
                    out.extend_from_slice(&key.to_be_bytes());
                    out.extend_from_slice(&(keys.len() as u16).to_be_bytes());
                    out.extend_from_slice(&keys);
                }
            }
            _ => {
                out.extend_from_slice(&key.to_be_bytes());
                out.extend_from_slice(&(value.len() as u16).to_be_bytes());
                out.extend_from_slice(value);
            }
        }
    }
    Some(out)
}

/// Append the name at `p` of `msg` uncompressed; returns where the name
/// ends at `p` (after its first pointer or its root label). Pointers must
/// point backwards (so the walk ends); at most 255 bytes of name.
fn expand_name(msg: &[u8], mut p: usize, out: &mut Vec<u8>) -> Option<usize> {
    let mut total = 0usize;
    let mut limit = p;
    let mut end = None;
    loop {
        let len = *msg.get(p)?;
        match len {
            0 => {
                out.push(0);
                return Some(end.unwrap_or(p + 1));
            }
            l if l & 0xc0 == 0xc0 => {
                let to = usize::from(u16::from_be_bytes([l & 0x3f, *msg.get(p + 1)?]));
                if to >= limit {
                    return None;
                }
                end.get_or_insert(p + 2);
                limit = to;
                p = to;
            }
            l if l > 63 => return None,
            l => {
                let l = usize::from(l);
                total += l + 1;
                if total > 255 {
                    return None;
                }
                out.extend_from_slice(msg.get(p..p + 1 + l)?);
                p += 1 + l;
            }
        }
    }
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
            if let Some(reply) = dns
                .handle(&msg, Transport::Udp(usize::from(u16::MAX)))
                .await
            {
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
        let Some(reply) = dns.handle(&msg, Transport::Tcp).await else {
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

    /// An AI name is fake-IP (A) or empty NOERROR (AAAA), never a query to
    /// the domestic upstream, even when a user rule says Direct.
    #[tokio::test]
    async fn ai_dns_is_not_forwarded_to_a_direct_upstream() {
        use crate::rules::{builtin_ai_list, Action, CidrTable, Matcher, Rule, RuleSet};

        let (suffixes, cidrs) = builtin_ai_list();
        let rules = RuleSet::new(
            vec![Rule {
                matcher: Matcher::DomainSuffix("claude.ai".into()),
                action: Action::Direct,
            }],
            Action::Direct,
        )
        .with_ai(suffixes, &cidrs, Action::Proxy("ai".into()));
        let store = Arc::new(PolicyStore::inline(Policy::inline(
            rules,
            CidrTable::default(),
        )));
        let pool = Arc::new(
            FakeIpPool::new(
                "198.18.0.0".parse().unwrap(),
                15,
                Duration::from_secs(60),
                Duration::from_secs(60),
                [7u8; 32],
            )
            .unwrap(),
        );
        let dns = Arc::new(SmartDns::new(
            store,
            pool,
            DnsSettings {
                domestic: vec!["127.0.0.1:1".parse().unwrap()],
                query_timeout: Duration::from_millis(50),
                cache_size: 16,
            },
        ));
        let a = dns
            .handle(
                &query_for_test(1, "api.claude.ai", TYPE_A),
                Transport::Udp(65535),
            )
            .await
            .unwrap();
        let (_, rc, ips) = answers_for_test(&a).unwrap();
        assert_eq!(rc, RCODE_OK);
        assert_eq!(ips.len(), 1);
        assert!(
            matches!(ips[0], IpAddr::V4(v4) if v4.octets()[0] == 198),
            "{ips:?}"
        );
        let aaaa = dns
            .handle(
                &query_for_test(2, "api.claude.ai", TYPE_AAAA),
                Transport::Udp(65535),
            )
            .await
            .unwrap();
        let (_, rc, ips) = answers_for_test(&aaaa).unwrap();
        assert_eq!((rc, ips.len()), (RCODE_OK, 0), "real AAAA leaked: {ips:?}");
        assert_eq!(
            dns.upstream_queries
                .load(std::sync::atomic::Ordering::Relaxed),
            0,
            "AI name was sent to a direct upstream"
        );
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
                let r = dns
                    .handle(&query_for_test(1, name, TYPE_A), Transport::Udp(65535))
                    .await
                    .unwrap();
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

    /// An HTTPS answer the way resolvers send it: a CNAME to `cdn.x.test`,
    /// then HTTPS records whose owner names are compression pointers; an
    /// authority SOA, an EDNS OPT. `params` per HTTPS record.
    fn https_reply(params: &[&[(u16, &[u8])]]) -> Vec<u8> {
        let q = query_for_test(0x4242, "www.x.test", TYPE_HTTPS);
        let mut m = q.clone();
        m[2] = 0x81;
        m[3] = 0x80;
        m[6..8].copy_from_slice(&(1 + params.len() as u16).to_be_bytes());
        m[8..10].copy_from_slice(&1u16.to_be_bytes());
        m[10..12].copy_from_slice(&1u16.to_be_bytes());
        // CNAME www.x.test -> "cdn" + pointer to "x.test" (offset 16).
        let cdn = m.len() + 12;
        m.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6]);
        m.extend_from_slice(&[3, b'c', b'd', b'n', 0xc0, 16]);
        for ps in params {
            m.extend_from_slice(&[0xc0 | (cdn >> 8) as u8, cdn as u8]);
            let mut rd = vec![0, 1, 0]; // priority 1, TargetName "."
            for (k, v) in *ps {
                rd.extend_from_slice(&k.to_be_bytes());
                rd.extend_from_slice(&(v.len() as u16).to_be_bytes());
                rd.extend_from_slice(v);
            }
            m.extend_from_slice(&[0, 65, 0, 1, 0, 0, 1, 44]);
            m.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            m.extend_from_slice(&rd);
        }
        // Authority: SOA owned by x.test (pointer), its names compressed.
        m.extend_from_slice(&[0xc0, 16, 0, 6, 0, 1, 0, 0, 0, 60, 0, 29]);
        m.extend_from_slice(&[2, b'n', b's', 0xc0, 16, 1, b'h', 0xc0, 16]);
        m.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5]);
        // Additional: OPT.
        m.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        m
    }

    /// (type, owner, rdata) of the answers, names expanded.
    fn answers(m: &[u8]) -> Vec<(u16, Vec<u8>, Vec<u8>)> {
        let an = u16::from_be_bytes([m[6], m[7]]);
        let mut p = 12;
        p = skip_name(m, p).unwrap() + 4;
        let mut out = Vec::new();
        for _ in 0..an {
            let mut name = Vec::new();
            expand_name(m, p, &mut name).unwrap();
            p = skip_name(m, p).unwrap();
            let ty = u16::from_be_bytes([m[p], m[p + 1]]);
            let len = usize::from(u16::from_be_bytes([m[p + 8], m[p + 9]]));
            out.push((ty, name, m[p + 10..p + 10 + len].to_vec()));
            p += 10 + len;
        }
        out
    }

    const ALPN: (u16, &[u8]) = (1, b"\x02h2");
    const HINT: (u16, &[u8]) = (4, &[1, 2, 3, 4]);
    const ECH: (u16, &[u8]) = (SVC_KEY_ECH, &[0, 4, 0xfe, 0x0d, 0, 0]);

    /// r9 F4 (a): the `ech` SvcParam leaves every HTTPS record (and the
    /// `mandatory` list), other params stay in order; names come out
    /// whole; CNAME target intact; authority kept with its SOA names
    /// written out, OPT kept.
    #[test]
    fn strip_ech_removes_only_the_ech_param() {
        let mandatory: (u16, &[u8]) = (0, &[0, 1, 0, 5]);
        let m = https_reply(&[&[mandatory, ALPN, HINT, ECH], &[ALPN, ECH]]);
        let out = strip_ech(&m).unwrap();
        assert_eq!(&out[..2], &m[..2]);
        assert_eq!(u16::from_be_bytes([out[8], out[9]]), 1, "authority kept");
        assert!(out.ends_with(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(u16::from_be_bytes([out[10], out[11]]), 1, "OPT kept");
        let a = answers(&out);
        let full = |s: &str| {
            let mut v = Vec::new();
            encode_name(&mut v, s).unwrap();
            v
        };
        assert_eq!(a[0], (TYPE_CNAME, full("www.x.test"), full("cdn.x.test")));
        let rd = |ps: &[(u16, &[u8])]| {
            let mut rd = vec![0, 1, 0];
            for (k, v) in ps {
                rd.extend_from_slice(&k.to_be_bytes());
                rd.extend_from_slice(&(v.len() as u16).to_be_bytes());
                rd.extend_from_slice(v);
            }
            rd
        };
        let only_alpn: (u16, &[u8]) = (0, &[0, 1]);
        assert_eq!(
            a[1],
            (TYPE_HTTPS, full("cdn.x.test"), rd(&[only_alpn, ALPN, HINT]))
        );
        assert_eq!(a[2], (TYPE_HTTPS, full("cdn.x.test"), rd(&[ALPN])));
        // Nothing left to strip: unchanged.
        assert_eq!(strip_ech(&out).unwrap(), out);
        // `mandatory` naming only ech goes away with it.
        let m = https_reply(&[&[(0, &[0, 5]), ECH]]);
        assert_eq!(answers(&strip_ech(&m).unwrap())[1].2, rd(&[]));
    }

    #[test]
    fn strip_ech_leaves_other_replies_alone_and_never_panics() {
        let m = https_reply(&[&[ALPN, HINT]]);
        assert_eq!(strip_ech(&m).unwrap(), m, "no ech: byte for byte");
        let q = query_for_test(1, "a.b", TYPE_A);
        let r = respond(
            &parse_question(&q).ok().unwrap(),
            RCODE_OK,
            &["9.9.9.9".parse().unwrap()],
            5,
        );
        assert_eq!(strip_ech(&r).unwrap(), r);
        // Keys out of order: malformed, not passed on.
        let bad = https_reply(&[&[HINT, ALPN, ECH]]);
        assert_eq!(strip_ech(&bad), None);
        let m = https_reply(&[&[ALPN, ECH]]);
        for n in 0..m.len() {
            let _ = strip_ech(&m[..n]);
        }
        let mut x: u32 = 99;
        for _ in 0..20000 {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
            let mut b = m.clone();
            let i = (x as usize >> 8) % b.len();
            b[i] = (x >> 16) as u8;
            if let Some(out) = strip_ech(&b) {
                // Whatever comes out has no ech left in an HTTPS answer.
                assert_eq!(strip_ech(&out).as_ref(), Some(&out));
            }
        }
    }

    /// A smart DNS whose one domestic resolver is `addr`; every name is
    /// unmatched (passed through).
    fn dns_to(addr: SocketAddr) -> Arc<SmartDns> {
        let policy = PolicyStore::inline(Policy::inline(
            crate::rules::RuleSet::new(vec![], Action::Proxy("p".into())),
            crate::rules::CidrTable::default(),
        ));
        let pool = Arc::new(
            FakeIpPool::new(
                "198.18.0.0".parse().unwrap(),
                15,
                Duration::from_secs(60),
                Duration::from_secs(60),
                [1; 32],
            )
            .unwrap(),
        );
        let settings = DnsSettings {
            domestic: vec![addr],
            query_timeout: Duration::from_millis(500),
            cache_size: 16,
        };
        Arc::new(SmartDns::new(policy, pool, settings))
    }

    /// r9 F4 (a) end to end: an HTTPS query for an unmatched name goes to
    /// the domestic resolver; its ECH config does not reach the client.
    #[tokio::test]
    async fn passthrough_https_answer_has_no_ech() {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = up.local_addr().unwrap();
        let canned = https_reply(&[&[ALPN, ECH]]);
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = up.recv_from(&mut b).await {
                let mut r = canned.clone();
                r[..2].copy_from_slice(&b[..2]);
                let _ = up.send_to(&r, from).await;
                let _ = n;
            }
        });
        let dns = dns_to(addr);
        let reply = dns
            .handle(
                &query_for_test(0x4242, "www.x.test", TYPE_HTTPS),
                Transport::Udp(65535),
            )
            .await
            .unwrap();
        let a = answers(&reply);
        assert_eq!(a.len(), 2);
        assert_eq!(
            a[1].2,
            [&[0u8, 1, 0][..], &[0, 1, 0, 3], b"\x02h2"].concat()
        );
    }

    /// Every record of `m` as (section, owner, type, class+TTL, data), all
    /// names written out: what a client decodes, whatever the compression.
    type Decoded = Vec<(usize, Vec<u8>, u16, Vec<u8>, Vec<u8>)>;
    fn decode(m: &[u8]) -> Decoded {
        let w = walk(m).unwrap();
        w.rrs
            .iter()
            .map(|r| {
                let mut owner = Vec::new();
                expand_name(m, r.name, &mut owner).unwrap();
                let mut data = Vec::new();
                match r.ty {
                    TYPE_HTTPS | TYPE_SVCB => data.extend_from_slice(&m[r.data.clone()]),
                    ty => expand_rdata(m, ty, r.data.clone(), &mut data).unwrap(),
                }
                (
                    r.section,
                    owner,
                    r.ty,
                    m[r.fixed + 2..r.fixed + 8].to_vec(),
                    data,
                )
            })
            .collect()
    }

    fn name_bytes(s: &str) -> Vec<u8> {
        let mut v = Vec::new();
        encode_name(&mut v, s).unwrap();
        v
    }

    /// Append one record (owner bytes as given, possibly a pointer).
    fn rr(m: &mut Vec<u8>, owner: &[u8], ty: u16, data: &[u8]) {
        m.extend_from_slice(owner);
        m.extend_from_slice(&ty.to_be_bytes());
        m.extend_from_slice(&[0, 1, 0, 0, 1, 44]);
        m.extend_from_slice(&(data.len() as u16).to_be_bytes());
        m.extend_from_slice(data);
    }

    fn ptr(at: usize) -> [u8; 2] {
        [0xc0 | (at >> 8) as u8, at as u8]
    }

    fn https_data(ech: bool) -> Vec<u8> {
        let mut d = vec![0, 1, 0];
        d.extend_from_slice(&[0, 1, 0, 3, 2, b'h', b'2']);
        if ech {
            d.extend_from_slice(&[0, 5, 0, 4, 0xfe, 0x0d, 0, 0]);
        }
        d
    }

    fn rrsig(covered: u16) -> Vec<u8> {
        let mut d = covered.to_be_bytes().to_vec();
        // alg, labels, original TTL, expiration, inception, key tag.
        d.extend_from_slice(&[13, 3, 0, 0, 1, 44, 0, 0, 0, 9, 0, 0, 0, 1, 0, 7]);
        d.extend_from_slice(&name_bytes("x.test"));
        d.extend_from_slice(&[0xaa; 64]);
        d
    }

    /// OPT: UDP size 1232, DO set, a cookie option.
    const OPT: &[u8] = &[
        0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 12, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8,
    ];

    /// An ANY reply for www.x.test, AD and CD set, every name after the
    /// question compressed: CNAME to cdn.x.test, HTTPS of cdn (with or
    /// without ech) and its RRSIG, then MX of cdn whose exchange points
    /// into the CNAME data (a cross-RDATA pointer) and its RRSIG; an
    /// authority NS whose target points into the MX data; the OPT above.
    fn any_reply(ech: bool) -> Vec<u8> {
        let mut m = query_for_test(0x77, "www.x.test", 255);
        m[2] = 0x81;
        m[3] = 0x80 | FLAG_AD | 0x10; // RA, AD, CD
        m[6..12].copy_from_slice(&[0, 5, 0, 1, 0, 1]);
        let cdn = m.len() + 12;
        rr(
            &mut m,
            &ptr(12),
            TYPE_CNAME,
            &[&b"\x03cdn"[..], &ptr(16)].concat(),
        );
        rr(&mut m, &ptr(cdn), TYPE_HTTPS, &https_data(ech));
        rr(&mut m, &ptr(cdn), TYPE_RRSIG, &rrsig(TYPE_HTTPS));
        let mail = m.len() + 12 + 2;
        rr(
            &mut m,
            &ptr(cdn),
            TYPE_MX,
            &[&[0u8, 10, 4][..], b"mail", &ptr(cdn)].concat(),
        );
        rr(&mut m, &ptr(cdn), TYPE_RRSIG, &rrsig(TYPE_MX));
        rr(
            &mut m,
            &ptr(16),
            TYPE_NS,
            &[&b"\x02ns"[..], &ptr(mail)].concat(),
        );
        m.extend_from_slice(OPT);
        m
    }

    /// r10 N7 / N8: a reply with no ech is passed on byte for byte, AD and
    /// signatures included.
    #[test]
    fn no_ech_is_byte_for_byte_with_ad_and_rrsig() {
        let m = any_reply(false);
        assert_eq!(decode(&m).len(), 7, "fixture walks");
        assert_eq!(strip_ech(&m).unwrap(), m);
    }

    /// r10 N7 / N8: with ech removed, AD is cleared (CD, RD, RA kept), the
    /// RRSIG over the rewritten HTTPS RRset is dropped, the one over MX
    /// stays, the OPT record (DO bit, cookie) is unchanged, and every
    /// other record decodes as before though its pointers moved.
    #[test]
    fn rewrite_clears_ad_drops_stale_rrsig_and_expands_rdata() {
        let m = any_reply(true);
        let out = strip_ech(&m).unwrap();
        assert_eq!(out[2], m[2]);
        assert_eq!(out[3], m[3] & !FLAG_AD);
        assert_eq!(out[3] & 0x10, 0x10, "CD kept");
        assert!(out.ends_with(OPT), "OPT, DO and options as they were");
        let (want, got) = (decode(&m), decode(&out));
        let mut expect: Decoded = want
            .into_iter()
            .filter(|r| !(r.2 == TYPE_RRSIG && r.4[..2] == TYPE_HTTPS.to_be_bytes()))
            .collect();
        expect[1].4 = https_data(false);
        assert_eq!(got, expect);
        assert_eq!(&out[6..12], &[0, 4, 0, 1, 0, 1]);
        // The MX exchange and NS target come out whole.
        let full = |s: &str| name_bytes(s);
        assert_eq!(
            got[2].4,
            [&[0u8, 10][..], &full("mail.cdn.x.test")].concat()
        );
        assert_eq!(got[4].4, full("ns.mail.cdn.x.test"));
        // No pointer is left anywhere after the header.
        let w = walk(&out).unwrap();
        for r in &w.rrs {
            assert_eq!(skip_name(&out, r.name).unwrap() - r.name, {
                let mut n = Vec::new();
                expand_name(&out, r.name, &mut n).unwrap();
                n.len()
            });
        }
        assert_eq!(strip_ech(&out).unwrap(), out, "idempotent");
    }

    /// r10 N8: a type we cannot rebuild safely next to an ech to strip
    /// makes the reply unusable (SERVFAIL by the caller); without ech it
    /// passes untouched.
    #[test]
    fn unknown_type_with_ech_is_refused_without_is_passed() {
        for ech in [true, false] {
            let mut m = any_reply(ech);
            m[7] += 1;
            let at = m.len() - OPT.len();
            let mut tail = Vec::new();
            rr(&mut tail, &ptr(16), 0xff00, &[0xc0, 12]);
            m.splice(at..at, tail);
            assert!(decode_ok(&m));
            if ech {
                assert_eq!(strip_ech(&m), None);
            } else {
                assert_eq!(strip_ech(&m).unwrap(), m);
            }
        }
    }

    fn decode_ok(m: &[u8]) -> bool {
        walk(m).is_some()
    }

    /// r10 N8: long names, many HTTPS records, all compressed: the
    /// rebuilt reply decodes to the same records less ech, however much
    /// it grew.
    #[test]
    fn long_names_and_many_https_records_rebuild_exactly() {
        let long = format!(
            "{}.{}.{}.x.test",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(60)
        );
        let mut m = query_for_test(9, &long, TYPE_HTTPS);
        m[2] = 0x81;
        m[3] = 0x80;
        let n = 12u16;
        m[6..8].copy_from_slice(&n.to_be_bytes());
        for i in 0..n {
            let mut d = https_data(true);
            d[1] = i as u8 + 1;
            rr(&mut m, &ptr(12), TYPE_HTTPS, &d);
        }
        m[10..12].copy_from_slice(&1u16.to_be_bytes());
        m.extend_from_slice(OPT);
        let out = strip_ech(&m).unwrap();
        assert!(out.len() > m.len() + 11 * 190, "names written out");
        let got = decode(&out);
        assert_eq!(got.len(), 13);
        for (i, r) in got.iter().take(12).enumerate() {
            assert_eq!(r.1, name_bytes(&long));
            let mut d = https_data(false);
            d[1] = i as u8 + 1;
            assert_eq!(r.4, d);
        }
        // Over UDP without EDNS: cut to 512 with TC; header + question.
        let q = query_for_test(9, &long, TYPE_HTTPS);
        let cut = truncate_udp(out.clone(), udp_limit(&q, 65535));
        assert_eq!(cut[2] & FLAG_TC, FLAG_TC);
        assert!(cut.len() <= 512);
        assert_eq!(&cut[4..12], &[0, 1, 0, 0, 0, 0, 0, 1], "OPT kept");
        assert!(cut.ends_with(OPT));
        // A client offering 4096 gets it whole; the path cap still applies.
        let mut q4096 = q.clone();
        q4096[10..12].copy_from_slice(&1u16.to_be_bytes());
        q4096.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(udp_limit(&q4096, 65535), 4096);
        assert_eq!(truncate_udp(out.clone(), udp_limit(&q4096, 65535)), out);
        assert_eq!(udp_limit(&q4096, 1472), 1472);
        // EDNS sizes below 512 count as 512 (RFC 6891 §6.2.5).
        let at = q4096.len() - 8;
        q4096[at..at + 2].copy_from_slice(&[0, 100]);
        assert_eq!(udp_limit(&q4096, 65535), 512);
    }

    /// An HTTPS reply too big for a 512-byte UDP answer even before the
    /// rewrite, every record with ech.
    fn big_https_reply(id: u16) -> Vec<u8> {
        let mut m = query_for_test(id, "www.x.test", TYPE_HTTPS);
        m[2] = 0x81;
        m[3] = 0x80;
        let n = 30u16;
        m[6..8].copy_from_slice(&n.to_be_bytes());
        for i in 0..n {
            let mut d = https_data(true);
            d[1] = i as u8 + 1;
            rr(&mut m, &ptr(12), TYPE_HTTPS, &d);
        }
        m
    }

    /// r10 N8: an upstream reply with TC is fetched again over TCP from
    /// the same resolver; the client gets the whole rewritten answer over
    /// TCP, and over UDP a TC reply cut to its size (so it retries on TCP
    /// and gets the whole answer, not TC again).
    #[tokio::test]
    async fn truncated_upstream_is_retried_over_tcp() {
        let up = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = up.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).await.unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = up.recv_from(&mut b).await {
                // Header + question, TC.
                let mut r = b[..n].to_vec();
                r[2] |= 0x80 | FLAG_TC;
                let _ = up.send_to(&r, from).await;
            }
        });
        let tcp_queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = tcp_queries.clone();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = tcp.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    while let Ok(n) = c.read_u16().await {
                        let mut q = vec![0u8; usize::from(n)];
                        if c.read_exact(&mut q).await.is_err() {
                            return;
                        }
                        seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let r = big_https_reply(u16::from_be_bytes([q[0], q[1]]));
                        let mut f = (r.len() as u16).to_be_bytes().to_vec();
                        f.extend_from_slice(&r);
                        let _ = c.write_all(&f).await;
                    }
                });
            }
        });
        let dns = dns_to(addr);
        let q = query_for_test(0x55, "www.x.test", TYPE_HTTPS);
        let whole = dns.handle(&q, Transport::Tcp).await.unwrap();
        assert_eq!(whole[2] & FLAG_TC, 0);
        let got = decode(&whole);
        assert_eq!(got.len(), 30);
        assert!(got.iter().all(|r| r.4[2..] == https_data(false)[2..]));
        assert!(whole.len() > 512);
        let cut = dns.handle(&q, Transport::Udp(65535)).await.unwrap();
        assert_eq!(cut[2] & FLAG_TC, FLAG_TC);
        assert_eq!(&cut[..2], &[0, 0x55]);
        assert!(cut.len() <= 512);
        assert_eq!(tcp_queries.load(std::sync::atomic::Ordering::Relaxed), 2);
    }

    /// What a fake resolver's TCP side does after its UDP reply had TC.
    #[derive(Clone, Copy, PartialEq)]
    enum TcpSide {
        /// No TCP listener: connection refused.
        Refused,
        /// Accepts, reads the query, never answers.
        Silent,
        /// Sends a length prefix and part of the message, then closes.
        HalfFrame,
        /// Answers over TCP with TC again.
        AlsoTc,
    }

    /// A resolver whose UDP reply comes after `udp_delay`: header and
    /// question with TC (NOERROR, no answers) when `tcp` is Some, else a
    /// complete answer `9.9.9.9`. Returns its address and a counter of TCP
    /// connections the kernel closed.
    async fn resolver(
        udp_delay: Duration,
        tcp: Option<TcpSide>,
    ) -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
        let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let addr = up.local_addr().unwrap();
        let closed = Arc::new(AtomicUsize::new(0));
        let listener = match tcp {
            Some(TcpSide::Refused) | None => None,
            Some(_) => Some(TcpListener::bind(addr).await.unwrap()),
        };
        let truncated = tcp.is_some();
        tokio::spawn(async move {
            let mut b = [0u8; 1500];
            while let Ok((n, from)) = up.recv_from(&mut b).await {
                let q = b[..n].to_vec();
                let up = up.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(udp_delay).await;
                    let r = if truncated {
                        let mut r = q;
                        r[2] |= 0x80 | FLAG_TC;
                        r
                    } else {
                        let parsed = parse_question(&q).ok().unwrap();
                        respond(&parsed, RCODE_OK, &["9.9.9.9".parse().unwrap()], 300)
                    };
                    let _ = up.send_to(&r, from).await;
                });
            }
        });
        if let Some(l) = listener {
            let side = tcp.unwrap();
            let closed = closed.clone();
            tokio::spawn(async move {
                while let Ok((mut c, _)) = l.accept().await {
                    let closed = closed.clone();
                    tokio::spawn(async move {
                        let n = c.read_u16().await.unwrap();
                        let mut q = vec![0u8; usize::from(n)];
                        c.read_exact(&mut q).await.unwrap();
                        match side {
                            TcpSide::Silent => {
                                let mut sink = [0u8; 64];
                                while c.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                                closed.fetch_add(1, Relaxed);
                            }
                            TcpSide::HalfFrame => {
                                let _ = c.write_all(&[0, 100, 1, 2, 3, 4, 5]).await;
                            }
                            TcpSide::AlsoTc => {
                                let mut r = q;
                                r[2] |= 0x80 | FLAG_TC;
                                let mut f = (r.len() as u16).to_be_bytes().to_vec();
                                f.extend_from_slice(&r);
                                let _ = c.write_all(&f).await;
                                let mut sink = [0u8; 64];
                                while c.read(&mut sink).await.is_ok_and(|n| n > 0) {}
                            }
                            TcpSide::Refused => unreachable!(),
                        }
                    });
                }
            });
        }
        (addr, closed)
    }

    fn dns_multi(addrs: Vec<SocketAddr>, timeout: Duration) -> Arc<SmartDns> {
        let one = dns_to(addrs[0]);
        let settings = DnsSettings {
            domestic: addrs,
            query_timeout: timeout,
            cache_size: 16,
        };
        Arc::new(SmartDns::new(
            one.policy.clone(),
            one.pool.clone(),
            settings,
        ))
    }

    fn cached(dns: &SmartDns, name: &str) -> Option<Vec<IpAddr>> {
        let cache = dns.cache.lock().unwrap();
        cache
            .get(&(name.to_owned(), TYPE_A))
            .map(|e| e.value.ips.clone())
    }

    /// r11 R2: an upstream TC reply whose TCP retry fails in any way is
    /// not an answer: SERVFAIL (over UDP and TCP, TC clear), nothing
    /// cached, and the upstream credit is back.
    #[tokio::test]
    async fn truncated_upstream_without_tcp_answer_is_servfail() {
        for side in [
            TcpSide::Refused,
            TcpSide::Silent,
            TcpSide::HalfFrame,
            TcpSide::AlsoTc,
        ] {
            let (addr, _) = resolver(Duration::ZERO, Some(side)).await;
            let dns = dns_multi(vec![addr], Duration::from_millis(300));
            for (i, via) in [Transport::Udp(65535), Transport::Tcp]
                .into_iter()
                .enumerate()
            {
                let q = query_for_test(0x70 + i as u16, "a.x.test", TYPE_A);
                let r = dns.handle(&q, via).await.unwrap();
                assert_eq!(r[3] & 0x0f, RCODE_SERVFAIL, "A, side {}", side as u8);
                assert_eq!(r[2] & FLAG_TC, 0);
                assert_eq!(&r[6..8], &[0, 0]);
                let q = query_for_test(0x80 + i as u16, "a.x.test", TYPE_HTTPS);
                let r = dns.handle(&q, via).await.unwrap();
                assert_eq!(r[3] & 0x0f, RCODE_SERVFAIL, "HTTPS, side {}", side as u8);
                assert_eq!(r[2] & FLAG_TC, 0);
            }
            assert_eq!(cached(&dns, "a.x.test"), None);
            assert_eq!(
                dns.upstream_limit.available_permits(),
                MAX_UPSTREAM_IN_FLIGHT
            );
        }
    }

    /// r11 R2: a fast truncated reply (TCP refused) does not beat a slower
    /// complete one from another resolver; that one is the answer and the
    /// only thing cached.
    #[tokio::test]
    async fn fast_truncated_loses_to_slow_complete() {
        for side in [TcpSide::Refused, TcpSide::HalfFrame, TcpSide::AlsoTc] {
            let (fast, _) = resolver(Duration::ZERO, Some(side)).await;
            let (slow, _) = resolver(Duration::from_millis(100), None).await;
            let dns = dns_multi(vec![fast, slow], Duration::from_millis(800));
            let q = query_for_test(0x91, "b.x.test", TYPE_A);
            let r = dns.handle(&q, Transport::Udp(65535)).await.unwrap();
            assert_eq!(r[3] & 0x0f, RCODE_OK, "side {}", side as u8);
            assert_eq!(r[2] & FLAG_TC, 0);
            assert_eq!(&r[6..8], &[0, 1], "one A record");
            assert_eq!(
                cached(&dns, "b.x.test"),
                Some(vec!["9.9.9.9".parse().unwrap()])
            );
            let q = query_for_test(0x92, "b.x.test", TYPE_HTTPS);
            let r = dns.handle(&q, Transport::Tcp).await.unwrap();
            assert_eq!(r[3] & 0x0f, RCODE_OK);
            assert_eq!(r[2] & FLAG_TC, 0);
        }
    }

    /// r11 R2: when the TCP retry times out, its connection is closed and
    /// the upstream credit returned when the query gives up.
    #[tokio::test]
    async fn tcp_retry_timeout_releases_connection_and_credit() {
        let (addr, closed) = resolver(Duration::ZERO, Some(TcpSide::Silent)).await;
        let dns = dns_multi(vec![addr], Duration::from_millis(200));
        let mut tasks = Vec::new();
        for i in 0..8u16 {
            let dns = dns.clone();
            tasks.push(tokio::spawn(async move {
                let q = query_for_test(0xa0 + i, &format!("c{i}.x.test"), TYPE_A);
                dns.handle(&q, Transport::Udp(65535)).await.unwrap()
            }));
        }
        let started = std::time::Instant::now();
        for t in tasks {
            let r = t.await.unwrap();
            assert_eq!(r[3] & 0x0f, RCODE_SERVFAIL);
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(
            dns.upstream_limit.available_permits(),
            MAX_UPSTREAM_IN_FLIGHT
        );
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while closed.load(std::sync::atomic::Ordering::Relaxed) < 8 {
            assert!(
                std::time::Instant::now() < deadline,
                "connections left open"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// r11 R2: parse_answers never reads a truncated message as an answer
    /// set (it would cache a partial or empty address list).
    #[test]
    fn parse_answers_rejects_tc() {
        let q = query_for_test(1, "a.b", TYPE_A);
        let parsed = parse_question(&q).ok().unwrap();
        let mut r = respond(&parsed, RCODE_OK, &["9.9.9.9".parse().unwrap()], 5);
        assert!(parse_answers(&r, TYPE_A).is_some());
        r[2] |= FLAG_TC;
        assert!(parse_answers(&r, TYPE_A).is_none());
    }
}
