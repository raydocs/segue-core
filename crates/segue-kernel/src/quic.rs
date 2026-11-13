//! QUIC Initial SNI (KERNEL_SPEC §5.2a.2).
//!
//! A client's first QUIC datagram carries Initial packets protected with
//! keys derived from public salts (RFC 9001 §5.2, RFC 9369 §3.3.1). We
//! remove header protection, decrypt, collect the CRYPTO frames and read
//! the ClientHello's server_name with the TCP sniffer's parser.
//!
//! Pure and allocation-bounded; arbitrary bytes never panic. Modern
//! clients (Chrome, quic-go) split a post-quantum ClientHello over two or
//! more Initial datagrams and shuffle the CRYPTO frames, so the name is
//! often not in the first datagram: [`InitialSniffer`] reassembles the
//! CRYPTO stream over up to [`MAX_DATAGRAMS`] datagrams. A flow whose name
//! cannot be confirmed is refused by the caller, so the app falls back to
//! TCP, where the name is always sniffable.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ring::aead::{self, quic, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;

use crate::sniff::{self, Sniff};

/// What the first datagram of a UDP flow says about QUIC.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Quic {
    /// A QUIC client Initial naming this server (lowercase, no trailing dot).
    Domain(String),
    /// A client Initial whose ClientHello is not complete enough yet: feed
    /// the flow's next datagram.
    NeedMore,
    /// Looks like QUIC (long header with the fixed bit, or an unknown QUIC
    /// version) but no server name could be confirmed. Final.
    Unclassified,
    /// Not a QUIC long-header packet.
    NotQuic,
}

const V1: u32 = 0x0000_0001;
const V2: u32 = 0x6b33_43cf;
const SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
/// Ignore CRYPTO data beyond this offset (a ClientHello is a few KB).
const MAX_CRYPTO: usize = 16 * 1024;
/// Datagrams looked at before giving up on a flow.
pub const MAX_DATAGRAMS: usize = 4;

/// One datagram on its own (see [`InitialSniffer`]).
pub fn initial_sni(dgram: &[u8]) -> Quic {
    InitialSniffer::default().push(dgram)
}

/// CRYPTO-stream reassembly over a flow's first datagrams.
///
/// The sniffer binds to the first QUIC connection it sees (the Destination
/// Connection ID of the first Initial that decrypts). Initials of any other
/// connection are never mixed into its CRYPTO stream; seeing one makes the
/// flow [`Quic::Unclassified`] (refused), since its datagrams could not be
/// attributed to a single ClientHello.
#[derive(Default)]
pub struct InitialSniffer {
    crypto: Crypto,
    seen: usize,
    initials: usize,
    dcid: Option<Vec<u8>>,
    foreign: bool,
}

impl InitialSniffer {
    /// Feed the flow's next client datagram. After a final answer (anything
    /// but [`Quic::NeedMore`]) the sniffer should be dropped.
    pub fn push(&mut self, dgram: &[u8]) -> Quic {
        self.seen += 1;
        let first = self.seen == 1;
        if !long_quic(dgram) {
            return if first { Quic::NotQuic } else { self.verdict() };
        }
        let mut rest = dgram;
        // Coalesced packets (RFC 9000 §12.2): walk every long-header packet.
        while long_quic(rest) {
            match packet(rest) {
                Some((used, Pkt::Initial(dcid, crypto))) => {
                    match &self.dcid {
                        None => self.dcid = Some(dcid.to_vec()),
                        Some(d) if d != dcid => self.foreign = true,
                        Some(_) => {}
                    }
                    if !self.foreign {
                        self.crypto.merge(crypto);
                        self.initials += 1;
                    }
                    rest = &rest[used..];
                }
                Some((used, Pkt::Other(_))) => rest = &rest[used..],
                None => break,
            }
        }
        self.verdict()
    }

    fn verdict(&self) -> Quic {
        if self.initials == 0 || self.foreign {
            return Quic::Unclassified;
        }
        let hello = self.crypto.contiguous();
        match sniff::client_hello_sni(&hello) {
            // A name later than the guard can keep could not be checked
            // against retransmissions (R11): refused up front instead.
            Sniff::Domain(_) if named_len(&hello).is_none_or(|n| n > MAX_HELLO) => {
                Quic::Unclassified
            }
            Sniff::Domain(d) => Quic::Domain(d),
            Sniff::NeedMore if self.seen < MAX_DATAGRAMS => Quic::NeedMore,
            _ => Quic::Unclassified,
        }
    }

    /// The connection this sniffer classified, for a [`ConnGuard`]: its
    /// DCID and the ClientHello bytes up to the end of the server name.
    fn conn(&self) -> Option<Conn> {
        let dcid = self.dcid.clone()?;
        let mut hello = self.crypto.contiguous();
        let named = named_len(&hello).filter(|&n| n <= MAX_HELLO)?;
        hello.truncate(named);
        hello.shrink_to_fit();
        Some(Conn { dcid, hello })
    }
}

/// Shortest prefix of `hello` that names the server (a prefix of a hello
/// is NeedMore until the name is in, then the name), or None if unnamed.
fn named_len(hello: &[u8]) -> Option<usize> {
    let is_named = |n: usize| matches!(sniff::client_hello_sni(&hello[..n]), Sniff::Domain(_));
    if !is_named(hello.len()) {
        return None;
    }
    let (mut lo, mut hi) = (0, hello.len());
    while lo < hi {
        let mid = (lo + hi) / 2;
        if is_named(mid) {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Some(hi)
}

/// Connections a [`ConnGuard`] remembers per flow, each way.
pub const MAX_CONNS: usize = 2;
/// ClientHello bytes a [`ConnGuard`] keeps per connection: everything up
/// to the end of the server name, so any retransmission of those bytes can
/// be checked. A hello naming its server later than this is refused at
/// classification ([`Quic::Unclassified`]).
pub const MAX_HELLO: usize = 3072;
/// Server-chosen connection IDs a [`ConnGuard`] remembers per flow.
pub const MAX_SERVER_CIDS: usize = 8;
/// Upper bound of what a [`ConnGuard`] keeps besides held datagrams: the
/// kept hellos and server IDs (with their allocation overhead).
pub const GUARD_KEPT: usize =
    MAX_CONNS * (MAX_HELLO + 64) + MAX_SERVER_CIDS * (20 + 32) + 128 + ROUTE_CLAIM_KEPT;
/// The route claim a QUIC flow holds (its tag name, inline bookkeeping).
const ROUTE_CLAIM_KEPT: usize = 192;

/// What to do with a datagram of a routed UDP flow (see [`ConnGuard`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Step<T> {
    /// Send these (held datagrams of a connection just allowed, then this
    /// one) on the flow.
    Forward(Vec<T>),
    /// Kept until the new connection's ClientHello is complete.
    Hold,
    /// Refused: drop these.
    Drop(Vec<T>),
    /// A packet of a connection this flow cannot vouch for, to a server
    /// another route also carries QUIC to (see [`QuicRoutes`]): drop these
    /// and refuse the flow where the front end can signal it (ICMP on TUN),
    /// so the app gives up on QUIC at once instead of timing out.
    Refuse(Vec<T>),
}

/// A classified connection: its DCID and the ClientHello prefix that
/// decided its name (at most [`MAX_HELLO`] bytes, all kept).
struct Conn {
    dcid: Vec<u8>,
    hello: Vec<u8>,
}

impl Conn {
    /// A later Initial with this DCID may only repeat the bytes that named
    /// the server (retransmission, however the CRYPTO data is split) or
    /// carry later parts of the hello; any other byte there is another
    /// ClientHello.
    fn consistent(&self, c: &Crypto) -> bool {
        c.parts.iter().all(|(off, data)| {
            let end = (off + data.len()).min(self.hello.len());
            *off >= end || self.hello[*off..end] == data[..end - off]
        })
    }
}

/// Connection IDs the server of a guarded flow chose (the Source
/// Connection ID of its long-header replies), shared with the task that
/// carries the flow's replies (see [`ConnGuard::watch`]).
#[derive(Clone, Default)]
pub struct ReplyWatch(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

impl ReplyWatch {
    /// Look at one reply datagram before it is delivered to the client:
    /// a QUIC v1/v2 long-header packet's SCID becomes a connection ID the
    /// client may address. The server only answers packets the guard
    /// forwarded, i.e. connections it allowed.
    pub fn observe(&self, dgram: &[u8]) {
        let Some(scid) = server_scid(dgram) else {
            return;
        };
        let mut ids = self.0.lock().expect("reply watch lock");
        if !ids.iter().any(|c| c == scid) {
            if ids.len() >= MAX_SERVER_CIDS {
                ids.remove(0);
            }
            ids.push(scid.to_vec());
        }
    }

    fn knows(&self, dcid: &[u8]) -> bool {
        self.0
            .lock()
            .expect("reply watch lock")
            .iter()
            .any(|c| c == dcid)
    }

    /// A short-header packet addressed to one of the server's non-empty IDs
    /// (its length is not in the packet: compare each). A zero-length ID
    /// matches no packet here: it would match every packet, of every
    /// connection, forever (R7 #2); such a server's packets go by the
    /// route check of [`ConnGuard`] instead.
    fn knows_short(&self, pkt: &[u8]) -> bool {
        self.0
            .lock()
            .expect("reply watch lock")
            .iter()
            .any(|c| !c.is_empty() && pkt.get(1..1 + c.len()) == Some(c.as_slice()))
    }

    /// Remember the ID a short-header packet is addressed to, taking the
    /// length of the server's latest non-empty ID (a server uses one length
    /// for its IDs in practice; a wrong guess only costs another check).
    fn learn_short(&self, pkt: &[u8]) {
        let mut ids = self.0.lock().expect("reply watch lock");
        let Some(len) = ids.iter().rev().map(Vec::len).find(|&n| n > 0) else {
            return;
        };
        let Some(cid) = pkt.get(1..1 + len) else {
            return;
        };
        if ids.len() >= MAX_SERVER_CIDS {
            ids.remove(0);
        }
        ids.push(cid.to_vec());
    }
}

/// How long a QUIC route claim outlives the last packet its flow carried:
/// longer than the idle timeout of the QUIC stacks in use (Chrome 30 s
/// to 5 min, quic-go 30 s, quinn 30 s), so a connection that went quiet
/// and then moved is still known.
pub const MIGRATION_WINDOW: Duration = Duration::from_secs(600);
/// Server addresses [`QuicRoutes`] tracks. When all are recent, it stops
/// vouching for anything until the window passes (fails closed).
pub const MAX_ROUTES: usize = 1024;

/// Worst-case bytes of [`QuicRoutes`]: [`MAX_ROUTES`] map entries (key,
/// Vec header, hashbrown control byte and slack), each with two routes whose
/// tag is counted at [`ROUTE_TAG_BUDGET`] bytes. Outbound tags longer than
/// that are shared `String`s from the config, so only their copies count.
pub const ROUTES_KEPT: usize = MAX_ROUTES
    * 2
    * (std::mem::size_of::<SocketAddr>()
        + std::mem::size_of::<Vec<(Option<String>, Instant)>>()
        + 1
        + 2 * (std::mem::size_of::<(Option<String>, Instant)>() + ROUTE_TAG_BUDGET));

/// Tag bytes counted per stored route in [`ROUTES_KEPT`].
pub const ROUTE_TAG_BUDGET: usize = 64;
/// A flow refreshes its claim at most this often.
const TOUCH_EVERY: Duration = Duration::from_secs(1);

/// Which routes (outbound tags) carried an allowed QUIC connection to each
/// server address recently, across all flows of one kernel (R7 #3).
///
/// A QUIC connection only comes into existence with a client Initial, and
/// every Initial on every routed flow is classified by a [`ConnGuard`], so
/// a connection that a short-header packet can address was allowed on some
/// flow. On a QUIC flow, a short header to an ID the guard never saw is
/// therefore either the flow's own connection after the client switched to
/// an ID the server issued inside the encryption (NEW_CONNECTION_ID,
/// preferred_address; RFC 9000 §5.1.1, §9.6), or a connection that moved
/// here from another flow to the same server (migration, NAT rebinding;
/// RFC 9000 §9). Only the latter can change a connection's route, and only
/// when that other flow went by another outbound. So a flow carries such a
/// packet when no other route carried QUIC to its server within
/// [`MIGRATION_WINDOW`], and refuses (fails fast) otherwise: established
/// connections survive CID rotation, and no connection changes route.
///
/// Bounded: at most [`MAX_ROUTES`] addresses, two routes each (two distinct
/// routes are enough to tell any route "someone else"); see [`ROUTES_KEPT`].
#[derive(Clone, Default)]
pub struct QuicRoutes(Arc<Mutex<Routes>>);

#[derive(Default)]
struct Routes {
    by_dst: HashMap<SocketAddr, Vec<(Option<String>, Instant)>>,
    /// Table was full of recent claims: vouch for nothing until then.
    blind_until: Option<Instant>,
}

impl QuicRoutes {
    fn lock(&self) -> std::sync::MutexGuard<'_, Routes> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Record that `tag` carries an allowed QUIC connection to `dst`.
    fn claim(&self, dst: SocketAddr, tag: &Option<String>, now: Instant) {
        let mut r = self.lock();
        if !r.by_dst.contains_key(&dst) && r.by_dst.len() >= MAX_ROUTES {
            r.by_dst.retain(|_, v| {
                v.iter()
                    .any(|(_, t)| now.saturating_duration_since(*t) < MIGRATION_WINDOW)
            });
            if r.by_dst.len() >= MAX_ROUTES {
                r.blind_until = Some(now + MIGRATION_WINDOW);
                return;
            }
        }
        let v = r.by_dst.entry(dst).or_default();
        if let Some(e) = v.iter_mut().find(|(t, _)| t == tag) {
            e.1 = e.1.max(now);
            return;
        }
        if v.len() >= 2 {
            // Drop the older of the two.
            let old = usize::from(v[1].1 < v[0].1);
            v.remove(old);
        }
        v.push((tag.clone(), now));
    }

    /// Whether another route carried QUIC to `dst` recently (or the table
    /// cannot tell).
    fn contested(&self, dst: SocketAddr, tag: &Option<String>, now: Instant) -> bool {
        let r = self.lock();
        r.blind_until.is_some_and(|t| now < t)
            || r.by_dst.get(&dst).is_some_and(|v| {
                v.iter().any(|(t, at)| {
                    t != tag && now.saturating_duration_since(*at) < MIGRATION_WINDOW
                })
            })
    }

    /// Addresses tracked (for tests and stats).
    pub fn len(&self) -> usize {
        self.lock().by_dst.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A flow's claim in [`QuicRoutes`].
struct Claim {
    routes: QuicRoutes,
    dst: SocketAddr,
    tag: Option<String>,
    touched: Option<Instant>,
}

enum Verdict {
    Ok,
    Drop,
    Refuse,
}

/// The SCID of a server's QUIC v1/v2 long-header packet (Initial,
/// Handshake or Retry).
fn server_scid(p: &[u8]) -> Option<&[u8]> {
    let mut c = Cur { b: p, p: 0 };
    let b0 = c.u8()?;
    if b0 & 0x80 == 0 {
        return None;
    }
    let version = u32::from_be_bytes(c.take(4)?.try_into().ok()?);
    let ptype = (b0 >> 4) & 0x03;
    // 0-RTT (v1 type 1, v2 type 2) is the client's only.
    match (version, ptype) {
        (V1, 1) | (V2, 2) => return None,
        (V1 | V2, _) => {}
        _ => return None,
    }
    let dcid_len = c.u8()? as usize;
    if dcid_len > 20 {
        return None;
    }
    c.take(dcid_len)?;
    let scid_len = c.u8()? as usize;
    if scid_len > 20 {
        return None;
    }
    c.take(scid_len)
}

struct Pending<T> {
    dcid: Vec<u8>,
    sniffer: InitialSniffer,
    held: Vec<T>,
}

/// Classifies every QUIC connection a routed UDP flow carries (§5.2a.2).
///
/// A flow is routed by its first connection's ClientHello, but the same
/// source socket can start another QUIC connection to the same address
/// later (a new client Initial with a new DCID and another SNI). Each new
/// connection is classified on its own and allowed only when it would get
/// the very same route as the flow; otherwise (or when it cannot be
/// classified) its datagrams are dropped, so the app falls back to TCP.
///
/// A new connection is recognized by its client Initial decrypting under
/// keys derived from its own DCID: that is what a server accepts as a new
/// connection. An Initial reusing a known DCID must repeat the ClientHello
/// bytes that connection was classified by.
///
/// Every packet of a datagram is checked, not just the first (R7 #2): a
/// QUIC long-header packet (fixed bit set) that is not such an Initial is
/// forwarded only when its DCID is an allowed connection's (0-RTT) or one
/// the server chose ([`ReplyWatch`]; later Initials and Handshake
/// packets); one of a QUIC version we cannot read, or that does not parse,
/// is dropped, on every port, as at flow start. A datagram carrying a new
/// connection's Initial carries nothing else but that connection's long
/// packets.
///
/// On a QUIC flow (`strict`, UDP/443, or one that carried an allowed QUIC
/// connection, including an ordinary UDP flow on which a client Initial
/// later appeared) a short-header packet, alone or trailing long ones,
/// must be addressed to a non-empty server-chosen ID. Failing that, a
/// flow with a route claim ([`ConnGuard::with_route`]) carries it when no
/// other route carried QUIC to the same server recently (the client moved
/// to an ID issued inside the encryption: the connection keeps working),
/// and refuses the flow ([`Step::Refuse`]) when one did (the packet may be
/// a connection that migrated from that route's flow). Without a claim it
/// is dropped.
pub struct ConnGuard<T> {
    conns: Vec<Conn>,
    refused: Vec<Vec<u8>>,
    pending: Option<Pending<T>>,
    /// Short-header packets need a known server ID.
    quic: bool,
    server: ReplyWatch,
    claim: Option<Box<Claim>>,
}

impl<T> ConnGuard<T> {
    /// For a flow routed after `sniffer` (None: routed without a QUIC
    /// connection, e.g. ordinary UDP on another port).
    pub fn new(sniffer: Option<&InitialSniffer>, strict: bool) -> Self {
        let conns: Vec<Conn> = sniffer.and_then(InitialSniffer::conn).into_iter().collect();
        Self {
            quic: strict || !conns.is_empty(),
            conns,
            refused: Vec::new(),
            pending: None,
            server: ReplyWatch::default(),
            claim: None,
        }
    }

    /// The flow goes to `dst` by outbound `tag` (None: direct); its QUIC
    /// connections are recorded in `routes`, and it may carry short headers
    /// of rotated IDs as [`QuicRoutes`] describes.
    pub fn with_route(mut self, routes: QuicRoutes, dst: SocketAddr, tag: Option<String>) -> Self {
        self.claim = Some(Box::new(Claim {
            routes,
            dst,
            tag,
            touched: None,
        }));
        self.touch(Instant::now());
        self
    }

    /// The handle the flow's reply path feeds every reply datagram to
    /// ([`ReplyWatch::observe`]) before delivering it.
    pub fn watch(&self) -> ReplyWatch {
        self.server.clone()
    }

    /// [`ReplyWatch::observe`] for a reply path that owns the guard.
    pub fn observe_reply(&self, dgram: &[u8]) {
        self.server.observe(dgram);
    }

    /// Whether a QUIC packet with this DCID belongs to an allowed
    /// connection.
    fn associated(&self, dcid: &[u8]) -> bool {
        !self.refused.iter().any(|r| r == dcid)
            && (self.conns.iter().any(|c| c.dcid == dcid) || self.server.knows(dcid))
    }

    /// Datagrams held for a connection being classified.
    pub fn held(&self) -> &[T] {
        self.pending.as_ref().map_or(&[], |p| &p.held)
    }

    /// Refresh the claim (at most every [`TOUCH_EVERY`]) while the flow
    /// carries an allowed connection.
    fn touch(&mut self, now: Instant) {
        if self.conns.is_empty() {
            return;
        }
        let Some(c) = &mut self.claim else {
            return;
        };
        if c.touched
            .is_some_and(|t| now.saturating_duration_since(t) < TOUCH_EVERY)
        {
            return;
        }
        c.touched = Some(now);
        c.routes.claim(c.dst, &c.tag, now);
    }

    /// Classify `bytes` (the payload of `d`). `allow` is asked, once a new
    /// connection's ClientHello is read, whether it routes like the flow.
    pub fn push(&mut self, d: T, bytes: &[u8], allow: impl FnOnce(&Quic) -> bool) -> Step<T> {
        self.push_at(d, bytes, allow, Instant::now())
    }

    fn push_at(
        &mut self,
        d: T,
        bytes: &[u8],
        allow: impl FnOnce(&Quic) -> bool,
        now: Instant,
    ) -> Step<T> {
        let step = self.classify(d, bytes, allow, now);
        if matches!(step, Step::Forward(_)) {
            self.touch(now);
        }
        step
    }

    fn classify(
        &mut self,
        d: T,
        bytes: &[u8],
        allow: impl FnOnce(&Quic) -> bool,
        now: Instant,
    ) -> Step<T> {
        let b0 = bytes.first().copied().unwrap_or(0);
        if b0 & 0x80 == 0 {
            // Short header (or not QUIC at all on an ordinary UDP flow).
            return step(self.short(bytes, now), d);
        }
        if !long_quic(bytes) && !self.quic {
            // Not QUIC-shaped, as at flow start: ordinary UDP.
            return Step::Forward(vec![d]);
        }
        if bytes.len() < 5
            || !matches!(
                u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
                V1 | V2
            )
        {
            return Step::Drop(vec![d]);
        }
        let Some((dcid, crypto)) = (match client_initial(bytes) {
            Initial::None => None,
            Initial::One(dcid, crypto) => Some((dcid, crypto)),
            Initial::Mixed => return Step::Drop(vec![d]),
        }) else {
            // No new client Initial: every packet must be an allowed
            // connection's.
            return step(self.coalesced(bytes, None, now), d);
        };
        if self.refused.contains(&dcid) {
            return Step::Drop(vec![d]);
        }
        if let Some(c) = self.conns.iter().find(|c| c.dcid == dcid) {
            if !c.consistent(&crypto) {
                return Step::Drop(vec![d]);
            }
            // The Initial is this connection's; so must the rest be.
            return step(self.coalesced(bytes, Some(&dcid), now), d);
        }
        // A new connection: its datagrams carry its own packets only (no
        // short header can exist before its handshake).
        if !self.only_own(bytes, &dcid) {
            return Step::Drop(vec![d]);
        }
        let mut p = match self.pending.take() {
            Some(p) if p.dcid == dcid => p,
            // One new connection at a time.
            Some(p) => {
                self.pending = Some(p);
                return Step::Drop(vec![d]);
            }
            None => Pending {
                dcid,
                sniffer: InitialSniffer::default(),
                held: Vec::new(),
            },
        };
        let q = p.sniffer.push(bytes);
        p.held.push(d);
        if q == Quic::NeedMore {
            self.pending = Some(p);
            return Step::Hold;
        }
        let ok = matches!(q, Quic::Domain(_)) && allow(&q);
        match (ok, p.sniffer.conn()) {
            (true, Some(conn)) => {
                if self.conns.len() >= MAX_CONNS {
                    self.conns.remove(0);
                }
                self.conns.push(conn);
                // An ordinary UDP flow that now carries QUIC is a QUIC flow
                // from here on (R7 #2).
                self.quic = true;
                Step::Forward(p.held)
            }
            _ => {
                if self.refused.len() >= MAX_CONNS {
                    self.refused.remove(0);
                }
                self.refused.push(p.dcid);
                Step::Drop(p.held)
            }
        }
    }

    /// A short-header packet (alone, or after a datagram's long packets).
    fn short(&mut self, pkt: &[u8], now: Instant) -> Verdict {
        if !self.quic || self.server.knows_short(pkt) {
            return Verdict::Ok;
        }
        let Some(c) = &self.claim else {
            return Verdict::Drop;
        };
        if self.conns.is_empty() {
            // No connection of this flow it could be.
            return Verdict::Drop;
        }
        if c.routes.contested(c.dst, &c.tag, now) {
            return Verdict::Refuse;
        }
        self.server.learn_short(pkt);
        Verdict::Ok
    }

    /// Every long-header packet in `dgram` parses and is addressed to
    /// `own` or an allowed connection, and what follows them is padding or
    /// a short-header packet that passes [`Self::short`]. Senders must not
    /// coalesce packets of different connections (RFC 9000 §12.2), but
    /// the guard does not rely on it.
    fn coalesced(&mut self, dgram: &[u8], own: Option<&[u8]>, now: Instant) -> Verdict {
        let Some(rest) =
            self.long_packets(dgram, |g, dcid| own == Some(dcid) || g.associated(dcid))
        else {
            return Verdict::Drop;
        };
        if padding(rest) {
            Verdict::Ok
        } else {
            self.short(rest, now)
        }
    }

    /// Every packet of a new connection's datagram is its own long packet.
    fn only_own(&self, dgram: &[u8], own: &[u8]) -> bool {
        self.long_packets(dgram, |_, dcid| dcid == own)
            .is_some_and(padding)
    }

    /// Walk the long-header packets at the start of `dgram`, each passing
    /// `ok`; the bytes after them. None: one does not parse or fails.
    fn long_packets<'a>(
        &self,
        dgram: &'a [u8],
        ok: impl Fn(&Self, &[u8]) -> bool,
    ) -> Option<&'a [u8]> {
        let mut rest = dgram;
        let mut any = false;
        while rest.first().is_some_and(|b| b & 0x80 != 0) {
            let (used, Pkt::Other(dcid) | Pkt::Initial(dcid, _)) = packet(rest)?;
            if !ok(self, dcid) {
                return None;
            }
            any = true;
            rest = &rest[used..];
        }
        any.then_some(rest)
    }
}

/// A QUIC long-header packet starts `b`: the fixed bit set, or a version
/// we read with the fixed bit greased away (RFC 9287; quinn, for one,
/// greases by default and its servers accept such Initials, so a cleared
/// bit must not make a QUIC packet "ordinary UDP").
fn long_quic(b: &[u8]) -> bool {
    b.len() >= 7
        && b[0] & 0x80 != 0
        && (b[0] & 0x40 != 0 || matches!(u32::from_be_bytes([b[1], b[2], b[3], b[4]]), V1 | V2))
}

/// Zero bytes after a datagram's packets (some stacks pad that way; no
/// QUIC packet starts with a zero byte unless the peer greased the fixed
/// bit, which the server would then have to have accepted).
fn padding(rest: &[u8]) -> bool {
    rest.iter().all(|&b| b == 0)
}

fn step<T>(v: Verdict, d: T) -> Step<T> {
    match v {
        Verdict::Ok => Step::Forward(vec![d]),
        Verdict::Drop => Step::Drop(vec![d]),
        Verdict::Refuse => Step::Refuse(vec![d]),
    }
}

enum Initial {
    None,
    One(Vec<u8>, Crypto),
    /// Initials of more than one connection in one datagram.
    Mixed,
}

/// The client Initial(s) in a datagram that decrypt under their own DCID.
fn client_initial(dgram: &[u8]) -> Initial {
    let mut out: Option<(Vec<u8>, Crypto)> = None;
    let mut rest = dgram;
    while long_quic(rest) {
        match packet(rest) {
            Some((used, Pkt::Initial(dcid, crypto))) => {
                match &mut out {
                    None => out = Some((dcid.to_vec(), crypto)),
                    Some((d, c)) if d == dcid => c.merge(crypto),
                    Some(_) => return Initial::Mixed,
                }
                rest = &rest[used..];
            }
            Some((used, Pkt::Other(_))) => rest = &rest[used..],
            None => break,
        }
    }
    match out {
        Some((d, c)) => Initial::One(d, c),
        None => Initial::None,
    }
}

enum Pkt<'a> {
    /// A client Initial that decrypted; its DCID and CRYPTO data.
    Initial(&'a [u8], Crypto),
    /// Any other v1/v2 long-header packet; its DCID.
    Other(&'a [u8]),
}

/// Parse one long-header packet at the start of `p`. Returns the bytes it
/// takes and, for a client Initial that decrypts, its DCID and CRYPTO data.
fn packet(p: &[u8]) -> Option<(usize, Pkt<'_>)> {
    let mut c = Cur { b: p, p: 0 };
    let b0 = c.u8()?;
    let version = u32::from_be_bytes(c.take(4)?.try_into().ok()?);
    let dcid_len = c.u8()? as usize;
    if dcid_len > 20 {
        return None;
    }
    let dcid = c.take(dcid_len)?;
    let scid_len = c.u8()? as usize;
    if scid_len > 20 {
        return None;
    }
    c.take(scid_len)?;
    let ptype = (b0 >> 4) & 0x03;
    let (salt, label_v2, initial_type) = match version {
        V1 => (&SALT_V1, false, 0),
        V2 => (&SALT_V2, true, 1),
        // Version negotiation or unknown version: no length to skip by.
        _ => return None,
    };
    // Retry (v1 type 3, v2 type 0) has no Length field.
    let retry_type = if label_v2 { 0 } else { 3 };
    if ptype == retry_type {
        return None;
    }
    if ptype == initial_type {
        let tlen = c.varint()?;
        c.take(usize::try_from(tlen).ok()?)?;
    }
    let len = usize::try_from(c.varint()?).ok()?;
    let pn_off = c.p;
    let end = pn_off.checked_add(len)?;
    if end > p.len() {
        return None;
    }
    if ptype != initial_type {
        return Some((end, Pkt::Other(dcid)));
    }
    let mut crypto = Crypto::default();
    let pkt = match decrypt_initial(&p[..end], pn_off, dcid, salt, label_v2, &mut crypto) {
        Some(()) => Pkt::Initial(dcid, crypto),
        None => Pkt::Other(dcid),
    };
    Some((end, pkt))
}

fn decrypt_initial(
    pkt: &[u8],
    pn_off: usize,
    dcid: &[u8],
    salt: &[u8],
    v2: bool,
    crypto: &mut Crypto,
) -> Option<()> {
    let (key, iv, hp) = client_keys(salt, dcid, v2)?;
    let sample = pkt.get(pn_off + 4..pn_off + 20)?;
    let hp = quic::HeaderProtectionKey::new(&quic::AES_128, &hp).ok()?;
    let mask = hp.new_mask(sample).ok()?;
    let mut hdr = pkt[..pn_off].to_vec();
    hdr[0] ^= mask[0] & 0x0f;
    let pn_len = usize::from(hdr[0] & 0x03) + 1;
    let pn_bytes = pkt.get(pn_off..pn_off + pn_len)?;
    let mut pn: u64 = 0;
    for (i, b) in pn_bytes.iter().enumerate() {
        let b = b ^ mask[1 + i];
        hdr.push(b);
        pn = (pn << 8) | u64::from(b);
    }
    let mut nonce = iv;
    for (i, b) in pn.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let mut body = pkt.get(pn_off + pn_len..)?.to_vec();
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).ok()?);
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&hdr),
            &mut body,
        )
        .ok()?;
    frames(plain, crypto)
}

/// Client Initial key, IV and header-protection key.
fn client_keys(salt: &[u8], dcid: &[u8], v2: bool) -> Option<([u8; 16], [u8; 12], [u8; 16])> {
    let initial = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(dcid);
    let mut client = [0u8; 32];
    expand(&initial, b"client in", &mut client)?;
    let client = hkdf::Prk::new_less_safe(hkdf::HKDF_SHA256, &client);
    let (lk, li, lh): (&[u8], &[u8], &[u8]) = if v2 {
        (b"quicv2 key", b"quicv2 iv", b"quicv2 hp")
    } else {
        (b"quic key", b"quic iv", b"quic hp")
    };
    let (mut k, mut iv, mut hp) = ([0u8; 16], [0u8; 12], [0u8; 16]);
    expand(&client, lk, &mut k)?;
    expand(&client, li, &mut iv)?;
    expand(&client, lh, &mut hp)?;
    Some((k, iv, hp))
}

struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// TLS 1.3 HKDF-Expand-Label with an empty context.
fn expand(prk: &hkdf::Prk, label: &[u8], out: &mut [u8]) -> Option<()> {
    let full = [b"tls13 ".as_slice(), label].concat();
    let len = u16::try_from(out.len()).ok()?.to_be_bytes();
    let llen = [u8::try_from(full.len()).ok()?];
    let info: [&[u8]; 4] = [&len, &llen, &full, &[0]];
    prk.expand(&info, Len(out.len())).ok()?.fill(out).ok()
}

/// Walk Initial frames, collecting CRYPTO data. Stops (keeping what it has)
/// at a frame type an Initial may not carry.
fn frames(b: &[u8], crypto: &mut Crypto) -> Option<()> {
    let mut c = Cur { b, p: 0 };
    while c.p < b.len() {
        match c.varint()? {
            0x00 | 0x01 => {} // PADDING, PING
            t @ (0x02 | 0x03) => {
                // ACK
                c.varint()?;
                c.varint()?;
                let ranges = c.varint()?;
                c.varint()?;
                for _ in 0..ranges.min(256) {
                    c.varint()?;
                    c.varint()?;
                }
                if t == 0x03 {
                    for _ in 0..3 {
                        c.varint()?;
                    }
                }
            }
            0x06 => {
                let off = usize::try_from(c.varint()?).ok()?;
                let len = usize::try_from(c.varint()?).ok()?;
                let data = c.take(len)?;
                crypto.add(off, data);
            }
            0x1c => return Some(()), // CONNECTION_CLOSE
            _ => return Some(()),
        }
    }
    Some(())
}

/// CRYPTO stream pieces, possibly out of order.
#[derive(Default)]
struct Crypto {
    parts: Vec<(usize, Vec<u8>)>,
}

impl Crypto {
    fn merge(&mut self, o: Crypto) {
        let room = 256usize.saturating_sub(self.parts.len());
        self.parts.extend(o.parts.into_iter().take(room));
    }

    fn add(&mut self, off: usize, data: &[u8]) {
        if off >= MAX_CRYPTO || self.parts.len() >= 256 {
            return;
        }
        let n = data.len().min(MAX_CRYPTO - off);
        self.parts.push((off, data[..n].to_vec()));
    }

    /// The bytes from offset 0 up to the first gap.
    fn contiguous(&self) -> Vec<u8> {
        let mut parts: Vec<_> = self.parts.iter().collect();
        parts.sort_by_key(|(o, _)| *o);
        let mut out = Vec::new();
        for (off, data) in parts {
            if *off > out.len() {
                break;
            }
            let skip = out.len() - off;
            if skip < data.len() {
                out.extend_from_slice(&data[skip..]);
            }
        }
        out
    }
}

struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let s = self.b.get(self.p..self.p.checked_add(n)?)?;
        self.p += n;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn varint(&mut self) -> Option<u64> {
        let first = self.u8()?;
        let n = 1usize << (first >> 6);
        let mut v = u64::from(first & 0x3f);
        for &b in self.take(n - 1)? {
            v = (v << 8) | u64::from(b);
        }
        Some(v)
    }
}

/// RFC 9001 Appendix A.2: the client Initial (QUIC v1, SNI example.com).
#[doc(hidden)]
pub const RFC9001_CLIENT_INITIAL: &str =
    include_str!("../testdata/quic/rfc9001-client-initial.hex");
/// RFC 9369 Appendix A.2: the same Initial for QUIC v2.
#[doc(hidden)]
pub const RFC9369_CLIENT_INITIAL: &str =
    include_str!("../testdata/quic/rfc9369-client-initial.hex");

/// The first datagram captured from quic-go (sing-box hysteria2 client,
/// SNI chatgpt.com): a 1975-byte ClientHello with shuffled CRYPTO frames,
/// the name not in this datagram.
#[doc(hidden)]
pub const QUIC_GO_CHATGPT_INITIAL: &str =
    include_str!("../testdata/quic/quic-go-chatgpt-initial.hex");
/// The second datagram of the same capture: the rest of the ClientHello.
#[doc(hidden)]
pub const QUIC_GO_CHATGPT_INITIAL_2: &str =
    include_str!("../testdata/quic/quic-go-chatgpt-initial-2.hex");

#[doc(hidden)]
pub fn hex(s: &str) -> Vec<u8> {
    let s: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    s.chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap_or("00"), 16).unwrap_or(0))
        .collect()
}

/// Build a 1200-byte QUIC v1 client Initial with `dcid` whose payload is
/// one CRYPTO frame (`off`, `data`) (tests: new connections on a flow).
#[doc(hidden)]
pub fn seal_initial_for_test(dcid: &[u8], off: u64, data: &[u8]) -> Vec<u8> {
    seal_initial_b0_for_test(0xc3, dcid, off, data)
}

/// [`seal_initial_for_test`] with first byte `b0` (e.g. the fixed bit
/// greased away, RFC 9287).
#[doc(hidden)]
pub fn seal_initial_b0_for_test(b0: u8, dcid: &[u8], off: u64, data: &[u8]) -> Vec<u8> {
    fn varint(out: &mut Vec<u8>, v: u64) {
        match v {
            0..=63 => out.push(v as u8),
            64..=16383 => out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes()),
            _ => out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes()),
        }
    }
    let (key, iv, hp) = client_keys(&SALT_V1, dcid, false).expect("keys");
    let mut plain = vec![0x06];
    varint(&mut plain, off);
    varint(&mut plain, data.len() as u64);
    plain.extend_from_slice(data);
    let mut hdr = vec![b0];
    hdr.extend_from_slice(&V1.to_be_bytes());
    hdr.push(dcid.len() as u8);
    hdr.extend_from_slice(dcid);
    hdr.push(0); // SCID
    hdr.push(0); // token
    let pn_len = 4;
    // Pad (PADDING frames) to a 1200-byte datagram.
    let fixed = hdr.len() + 2 + pn_len + 16;
    plain.resize(plain.len().max(1200 - fixed), 0);
    let len = (pn_len + plain.len() + 16) as u16;
    hdr.extend_from_slice(&(len | 0x4000).to_be_bytes());
    let pn_off = hdr.len();
    let pn: u32 = 2;
    hdr.extend_from_slice(&pn.to_be_bytes());
    let mut nonce = iv;
    for (i, b) in u64::from(pn).to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).expect("key"));
    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(&hdr),
            &mut plain,
        )
        .expect("seal");
    let mut pkt = hdr;
    pkt.extend_from_slice(&plain);
    pkt.extend_from_slice(tag.as_ref());
    let hp = quic::HeaderProtectionKey::new(&quic::AES_128, &hp).expect("hp");
    let mask = hp.new_mask(&pkt[pn_off + 4..pn_off + 20]).expect("mask");
    pkt[0] ^= mask[0] & 0x0f;
    for i in 0..pn_len {
        pkt[pn_off + i] ^= mask[1 + i];
    }
    pkt
}

/// A complete ClientHello for `sni` sealed in one Initial with `dcid`.
#[doc(hidden)]
pub fn initial_for_test(dcid: &[u8], sni: &str) -> Vec<u8> {
    let rec = crate::sniff::client_hello_for_test(Some(sni), 0);
    seal_initial_for_test(dcid, 0, &rec[5..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9001_client_initial() {
        let pkt = hex(RFC9001_CLIENT_INITIAL);
        assert_eq!(pkt.len(), 1200);
        assert_eq!(initial_sni(&pkt), Quic::Domain("example.com".into()));
    }

    #[test]
    fn rfc9369_client_initial_v2() {
        let pkt = hex(RFC9369_CLIENT_INITIAL);
        assert_eq!(pkt.len(), 1200);
        assert_eq!(initial_sni(&pkt), Quic::Domain("example.com".into()));
    }

    #[test]
    fn quic_go_capture() {
        let pkt = hex(QUIC_GO_CHATGPT_INITIAL);
        assert_eq!(pkt.len(), 1250);
        let mut s = InitialSniffer::default();
        assert_eq!(s.push(&pkt), Quic::NeedMore);
        // Retransmissions of the same datagram never complete it.
        for _ in 1..MAX_DATAGRAMS - 1 {
            assert_eq!(s.push(&pkt), Quic::NeedMore);
        }
        assert_eq!(s.push(&pkt), Quic::Unclassified);
        // Both datagrams, either order.
        let second = hex(QUIC_GO_CHATGPT_INITIAL_2);
        let mut s = InitialSniffer::default();
        assert_eq!(s.push(&pkt), Quic::NeedMore);
        assert_eq!(s.push(&second), Quic::Domain("chatgpt.com".into()));
        let mut s = InitialSniffer::default();
        let r = s.push(&second);
        assert!(
            r == Quic::NeedMore || r == Quic::Domain("chatgpt.com".into()),
            "{r:?}"
        );
        if r == Quic::NeedMore {
            assert_eq!(s.push(&pkt), Quic::Domain("chatgpt.com".into()));
        }
    }

    #[test]
    fn rfc9001_key_schedule() {
        // RFC 9001 A.1.
        let dcid = hex("8394c8f03e515708");
        let (k, iv, hp) = client_keys(&SALT_V1, &dcid, false).unwrap();
        assert_eq!(k.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn tampered_or_truncated_is_unclassified_never_panics() {
        let pkt = hex(RFC9001_CLIENT_INITIAL);
        let mut bad = pkt.clone();
        bad[100] ^= 1;
        assert_eq!(initial_sni(&bad), Quic::Unclassified);
        for n in [0, 1, 6, 7, 20, 40, 600, 1199] {
            let r = initial_sni(&pkt[..n]);
            assert_ne!(r, Quic::Domain("example.com".into()), "len {n}");
        }
        // Unknown version: QUIC-shaped, not classifiable.
        let mut v = pkt.clone();
        v[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        assert_eq!(initial_sni(&v), Quic::Unclassified);
        // Short header / not QUIC.
        assert_eq!(initial_sni(&[0x40, 1, 2, 3]), Quic::NotQuic);
        assert_eq!(initial_sni(b"\x12\x34 dns query"), Quic::NotQuic);
        for seed in 0u8..=255 {
            let mut junk = vec![seed | 0xc0; 1200];
            junk[1..5].copy_from_slice(&V1.to_be_bytes());
            let _ = initial_sni(&junk);
        }
    }

    #[test]
    fn crypto_reassembly_out_of_order() {
        let mut c = Crypto::default();
        c.add(5, b"fghij");
        c.add(0, b"abcdef");
        c.add(20, b"zz");
        assert_eq!(c.contiguous(), b"abcdefghij");
    }

    #[test]
    fn sealed_initial_roundtrip() {
        let pkt = initial_for_test(&[1; 8], "example.com");
        assert_eq!(pkt.len(), 1200);
        assert_eq!(initial_sni(&pkt), Quic::Domain("example.com".into()));
    }

    #[test]
    fn sniffer_never_mixes_connections() {
        // A non-AI connection's start and an AI connection's ClientHello in
        // the first datagrams: refused, not routed by either name.
        let rec = crate::sniff::client_hello_for_test(Some("example.com"), 0);
        let hs = &rec[5..];
        let mut s = InitialSniffer::default();
        assert_eq!(
            s.push(&seal_initial_for_test(&[1; 8], 0, &hs[..20])),
            Quic::NeedMore
        );
        assert_eq!(
            s.push(&initial_for_test(&[2; 8], "chatgpt.com")),
            Quic::Unclassified
        );
    }

    fn guard_after(dgram: &[u8]) -> ConnGuard<u32> {
        let mut s = InitialSniffer::default();
        assert!(matches!(s.push(dgram), Quic::Domain(_)));
        ConnGuard::new(Some(&s), true)
    }

    /// Same UDP tuple: an allowed connection, then a new Initial (new DCID)
    /// naming an AI host. The second connection is classified on its own
    /// and dropped; the first keeps flowing.
    #[test]
    fn guard_classifies_each_new_connection() {
        let first = initial_for_test(&[1; 8], "example.com");
        let mut g = guard_after(&first);
        let allow = |q: &Quic| q == &Quic::Domain("example.com".into());
        // Retransmission of the classified Initial; a short-header packet
        // to the ID the server chose.
        assert_eq!(g.push(1, &first, allow), Step::Forward(vec![1]));
        g.observe_reply(&long_for_test(0xe0, &[], &[1, 2, 3, 4], 40));
        assert_eq!(
            g.push(2, &[0x40, 1, 2, 3, 4, 5, 6, 7], allow),
            Step::Forward(vec![2])
        );
        // New connection, AI name: dropped, also on retransmission.
        let ai = initial_for_test(&[9; 8], "chatgpt.com");
        assert_eq!(g.push(3, &ai, allow), Step::Drop(vec![3]));
        assert_eq!(g.push(4, &ai, |_| true), Step::Drop(vec![4]));
        // Split over datagrams (real quic-go capture): held, then dropped.
        let a = hex(QUIC_GO_CHATGPT_INITIAL);
        let b = hex(QUIC_GO_CHATGPT_INITIAL_2);
        assert_eq!(g.push(5, &a, allow), Step::Hold);
        assert_eq!(g.held(), &[5]);
        assert_eq!(g.push(6, &b, allow), Step::Drop(vec![5, 6]));
        // A new connection that routes the same way is allowed.
        let again = initial_for_test(&[7; 8], "example.com");
        assert_eq!(g.push(8, &again, allow), Step::Forward(vec![8]));
        // Reusing the classified DCID for another ClientHello: dropped.
        assert_eq!(
            g.push(9, &initial_for_test(&[1; 8], "chatgpt.com"), |_| true),
            Step::Drop(vec![9])
        );
        // Unknown QUIC version on 443.
        let mut v = first.clone();
        v[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        assert_eq!(g.push(10, &v, |_| true), Step::Drop(vec![10]));
    }

    /// A flow routed as ordinary UDP (not QUIC at first) still classifies a
    /// QUIC Initial that shows up later, and refuses QUIC it cannot read.
    #[test]
    fn guard_on_plain_udp_flow() {
        let mut g: ConnGuard<u8> = ConnGuard::new(None, false);
        assert_eq!(
            g.push(1, b"\x12\x34hello", |_| true),
            Step::Forward(vec![1])
        );
        let ai = initial_for_test(&[9; 8], "chatgpt.com");
        assert_eq!(g.push(2, &ai, |_| false), Step::Drop(vec![2]));
        // R7: an unknown QUIC version is refused on every port, as at flow
        // start; the classifier is never skipped.
        let mut junk = vec![0xc0u8; 40];
        junk[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
        assert_eq!(g.push(3, &junk, |_| true), Step::Drop(vec![3]));
        // A v1 Handshake packet of a connection never seen to start.
        let hs = long_for_test(0xe0, &[5; 8], &[], 40);
        assert_eq!(g.push(4, &hs, |_| true), Step::Drop(vec![4]));
        // Ordinary UDP (short-header shaped) still goes by the IP rules.
        assert_eq!(
            g.push(5, &[0x40, 9, 9, 9], |_| true),
            Step::Forward(vec![5])
        );
        assert_eq!(g.push(6, &[0x80, 9], |_| true), Step::Forward(vec![6]));
    }

    /// A v1 long-header packet (first byte `b0`) with this DCID/SCID and a
    /// `len`-byte opaque body; its header is all a guard reads.
    fn long_for_test(b0: u8, dcid: &[u8], scid: &[u8], len: u8) -> Vec<u8> {
        let mut p = vec![b0];
        p.extend_from_slice(&V1.to_be_bytes());
        p.push(dcid.len() as u8);
        p.extend_from_slice(dcid);
        p.push(scid.len() as u8);
        p.extend_from_slice(scid);
        if b0 & 0x30 == 0 {
            p.push(0); // Initial: empty token
        }
        p.push(len);
        p.extend(std::iter::repeat_n(0x5a, len.into()));
        p
    }

    /// R7: on a routed QUIC flow nothing rides along unclassified: not an
    /// unknown QUIC version, not a long-header packet or short-header
    /// packet addressed to an ID no allowed connection has.
    #[test]
    fn guard_refuses_unassociated_packets() {
        let first = initial_for_test(&[1; 8], "example.com");
        for strict in [true, false] {
            let mut s = InitialSniffer::default();
            assert!(matches!(s.push(&first), Quic::Domain(_)));
            let mut g: ConnGuard<u8> = ConnGuard::new(Some(&s), strict);
            let ok = |_: &Quic| true;
            // Unknown version, also with a known DCID.
            let mut v = first.clone();
            v[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
            assert_eq!(g.push(1, &v, ok), Step::Drop(vec![1]));
            // Before the server answered, no short-header ID is known.
            assert_eq!(g.push(2, &[0x40, 7, 7, 7, 7, 0], ok), Step::Drop(vec![2]));
            // 0-RTT of the allowed connection (its own DCID).
            let zero_rtt = long_for_test(0xd0, &[1; 8], &[], 40);
            assert_eq!(g.push(3, &zero_rtt, ok), Step::Forward(vec![3]));
            // The server's Initial names its ID; replies of other types
            // and versions teach nothing.
            g.observe_reply(&long_for_test(0xc0, &[], &[7, 7, 7, 7], 40));
            g.observe_reply(&long_for_test(0xd0, &[], &[8, 8, 8, 8], 40));
            g.observe_reply(&[0x40, 8, 8, 8, 8, 0]);
            // Client Initial and Handshake to the server's ID; short header.
            let later = long_for_test(0xc0, &[7, 7, 7, 7], &[], 40);
            assert_eq!(g.push(4, &later, ok), Step::Forward(vec![4]));
            let hs = long_for_test(0xe0, &[7, 7, 7, 7], &[], 40);
            assert_eq!(g.push(5, &hs, ok), Step::Forward(vec![5]));
            let mut both = hs.clone();
            both.extend_from_slice(&[0x40, 7, 7, 7, 7, 1, 2]);
            assert_eq!(g.push(6, &both, ok), Step::Forward(vec![6]));
            assert_eq!(
                g.push(7, &[0x40, 7, 7, 7, 7, 0], ok),
                Step::Forward(vec![7])
            );
            // Unknown IDs: dropped.
            assert_eq!(g.push(8, &[0x40, 8, 8, 8, 8, 0], ok), Step::Drop(vec![8]));
            let other = long_for_test(0xe0, &[8, 8, 8, 8], &[], 40);
            assert_eq!(g.push(9, &other, ok), Step::Drop(vec![9]));
            let mut mixed = hs.clone();
            mixed.extend_from_slice(&other);
            assert_eq!(g.push(10, &mixed, ok), Step::Drop(vec![10]));
            // Truncated or unparsable long headers.
            assert_eq!(g.push(11, &hs[..20], ok), Step::Drop(vec![11]));
            assert_eq!(g.push(12, &[0xc0, 0, 0, 0], ok), Step::Drop(vec![12]));
            // Version 1 Retry (the client never sends one).
            let retry = long_for_test(0xf0, &[7, 7, 7, 7], &[], 40);
            assert_eq!(g.push(13, &retry, ok), Step::Drop(vec![13]));
        }
    }

    fn dst() -> SocketAddr {
        "192.0.2.1:443".parse().unwrap()
    }

    fn claimed(first: &[u8], routes: &QuicRoutes, tag: &str) -> ConnGuard<u8> {
        let mut s = InitialSniffer::default();
        assert!(matches!(s.push(first), Quic::Domain(_)));
        ConnGuard::new(Some(&s), true).with_route(routes.clone(), dst(), Some(tag.into()))
    }

    /// R7 #3: the client moves to an ID the server issued inside the
    /// encryption. With no other route carrying QUIC to the server, the
    /// flow keeps carrying the connection (and learns the ID); once
    /// another route does, the unknown ID refuses the flow (fail fast),
    /// never silently drops it.
    #[test]
    fn rotated_cid_keeps_flowing_unless_route_is_contested() {
        let routes = QuicRoutes::default();
        let first = initial_for_test(&[1; 8], "example.com");
        let mut g = claimed(&first, &routes, "p1");
        assert_eq!(routes.len(), 1);
        g.observe_reply(&long_for_test(0xe0, &[], &[7; 8], 40));
        let ok = |_: &Quic| true;
        let rotated = [0x40, 3, 3, 3, 3, 3, 3, 3, 3, 0xaa];
        assert_eq!(g.push(1, &rotated, ok), Step::Forward(vec![1]));
        // Another flow carries QUIC to the same server by another route.
        let other = claimed(&initial_for_test(&[2; 8], "example.org"), &routes, "p2");
        // The learned ID still flows; a further unknown ID refuses.
        assert_eq!(g.push(2, &rotated, ok), Step::Forward(vec![2]));
        let next = [0x40, 4, 4, 4, 4, 4, 4, 4, 4, 0xaa];
        assert_eq!(g.push(3, &next, ok), Step::Refuse(vec![3]));
        drop(other);
        // The other route's claim ages out after the window.
        let later = Instant::now() + MIGRATION_WINDOW + Duration::from_secs(1);
        assert_eq!(g.push_at(4, &next, ok, later), Step::Forward(vec![4]));
        // Same route on another flow (another source port) is no conflict.
        let routes = QuicRoutes::default();
        let mut g = claimed(&first, &routes, "p1");
        let _same = claimed(&initial_for_test(&[2; 8], "example.org"), &routes, "p1");
        assert_eq!(g.push(5, &next, ok), Step::Forward(vec![5]));
    }

    /// R7 #2: a server that chose a zero-length ID is no wildcard for
    /// short headers: they go by the route check like any unknown ID.
    #[test]
    fn zero_length_server_cid_is_not_a_wildcard() {
        let first = initial_for_test(&[1; 8], "example.com");
        let ok = |_: &Quic| true;
        let pkt = [0x40, 9, 9, 9, 9, 9, 9, 9, 9, 0];
        // No claim: dropped (it used to match every packet).
        let mut g = guard_after(&first);
        g.observe_reply(&long_for_test(0xe0, &[], &[], 40));
        assert_eq!(g.push(1u32, &pkt, ok), Step::Drop(vec![1]));
        // Long headers to the empty ID are the connection's.
        let hs = long_for_test(0xe0, &[], &[], 40);
        assert_eq!(g.push(2, &hs, ok), Step::Forward(vec![2]));
        // With a claim: contested refuses.
        let routes = QuicRoutes::default();
        let mut g = claimed(&first, &routes, "p1");
        g.observe_reply(&long_for_test(0xe0, &[], &[], 40));
        let _other = claimed(&initial_for_test(&[2; 8], "example.org"), &routes, "p2");
        assert_eq!(g.push(3, &pkt, ok), Step::Refuse(vec![3]));
    }

    /// R7 #2: an ordinary UDP flow that later carries an allowed QUIC
    /// connection is a QUIC flow from then on.
    #[test]
    fn plain_flow_turns_quic_after_an_allowed_initial() {
        let routes = QuicRoutes::default();
        let mut g: ConnGuard<u8> =
            ConnGuard::new(None, false).with_route(routes.clone(), dst(), Some("p1".into()));
        assert!(routes.is_empty(), "no claim without a connection");
        let pkt = [0x40, 9, 9, 9, 9, 9, 9, 9, 9, 0];
        assert_eq!(g.push(1, &pkt, |_| true), Step::Forward(vec![1]));
        let first = initial_for_test(&[1; 8], "example.com");
        assert_eq!(g.push(2, &first, |_| true), Step::Forward(vec![2]));
        assert_eq!(routes.len(), 1, "claimed once it carries QUIC");
        let _other = claimed(&initial_for_test(&[2; 8], "example.org"), &routes, "p2");
        assert_eq!(g.push(3, &pkt, |_| true), Step::Refuse(vec![3]));
        // Without a claim: dropped, no longer ordinary UDP.
        let mut g: ConnGuard<u8> = ConnGuard::new(None, false);
        assert_eq!(g.push(4, &first, |_| true), Step::Forward(vec![4]));
        assert_eq!(g.push(5, &pkt, |_| true), Step::Drop(vec![5]));
    }

    /// R7 #2: every packet of a coalesced datagram is checked, whatever
    /// the first one is.
    #[test]
    fn coalesced_packets_are_each_checked() {
        let first = initial_for_test(&[1; 8], "example.com");
        let ok = |_: &Quic| true;
        let mut g = guard_after(&first);
        g.observe_reply(&long_for_test(0xe0, &[], &[7; 4], 40));
        let stranger = long_for_test(0xe0, &[8; 4], &[], 40);
        // Known Initial + another connection's Handshake.
        let mut d = first.clone();
        d.extend_from_slice(&stranger);
        assert_eq!(g.push(1u32, &d, ok), Step::Drop(vec![1]));
        // Known Initial + trailing short header to an unknown ID.
        let mut d = first.clone();
        d.extend_from_slice(&[0x40, 8, 8, 8, 8, 0]);
        assert_eq!(g.push(2, &d, ok), Step::Drop(vec![2]));
        // ... to the server's ID, or zero padding: fine.
        let mut d = first.clone();
        d.extend_from_slice(&[0x40, 7, 7, 7, 7, 0]);
        assert_eq!(g.push(3, &d, ok), Step::Forward(vec![3]));
        let mut d = first.clone();
        d.extend_from_slice(&[0; 32]);
        assert_eq!(g.push(4, &d, ok), Step::Forward(vec![4]));
        // Handshake of the connection + trailing unknown short header.
        let mut d = long_for_test(0xe0, &[7; 4], &[], 40);
        d.extend_from_slice(&[0x40, 8, 8, 8, 8, 0]);
        assert_eq!(g.push(5, &d, ok), Step::Drop(vec![5]));
        // A new connection's Initial carries nothing else.
        let fresh = initial_for_test(&[2; 8], "example.org");
        let mut d = fresh.clone();
        d.extend_from_slice(&long_for_test(0xe0, &[7; 4], &[], 40));
        assert_eq!(g.push(6, &d, ok), Step::Drop(vec![6]));
        let mut d = fresh.clone();
        d.extend_from_slice(&[0x40, 7, 7, 7, 7, 0]);
        assert_eq!(g.push(7, &d, ok), Step::Drop(vec![7]));
        assert_eq!(g.push(8, &fresh, ok), Step::Forward(vec![8]));
    }

    /// R7 #2: a QUIC Initial with the fixed bit greased away (RFC 9287;
    /// quinn servers accept them) is QUIC, not ordinary UDP: classified at
    /// flow start, and on a plain flow it starts QUIC mode.
    #[test]
    fn greased_fixed_bit_is_still_quic() {
        let rec = crate::sniff::client_hello_for_test(Some("chatgpt.com"), 0);
        let ai = seal_initial_b0_for_test(0x83, &[9; 8], 0, &rec[5..]);
        assert_eq!(initial_sni(&ai), Quic::Domain("chatgpt.com".into()));
        let mut g: ConnGuard<u8> = ConnGuard::new(None, false);
        let allow = |q: &Quic| q == &Quic::Domain("example.com".into());
        assert_eq!(g.push(1, &ai, allow), Step::Drop(vec![1]));
        let rec = crate::sniff::client_hello_for_test(Some("example.com"), 0);
        let ok = seal_initial_b0_for_test(0x83, &[1; 8], 0, &rec[5..]);
        assert_eq!(g.push(2, &ok, allow), Step::Forward(vec![2]));
        // A greased reply teaches the server's ID.
        g.observe_reply(&long_for_test(0xa0, &[], &[7; 4], 40));
        assert_eq!(
            g.push(3, &[0x00, 7, 7, 7, 7, 1], allow),
            Step::Forward(vec![3])
        );
        assert_eq!(
            g.push(4, &[0x00, 8, 8, 8, 8, 1], allow),
            Step::Drop(vec![4])
        );
    }

    /// The route table stays bounded and, when full of live claims,
    /// vouches for nothing (fails closed) until they age out.
    #[test]
    fn quic_routes_bounded_and_fail_closed() {
        let r = QuicRoutes::default();
        let now = Instant::now();
        let p1 = Some("p1".to_string());
        for i in 0..MAX_ROUTES {
            let a = SocketAddr::new(std::net::Ipv4Addr::from(i as u32 + 1).into(), 443);
            r.claim(a, &p1, now);
        }
        assert!(!r.contested(dst(), &p1, now));
        r.claim(dst(), &p1, now);
        assert_eq!(r.len(), MAX_ROUTES);
        assert!(r.contested(dst(), &p1, now));
        let later = now + MIGRATION_WINDOW;
        assert!(!r.contested(dst(), &p1, later));
        r.claim(dst(), &p1, later);
        assert_eq!(r.len(), 1, "aged-out claims pruned");
        // Three routes to one server: every one of them sees another.
        for t in ["a", "b", "c"] {
            r.claim(dst(), &Some(t.into()), later);
        }
        for t in ["a", "b", "c", "p1"] {
            assert!(r.contested(dst(), &Some(t.into()), later), "{t}");
        }
    }

    /// The CRYPTO data of `hello` split over Initials of `dcid` with at
    /// most `chunk` bytes each.
    fn split_initials(dcid: &[u8], hello: &[u8], chunk: usize) -> Vec<Vec<u8>> {
        hello
            .chunks(chunk)
            .enumerate()
            .map(|(i, c)| seal_initial_for_test(dcid, (i * chunk) as u64, c))
            .collect()
    }

    /// R11: a ClientHello naming its server after 2048 bytes is allowed,
    /// and so are its retransmissions, verbatim or split differently.
    #[test]
    fn guard_allows_retransmits_of_a_late_name() {
        let rec = crate::sniff::client_hello_for_test(Some("example.com"), 2600);
        let hello = &rec[5..];
        assert!(named_len(hello).unwrap() > 2600);
        let first = split_initials(&[1; 8], hello, 1000);
        assert_eq!(first.len(), 3);
        let mut s = InitialSniffer::default();
        assert_eq!(s.push(&first[0]), Quic::NeedMore);
        assert_eq!(s.push(&first[1]), Quic::NeedMore);
        assert_eq!(s.push(&first[2]), Quic::Domain("example.com".into()));
        let mut g: ConnGuard<u8> = ConnGuard::new(Some(&s), true);
        let never = |_: &Quic| false;
        for (i, d) in first.iter().enumerate() {
            assert_eq!(g.push(i as u8, d, never), Step::Forward(vec![i as u8]));
        }
        for (i, d) in split_initials(&[1; 8], hello, 700).iter().enumerate() {
            assert_eq!(g.push(i as u8, d, never), Step::Forward(vec![i as u8]));
        }
        let all = seal_initial_for_test(&[1; 8], 0, hello);
        assert_eq!(g.push(9, &all, never), Step::Forward(vec![9]));
        // The same DCID with another name there is still refused.
        let ai = crate::sniff::client_hello_for_test(Some("chatgpt.com"), 2600);
        let late = seal_initial_for_test(&[1; 8], 2000, &ai[5 + 2000..]);
        assert_eq!(g.push(10, &late, |_| true), Step::Drop(vec![10]));
    }

    /// R11: a name later than the guard can keep is refused up front, not
    /// allowed and then broken on its first retransmission.
    #[test]
    fn name_past_kept_hello_is_unclassified() {
        let rec = crate::sniff::client_hello_for_test(Some("example.com"), MAX_HELLO);
        let pkt = seal_initial_for_test(&[1; 8], 0, &rec[5..]);
        assert_eq!(initial_sni(&pkt), Quic::Unclassified);
        let rec = crate::sniff::client_hello_for_test(Some("example.com"), MAX_HELLO - 100);
        let pkt = seal_initial_for_test(&[1; 8], 0, &rec[5..]);
        assert_eq!(initial_sni(&pkt), Quic::Domain("example.com".into()));
    }
}
