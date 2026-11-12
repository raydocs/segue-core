//! TUN core tests: synthetic packets in, packets out. No root, no device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use segue_kernel::dial::{DialError, Dialer, Stream};
use segue_kernel::rules::{Action, Cidr, Matcher, Rule, RuleSet};
use segue_kernel::tun::{
    mss_for, Event, FlowKey, Netstack, NetstackConfig, PacketIo, Proto, TunStack, UdpDatagram, UdpHandler,
    UdpReply, Verdict,
};
use segue_routing::TargetAddr;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpAddress, IpProtocol, Icmpv4Packet, Icmpv6Packet, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr, TcpControl,
    TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Packet helpers (the "application" side)

const CLIENT4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 2)), 40000);
const SITE4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443);

fn client6() -> SocketAddr {
    SocketAddr::new(IpAddr::V6("fd00:5e9e::2".parse().unwrap()), 40000)
}
fn site6() -> SocketAddr {
    SocketAddr::new(IpAddr::V6("2606:2800:220:1::248".parse().unwrap()), 443)
}

fn caps() -> ChecksumCapabilities {
    ChecksumCapabilities::default()
}

fn ip_packet(src: IpAddr, dst: IpAddr, proto: IpProtocol, len: usize, fill: impl FnOnce(&mut [u8])) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let repr = Ipv4Repr { src_addr: s, dst_addr: d, next_header: proto, payload_len: len, hop_limit: 64 };
            let mut buf = vec![0u8; 20 + len];
            let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
            repr.emit(&mut p, &caps());
            fill(p.payload_mut());
            buf
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let repr = Ipv6Repr { src_addr: s, dst_addr: d, next_header: proto, payload_len: len, hop_limit: 64 };
            let mut buf = vec![0u8; 40 + len];
            let mut p = Ipv6Packet::new_unchecked(&mut buf[..]);
            repr.emit(&mut p);
            fill(p.payload_mut());
            buf
        }
        _ => unreachable!(),
    }
}

#[derive(Clone, Copy)]
struct Flags {
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
}

const SYN: Flags = Flags { syn: true, ack: false, fin: false, rst: false };
const ACK: Flags = Flags { syn: false, ack: true, fin: false, rst: false };
const FIN: Flags = Flags { syn: false, ack: true, fin: true, rst: false };

fn tcp(src: SocketAddr, dst: SocketAddr, f: Flags, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
    let control = if f.syn {
        TcpControl::Syn
    } else if f.fin {
        TcpControl::Fin
    } else if f.rst {
        TcpControl::Rst
    } else {
        TcpControl::None
    };
    let repr = TcpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
        control,
        seq_number: TcpSeqNumber(seq as i32),
        ack_number: f.ack.then_some(TcpSeqNumber(ack as i32)),
        window_len: 65535,
        window_scale: None,
        max_seg_size: f.syn.then_some(1460),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload,
    };
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    ip_packet(src.ip(), dst.ip(), IpProtocol::Tcp, repr.buffer_len(), |b| {
        repr.emit(&mut TcpPacket::new_unchecked(b), &s, &d, &caps());
    })
}

fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let repr = UdpRepr { src_port: src.port(), dst_port: dst.port() };
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    ip_packet(src.ip(), dst.ip(), IpProtocol::Udp, 8 + payload.len(), |b| {
        repr.emit(&mut UdpPacket::new_unchecked(b), &s, &d, payload.len(), |p| p.copy_from_slice(payload), &caps());
    })
}

/// Parsed view of an output packet.
#[derive(Debug)]
struct Out {
    src: IpAddr,
    dst: IpAddr,
    proto: IpProtocol,
    l4: Vec<u8>,
}

fn out(pkt: &[u8]) -> Out {
    if pkt[0] >> 4 == 4 {
        let p = Ipv4Packet::new_checked(pkt).unwrap();
        assert!(p.verify_checksum());
        Out { src: p.src_addr().into(), dst: p.dst_addr().into(), proto: p.next_header(), l4: p.payload().to_vec() }
    } else {
        let p = Ipv6Packet::new_checked(pkt).unwrap();
        Out { src: p.src_addr().into(), dst: p.dst_addr().into(), proto: p.next_header(), l4: p.payload().to_vec() }
    }
}

#[derive(Debug)]
struct Seg {
    src_port: u16,
    dst_port: u16,
    syn: bool,
    ack: bool,
    fin: bool,
    rst: bool,
    seq: u32,
    ack_no: u32,
    mss: Option<u16>,
    payload: Vec<u8>,
}

fn seg(pkt: &[u8]) -> Seg {
    let o = out(pkt);
    assert_eq!(o.proto, IpProtocol::Tcp, "expected TCP, got {o:?}");
    let t = TcpPacket::new_checked(&o.l4[..]).unwrap();
    assert!(t.verify_checksum(&IpAddress::from(o.src), &IpAddress::from(o.dst)), "bad TCP checksum");
    let repr = TcpRepr::parse(&t, &IpAddress::from(o.src), &IpAddress::from(o.dst), &caps()).unwrap();
    Seg {
        src_port: t.src_port(),
        dst_port: t.dst_port(),
        syn: t.syn(),
        ack: t.ack(),
        fin: t.fin(),
        rst: t.rst(),
        seq: t.seq_number().0 as u32,
        ack_no: t.ack_number().0 as u32,
        mss: repr.max_seg_size,
        payload: t.payload().to_vec(),
    }
}

fn accept_all(_: &FlowKey) -> Verdict {
    Verdict::Accept(Some("proxy".into()))
}

fn refuse_all(_: &FlowKey) -> Verdict {
    Verdict::Refuse
}

fn drain(stack: &mut Netstack) -> Vec<Bytes> {
    std::iter::from_fn(|| stack.pop_output()).collect()
}

fn one(stack: &mut Netstack) -> Bytes {
    let mut v = drain(stack);
    assert_eq!(v.len(), 1, "expected exactly one packet");
    v.pop().unwrap()
}

/// SYN → SYN-ACK → ACK; returns (stack, flow id, client next seq, server next seq).
fn handshake(cfg: NetstackConfig, client: SocketAddr, site: SocketAddr) -> (Netstack, segue_kernel::tun::FlowId, u32, u32) {
    let now = Instant::now();
    let mut stack = Netstack::new(cfg, now);
    stack.input(&tcp(client, site, SYN, 1000, 0, b""), now, &mut accept_all);
    let id = match stack.pop_event() {
        Some(Event::TcpAccepted { id, key, tag }) => {
            assert_eq!(key, FlowKey { proto: Proto::Tcp, src: client, dst: site });
            assert_eq!(tag.as_deref(), Some("proxy"));
            id
        }
        e => panic!("expected TcpAccepted, got {e:?}"),
    };
    let synack = seg(&one(&mut stack));
    assert!(synack.syn && synack.ack && !synack.rst);
    assert_eq!((synack.src_port, synack.dst_port), (site.port(), client.port()));
    assert_eq!(synack.ack_no, 1001);
    let server_seq = synack.seq.wrapping_add(1);
    stack.input(&tcp(client, site, ACK, 1001, server_seq, b""), now, &mut accept_all);
    assert!(stack.tcp_established(id).unwrap());
    (stack, id, 1001, server_seq)
}

// ---------------------------------------------------------------------------
// Netstack: refusals

#[test]
fn refused_syn_gets_rst_acking_the_syn() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    stack.input(&tcp(CLIENT4, SITE4, SYN, 5000, 0, b""), now, &mut refuse_all);
    let rst = seg(&one(&mut stack));
    assert!(rst.rst && rst.ack && !rst.syn);
    assert_eq!(rst.ack_no, 5001);
    assert_eq!(rst.seq, 0);
    assert_eq!((rst.src_port, rst.dst_port), (443, 40000));
    assert_eq!(stack.tcp_flows(), 0);
    assert_eq!(stack.stats().tcp_refused_policy, 1);
    assert!(stack.pop_event().is_none());
}

#[test]
fn refused_syn_v6_gets_rst() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    stack.input(&tcp(client6(), site6(), SYN, 7, 0, b""), now, &mut refuse_all);
    let pkt = one(&mut stack);
    let o = out(&pkt);
    assert_eq!((o.src, o.dst), (site6().ip(), client6().ip()));
    let rst = seg(&pkt);
    assert!(rst.rst && rst.ack_no == 8);
}

#[test]
fn private_and_loopback_destinations_are_refused_without_asking_the_router() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    let mut asked = 0;
    let mut policy = |_: &FlowKey| {
        asked += 1;
        Verdict::Accept(None)
    };
    for dst in ["10.1.2.3:80", "192.168.1.1:80", "172.16.0.1:80", "127.0.0.1:80", "169.254.1.1:80", "100.64.0.1:80", "[fe80::1]:80", "[fc00::1]:80", "[::1]:80"] {
        let dst: SocketAddr = dst.parse().unwrap();
        let src = if dst.is_ipv4() { CLIENT4 } else { client6() };
        stack.input(&tcp(src, dst, SYN, 1, 0, b""), now, &mut policy);
        assert!(seg(&one(&mut stack)).rst, "{dst} not refused");
    }
    // Multicast / broadcast: dropped silently.
    stack.input(&udp(CLIENT4, "224.0.0.251:5353".parse().unwrap(), b"mdns"), now, &mut policy);
    stack.input(&udp(CLIENT4, "255.255.255.255:67".parse().unwrap(), b"dhcp"), now, &mut policy);
    assert!(drain(&mut stack).is_empty());
    assert_eq!(asked, 0);
    assert_eq!(stack.stats().tcp_refused_reserved, 9);
}

#[test]
fn flow_table_full_refuses_new_flows_with_rst() {
    let now = Instant::now();
    let cfg = NetstackConfig { max_tcp_flows: 2, ..Default::default() };
    let mut stack = Netstack::new(cfg, now);
    for port in [1, 2] {
        let src = SocketAddr::new(CLIENT4.ip(), port);
        stack.input(&tcp(src, SITE4, SYN, 1, 0, b""), now, &mut accept_all);
        assert!(seg(&one(&mut stack)).syn);
    }
    let src = SocketAddr::new(CLIENT4.ip(), 3);
    stack.input(&tcp(src, SITE4, SYN, 1, 0, b""), now, &mut accept_all);
    assert!(seg(&one(&mut stack)).rst);
    assert_eq!(stack.tcp_flows(), 2);
    assert_eq!(stack.stats().tcp_refused_full, 1);
}

#[test]
fn segment_for_unknown_flow_gets_rst_from_its_ack() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    stack.input(&tcp(CLIENT4, SITE4, ACK, 100, 777, b"late"), now, &mut accept_all);
    let rst = seg(&one(&mut stack));
    assert!(rst.rst && !rst.ack);
    assert_eq!(rst.seq, 777);
    // A RST for an unknown flow is never answered.
    let rst_in = tcp(CLIENT4, SITE4, Flags { syn: false, ack: false, fin: false, rst: true }, 1, 0, b"");
    stack.input(&rst_in, now, &mut accept_all);
    assert!(drain(&mut stack).is_empty());
}

#[test]
fn refused_udp_gets_icmp_admin_prohibited_v4() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let sent = udp(CLIENT4, dst, b"quic-initial");
    stack.input(&sent, now, &mut refuse_all);
    let pkt = one(&mut stack);
    let o = out(&pkt);
    assert_eq!(o.proto, IpProtocol::Icmp);
    assert_eq!(o.dst, CLIENT4.ip());
    assert_eq!(o.src, IpAddr::V4(NetstackConfig::default().v4_addr));
    let icmp = Icmpv4Packet::new_checked(&o.l4[..]).unwrap();
    assert!(icmp.verify_checksum());
    assert_eq!(u8::from(icmp.msg_type()), 3);
    assert_eq!(icmp.msg_code(), 13);
    // Quotes the original IP header + first 8 bytes of the datagram.
    assert_eq!(icmp.data(), &sent[..28]);
}

#[test]
fn refused_udp_gets_icmpv6_admin_prohibited() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    let dst: SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
    let sent = udp(client6(), dst, b"quic");
    stack.input(&sent, now, &mut refuse_all);
    let pkt = one(&mut stack);
    let o = out(&pkt);
    assert_eq!(o.proto, IpProtocol::Icmpv6);
    let icmp = Icmpv6Packet::new_checked(&o.l4[..]).unwrap();
    assert!(icmp.verify_checksum(&o.src.to_v6(), &o.dst.to_v6()));
    assert_eq!(u8::from(icmp.msg_type()), 1);
    assert_eq!(icmp.msg_code(), 1);
    assert_eq!(&o.l4[8..], &sent[..]);
}

trait ToV6 {
    fn to_v6(&self) -> Ipv6Addr;
}
impl ToV6 for IpAddr {
    fn to_v6(&self) -> Ipv6Addr {
        match self {
            IpAddr::V6(v6) => *v6,
            IpAddr::V4(_) => panic!("not v6"),
        }
    }
}

#[test]
fn synthesized_icmp_is_rate_limited() {
    let now = Instant::now();
    let cfg = NetstackConfig { icmp_burst: 3, icmp_per_sec: 1, ..Default::default() };
    let mut stack = Netstack::new(cfg, now);
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
    for _ in 0..10 {
        stack.input(&udp(CLIENT4, dst, b"x"), now, &mut refuse_all);
    }
    assert_eq!(drain(&mut stack).len(), 3);
    assert_eq!(stack.stats().icmp_suppressed, 7);
    stack.input(&udp(CLIENT4, dst, b"x"), now + Duration::from_secs(2), &mut refuse_all);
    assert_eq!(drain(&mut stack).len(), 1);
}

#[test]
fn malformed_fragmented_and_oversize_packets_are_dropped() {
    let now = Instant::now();
    let cfg = NetstackConfig { mtu: 1280, ..Default::default() };
    let mut stack = Netstack::new(cfg, now);
    let mut bad = tcp(CLIENT4, SITE4, SYN, 1, 0, b"");
    let last = bad.len() - 1;
    bad[last] ^= 0xff; // corrupt TCP checksum region (header byte)
    bad[30] ^= 0x01;
    stack.input(&bad, now, &mut accept_all);
    let mut frag = udp(CLIENT4, "8.8.8.8:53".parse().unwrap(), b"dns");
    {
        let mut p = Ipv4Packet::new_unchecked(&mut frag[..]);
        p.set_more_frags(true);
        p.fill_checksum();
    }
    stack.input(&frag, now, &mut accept_all);
    stack.input(&udp(CLIENT4, "8.8.8.8:53".parse().unwrap(), &[0u8; 1300]), now, &mut accept_all);
    stack.input(&[0x45, 0, 0], now, &mut accept_all);
    assert!(drain(&mut stack).is_empty());
    let s = stack.stats();
    assert_eq!((s.dropped_malformed, s.dropped_fragment, s.dropped_oversize), (2, 1, 1));
    assert_eq!(stack.tcp_flows() + stack.udp_flows(), 0);
}

// ---------------------------------------------------------------------------
// Netstack: TCP through the stack

#[test]
fn syn_ack_mss_is_clamped_to_tun_mtu() {
    let cfg = NetstackConfig { mtu: 1400, ..Default::default() };
    let now = Instant::now();
    let mut stack = Netstack::new(cfg.clone(), now);
    stack.input(&tcp(CLIENT4, SITE4, SYN, 1, 0, b""), now, &mut accept_all);
    assert_eq!(seg(&one(&mut stack)).mss, Some(1360));
    stack.input(&tcp(client6(), site6(), SYN, 1, 0, b""), now, &mut accept_all);
    assert_eq!(seg(&one(&mut stack)).mss, Some(1340));
    assert_eq!(mss_for(1400, false), 1360);
    assert_eq!(mss_for(1400, true), 1340);
}

#[test]
fn tcp_data_flows_both_ways_and_segments_fit_mtu() {
    for (client, site) in [(CLIENT4, SITE4), (client6(), site6())] {
        let cfg = NetstackConfig { mtu: 1280, ..Default::default() };
        let (mut stack, id, cseq, sseq) = handshake(cfg, client, site);
        let now = Instant::now();
        stack.input(&tcp(client, site, ACK, cseq, sseq, b"GET / HTTP/1.1\r\n\r\n"), now, &mut accept_all);
        let mut buf = [0u8; 64];
        let n = stack.tcp_read(id, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"GET / HTTP/1.1\r\n\r\n");
        let body = vec![b'z'; 5000];
        assert_eq!(stack.tcp_write(id, &body).unwrap(), 5000);
        stack.poll(now);
        let mut got = Vec::new();
        // The sender is congestion-window limited: ACK what arrived, repeat.
        for _ in 0..20 {
            for pkt in drain(&mut stack) {
                assert!(pkt.len() <= 1280);
                let s = seg(&pkt);
                if !s.payload.is_empty() {
                    assert_eq!(s.seq, sseq.wrapping_add(got.len() as u32));
                    assert!(s.payload.len() <= mss_for(1280, client.is_ipv6()));
                    got.extend_from_slice(&s.payload);
                }
            }
            if got.len() == body.len() {
                break;
            }
            let acked = sseq.wrapping_add(got.len() as u32);
            stack.input(&tcp(client, site, ACK, cseq + 18, acked, b""), now, &mut accept_all);
        }
        assert_eq!(got, body);
    }
}

#[test]
fn abort_after_accept_sends_rst_and_reaps_flow() {
    let (mut stack, id, cseq, _) = handshake(NetstackConfig::default(), CLIENT4, SITE4);
    let _ = cseq;
    stack.tcp_abort(id).unwrap();
    stack.poll(Instant::now());
    let rst = seg(&one(&mut stack));
    assert!(rst.rst);
    assert_eq!(stack.tcp_flows(), 0);
    assert!(matches!(stack.pop_event(), Some(Event::TcpClosed { id: closed, .. }) if closed == id));
    assert!(stack.tcp_read(id, &mut [0u8; 4]).is_err());
}

#[test]
fn fin_from_application_is_seen_and_close_completes() {
    let (mut stack, id, cseq, sseq) = handshake(NetstackConfig::default(), CLIENT4, SITE4);
    let now = Instant::now();
    stack.input(&tcp(CLIENT4, SITE4, FIN, cseq, sseq, b"bye"), now, &mut accept_all);
    let mut buf = [0u8; 8];
    assert_eq!(stack.tcp_read(id, &mut buf).unwrap(), 3);
    assert!(stack.tcp_peer_finished(id).unwrap());
    stack.tcp_close(id).unwrap();
    stack.poll(now);
    let fin = drain(&mut stack).iter().map(|p| seg(p)).find(|s| s.fin).expect("FIN");
    stack.input(&tcp(CLIENT4, SITE4, ACK, cseq + 4, fin.seq + 1, b""), now, &mut accept_all);
    assert_eq!(stack.tcp_flows(), 0, "flow reaped after LAST_ACK");
}

#[test]
fn udp_accepted_datagrams_queue_bounded_and_reply_is_addressed_back() {
    let now = Instant::now();
    let cfg = NetstackConfig { udp_queue: 2, ..Default::default() };
    let mut stack = Netstack::new(cfg, now);
    let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    for msg in [&b"a"[..], b"b", b"c"] {
        stack.input(&udp(CLIENT4, dst, msg), now, &mut accept_all);
    }
    assert_eq!(stack.udp_flows(), 1);
    let got: Vec<UdpDatagram> = std::iter::from_fn(|| stack.pop_udp()).collect();
    assert_eq!(got.iter().map(|d| d.payload.clone()).collect::<Vec<_>>(), vec![Bytes::from("b"), Bytes::from("c")]);
    assert_eq!(stack.stats().dropped_udp_queue_full, 1);
    stack.send_udp(&got[0].key, b"answer");
    let pkt = one(&mut stack);
    let o = out(&pkt);
    assert_eq!((o.src, o.dst), (dst.ip(), CLIENT4.ip()));
    let u = UdpPacket::new_checked(&o.l4[..]).unwrap();
    assert!(u.verify_checksum(&IpAddress::from(o.src), &IpAddress::from(o.dst)));
    assert_eq!((u.src_port(), u.dst_port(), u.payload()), (53, 40000, &b"answer"[..]));
    // Expires after idle timeout.
    stack.poll(now + Duration::from_secs(61));
    assert_eq!(stack.udp_flows(), 0);
}

// ---------------------------------------------------------------------------
// Driver: device ↔ stack ↔ router ↔ fake dialer

struct ChanIo {
    rx: tokio::sync::Mutex<mpsc::Receiver<Bytes>>,
    tx: mpsc::Sender<Bytes>,
}

#[async_trait]
impl PacketIo for ChanIo {
    async fn recv(&self) -> std::io::Result<Bytes> {
        self.rx.lock().await.recv().await.ok_or_else(|| std::io::Error::other("closed"))
    }
    async fn send(&self, pkt: Bytes) -> std::io::Result<()> {
        self.tx.send(pkt).await.map_err(|_| std::io::Error::other("closed"))
    }
}

/// Dialer whose "site" is an in-memory duplex. Records every dial.
#[derive(Default)]
struct FakeDialer {
    dials: Mutex<Vec<(Option<String>, TargetAddr, u16)>>,
    fail: bool,
    sites: Mutex<Vec<tokio::io::DuplexStream>>,
    notify: tokio::sync::Notify,
}

#[async_trait]
impl Dialer for FakeDialer {
    async fn dial(&self, tag: Option<&str>, addr: &TargetAddr, port: u16) -> Result<Stream, DialError> {
        self.dials.lock().unwrap().push((tag.map(str::to_owned), addr.clone(), port));
        if self.fail {
            return Err(DialError("proxy down".into()));
        }
        let (a, b) = tokio::io::duplex(64 * 1024);
        self.sites.lock().unwrap().push(b);
        self.notify.notify_one();
        Ok(Box::new(a))
    }
}

impl FakeDialer {
    async fn site(&self) -> tokio::io::DuplexStream {
        loop {
            if let Some(s) = self.sites.lock().unwrap().pop() {
                return s;
            }
            self.notify.notified().await;
        }
    }
}

struct Harness {
    to_stack: mpsc::Sender<Bytes>,
    from_stack: mpsc::Receiver<Bytes>,
}

impl Harness {
    fn start(rules: RuleSet, dialer: Arc<FakeDialer>, udp: Option<Arc<dyn UdpHandler>>) -> Self {
        let (to_stack, rx) = mpsc::channel(256);
        let (tx, from_stack) = mpsc::channel(256);
        let io = Arc::new(ChanIo { rx: tokio::sync::Mutex::new(rx), tx });
        let mut tun = TunStack::new(Arc::new(rules), dialer);
        tun.udp = udp;
        tokio::spawn(tun.run(io));
        Self { to_stack, from_stack }
    }

    async fn send(&self, pkt: Vec<u8>) {
        self.to_stack.send(Bytes::from(pkt)).await.unwrap();
    }

    async fn next(&mut self) -> Bytes {
        tokio::time::timeout(Duration::from_secs(5), self.from_stack.recv()).await.expect("no packet").unwrap()
    }

    /// Next TCP segment that is not a pure ACK.
    async fn next_meaningful(&mut self) -> Seg {
        loop {
            let s = seg(&self.next().await);
            if s.syn || s.fin || s.rst || !s.payload.is_empty() {
                return s;
            }
        }
    }
}

fn rules_proxy_default() -> RuleSet {
    RuleSet::new(
        vec![Rule { matcher: Matcher::Cidr(Cidr::parse("203.0.113.0/24").unwrap()), action: Action::Reject }],
        Action::Proxy("p1".into()),
    )
}

#[tokio::test]
async fn tcp_handshake_and_data_reach_the_dialer_and_back() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone(), None);
    h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    let synack = h.next_meaningful().await;
    assert!(synack.syn && synack.ack && synack.ack_no == 101);
    let sseq = synack.seq + 1;
    h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq, b"hello")).await;

    let mut site = dialer.site().await;
    let mut buf = [0u8; 5];
    site.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello");
    assert_eq!(
        dialer.dials.lock().unwrap().clone(),
        vec![(Some("p1".to_string()), TargetAddr::Ip(SITE4.ip()), 443)]
    );

    site.write_all(b"world").await.unwrap();
    let data = h.next_meaningful().await;
    assert_eq!(data.payload, b"world");
    assert_eq!(data.seq, sseq);

    // Site closes: the application sees a FIN after the data.
    drop(site);
    let fin = h.next_meaningful().await;
    assert!(fin.fin && !fin.rst);
    assert_eq!(fin.seq, sseq + 5);
}

#[tokio::test]
async fn application_half_close_reaches_the_site() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone(), None);
    h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    let sseq = h.next_meaningful().await.seq + 1;
    h.send(tcp(CLIENT4, SITE4, FIN, 101, sseq, b"req")).await;
    let mut site = dialer.site().await;
    let mut got = Vec::new();
    site.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"req");
    // The other direction still works after the half-close.
    site.write_all(b"resp").await.unwrap();
    let data = h.next_meaningful().await;
    assert_eq!(data.payload, b"resp");
}

#[tokio::test]
async fn rejected_route_gets_rst_and_never_dials() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone(), None);
    let blocked: SocketAddr = "203.0.113.9:443".parse().unwrap();
    h.send(tcp(CLIENT4, blocked, SYN, 100, 0, b"")).await;
    let rst = h.next_meaningful().await;
    assert!(rst.rst && rst.ack_no == 101);
    assert!(dialer.dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_dial_resets_after_local_handshake_never_direct() {
    let dialer = Arc::new(FakeDialer { fail: true, ..Default::default() });
    let mut h = Harness::start(rules_proxy_default(), dialer.clone(), None);
    h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    let synack = h.next_meaningful().await;
    assert!(synack.syn && synack.ack);
    h.send(tcp(CLIENT4, SITE4, ACK, 101, synack.seq + 1, b"")).await;
    let rst = h.next_meaningful().await;
    assert!(rst.rst, "expected RST, got {rst:?}");
    // Exactly one dial, through the proxy tag: no direct retry.
    let dials = dialer.dials.lock().unwrap().clone();
    assert_eq!(dials.len(), 1);
    assert_eq!(dials[0].0.as_deref(), Some("p1"));
}

#[tokio::test]
async fn udp_is_refused_with_icmp_without_a_handler() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer, None);
    h.send(udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), b"quic")).await;
    let o = out(&h.next().await);
    assert_eq!(o.proto, IpProtocol::Icmp);
}

struct Echo;
impl UdpHandler for Echo {
    fn datagram(&self, d: UdpDatagram, reply: UdpReply) {
        let mut v = b"echo:".to_vec();
        v.extend_from_slice(&d.payload);
        assert!(reply.send(Bytes::from(v)));
    }
}

struct UdpRouter;
impl segue_kernel::tun::TunRouter for UdpRouter {
    fn route_tcp(&self, _: &FlowKey) -> segue_kernel::tun::Route {
        segue_kernel::tun::Route::Refuse
    }
    fn route_udp(&self, _: &FlowKey) -> segue_kernel::tun::Route {
        segue_kernel::tun::Route::Dial(None)
    }
}

#[tokio::test]
async fn udp_flows_reach_the_handler_and_replies_return() {
    let (to_stack, rx) = mpsc::channel(16);
    let (tx, mut from_stack) = mpsc::channel(16);
    let io = Arc::new(ChanIo { rx: tokio::sync::Mutex::new(rx), tx });
    let mut tun = TunStack::new(Arc::new(UdpRouter), Arc::new(FakeDialer::default()));
    tun.udp = Some(Arc::new(Echo));
    tokio::spawn(tun.run(io));
    let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    to_stack.send(Bytes::from(udp(CLIENT4, dst, b"q"))).await.unwrap();
    let pkt = tokio::time::timeout(Duration::from_secs(5), from_stack.recv()).await.unwrap().unwrap();
    let o = out(&pkt);
    let u = UdpPacket::new_checked(&o.l4[..]).unwrap();
    assert_eq!((o.src, u.src_port(), u.payload()), (dst.ip(), 53, &b"echo:q"[..]));
}
