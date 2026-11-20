//! TUN core tests: synthetic packets in, packets out. No root, no device.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use segue_kernel::dial::{Datagrams, DialError, Dialer, Stream, UdpSession};
use segue_kernel::dns::{answers_for_test, query_for_test, DnsSettings, SmartDns, TYPE_A};
use segue_kernel::fakeip::FakeIpPool;
use segue_kernel::policy::{Policy, PolicyStore};
use segue_kernel::quic::{
    hex, QUIC_GO_CHATGPT_INITIAL, RFC9001_CLIENT_INITIAL, RFC9369_CLIENT_INITIAL,
};
use segue_kernel::rules::{Action, Cidr, CidrTable, Matcher, Rule, RuleSet};
use segue_kernel::sniff::{client_hello_ech_for_test, client_hello_for_test};
use segue_kernel::socks::{Kernel, SniffSettings};
use segue_kernel::tun::{
    mss_for, Event, FlowKey, MemoryBudget, Netstack, NetstackConfig, PacketIo, Proto, TunStack,
    UdpDatagram, Verdict, BLOCK,
};
use segue_kernel::udp::{Udp, UdpSettings};
use segue_routing::TargetAddr;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Packet, Icmpv6Packet, IpAddress, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
    TcpControl, TcpPacket, TcpRepr, TcpSeqNumber, UdpPacket, UdpRepr,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Packet helpers (the "application" side)

const CLIENT4: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 19, 0, 2)), 40000);
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

fn ip_packet(
    src: IpAddr,
    dst: IpAddr,
    proto: IpProtocol,
    len: usize,
    fill: impl FnOnce(&mut [u8]),
) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let repr = Ipv4Repr {
                src_addr: s,
                dst_addr: d,
                next_header: proto,
                payload_len: len,
                hop_limit: 64,
            };
            let mut buf = vec![0u8; 20 + len];
            let mut p = Ipv4Packet::new_unchecked(&mut buf[..]);
            repr.emit(&mut p, &caps());
            fill(p.payload_mut());
            buf
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let repr = Ipv6Repr {
                src_addr: s,
                dst_addr: d,
                next_header: proto,
                payload_len: len,
                hop_limit: 64,
            };
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

const SYN: Flags = Flags {
    syn: true,
    ack: false,
    fin: false,
    rst: false,
};
const ACK: Flags = Flags {
    syn: false,
    ack: true,
    fin: false,
    rst: false,
};
const FIN: Flags = Flags {
    syn: false,
    ack: true,
    fin: true,
    rst: false,
};

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
    ip_packet(
        src.ip(),
        dst.ip(),
        IpProtocol::Tcp,
        repr.buffer_len(),
        |b| {
            repr.emit(&mut TcpPacket::new_unchecked(b), &s, &d, &caps());
        },
    )
}

fn udp(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let repr = UdpRepr {
        src_port: src.port(),
        dst_port: dst.port(),
    };
    let (s, d) = (IpAddress::from(src.ip()), IpAddress::from(dst.ip()));
    ip_packet(
        src.ip(),
        dst.ip(),
        IpProtocol::Udp,
        8 + payload.len(),
        |b| {
            repr.emit(
                &mut UdpPacket::new_unchecked(b),
                &s,
                &d,
                payload.len(),
                |p| p.copy_from_slice(payload),
                &caps(),
            );
        },
    )
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
        Out {
            src: p.src_addr().into(),
            dst: p.dst_addr().into(),
            proto: p.next_header(),
            l4: p.payload().to_vec(),
        }
    } else {
        let p = Ipv6Packet::new_checked(pkt).unwrap();
        Out {
            src: p.src_addr().into(),
            dst: p.dst_addr().into(),
            proto: p.next_header(),
            l4: p.payload().to_vec(),
        }
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
    /// Advertised receive window (no scaling: test SYNs offer none).
    window: u16,
    payload: Vec<u8>,
}

fn seg(pkt: &[u8]) -> Seg {
    let o = out(pkt);
    assert_eq!(o.proto, IpProtocol::Tcp, "expected TCP, got {o:?}");
    let t = TcpPacket::new_checked(&o.l4[..]).unwrap();
    assert!(
        t.verify_checksum(&IpAddress::from(o.src), &IpAddress::from(o.dst)),
        "bad TCP checksum"
    );
    let repr = TcpRepr::parse(
        &t,
        &IpAddress::from(o.src),
        &IpAddress::from(o.dst),
        &caps(),
    )
    .unwrap();
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
        window: t.window_len(),
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
fn handshake(
    cfg: NetstackConfig,
    client: SocketAddr,
    site: SocketAddr,
) -> (Netstack, segue_kernel::tun::FlowId, u32, u32) {
    let now = Instant::now();
    let mut stack = Netstack::new(cfg, now);
    stack.input(&tcp(client, site, SYN, 1000, 0, b""), now, &mut accept_all);
    let id = match stack.pop_event() {
        Some(Event::TcpAccepted { id, key, tag }) => {
            assert_eq!(
                key,
                FlowKey {
                    proto: Proto::Tcp,
                    src: client,
                    dst: site
                }
            );
            assert_eq!(tag.as_deref(), Some("proxy"));
            id
        }
        e => panic!("expected TcpAccepted, got {e:?}"),
    };
    let synack = seg(&one(&mut stack));
    assert!(synack.syn && synack.ack && !synack.rst);
    assert_eq!(
        (synack.src_port, synack.dst_port),
        (site.port(), client.port())
    );
    assert_eq!(synack.ack_no, 1001);
    let server_seq = synack.seq.wrapping_add(1);
    stack.input(
        &tcp(client, site, ACK, 1001, server_seq, b""),
        now,
        &mut accept_all,
    );
    assert!(stack.tcp_established(id).unwrap());
    (stack, id, 1001, server_seq)
}

// ---------------------------------------------------------------------------
// Netstack: refusals

#[test]
fn refused_syn_gets_rst_acking_the_syn() {
    let now = Instant::now();
    let mut stack = Netstack::new(NetstackConfig::default(), now);
    stack.input(
        &tcp(CLIENT4, SITE4, SYN, 5000, 0, b""),
        now,
        &mut refuse_all,
    );
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
    stack.input(
        &tcp(client6(), site6(), SYN, 7, 0, b""),
        now,
        &mut refuse_all,
    );
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
    for dst in [
        "10.1.2.3:80",
        "192.168.1.1:80",
        "172.16.0.1:80",
        "127.0.0.1:80",
        "169.254.1.1:80",
        "100.64.0.1:80",
        "[fe80::1]:80",
        "[fc00::1]:80",
        "[::1]:80",
    ] {
        let dst: SocketAddr = dst.parse().unwrap();
        let src = if dst.is_ipv4() { CLIENT4 } else { client6() };
        stack.input(&tcp(src, dst, SYN, 1, 0, b""), now, &mut policy);
        assert!(seg(&one(&mut stack)).rst, "{dst} not refused");
    }
    // Multicast / broadcast: dropped silently.
    stack.input(
        &udp(CLIENT4, "224.0.0.251:5353".parse().unwrap(), b"mdns"),
        now,
        &mut policy,
    );
    stack.input(
        &udp(CLIENT4, "255.255.255.255:67".parse().unwrap(), b"dhcp"),
        now,
        &mut policy,
    );
    assert!(drain(&mut stack).is_empty());
    assert_eq!(asked, 0);
    assert_eq!(stack.stats().tcp_refused_reserved, 9);
}

#[test]
fn flow_table_full_refuses_new_flows_with_rst() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        max_tcp_flows: 2,
        ..Default::default()
    };
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
    stack.input(
        &tcp(CLIENT4, SITE4, ACK, 100, 777, b"late"),
        now,
        &mut accept_all,
    );
    let rst = seg(&one(&mut stack));
    assert!(rst.rst && !rst.ack);
    assert_eq!(rst.seq, 777);
    // A RST for an unknown flow is never answered.
    let rst_in = tcp(
        CLIENT4,
        SITE4,
        Flags {
            syn: false,
            ack: false,
            fin: false,
            rst: true,
        },
        1,
        0,
        b"",
    );
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
    let cfg = NetstackConfig {
        icmp_burst: 3,
        icmp_per_sec: 1,
        ..Default::default()
    };
    let mut stack = Netstack::new(cfg, now);
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
    for _ in 0..10 {
        stack.input(&udp(CLIENT4, dst, b"x"), now, &mut refuse_all);
    }
    assert_eq!(drain(&mut stack).len(), 3);
    assert_eq!(stack.stats().icmp_suppressed, 7);
    stack.input(
        &udp(CLIENT4, dst, b"x"),
        now + Duration::from_secs(2),
        &mut refuse_all,
    );
    assert_eq!(drain(&mut stack).len(), 1);
}

#[test]
fn malformed_fragmented_and_oversize_packets_are_dropped() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        mtu: 1280,
        ..Default::default()
    };
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
    stack.input(
        &udp(CLIENT4, "8.8.8.8:53".parse().unwrap(), &[0u8; 1300]),
        now,
        &mut accept_all,
    );
    stack.input(&[0x45, 0, 0], now, &mut accept_all);
    // Only the oversize datagram (DF set) is answered: frag-needed.
    let icmp = drain(&mut stack);
    assert_eq!(icmp.len(), 1);
    assert_eq!(out(&icmp[0]).proto, IpProtocol::Icmp);
    let s = stack.stats();
    assert_eq!(
        (s.dropped_malformed, s.dropped_fragment, s.dropped_oversize),
        (2, 1, 1)
    );
    assert_eq!(s.icmp_too_big, 1);
    assert_eq!(stack.tcp_flows() + stack.udp_flows(), 0);
}

// ---------------------------------------------------------------------------
// Netstack: TCP through the stack

#[test]
fn syn_ack_mss_is_clamped_to_tun_mtu() {
    let cfg = NetstackConfig {
        mtu: 1400,
        ..Default::default()
    };
    let now = Instant::now();
    let mut stack = Netstack::new(cfg.clone(), now);
    stack.input(&tcp(CLIENT4, SITE4, SYN, 1, 0, b""), now, &mut accept_all);
    assert_eq!(seg(&one(&mut stack)).mss, Some(1360));
    stack.input(
        &tcp(client6(), site6(), SYN, 1, 0, b""),
        now,
        &mut accept_all,
    );
    assert_eq!(seg(&one(&mut stack)).mss, Some(1340));
    assert_eq!(mss_for(1400, false), 1360);
    assert_eq!(mss_for(1400, true), 1340);
}

#[test]
fn tcp_data_flows_both_ways_and_segments_fit_mtu() {
    for (client, site) in [(CLIENT4, SITE4), (client6(), site6())] {
        let cfg = NetstackConfig {
            mtu: 1280,
            ..Default::default()
        };
        let (mut stack, id, cseq, sseq) = handshake(cfg, client, site);
        let now = Instant::now();
        stack.input(
            &tcp(client, site, ACK, cseq, sseq, b"GET / HTTP/1.1\r\n\r\n"),
            now,
            &mut accept_all,
        );
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
            stack.input(
                &tcp(client, site, ACK, cseq + 18, acked, b""),
                now,
                &mut accept_all,
            );
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
    stack.input(
        &tcp(CLIENT4, SITE4, FIN, cseq, sseq, b"bye"),
        now,
        &mut accept_all,
    );
    let mut buf = [0u8; 8];
    assert_eq!(stack.tcp_read(id, &mut buf).unwrap(), 3);
    assert!(stack.tcp_peer_finished(id).unwrap());
    stack.tcp_close(id).unwrap();
    stack.poll(now);
    let fin = drain(&mut stack)
        .iter()
        .map(|p| seg(p))
        .find(|s| s.fin)
        .expect("FIN");
    stack.input(
        &tcp(CLIENT4, SITE4, ACK, cseq + 4, fin.seq + 1, b""),
        now,
        &mut accept_all,
    );
    assert_eq!(stack.tcp_flows(), 0, "flow reaped after LAST_ACK");
}

#[test]
fn udp_accepted_datagrams_queue_bounded_and_reply_is_addressed_back() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        udp_queue: 2,
        ..Default::default()
    };
    let mut stack = Netstack::new(cfg, now);
    let dst: SocketAddr = "1.1.1.1:53".parse().unwrap();
    for msg in [&b"a"[..], b"b", b"c"] {
        stack.input(&udp(CLIENT4, dst, msg), now, &mut accept_all);
    }
    assert_eq!(stack.udp_flows(), 1);
    let got: Vec<UdpDatagram> = std::iter::from_fn(|| stack.pop_udp()).collect();
    assert_eq!(
        got.iter().map(|d| d.payload.clone()).collect::<Vec<_>>(),
        vec![Bytes::from("b"), Bytes::from("c")]
    );
    assert_eq!(stack.stats().dropped_udp_queue_full, 1);
    stack.send_udp(&got[0].key, b"answer");
    let pkt = one(&mut stack);
    let o = out(&pkt);
    assert_eq!((o.src, o.dst), (dst.ip(), CLIENT4.ip()));
    let u = UdpPacket::new_checked(&o.l4[..]).unwrap();
    assert!(u.verify_checksum(&IpAddress::from(o.src), &IpAddress::from(o.dst)));
    assert_eq!(
        (u.src_port(), u.dst_port(), u.payload()),
        (53, 40000, &b"answer"[..])
    );
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
        self.rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("closed"))
    }
    async fn send(&self, pkt: Bytes) -> std::io::Result<()> {
        self.tx
            .send(pkt)
            .await
            .map_err(|_| std::io::Error::other("closed"))
    }
}

/// Dialer whose "site" is an in-memory duplex. Records every dial.
#[derive(Default)]
struct FakeDialer {
    dials: Mutex<Vec<(Option<String>, TargetAddr, u16)>>,
    udp_dials: Mutex<Vec<(Option<String>, TargetAddr, u16)>>,
    fail: bool,
    /// Every dial is a session that sends "partial" and is then reset.
    session_reset: bool,
    sites: Mutex<Vec<tokio::io::DuplexStream>>,
    notify: tokio::sync::Notify,
    /// UDP payload cap of the sessions (0: 1000).
    udp_max: usize,
    /// Every datagram a UDP session was asked to send.
    udp_sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl Dialer for FakeDialer {
    async fn dial(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Stream, DialError> {
        self.dials
            .lock()
            .unwrap()
            .push((tag.map(str::to_owned), addr.clone(), port));
        if self.fail {
            return Err(DialError("proxy down".into()));
        }
        if self.session_reset {
            use segue_session::client::CloseReason;
            let (app, mut far) = tokio::io::duplex(4096);
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                far.write_all(b"partial").await.unwrap();
                tokio::time::sleep(Duration::from_millis(50)).await;
                let _ = tx.send(CloseReason::Reset(segue_session::codec::code::REVOKED));
            });
            return Ok(Box::new(segue_kernel::session::SessionStream::new(app, rx)));
        }
        let (a, b) = tokio::io::duplex(64 * 1024);
        self.sites.lock().unwrap().push(b);
        self.notify.notify_one();
        Ok(Box::new(a))
    }

    async fn dial_udp(
        &self,
        tag: Option<&str>,
        addr: &TargetAddr,
        port: u16,
    ) -> Result<Datagrams, DialError> {
        self.udp_dials
            .lock()
            .unwrap()
            .push((tag.map(str::to_owned), addr.clone(), port));
        if self.fail {
            return Err(DialError("proxy down".into()));
        }
        let (tx, rx) = mpsc::channel(8);
        Ok(Box::new(EchoSession {
            tx,
            rx: tokio::sync::Mutex::new(rx),
            from: (addr.clone(), port),
            max: if self.udp_max == 0 {
                1000
            } else {
                self.udp_max
            },
            sent: self.udp_sent.clone(),
        }))
    }
}

/// UDP "site" that answers every datagram with `echo:` + payload.
struct EchoSession {
    tx: mpsc::Sender<Vec<u8>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    from: (TargetAddr, u16),
    max: usize,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl UdpSession for EchoSession {
    fn max_payload(&self, _: &TargetAddr, _: u16) -> usize {
        self.max
    }
    async fn send(&self, _: &TargetAddr, _: u16, p: &[u8]) -> Result<(), DialError> {
        self.sent.lock().unwrap().push(p.to_vec());
        let mut v = b"echo:".to_vec();
        v.extend_from_slice(p);
        self.tx.send(v).await.map_err(|e| DialError(e.to_string()))
    }
    async fn recv(&self, buf: &mut Vec<u8>) -> Result<(TargetAddr, u16), DialError> {
        let v = self
            .rx
            .lock()
            .await
            .recv()
            .await
            .ok_or(DialError("closed".into()))?;
        buf.clear();
        buf.extend_from_slice(&v);
        Ok(self.from.clone())
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
    fn start(rules: RuleSet, dialer: Arc<FakeDialer>) -> Self {
        Self::run(TunStack::new(Arc::new(rules), dialer))
    }

    fn run(tun: TunStack) -> Self {
        let (to_stack, rx) = mpsc::channel(256);
        let (tx, from_stack) = mpsc::channel(256);
        let io = Arc::new(ChanIo {
            rx: tokio::sync::Mutex::new(rx),
            tx,
        });
        tokio::spawn(tun.run(io));
        Self {
            to_stack,
            from_stack,
        }
    }

    async fn send(&self, pkt: Vec<u8>) {
        self.to_stack.send(Bytes::from(pkt)).await.unwrap();
    }

    async fn next(&mut self) -> Bytes {
        tokio::time::timeout(Duration::from_secs(5), self.from_stack.recv())
            .await
            .expect("no packet")
            .unwrap()
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
        vec![Rule {
            matcher: Matcher::Cidr(Cidr::parse("203.0.113.0/24").unwrap()),
            action: Action::Reject,
        }],
        Action::Proxy("p1".into()),
    )
}

#[tokio::test]
async fn tcp_handshake_and_data_reach_the_dialer_and_back() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone());
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
async fn session_reset_after_data_is_rst_not_fin() {
    let dialer = Arc::new(FakeDialer {
        session_reset: true,
        ..Default::default()
    });
    let mut h = Harness::start(rules_proxy_default(), dialer.clone());
    h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    let sseq = h.next_meaningful().await.seq + 1;
    h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq, b"")).await;
    let data = h.next_meaningful().await;
    assert_eq!(data.payload, b"partial");
    h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq + 7, b"")).await;
    let end = h.next_meaningful().await;
    assert!(end.rst && !end.fin, "a reset session ended with {end:?}");
}

#[tokio::test]
async fn application_half_close_reaches_the_site() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone());
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
async fn upload_lost_after_site_closed_resets_the_application() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone());
    h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    let sseq = h.next_meaningful().await.seq + 1;
    h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq, b"")).await;
    // The site goes away entirely: its FIN reaches the application...
    drop(dialer.site().await);
    let fin = h.next_meaningful().await;
    assert!(fin.fin && !fin.rst);
    // ...but bytes the application still sends can no longer be delivered,
    // so the flow must be reset, not left looking cleanly closed.
    h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq + 1, b"more"))
        .await;
    let rst = h.next_meaningful().await;
    assert!(rst.rst, "expected RST, got {rst:?}");
}

#[tokio::test]
async fn rejected_route_gets_rst_and_never_dials() {
    let dialer = Arc::new(FakeDialer::default());
    let mut h = Harness::start(rules_proxy_default(), dialer.clone());
    let blocked: SocketAddr = "203.0.113.9:443".parse().unwrap();
    h.send(tcp(CLIENT4, blocked, SYN, 100, 0, b"")).await;
    let rst = h.next_meaningful().await;
    assert!(rst.rst && rst.ack_no == 101);
    assert!(dialer.dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_dial_resets_after_local_handshake_never_direct() {
    let dialer = Arc::new(FakeDialer {
        fail: true,
        ..Default::default()
    });
    let mut h = Harness::start(rules_proxy_default(), dialer.clone());
    h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    let synack = h.next_meaningful().await;
    assert!(synack.syn && synack.ack);
    h.send(tcp(CLIENT4, SITE4, ACK, 101, synack.seq + 1, b""))
        .await;
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
    let mut h = Harness::start(rules_proxy_default(), dialer);
    h.send(udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), b"quic"))
        .await;
    let o = out(&h.next().await);
    assert_eq!(o.proto, IpProtocol::Icmp);
}

// ---------------------------------------------------------------------------
// Netstack: size limits (ICMP packet-too-big)

fn icmpv4(pkt: &[u8]) -> (u8, u8, Vec<u8>) {
    let o = out(pkt);
    assert_eq!(o.proto, IpProtocol::Icmp);
    let icmp = Icmpv4Packet::new_checked(&o.l4[..]).unwrap();
    assert!(icmp.verify_checksum());
    (u8::from(icmp.msg_type()), icmp.msg_code(), o.l4.clone())
}

#[test]
fn oversize_ipv4_with_df_gets_frag_needed_with_mtu() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        mtu: 1280,
        ..Default::default()
    };
    let mut stack = Netstack::new(cfg, now);
    let big = udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), &[1u8; 1400]);
    assert!(Ipv4Packet::new_unchecked(&big[..]).dont_frag());
    stack.input(&big, now, &mut accept_all);
    let (t, code, l4) = icmpv4(&one(&mut stack));
    assert_eq!((t, code), (3, 4));
    // Next-hop MTU (RFC 1191) in bytes 6..8.
    assert_eq!(u16::from_be_bytes([l4[6], l4[7]]), 1280);
    assert_eq!(&l4[8..36], &big[..28]);
    assert_eq!(stack.udp_flows(), 0);
}

#[test]
fn oversize_ipv4_without_df_is_dropped_silently() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        mtu: 1280,
        ..Default::default()
    };
    let mut stack = Netstack::new(cfg, now);
    let mut big = udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), &[1u8; 1400]);
    {
        let mut p = Ipv4Packet::new_unchecked(&mut big[..]);
        p.set_dont_frag(false);
        p.fill_checksum();
    }
    stack.input(&big, now, &mut accept_all);
    assert!(drain(&mut stack).is_empty());
    assert_eq!(stack.stats().dropped_oversize, 1);
}

#[test]
fn oversize_ipv6_gets_packet_too_big_with_mtu() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        mtu: 1280,
        ..Default::default()
    };
    let mut stack = Netstack::new(cfg, now);
    let big = tcp(client6(), site6(), ACK, 1, 1, &[2u8; 1300]);
    stack.input(&big, now, &mut accept_all);
    let pkt = one(&mut stack);
    assert!(pkt.len() <= 1280);
    let o = out(&pkt);
    assert_eq!(o.proto, IpProtocol::Icmpv6);
    let icmp = Icmpv6Packet::new_checked(&o.l4[..]).unwrap();
    assert!(icmp.verify_checksum(&o.src.to_v6(), &o.dst.to_v6()));
    assert_eq!((u8::from(icmp.msg_type()), icmp.msg_code()), (2, 0));
    assert_eq!(
        u32::from_be_bytes([o.l4[4], o.l4[5], o.l4[6], o.l4[7]]),
        1280
    );
    assert_eq!(&o.l4[8..48], &big[..40]);
    assert_eq!(stack.stats().icmp_too_big, 1);
}

// ---------------------------------------------------------------------------
// Netstack: timers

fn acked_fin(stack: &mut Netstack, id: segue_kernel::tun::FlowId, cseq: u32, now: Instant) {
    stack.tcp_close(id).unwrap();
    stack.poll(now);
    let fin = drain(stack)
        .iter()
        .map(|p| seg(p))
        .find(|s| s.fin)
        .expect("FIN");
    // ACK the FIN but never send ours: FIN_WAIT2.
    stack.input(
        &tcp(CLIENT4, SITE4, ACK, cseq, fin.seq + 1, b""),
        now,
        &mut accept_all,
    );
}

#[test]
fn fin_wait2_flow_is_reaped_after_half_close_timeout() {
    let (mut stack, id, cseq, _) = handshake(NetstackConfig::default(), CLIENT4, SITE4);
    let now = Instant::now();
    acked_fin(&mut stack, id, cseq, now);
    stack.poll(now + Duration::from_secs(30));
    assert_eq!(stack.tcp_flows(), 1, "still within the timeout");
    stack.poll(now + Duration::from_secs(61));
    assert_eq!(stack.tcp_flows(), 0);
    assert_eq!(stack.stats().tcp_half_close_timeouts, 1);
    assert!(drain(&mut stack).iter().any(|p| seg(p).rst));
}

#[test]
fn close_wait_flow_is_reaped_after_half_close_timeout() {
    let (mut stack, id, cseq, sseq) = handshake(NetstackConfig::default(), CLIENT4, SITE4);
    let now = Instant::now();
    stack.input(
        &tcp(CLIENT4, SITE4, FIN, cseq, sseq, b""),
        now,
        &mut accept_all,
    );
    assert!(stack.tcp_peer_finished(id).unwrap());
    stack.poll(now + Duration::from_secs(61));
    assert_eq!(stack.tcp_flows(), 0);
    assert_eq!(stack.stats().tcp_half_close_timeouts, 1);
}

#[test]
fn activity_keeps_a_half_closed_flow_alive() {
    let (mut stack, id, cseq, sseq) = handshake(NetstackConfig::default(), CLIENT4, SITE4);
    let now = Instant::now();
    stack.input(
        &tcp(CLIENT4, SITE4, FIN, cseq, sseq, b""),
        now,
        &mut accept_all,
    );
    // We keep sending the response; the application keeps ACKing.
    let mut t = now;
    let mut acked = sseq;
    for _ in 0..4 {
        t += Duration::from_secs(40);
        stack.tcp_write(id, b"chunk").unwrap();
        stack.poll(t);
        for p in drain(&mut stack) {
            let s = seg(&p);
            acked = acked.max(s.seq + s.payload.len() as u32);
        }
        stack.input(
            &tcp(CLIENT4, SITE4, ACK, cseq + 1, acked, b""),
            t,
            &mut accept_all,
        );
    }
    stack.poll(t);
    assert_eq!(stack.tcp_flows(), 1);
}

#[test]
fn idle_established_flow_is_reaped_after_idle_timeout() {
    let cfg = NetstackConfig {
        tcp_idle_timeout: Duration::from_secs(300),
        ..Default::default()
    };
    let (mut stack, _, _, _) = handshake(cfg, CLIENT4, SITE4);
    let now = Instant::now();
    stack.poll(now + Duration::from_secs(200));
    assert_eq!(stack.tcp_flows(), 1);
    stack.poll(now + Duration::from_secs(301));
    assert_eq!(stack.tcp_flows(), 0);
    assert_eq!(stack.stats().tcp_idle_timeouts, 1);
}

// ---------------------------------------------------------------------------
// Netstack: pooled, lazily grown buffers (§4.2)

#[test]
fn buffers_start_small_grow_with_traffic_and_are_released_when_idle() {
    let (mut stack, id, cseq, sseq) = handshake(NetstackConfig::default(), CLIENT4, SITE4);
    let now = Instant::now();
    assert_eq!(stack.tcp_buffers(id).unwrap(), (BLOCK, 0));
    assert_eq!(stack.pool().used_bytes(), 2 * BLOCK);
    // Upload through the receive ring, reading as it arrives.
    let mut seq = cseq;
    let mut total = 0;
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..40 {
        let payload = vec![b'u'; 1400];
        stack.input(
            &tcp(CLIENT4, SITE4, ACK, seq, sseq, &payload),
            now,
            &mut accept_all,
        );
        seq += 1400;
        total += stack.tcp_read(id, &mut buf).unwrap();
        stack.poll(now);
        drain(&mut stack);
    }
    assert_eq!(total, 40 * 1400);
    let (rx, _) = stack.tcp_buffers(id).unwrap();
    assert!(rx > BLOCK, "rx ring grew: {rx}");
    assert!(rx <= 64 * 1024);
    // Download: the transmit ring is grown on demand.
    assert_eq!(stack.tcp_write(id, &[b'd'; 6000]).unwrap(), 6000);
    let (_, tx) = stack.tcp_buffers(id).unwrap();
    assert!(tx >= 6000);
    stack.poll(now);
    let mut acked = sseq;
    for p in drain(&mut stack) {
        let s = seg(&p);
        acked = acked.max(s.seq + s.payload.len() as u32);
    }
    for _ in 0..10 {
        stack.input(
            &tcp(CLIENT4, SITE4, ACK, seq, acked, b""),
            now,
            &mut accept_all,
        );
        stack.poll(now);
        for p in drain(&mut stack) {
            let s = seg(&p);
            acked = acked.max(s.seq + s.payload.len() as u32);
        }
    }
    assert_eq!(acked, sseq + 6000);
    assert!(stack.pool().used_bytes() > 2 * BLOCK);
    // Idle: both rings go back to the pool.
    let later = now + Duration::from_secs(11);
    stack.poll(later);
    assert_eq!(stack.tcp_buffers(id).unwrap(), (0, 0));
    assert_eq!(stack.stats().buffers_released, 1);
    assert_eq!(
        stack.pool().used_bytes(),
        2 * BLOCK,
        "admission reservation kept"
    );
    // Traffic again: the flow still works.
    stack.input(
        &tcp(CLIENT4, SITE4, ACK, seq, acked, b"again"),
        later,
        &mut accept_all,
    );
    let n = stack.tcp_read(id, &mut buf).unwrap();
    assert_eq!(&buf[..n], b"again");
}

#[test]
fn large_rx_buffer_advertises_window_scale_and_grows_past_64kib() {
    let cfg = NetstackConfig {
        tcp_rx_buffer: 256 * 1024,
        ..Default::default()
    };
    let now = Instant::now();
    let mut stack = Netstack::new(cfg, now);

    let syn_repr = TcpRepr {
        src_port: CLIENT4.port(),
        dst_port: SITE4.port(),
        control: TcpControl::Syn,
        seq_number: TcpSeqNumber(1000),
        ack_number: None,
        window_len: 65535,
        window_scale: Some(4),
        max_seg_size: Some(1460),
        sack_permitted: false,
        sack_ranges: [None; 3],
        timestamp: None,
        payload: &[],
    };
    let (syn_s, syn_d) = (IpAddress::from(CLIENT4.ip()), IpAddress::from(SITE4.ip()));
    let syn_pkt = ip_packet(
        CLIENT4.ip(),
        SITE4.ip(),
        IpProtocol::Tcp,
        syn_repr.buffer_len(),
        |b| {
            syn_repr.emit(&mut TcpPacket::new_unchecked(b), &syn_s, &syn_d, &caps());
        },
    );
    stack.input(&syn_pkt, now, &mut accept_all);
    let id = match stack.pop_event() {
        Some(Event::TcpAccepted { id, .. }) => id,
        other => panic!("expected TcpAccepted, got {other:?}"),
    };
    let raw_synack = one(&mut stack);
    let out_pkt = out(&raw_synack);
    let t = TcpPacket::new_checked(&out_pkt.l4[..]).unwrap();
    let repr = TcpRepr::parse(
        &t,
        &IpAddress::from(out_pkt.src),
        &IpAddress::from(out_pkt.dst),
        &caps(),
    )
    .unwrap();
    assert_eq!(repr.window_scale, Some(3));

    let server_seq = (t.seq_number().0 as u32).wrapping_add(1);
    stack.input(
        &tcp(CLIENT4, SITE4, ACK, 1001, server_seq, b""),
        now,
        &mut accept_all,
    );
    assert!(stack.tcp_established(id).unwrap());

    // Drive more than 64 KiB of upload with reads so the ring grows past 64 KiB.
    let mut seq = 1001;
    let mut total = 0;
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..120 {
        let payload = vec![b'x'; 1400];
        stack.input(
            &tcp(CLIENT4, SITE4, ACK, seq, server_seq, &payload),
            now,
            &mut accept_all,
        );
        seq += 1400;
        total += stack.tcp_read(id, &mut buf).unwrap();
        stack.poll(now);
        drain(&mut stack);
    }
    assert_eq!(total, 120 * 1400);
    let (rx, _) = stack.tcp_buffers(id).unwrap();
    assert!(rx > 64 * 1024, "expected rx ring > 64 KiB, got {rx}");
}

#[test]
fn exhausted_pool_refuses_new_flows_with_rst() {
    let now = Instant::now();
    let cfg = NetstackConfig {
        buffer_pool: 5 * BLOCK,
        ..Default::default()
    };
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
    assert_eq!(stack.stats().tcp_refused_memory, 1);
}

// Counting allocator: allocations made on a thread that set `TRACKED` are
// counted (wherever they are freed), so tests on other threads do not
// disturb a measurement.
mod counting {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::atomic::{AtomicIsize, Ordering};

    thread_local! {
        pub static TRACKED: Cell<bool> = const { Cell::new(false) };
    }
    pub static LIVE: AtomicIsize = AtomicIsize::new(0);
    pub static PEAK: AtomicIsize = AtomicIsize::new(0);
    const HDR: usize = 16;

    fn padded(l: Layout) -> (Layout, usize) {
        let pad = HDR.max(l.align());
        (
            Layout::from_size_align(l.size() + pad, l.align().max(HDR)).unwrap(),
            pad,
        )
    }

    pub struct Counting;

    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let (pl, pad) = padded(l);
            let base = System.alloc(pl);
            if base.is_null() {
                return base;
            }
            let tracked = TRACKED.try_with(|c| c.get()).unwrap_or(false);
            let p = base.add(pad);
            (p.sub(8) as *mut u64).write(tracked as u64);
            if tracked {
                let n = l.size() as isize;
                let now = LIVE.fetch_add(n, Ordering::Relaxed) + n;
                PEAK.fetch_max(now, Ordering::Relaxed);
            }
            p
        }

        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            let (pl, pad) = padded(l);
            if (p.sub(8) as *const u64).read() == 1 {
                LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
            }
            System.dealloc(p.sub(pad), pl);
        }
    }

    pub fn live() -> isize {
        LIVE.load(Ordering::Relaxed)
    }

    pub fn reset_peak() {
        PEAK.store(live(), Ordering::Relaxed);
    }

    pub fn peak() -> isize {
        PEAK.load(Ordering::Relaxed)
    }
}

#[global_allocator]
static ALLOC: counting::Counting = counting::Counting;

/// Real allocations of the TCP side of the stack (KERNEL_SPEC §6.3), its
/// blocks charged to the process pool that sessions also use: many flows
/// upload while the app does not read and get a download queued (peak),
/// then everything is drained and the flows go idle (retained).
#[test]
fn tcp_memory_follows_the_shared_pool_and_is_released_when_idle() {
    const FLOWS: u16 = 50;
    const MIB: f64 = (1 << 20) as f64;
    // The process pool: sessions already hold 1 MiB of its 3 MiB.
    let shared = segue_session::pool::Pool::new(3 << 20);
    let sessions = segue_session::pool::Grant::fixed(&shared, 1 << 20).unwrap();
    let for_tun = (shared.blocks() - shared.used_blocks()) * BLOCK;
    let cfg = NetstackConfig {
        shared_pool: Some(shared.clone()),
        ..Default::default()
    };
    counting::TRACKED.with(|t| t.set(true));
    let now = Instant::now();
    let mut stack = Netstack::new(cfg, now);
    let base = counting::live();
    counting::reset_peak();
    let mut flows = Vec::new();
    for i in 0..FLOWS {
        let src = SocketAddr::new(CLIENT4.ip(), 1000 + i);
        stack.input(&tcp(src, SITE4, SYN, 1000, 0, b""), now, &mut accept_all);
        let id = match stack.pop_event() {
            Some(Event::TcpAccepted { id, .. }) => id,
            e => panic!("flow {i}: expected TcpAccepted, got {e:?}"),
        };
        let synack = seg(&one(&mut stack));
        let sseq = synack.seq.wrapping_add(1);
        stack.input(&tcp(src, SITE4, ACK, 1001, sseq, b""), now, &mut accept_all);
        flows.push((src, id, 1001u32, sseq));
    }
    // Upload without the app reading, and a 64 KiB download queued on each.
    let payload = vec![b'u'; 1400];
    // Highest download byte sent on each flow (not acked until the drain).
    let mut sent_hi: Vec<u32> = flows.iter().map(|f| f.3).collect();
    for round in 0..40 {
        for (k, f) in flows.iter_mut().enumerate() {
            let (src, id, seq, sseq) = *f;
            stack.input(
                &tcp(src, SITE4, ACK, seq, sseq, &payload),
                now,
                &mut accept_all,
            );
            stack.poll(now);
            let mut acked = seq;
            for p in drain(&mut stack) {
                let s = seg(&p);
                if s.dst_port == src.port() && s.ack {
                    acked = s.ack_no;
                }
                if s.dst_port == src.port() && !s.payload.is_empty() {
                    let end = s.seq.wrapping_add(s.payload.len() as u32);
                    if end.wrapping_sub(sent_hi[k]) as i32 > 0 {
                        sent_hi[k] = end;
                    }
                }
            }
            f.2 = acked;
            if round == 0 {
                let mut put = 0;
                while put < 64 * 1024 {
                    match stack.tcp_write(id, &[b'd'; 16 * 1024]) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => put += n,
                    }
                }
            }
        }
    }
    let busy = counting::live() - base;
    let peak = counting::peak() - base;
    let tun_used = stack.pool().used_bytes();
    println!(
        "{FLOWS} TCP flows: pool {:.2} MiB of {:.2} MiB for TUN, heap {:.2} MiB, peak {:.2} MiB",
        tun_used as f64 / MIB,
        for_tun as f64 / MIB,
        busy as f64 / MIB,
        peak as f64 / MIB
    );
    // The traffic wanted ~6 MiB of rings; the shared pool held it back.
    assert!(tun_used > for_tun / 2, "pool barely used: {tun_used}");
    assert!(shared.used_bytes() <= shared.blocks() * BLOCK);
    assert_eq!(
        shared.used_bytes(),
        tun_used + (1 << 20),
        "TUN blocks are charged to the process pool"
    );
    // Heap ≈ charged rings plus a fixed cost per flow (smoltcp socket,
    // flow entry; `TCP_FLOW_OVERHEAD` in the budget) and the packet queues.
    const FIXED: isize = 8 * 1024;
    let bound = for_tun as isize + FLOWS as isize * FIXED + (256 << 10);
    assert!(
        peak <= bound,
        "peak {:.2} MiB over {:.2} MiB",
        peak as f64 / MIB,
        bound as f64 / MIB
    );
    // A new flow while the process pool is spent is refused, not admitted
    // past the budget.
    let hog = segue_session::pool::Grant::fixed(
        &shared,
        (shared.blocks() - shared.used_blocks()) * BLOCK,
    );
    let src = SocketAddr::new(CLIENT4.ip(), 9);
    stack.input(&tcp(src, SITE4, SYN, 1, 0, b""), now, &mut accept_all);
    assert!(seg(&one(&mut stack)).rst);
    assert_eq!(stack.stats().tcp_refused_memory, 1);
    drop(hog);
    // Drain both directions, then let the flows go idle.
    let mut buf = vec![0u8; 64 * 1024];
    for _ in 0..40 {
        for f in &flows {
            while stack.tcp_read(f.1, &mut buf).unwrap_or(0) > 0 {}
        }
        stack.poll(now);
        for p in drain(&mut stack) {
            let s = seg(&p);
            let end = s.seq.wrapping_add(s.payload.len() as u32);
            if let Some(k) = flows.iter().position(|f| f.0.port() == s.dst_port) {
                if end.wrapping_sub(sent_hi[k]) as i32 > 0 {
                    sent_hi[k] = end;
                }
            }
        }
        for (k, f) in flows.iter().enumerate() {
            stack.input(
                &tcp(f.0, SITE4, ACK, f.2, sent_hi[k], b""),
                now,
                &mut accept_all,
            );
        }
    }
    drop(buf);
    let later = now + Duration::from_secs(11);
    stack.poll(later);
    drain(&mut stack);
    let retained = counting::live() - base;
    println!(
        "idle: heap {:.0} KiB = {:.1} KiB/flow, pool {} KiB",
        retained as f64 / 1024.0,
        retained as f64 / 1024.0 / FLOWS as f64,
        stack.pool().used_bytes() / 1024
    );
    assert_eq!(
        stack.pool().used_bytes(),
        FLOWS as usize * 2 * BLOCK,
        "only admission blocks kept"
    );
    assert_eq!(shared.used_bytes(), FLOWS as usize * 2 * BLOCK + (1 << 20));
    assert!(
        retained <= FLOWS as isize * FIXED,
        "idle flows keep {:.1} KiB each",
        retained as f64 / 1024.0 / FLOWS as f64
    );
    counting::TRACKED.with(|t| t.set(false));
    drop(sessions);
}

#[test]
fn default_memory_budget_is_well_under_20_mib() {
    // The configured worst case (the measured behaviour is checked by
    // `tcp_memory_follows_the_shared_pool_and_is_released_when_idle`).
    let stack = TunStack::new(Arc::new(RefuseAllRules), Arc::new(FakeDialer::default()));
    let b = stack.memory_budget();
    println!("default TUN memory budget: {b:?}");
    assert_eq!(
        b.total,
        b.tcp_pool + b.tcp_flows + b.packet_queues + b.udp_flows + b.dns
    );
    // r7 #8: every term is the worst case the code can hold, computed here
    // from the defaults independently of `memory_budget`. QUIC keeps no
    // per-flow or kernel-wide state (r8 N1–N3: no guard, no route table).
    let cfg = NetstackConfig::default();
    let mtu = cfg.mtu;
    assert_eq!(mtu, 1500);
    let per_udp = (8 + 1) * mtu + 1024;
    let want = MemoryBudget {
        tcp_pool: cfg.buffer_pool / 4096 * 4096,
        tcp_flows: 512 * 4096,
        packet_queues: (512 + 2 * 256 + 1) * mtu,
        udp_flows: 256 * per_udp,
        dns: 32 * 2 * mtu,
        total: 0,
    };
    let want = MemoryBudget {
        total: want.tcp_pool + want.tcp_flows + want.packet_queues + want.udp_flows + want.dns,
        ..want
    };
    assert_eq!(b, want);
    assert_eq!(b.total, 13_740_252);
    assert!(b.total < 20 * 1024 * 1024, "{b:?}");
    // The pool, not the flow count, bounds TCP buffering.
    assert!(b.tcp_pool < cfg.max_tcp_flows * (cfg.tcp_rx_buffer + cfg.tcp_tx_buffer) / 4);
}

struct RefuseAllRules;
impl segue_kernel::tun::TunRouter for RefuseAllRules {
    fn route_tcp(&self, _: &FlowKey) -> segue_kernel::tun::TcpRoute {
        segue_kernel::tun::TcpRoute::Refuse
    }
}

// ---------------------------------------------------------------------------
// Driver with the kernel's routing (TunKernel)

fn kernel_rules() -> RuleSet {
    RuleSet::new(
        vec![
            Rule {
                matcher: Matcher::DomainSuffix("openai.com".into()),
                action: Action::Proxy("ai".into()),
            },
            Rule {
                matcher: Matcher::DomainSuffix("chatgpt.com".into()),
                action: Action::Proxy("ai".into()),
            },
            Rule {
                matcher: Matcher::DomainSuffix("blocked.test".into()),
                action: Action::Reject,
            },
            Rule {
                matcher: Matcher::Cidr(Cidr::parse("203.0.113.0/24").unwrap()),
                action: Action::Reject,
            },
            Rule {
                matcher: Matcher::Cidr(Cidr::parse("198.51.100.0/24").unwrap()),
                action: Action::Proxy("ai".into()),
            },
            Rule {
                matcher: Matcher::DomainSuffix("p2.test".into()),
                action: Action::Proxy("p2".into()),
            },
            Rule {
                matcher: Matcher::Cidr(Cidr::parse("192.0.2.0/24").unwrap()),
                action: Action::Direct,
            },
        ],
        Action::Proxy("p1".into()),
    )
}

fn fake_pool() -> Arc<FakeIpPool> {
    Arc::new(
        FakeIpPool::new(
            "198.18.0.0".parse().unwrap(),
            15,
            Duration::from_secs(60),
            Duration::from_secs(600),
            [7; 32],
        )
        .unwrap(),
    )
}

struct Env {
    h: Harness,
    dialer: Arc<FakeDialer>,
    pool: Arc<FakeIpPool>,
    kernel: Arc<Kernel>,
}

fn kernel_env(policy: Policy, sniff: bool, udp: bool, fail: bool, dns: bool) -> Env {
    kernel_env_with(
        policy,
        sniff,
        udp,
        dns,
        FakeDialer {
            fail,
            ..Default::default()
        },
    )
}

fn kernel_env_with(policy: Policy, sniff: bool, udp: bool, dns: bool, dialer: FakeDialer) -> Env {
    let dialer = Arc::new(dialer);
    let pool = fake_pool();
    let policy = PolicyStore::inline(policy);
    let kernel = Arc::new(Kernel {
        policy: policy.clone(),
        dialer: dialer.clone(),
        fake_ip: Some(pool.clone()),
        sniff: sniff.then_some(SniffSettings {
            timeout: Duration::from_millis(300),
            max_bytes: 16 * 1024,
        }),
        udp: udp.then(|| {
            Arc::new(Udp::new(UdpSettings {
                refuse: ["ai".to_string()].into(),
                ..Default::default()
            }))
        }),
        hidden: Default::default(),
        flows: None,
    });
    let smart = dns.then(|| {
        Arc::new(SmartDns::new(
            policy,
            pool.clone(),
            DnsSettings {
                // Never reached: every name asked here has a rule.
                domestic: vec!["127.0.0.1:9".parse().unwrap()],
                query_timeout: Duration::from_millis(200),
                cache_size: 64,
            },
        ))
    });
    let h = Harness::run(TunStack::for_kernel(kernel.clone(), smart));
    Env {
        h,
        dialer,
        pool,
        kernel,
    }
}

fn inline() -> Policy {
    Policy::inline(kernel_rules(), CidrTable::default())
}

/// SYN + ACK; returns the server's next sequence number.
async fn connect(h: &mut Harness, dst: SocketAddr) -> u32 {
    h.send(tcp(CLIENT4, dst, SYN, 100, 0, b"")).await;
    let synack = h.next_meaningful().await;
    assert!(synack.syn && synack.ack, "{synack:?}");
    let sseq = synack.seq + 1;
    h.send(tcp(CLIENT4, dst, ACK, 101, sseq, b"")).await;
    sseq
}

#[tokio::test]
async fn sniffed_sni_routes_a_bare_ip_by_name() {
    let mut e = kernel_env(inline(), true, false, false, false);
    let sseq = connect(&mut e.h, SITE4).await;
    let hello = client_hello_for_test(Some("chat.openai.com"), 0);
    e.h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq, &hello)).await;
    let mut site = e.dialer.site().await;
    let mut got = vec![0u8; hello.len()];
    site.read_exact(&mut got).await.unwrap();
    assert_eq!(got, hello, "sniffed bytes are forwarded");
    assert_eq!(
        e.dialer.dials.lock().unwrap().clone(),
        vec![(
            Some("ai".to_string()),
            TargetAddr::Domain("chat.openai.com".into()),
            443
        )]
    );
}

#[tokio::test]
async fn sniffed_rejected_name_resets_and_never_dials() {
    let mut e = kernel_env(inline(), true, false, false, false);
    let sseq = connect(&mut e.h, SITE4).await;
    let hello = client_hello_for_test(Some("x.blocked.test"), 0);
    e.h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq, &hello)).await;
    let rst = e.h.next_meaningful().await;
    assert!(rst.rst, "{rst:?}");
    assert!(e.dialer.dials.lock().unwrap().is_empty());
}

/// r10 N2 on TUN: an ECH extension with an ordinary SNI is GREASE and is
/// routed by that SNI (here an AI name on an unmatched IP goes "ai" by
/// name; a plain name on a direct IP goes direct). Real ECH (a known
/// public name as SNI, or none) to an AI IP takes the AI route by IP; to
/// any other IP it is reset locally, counted, and nothing is dialled.
#[tokio::test]
async fn ech_hello_grease_by_sni_real_ech_ai_ip_or_local_refuse() {
    let ai_ip: SocketAddr = "198.51.100.7:443".parse().unwrap();
    let policy = || {
        inline()
            .with_hidden_name(Action::Proxy("ai".into()))
            .with_ai_ips(&[Cidr::parse("198.51.100.0/24").unwrap()])
    };
    type Want = (Option<&'static str>, TargetAddr);
    let cases: [(&str, SocketAddr, Want); 4] = [
        (
            "chat.openai.com",
            SITE4,
            (Some("ai"), TargetAddr::Domain("chat.openai.com".into())),
        ),
        (
            "x.p2.test",
            SITE4,
            (Some("p2"), TargetAddr::Domain("x.p2.test".into())),
        ),
        (
            "cloudflare-ech.com",
            ai_ip,
            (Some("ai"), TargetAddr::Ip(ai_ip.ip())),
        ),
        ("", ai_ip, (Some("ai"), TargetAddr::Ip(ai_ip.ip()))),
    ];
    for (sni, dst, want) in cases {
        let mut e = kernel_env(policy(), true, false, false, false);
        let sseq = connect(&mut e.h, dst).await;
        let hello = client_hello_ech_for_test(sni, false);
        e.h.send(tcp(CLIENT4, dst, ACK, 101, sseq, &hello)).await;
        let mut site = e.dialer.site().await;
        let mut got = vec![0u8; hello.len()];
        site.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello, "{sni}");
        assert_eq!(
            e.dialer.dials.lock().unwrap().clone(),
            vec![(want.0.map(str::to_owned), want.1, 443)],
            "{sni}"
        );
        assert_eq!(e.kernel.hidden.refused(), 0);
    }
    // Real ECH to an IP outside the AI ranges: RST, nothing dialled.
    for sni in ["cloudflare-ech.com", "a.cloudflare-ech.com", ""] {
        let mut e = kernel_env(policy(), true, false, false, false);
        let sseq = connect(&mut e.h, SITE4).await;
        let hello = client_hello_ech_for_test(sni, true);
        e.h.send(tcp(CLIENT4, SITE4, ACK, 101, sseq, &hello)).await;
        let rst = e.h.next_meaningful().await;
        assert!(rst.rst, "{sni}: {rst:?}");
        assert!(e.dialer.dials.lock().unwrap().is_empty());
        assert_eq!(e.kernel.hidden.refused(), 1);
    }
    // Inline policy without a hidden-name route: refused even to an AI IP.
    let mut e = kernel_env(
        inline().with_ai_ips(&[Cidr::parse("198.51.100.0/24").unwrap()]),
        true,
        false,
        false,
        false,
    );
    let sseq = connect(&mut e.h, ai_ip).await;
    let hello = client_hello_ech_for_test("cloudflare-ech.com", true);
    e.h.send(tcp(CLIENT4, ai_ip, ACK, 101, sseq, &hello)).await;
    let rst = e.h.next_meaningful().await;
    assert!(rst.rst, "{rst:?}");
    assert!(e.dialer.dials.lock().unwrap().is_empty());
}

/// r9 F4 (c), accepted boundary: a sniff that times out (the app sends
/// nothing) keeps the IP rules; on a direct IP the flow goes direct.
#[tokio::test]
async fn sniff_timeout_keeps_ip_rules() {
    let mut e = kernel_env(inline(), true, false, false, false);
    let dst: SocketAddr = "192.0.2.9:22".parse().unwrap();
    let _ = connect(&mut e.h, dst).await;
    let _site = e.dialer.site().await;
    assert_eq!(
        e.dialer.dials.lock().unwrap().clone(),
        vec![(None, TargetAddr::Ip(dst.ip()), 22)]
    );
}

#[tokio::test]
async fn sniff_without_a_name_falls_back_to_ip_rules() {
    let mut e = kernel_env(inline(), true, false, false, false);
    let dst: SocketAddr = "198.51.100.7:443".parse().unwrap();
    let sseq = connect(&mut e.h, dst).await;
    e.h.send(tcp(CLIENT4, dst, ACK, 101, sseq, b"\x00\x01binary"))
        .await;
    let _site = e.dialer.site().await;
    assert_eq!(
        e.dialer.dials.lock().unwrap().clone(),
        vec![(Some("ai".to_string()), TargetAddr::Ip(dst.ip()), 443)]
    );
}

#[tokio::test]
async fn ip_reject_refuses_the_syn_even_with_sniffing() {
    let mut e = kernel_env(inline(), true, false, false, false);
    e.h.send(tcp(
        CLIENT4,
        "203.0.113.9:443".parse().unwrap(),
        SYN,
        100,
        0,
        b"",
    ))
    .await;
    assert!(e.h.next_meaningful().await.rst);
}

#[tokio::test]
async fn fake_ip_destination_is_dialled_by_name_and_stale_fake_is_refused() {
    let mut e = kernel_env(inline(), false, false, false, false);
    let ip = e.pool.assign("api.openai.com", 0).unwrap();
    let dst = SocketAddr::new(IpAddr::V4(ip), 443);
    connect(&mut e.h, dst).await;
    let _site = e.dialer.site().await;
    assert_eq!(
        e.dialer.dials.lock().unwrap().clone(),
        vec![(
            Some("ai".to_string()),
            TargetAddr::Domain("api.openai.com".into()),
            443
        )]
    );
    // Unknown address inside the fake range: never dialled as an IP.
    let stale: SocketAddr = "198.19.200.200:443".parse().unwrap();
    e.h.send(tcp(CLIENT4, stale, SYN, 100, 0, b"")).await;
    assert!(e.h.next_meaningful().await.rst);
    assert_eq!(e.dialer.dials.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn fail_closed_policy_refuses_everything() {
    let mut e = kernel_env(Policy::fail_closed(), true, true, false, false);
    e.h.send(tcp(CLIENT4, SITE4, SYN, 100, 0, b"")).await;
    assert!(e.h.next_meaningful().await.rst);
    e.h.send(udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), b"q"))
        .await;
    assert_eq!(out(&e.h.next().await).proto, IpProtocol::Icmp);
    assert!(e.dialer.dials.lock().unwrap().is_empty());
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn dns_over_udp_is_hijacked_to_the_smart_dns() {
    let mut e = kernel_env(inline(), false, false, false, true);
    // Any resolver address, even a private one, is answered locally.
    let resolver: SocketAddr = "192.168.1.1:53".parse().unwrap();
    e.h.send(udp(
        CLIENT4,
        resolver,
        &query_for_test(7, "chat.openai.com", TYPE_A),
    ))
    .await;
    let o = out(&e.h.next().await);
    assert_eq!((o.src, o.dst), (resolver.ip(), CLIENT4.ip()));
    let u = UdpPacket::new_checked(&o.l4[..]).unwrap();
    assert_eq!((u.src_port(), u.dst_port()), (53, 40000));
    let (id, rcode, ips) = answers_for_test(u.payload()).unwrap();
    assert_eq!((id, rcode), (7, 0));
    assert_eq!(ips.len(), 1);
    let entry = e.pool.lookup(ips[0]).expect("fake-IP answer");
    assert_eq!(entry.domain, "chat.openai.com");
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn dns_over_tcp_is_hijacked_to_the_smart_dns() {
    let mut e = kernel_env(inline(), false, false, false, true);
    let resolver: SocketAddr = "192.168.1.1:53".parse().unwrap();
    let sseq = connect(&mut e.h, resolver).await;
    let q = query_for_test(9, "chat.openai.com", TYPE_A);
    let mut framed = (q.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&q);
    e.h.send(tcp(CLIENT4, resolver, ACK, 101, sseq, &framed))
        .await;
    let data = e.h.next_meaningful().await;
    let len = u16::from_be_bytes([data.payload[0], data.payload[1]]) as usize;
    assert_eq!(data.payload.len(), 2 + len);
    let (id, rcode, ips) = answers_for_test(&data.payload[2..]).unwrap();
    assert_eq!((id, rcode), (9, 0));
    assert!(e.pool.lookup(ips[0]).is_some());
    assert!(e.dialer.dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn udp_goes_through_the_kernel_dialer_and_replies_return() {
    let mut e = kernel_env(inline(), false, true, false, false);
    let dst: SocketAddr = "8.8.8.8:3478".parse().unwrap();
    e.h.send(udp(CLIENT4, dst, b"stun")).await;
    let o = out(&e.h.next().await);
    assert_eq!(o.proto, IpProtocol::Udp);
    let u = UdpPacket::new_checked(&o.l4[..]).unwrap();
    assert_eq!(
        (o.src, u.src_port(), u.dst_port(), u.payload()),
        (dst.ip(), 3478, 40000, &b"echo:stun"[..])
    );
    assert_eq!(
        e.dialer.udp_dials.lock().unwrap().clone(),
        vec![(Some("p1".to_string()), TargetAddr::Ip(dst.ip()), 3478)]
    );
}

#[tokio::test]
async fn udp_to_the_home_route_is_refused_with_icmp() {
    let mut e = kernel_env(inline(), false, true, false, false);
    e.h.send(udp(CLIENT4, "198.51.100.7:443".parse().unwrap(), b"quic"))
        .await;
    let (t, code, _) = icmpv4(&e.h.next().await);
    assert_eq!((t, code), (3, 13));
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

#[tokio::test]
async fn failed_udp_proxy_is_refused_never_direct() {
    let mut e = kernel_env(inline(), false, true, true, false);
    let dst: SocketAddr = "8.8.8.8:3478".parse().unwrap();
    e.h.send(udp(CLIENT4, dst, b"one")).await;
    // The dial fails; the next datagram of the flow is answered with ICMP.
    let mut icmp = None;
    for _ in 0..50 {
        e.h.send(udp(CLIENT4, dst, b"again")).await;
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_millis(100), e.h.from_stack.recv()).await
        {
            icmp = Some(p);
            break;
        }
    }
    let (t, code, _) = icmpv4(&icmp.expect("ICMP after failed dial"));
    assert_eq!((t, code), (3, 13));
    let dials = e.dialer.udp_dials.lock().unwrap().clone();
    assert_eq!(dials.len(), 1, "no retry, no direct: {dials:?}");
    assert_eq!(dials[0].0.as_deref(), Some("p1"));
}

#[tokio::test]
async fn udp_without_kernel_udp_is_refused() {
    let mut e = kernel_env(inline(), false, false, false, false);
    e.h.send(udp(CLIENT4, "8.8.8.8:3478".parse().unwrap(), b"x"))
        .await;
    assert_eq!(out(&e.h.next().await).proto, IpProtocol::Icmp);
}

/// Wait for the kernel's UDP dials (the fake echo session caps payloads at
/// 1000 bytes, so a 1200-byte Initial gets no echo here).
async fn udp_dials(e: &Env) -> Vec<(Option<String>, TargetAddr, u16)> {
    for _ in 0..100 {
        let d = e.dialer.udp_dials.lock().unwrap().clone();
        if !d.is_empty() {
            return d;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    Vec::new()
}

async fn next_icmp(h: &mut Harness) -> (u8, u8, Vec<u8>) {
    loop {
        let p = h.next().await;
        if out(&p).proto == IpProtocol::Icmp {
            return icmpv4(&p);
        }
    }
}

/// Wait until the UDP sessions were asked to send `n` datagrams.
async fn udp_sent(e: &Env, n: usize) -> Vec<Vec<u8>> {
    for _ in 0..100 {
        let s = e.dialer.udp_sent.lock().unwrap().clone();
        if s.len() >= n {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    e.dialer.udp_sent.lock().unwrap().clone()
}

/// A QUIC v1 Initial with an unknown version, the fixed bit greased away,
/// and a short header of another connection hidden behind an Initial.
fn quic_variants() -> Vec<(&'static str, Vec<u8>)> {
    let rfc = hex(RFC9001_CLIENT_INITIAL);
    let mut unknown = rfc.clone();
    unknown[1..5].copy_from_slice(&[0xff, 0, 0, 0x1d]);
    let mut greased = rfc.clone();
    greased[0] &= !0x40;
    let mut coalesced = rfc[..600].to_vec();
    coalesced.extend_from_slice(b"\x40\x99\x99\x99\x99\x99\x99\x99\x99 hidden");
    vec![
        ("v1", rfc),
        ("v2", hex(RFC9369_CLIENT_INITIAL)),
        ("quic-go", hex(QUIC_GO_CHATGPT_INITIAL)),
        ("unknown version", unknown),
        ("fixed bit greased", greased),
        ("coalesced", coalesced),
    ]
}

/// §5.2a.2: to a fake IP the flow is routed by the recorded name at its
/// first datagram and pinned there: every later datagram (short headers,
/// other versions, a coalesced pair) rides the same flow, uninspected.
#[tokio::test]
async fn tun_quic_to_fake_ip_dials_by_name_and_stays_pinned() {
    let e = kernel_env_with(
        inline(),
        false,
        true,
        false,
        FakeDialer {
            udp_max: 1500,
            ..Default::default()
        },
    );
    let ip = e.pool.assign("example.com", 0).unwrap();
    let dst = SocketAddr::new(IpAddr::V4(ip), 443);
    let mut sent = Vec::new();
    for (_, d) in quic_variants() {
        e.h.send(udp(CLIENT4, dst, &d)).await;
        sent.push(d);
    }
    let short = b"\x40\x01\x02\x03\x04\x05\x06\x07\x08 short".to_vec();
    e.h.send(udp(CLIENT4, dst, &short)).await;
    sent.push(short);
    assert_eq!(udp_sent(&e, sent.len()).await, sent);
    assert_eq!(
        e.dialer.udp_dials.lock().unwrap().clone(),
        vec![(
            Some("p1".to_string()),
            TargetAddr::Domain("example.com".into()),
            443
        )]
    );
}

/// The fake IP's name decides, as for TCP: an AI name (no UDP on that
/// exit) is refused with "administratively prohibited", never dialled.
#[tokio::test]
async fn tun_quic_to_fake_ip_of_ai_name_is_refused() {
    let mut e = kernel_env(inline(), false, true, false, false);
    let ip = e.pool.assign("chatgpt.com", 0).unwrap();
    let dst = SocketAddr::new(IpAddr::V4(ip), 443);
    e.h.send(udp(CLIENT4, dst, &hex(QUIC_GO_CHATGPT_INITIAL)))
        .await;
    let (t, code, _) = next_icmp(&mut e.h).await;
    assert_eq!((t, code), (3, 13));
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

/// r8 N1–N3: QUIC to a real IP is refused at its first datagram with ICMP
/// port unreachable (sent back at once; see
/// `refusal_icmp_reaches_the_connected_client_socket_v4_and_v6`), on any port and
/// whatever the version, the fixed bit or what hides behind the first
/// packet. Nothing is dialled.
#[tokio::test]
async fn tun_quic_to_real_ip_is_refused_at_once() {
    for port in [443, 8443] {
        for (name, d) in quic_variants() {
            let mut e = kernel_env(inline(), false, true, false, false);
            let dst = SocketAddr::new("8.8.8.8".parse().unwrap(), port);
            e.h.send(udp(CLIENT4, dst, &d)).await;
            let (t, code, _) = next_icmp(&mut e.h).await;
            assert_eq!((t, code), (3, 3), "{name} on {port}");
            // Every retry too.
            e.h.send(udp(CLIENT4, dst, &d)).await;
            let (t, code, _) = next_icmp(&mut e.h).await;
            assert_eq!((t, code), (3, 3), "{name} on {port}, again");
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(e.dialer.udp_dials.lock().unwrap().is_empty(), "{name}");
        }
    }
}

/// UDP/443 to a real IP is taken for QUIC whatever it carries.
#[tokio::test]
async fn tun_udp_443_to_real_ip_is_refused() {
    let mut e = kernel_env(inline(), false, true, false, false);
    e.h.send(udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), b"\x40short"))
        .await;
    let (t, code, _) = next_icmp(&mut e.h).await;
    assert_eq!((t, code), (3, 3));
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

/// r8 N1: a plain UDP flow to a real IP goes by the IP rules, but every
/// datagram is checked: the first QUIC one refuses the flow (ICMP, not
/// sent) and the flow stays refused; short headers and other plain UDP
/// before it flow.
#[tokio::test]
async fn tun_plain_udp_flow_turning_quic_is_refused() {
    let mut e = kernel_env_with(
        inline(),
        false,
        true,
        false,
        FakeDialer {
            udp_max: 1500,
            ..Default::default()
        },
    );
    let dst: SocketAddr = "8.8.8.8:8443".parse().unwrap();
    let plain = b"\x12\x34plain".to_vec();
    let short = b"\x40\x01\x02\x03\x04\x05\x06\x07\x08 short".to_vec();
    e.h.send(udp(CLIENT4, dst, &plain)).await;
    e.h.send(udp(CLIENT4, dst, &short)).await;
    assert_eq!(udp_sent(&e, 2).await, vec![plain.clone(), short.clone()]);
    assert_eq!(
        udp_dials(&e).await,
        vec![(
            Some("p1".to_string()),
            TargetAddr::Ip("8.8.8.8".parse().unwrap()),
            8443
        )]
    );
    e.h.send(udp(CLIENT4, dst, &hex(RFC9001_CLIENT_INITIAL)))
        .await;
    let (t, code, _) = next_icmp(&mut e.h).await;
    assert_eq!((t, code), (3, 3));
    e.h.send(udp(CLIENT4, dst, &plain)).await;
    let (t, code, _) = next_icmp(&mut e.h).await;
    assert_eq!((t, code), (3, 3), "stays refused");
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(e.dialer.udp_sent.lock().unwrap().len(), 2);
    assert_eq!(e.dialer.udp_dials.lock().unwrap().len(), 1);
}

async fn next_icmp6(h: &mut Harness) -> (u8, u8, Vec<u8>) {
    loop {
        let p = h.next().await;
        let o = out(&p);
        if o.proto == IpProtocol::Icmpv6 {
            let icmp = Icmpv6Packet::new_checked(&o.l4[..]).unwrap();
            assert!(icmp.verify_checksum(&o.src.to_v6(), &o.dst.to_v6()));
            assert_eq!(o.dst, client6().ip());
            return (u8::from(icmp.msg_type()), icmp.msg_code(), o.l4.clone());
        }
    }
}

fn short_header(first: u8, n: usize) -> Vec<u8> {
    let mut p = vec![first];
    p.resize(n, 0x31);
    p
}

/// r9 F1: a new real-IP flow whose first datagram is a QUIC short header
/// (a connection set up before the kernel started, or moved here from
/// another path) is refused like an Initial: ICMP port unreachable on v4,
/// ICMPv6 destination unreachable / port unreachable (1/4) on v6, quoting
/// the datagram; nothing is dialled. Below 21 bytes it is not taken for
/// QUIC.
#[tokio::test]
async fn tun_short_header_first_to_real_ip_is_refused_v4_and_v6() {
    let mut e = kernel_env(inline(), false, true, false, false);
    let v4: SocketAddr = "8.8.8.8:8443".parse().unwrap();
    let v6: SocketAddr = "[2001:4860:4860::8888]:8443".parse().unwrap();
    for first in [0x40, 0x5c, 0x7f] {
        let d = short_header(first, 40);
        e.h.send(udp(CLIENT4, v4, &d)).await;
        let (t, code, l4) = next_icmp(&mut e.h).await;
        assert_eq!((t, code), (3, 3), "v4 {first:#x}");
        // Quotes the original IP header + the first 8 bytes of UDP.
        assert_eq!(&l4[8..], &udp(CLIENT4, v4, &d)[..28]);
        let sent = udp(client6(), v6, &d);
        e.h.send(sent.clone()).await;
        let (t, code, l4) = next_icmp6(&mut e.h).await;
        assert_eq!((t, code), (1, 4), "v6 {first:#x}");
        assert_eq!(&l4[8..], &sent[..]);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

/// r9 F1: the first datagrams of ordinary UDP protocols to a real IP are
/// not QUIC-shaped and go by the IP rules (here: the default proxy).
#[tokio::test]
async fn tun_plain_udp_protocols_to_real_ip_pass() {
    let sized = |head: &[u8], n: usize| {
        let mut p = head.to_vec();
        p.resize(n, 0x5a);
        p
    };
    let cases = [
        ("wireguard", sized(&[0x01, 0, 0, 0], 148)),
        (
            "stun",
            sized(&[0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42], 28),
        ),
        (
            "dtls",
            sized(&[0x16, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0], 200),
        ),
        ("rtp", sized(&[0x80, 0x60, 0x12, 0x34], 1300)),
        ("dns-like", sized(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01], 40)),
        ("short-header-sized-20", short_header(0x40, 20)),
    ];
    let e = kernel_env_with(
        inline(),
        false,
        true,
        false,
        FakeDialer {
            udp_max: 1500,
            ..Default::default()
        },
    );
    for (i, (_, d)) in cases.iter().enumerate() {
        let dst = SocketAddr::new("8.8.8.8".parse().unwrap(), 9000 + i as u16);
        e.h.send(udp(CLIENT4, dst, d)).await;
    }
    let mut sent = udp_sent(&e, cases.len()).await;
    sent.sort();
    let mut want: Vec<Vec<u8>> = cases.iter().map(|(_, d)| d.clone()).collect();
    want.sort();
    assert_eq!(sent, want);
    assert_eq!(e.dialer.udp_dials.lock().unwrap().len(), cases.len());
}

/// r10 N1, accepted residual (KERNEL_SPEC §5.2a.2): migration protection
/// on real-IP UDP is not complete. A QUIC connection established before
/// the kernel started, or moved onto a new real-IP 5-tuple, gets through
/// when that flow's first datagram is not QUIC-shaped: a short header with
/// the fixed bit greased away (RFC 9287; first byte 0x00..=0x3F), or any
/// ordinary leading datagram. The flow is then plain UDP routed by the IP
/// rules, and later short headers, fixed bit set or not, are carried:
/// only long headers are refused mid-flow. v4 and v6. This test pins the
/// behaviour so that a change to it is deliberate.
#[tokio::test]
async fn tun_residual_greased_or_plain_first_datagram_lets_short_headers_through() {
    let e = kernel_env_with(
        inline(),
        false,
        true,
        false,
        FakeDialer {
            udp_max: 1500,
            ..Default::default()
        },
    );
    let mut expect = Vec::new();
    let mut port = 8443;
    for dst_ip in ["8.8.8.8", "2001:4860:4860::8888"] {
        let src = if dst_ip.contains(':') {
            client6()
        } else {
            CLIENT4
        };
        for first in [
            short_header(0x00, 40),
            short_header(0x3f, 1200),
            b"\x12\x34hello".to_vec(),
        ] {
            let dst = SocketAddr::new(dst_ip.parse().unwrap(), port);
            port += 1;
            let later = [
                short_header(0x40, 60),
                short_header(0x1c, 60),
                short_header(0x7f, 1200),
            ];
            e.h.send(udp(src, dst, &first)).await;
            expect.push(first);
            for d in later {
                e.h.send(udp(src, dst, &d)).await;
                expect.push(d);
            }
        }
    }
    let mut sent = udp_sent(&e, expect.len()).await;
    sent.sort();
    expect.sort();
    assert_eq!(sent, expect, "every datagram carried");
    let dials = e.dialer.udp_dials.lock().unwrap().clone();
    assert_eq!(dials.len(), 6);
    assert!(dials
        .iter()
        .all(|(tag, a, _)| tag.as_deref() == Some("p1") && matches!(a, TargetAddr::Ip(_))));
}

/// The demultiplexing an OS stack does with an ICMP error for UDP (BSD
/// `udp_ctlinput` / `udp6_ctlinput`, Linux `__udp4_lib_err` /
/// `__udp6_lib_err`): the outer ICMP must verify and be addressed to the
/// socket's address; the quoted IP + UDP header names the socket's own
/// 4-tuple (inner source = its local address, inner destination = its
/// peer). Returns which connected socket gets which error.
fn os_udp_error(
    pkt: &[u8],
    sockets: &[(SocketAddr, SocketAddr)],
) -> Option<(usize, std::io::ErrorKind)> {
    use std::io::ErrorKind::*;
    let o = out(pkt);
    let (kind, quoted) = match o.proto {
        IpProtocol::Icmp => {
            let icmp = Icmpv4Packet::new_checked(&o.l4[..]).ok()?;
            if !icmp.verify_checksum() {
                return None;
            }
            let kind = match (u8::from(icmp.msg_type()), icmp.msg_code()) {
                (3, 3) => ConnectionRefused,
                (3, 13) => HostUnreachable,
                _ => return None,
            };
            (kind, &o.l4[8..])
        }
        IpProtocol::Icmpv6 => {
            let icmp = Icmpv6Packet::new_checked(&o.l4[..]).ok()?;
            if !icmp.verify_checksum(&o.src.to_v6(), &o.dst.to_v6()) {
                return None;
            }
            let kind = match (u8::from(icmp.msg_type()), icmp.msg_code()) {
                (1, 4) => ConnectionRefused,
                (1, 1) => PermissionDenied,
                _ => return None,
            };
            (kind, &o.l4[8..])
        }
        _ => return None,
    };
    // Quoted header: IPv4 (IHL) or IPv6 (40 bytes, next header UDP), then
    // at least the 8-byte UDP header.
    let (src, dst, udp) = match quoted.first()? >> 4 {
        4 => {
            let ihl = usize::from(quoted[0] & 0x0f) * 4;
            if quoted.get(9) != Some(&17) || ihl < 20 {
                return None;
            }
            let a = |i: usize| {
                IpAddr::V4(Ipv4Addr::new(
                    quoted[i],
                    quoted[i + 1],
                    quoted[i + 2],
                    quoted[i + 3],
                ))
            };
            (a(12), a(16), quoted.get(ihl..ihl + 8)?)
        }
        6 => {
            if quoted.get(6) != Some(&17) {
                return None;
            }
            let a = |i: usize| {
                let b: [u8; 16] = quoted[i..i + 16].try_into().unwrap();
                IpAddr::V6(Ipv6Addr::from(b))
            };
            (a(8), a(24), quoted.get(40..48)?)
        }
        _ => return None,
    };
    let local = SocketAddr::new(src, u16::from_be_bytes([udp[0], udp[1]]));
    let peer = SocketAddr::new(dst, u16::from_be_bytes([udp[2], udp[3]]));
    if o.dst != local.ip() {
        return None;
    }
    let i = sockets.iter().position(|&s| s == (local, peer))?;
    Some((i, kind))
}

/// r9 F6: the refusal of real-IP QUIC reaches the client socket. A real
/// OS socket cannot be fed a crafted ICMP without privileges, so the
/// client's stack is modelled ([`os_udp_error`]): for v4 and v6, the ICMP
/// the TUN writes back for a QUIC Initial is the one a connected UDP
/// socket for exactly that 4-tuple turns into ECONNREFUSED, it comes back
/// while the datagram is being taken in (no timer), and a plain UDP flow
/// from the same app to the same host is left alone.
#[tokio::test]
async fn refusal_icmp_reaches_the_connected_client_socket_v4_and_v6() {
    let mut e = kernel_env_with(
        inline(),
        false,
        true,
        false,
        FakeDialer {
            udp_max: 1500,
            ..Default::default()
        },
    );
    let quic_v4 = (
        SocketAddr::new(CLIENT4.ip(), 40001),
        "8.8.8.8:8443".parse().unwrap(),
    );
    let plain_v4 = (
        SocketAddr::new(CLIENT4.ip(), 40002),
        "8.8.8.8:8443".parse().unwrap(),
    );
    let quic_v6 = (
        SocketAddr::new(client6().ip(), 40001),
        "[2001:4860:4860::8888]:8443".parse().unwrap(),
    );
    let sockets = [quic_v4, plain_v4, quic_v6];
    e.h.send(udp(plain_v4.0, plain_v4.1, b"\x12\x34plain"))
        .await;
    assert_eq!(udp_sent(&e, 1).await.len(), 1);
    for (i, s) in [(0, quic_v4), (2, quic_v6)] {
        let t = Instant::now();
        e.h.send(udp(s.0, s.1, &hex(RFC9001_CLIENT_INITIAL))).await;
        let pkt = loop {
            let p = e.h.next().await;
            if matches!(out(&p).proto, IpProtocol::Icmp | IpProtocol::Icmpv6) {
                break p;
            }
        };
        let took = t.elapsed();
        assert_eq!(
            os_udp_error(&pkt, &sockets),
            Some((i, std::io::ErrorKind::ConnectionRefused)),
            "{s:?}"
        );
        assert!(took < Duration::from_millis(100), "{s:?}: {took:?}");
    }
    // The model is not trivially true: the same ICMP matches no socket
    // with another local port or another peer.
    e.h.send(udp(quic_v4.0, quic_v4.1, &hex(RFC9001_CLIENT_INITIAL)))
        .await;
    let pkt = e.h.next().await;
    assert_eq!(os_udp_error(&pkt, &sockets[..1]).map(|r| r.0), Some(0));
    let others = [
        (SocketAddr::new(CLIENT4.ip(), 40009), quic_v4.1),
        (quic_v4.0, "8.8.4.4:8443".parse().unwrap()),
        (quic_v4.0, "8.8.8.8:8444".parse().unwrap()),
    ];
    assert_eq!(os_udp_error(&pkt, &others), None);
    assert_eq!(
        e.dialer.udp_dials.lock().unwrap().len(),
        1,
        "only the plain flow"
    );
}

// r6 R5: a TUN flow through a real segue session keeps moving bytes both
// ways while every elastic block of the shared pool is held elsewhere.

/// Engine stand-in: every carrier is a duplex pipe into one in-process
/// relay.
struct RelayEngine {
    accept: mpsc::Sender<segue_session::driver::BoxCarrier>,
}

#[async_trait]
impl Dialer for RelayEngine {
    async fn dial(
        &self,
        _tag: Option<&str>,
        _addr: &TargetAddr,
        _port: u16,
    ) -> Result<segue_kernel::dial::Stream, DialError> {
        let (client, relay) = tokio::io::duplex(64 << 10);
        self.accept
            .send(Box::new(relay))
            .await
            .map_err(|_| DialError("relay gone".into()))?;
        Ok(Box::new(client))
    }
}

fn pattern_byte(i: u64, salt: u8) -> u8 {
    ((i % 251) as u8) ^ salt
}

/// The application side of one TCP flow, by hand: sends `up` bytes and
/// takes the download until the site's FIN, acknowledging everything,
/// retransmitting from the last ACK when nothing moves. The FIN goes out
/// once `site_got` shows the whole upload reached the site (a relay that
/// closes a session with data still buffered is a separate bug, not what
/// this exercises). Returns the download.
async fn raw_transfer(
    h: &mut Harness,
    src: SocketAddr,
    dst: SocketAddr,
    up: usize,
    site_got: &std::sync::atomic::AtomicUsize,
) -> Vec<u8> {
    const SEG: usize = 1000;
    h.send(tcp(src, dst, SYN, 1000, 0, b"")).await;
    let synack = h.next_meaningful().await;
    assert!(synack.syn && synack.ack, "no SYN-ACK");
    let iss = 1001u32;
    let mut their_next = synack.seq.wrapping_add(1);
    h.send(tcp(src, dst, ACK, iss, their_next, b"")).await;
    let body: Vec<u8> = (0..up as u64).map(|i| pattern_byte(i, 0x5a)).collect();
    let (mut sent, mut acked) = (0usize, 0usize);
    let mut fin_sent = false;
    let mut down = Vec::new();
    let mut their_fin = false;
    let mut window = synack.window as usize;
    while !(their_fin && fin_sent && acked > up) {
        while sent < up && sent < acked + window {
            let n = SEG.min(up - sent).min(acked + window - sent);
            let seq = iss.wrapping_add(sent as u32);
            h.send(tcp(src, dst, ACK, seq, their_next, &body[sent..sent + n]))
                .await;
            sent += n;
        }
        if sent == up
            && acked == up
            && !fin_sent
            && site_got.load(std::sync::atomic::Ordering::SeqCst) >= up
        {
            let seq = iss.wrapping_add(up as u32);
            h.send(tcp(src, dst, FIN, seq, their_next, b"")).await;
            fin_sent = true;
            sent += 1;
        }
        let wait = if acked == up && !fin_sent { 5 } else { 300 };
        let pkt = tokio::time::timeout(Duration::from_millis(wait), h.from_stack.recv()).await;
        let Ok(Some(pkt)) = pkt else {
            if acked == up && !fin_sent {
                continue;
            }
            // Nothing moved: resend from the last ACK.
            sent = acked.min(up);
            fin_sent = false;
            h.send(tcp(
                src,
                dst,
                ACK,
                iss.wrapping_add(sent as u32),
                their_next,
                b"",
            ))
            .await;
            continue;
        };
        let s = seg(&pkt);
        assert!(!s.rst, "flow reset after {} down / {acked} up", down.len());
        if s.ack {
            let a = s.ack_no.wrapping_sub(iss) as usize;
            if a >= acked && a <= sent {
                acked = a;
                window = s.window as usize;
            }
        }
        let mut reply = false;
        if !s.payload.is_empty() {
            if s.seq == their_next {
                down.extend_from_slice(&s.payload);
                their_next = their_next.wrapping_add(s.payload.len() as u32);
            }
            reply = true;
        }
        if s.fin && s.seq.wrapping_add(s.payload.len() as u32) == their_next && !their_fin {
            their_fin = true;
            their_next = their_next.wrapping_add(1);
            reply = true;
        }
        if reply {
            let seq = iss.wrapping_add(sent.min(up + usize::from(fin_sent)) as u32);
            h.send(tcp(src, dst, ACK, seq, their_next, b"")).await;
        }
    }
    down
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tun_session_flow_moves_both_ways_with_the_elastic_pool_spent() {
    use segue_kernel::session::{Exit, KernelDialer, SegueRoute};
    use segue_session::codec::{Kind, Target};
    use segue_session::driver::{run_relay, BoxCarrier, SiteConnector};
    use segue_session::pool::{Grant, Pool, Tier};
    use segue_session::relay::{AllowAll, RelayTable};
    const UP: usize = 192 << 10;
    const DOWN: u64 = 192 << 10;

    let pool = Pool::new(1 << 20);
    // The site: sends DOWN pattern bytes then FIN, reads and checks the
    // upload, reports how much arrived.
    let (got_tx, mut got_rx) = mpsc::unbounded_channel::<usize>();
    let site_got = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = site_got.clone();
    let (connected_tx, mut connected_rx) = mpsc::unbounded_channel::<()>();
    let site: SiteConnector = Arc::new(move |_t: Target, _k: Kind| {
        let got_tx = got_tx.clone();
        let connected_tx = connected_tx.clone();
        let seen = seen.clone();
        Box::pin(async move {
            let (a, b) = tokio::io::duplex(64 << 10);
            let (mut r, mut w) = tokio::io::split(b);
            tokio::spawn(async move {
                let mut i = 0u64;
                while i < DOWN {
                    let chunk: Vec<u8> = (i..(i + 4096).min(DOWN))
                        .map(|x| pattern_byte(x, 0))
                        .collect();
                    if w.write_all(&chunk).await.is_err() {
                        return;
                    }
                    i += chunk.len() as u64;
                }
                let _ = w.shutdown().await;
            });
            tokio::spawn(async move {
                let mut at = 0u64;
                let mut buf = vec![0u8; 4096];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            for &x in &buf[..n] {
                                assert_eq!(x, pattern_byte(at, 0x5a), "upload byte {at}");
                                at += 1;
                            }
                            seen.store(at as usize, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                }
                let _ = got_tx.send(at as usize);
            });
            let _ = connected_tx.send(());
            Ok(Box::new(a) as BoxCarrier)
        })
    });
    let (accept_tx, accept_rx) = mpsc::channel(16);
    let table = RelayTable::new(
        segue_session::Config::default(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        9,
    );
    tokio::spawn(run_relay(table, accept_rx, site, None));
    let dialer = KernelDialer::new(
        Arc::new(RelayEngine { accept: accept_tx }),
        vec![Exit {
            name: "la".into(),
            carrier: "relay".into(),
            redundant_carrier: None,
            relay: "127.0.0.1:7443".parse().unwrap(),
            node_id: 1,
            egress_group: String::new(),
        }],
        [(
            "p1".to_string(),
            SegueRoute {
                ticket: b"ticket".to_vec(),
                exit_class: 0,
            },
        )]
        .into(),
        Default::default(),
    )
    .with_pool(pool.clone());
    let mut tun = TunStack::new(Arc::new(rules_proxy_default()), Arc::new(dialer));
    tun.config.shared_pool = Some(pool.clone());
    let mut h = Harness::run(tun);

    // Hold every elastic block from the moment the flow's session is
    // admitted to the end of the transfer: what windows, replay buffers and
    // rings of other flows would hold. Whatever the flow frees is taken
    // again within a few milliseconds.
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hog = tokio::spawn({
        let (pool, done) = (pool.clone(), done.clone());
        async move {
            connected_rx.recv().await.expect("site connected");
            let mut hog = Vec::new();
            while !done.load(std::sync::atomic::Ordering::SeqCst) {
                while let Some(g) = Grant::fixed(&pool, BLOCK) {
                    hog.push(g);
                }
                assert!(pool.used_blocks() >= pool.limit(Tier::Elastic));
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            hog
        }
    });
    let started = Instant::now();
    let down = tokio::time::timeout(
        Duration::from_secs(60),
        raw_transfer(&mut h, CLIENT4, SITE4, UP, &site_got),
    )
    .await
    .expect("TUN flow stalled with the pool spent");
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    let hog = hog.await.unwrap();
    println!(
        "{} KiB each way in {:?} with {} blocks hogged",
        UP >> 10,
        started.elapsed(),
        hog.len()
    );
    assert!(
        hog.len() > 100,
        "the pool was never spent ({} blocks)",
        hog.len()
    );
    assert_eq!(down.len() as u64, DOWN);
    for (i, &x) in down.iter().enumerate() {
        assert_eq!(x, pattern_byte(i as u64, 0), "download byte {i}");
    }
    let up = tokio::time::timeout(Duration::from_secs(10), got_rx.recv())
        .await
        .expect("site never saw the upload end")
        .unwrap();
    assert_eq!(up, UP);
    drop(hog);
}

/// Review r8 checklist #4: several sessions on slow (but moving) carriers
/// and one healthy TUN flow both ways over a real carrier (an in-memory
/// duplex through `KernelDialer` to `run_relay`), all on one shared pool
/// with its elastic part spent, so every frame competes for the transport
/// region. The healthy flow must finish in bounded time, the slow sessions
/// must finish too, with bounded redials; the pool's peak use is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_carriers_and_a_healthy_tun_flow_share_the_pool() {
    use segue_kernel::session::{Exit, KernelDialer, SegueRoute};
    use segue_session::client::{ClientSession, CloseReason, OpenParams};
    use segue_session::codec::{Kind, Target};
    use segue_session::driver::{run_client, run_relay, BoxCarrier, Connector, SiteConnector};
    use segue_session::pool::{Grant, Pool, Tier};
    use segue_session::relay::{AllowAll, RelayTable};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    const UP: usize = 192 << 10;
    const DOWN: u64 = 192 << 10;
    const SLOW: usize = 6;
    const SLOW_DOWN: usize = 48 << 10;
    // Each slow carrier moves 1000 B per 100 ms each way: 10 KB/s, a full
    // frame in about 1.6 s.
    const SLOW_CHUNK: usize = 1000;
    const SLOW_EVERY: Duration = Duration::from_millis(100);

    let pool = Pool::new(1 << 20);
    let site_got = Arc::new(AtomicUsize::new(0));
    let (got_tx, mut got_rx) = mpsc::unbounded_channel::<usize>();
    let (connected_tx, mut connected_rx) = mpsc::unbounded_channel::<()>();
    let site: SiteConnector = {
        let seen = site_got.clone();
        Arc::new(move |t: Target, _k: Kind| {
            let got_tx = got_tx.clone();
            let connected_tx = connected_tx.clone();
            let seen = seen.clone();
            Box::pin(async move {
                let (a, b) = tokio::io::duplex(64 << 10);
                let (mut r, mut w) = tokio::io::split(b);
                if matches!(t, Target::Domain(..)) {
                    // A slow session's site: a large download in large
                    // writes (full frames), the upload taken and dropped.
                    tokio::spawn(async move {
                        let down: Vec<u8> =
                            (0..SLOW_DOWN as u64).map(|x| pattern_byte(x, 3)).collect();
                        let _ = w.write_all(&down).await;
                        let _ = w.shutdown().await;
                        std::future::pending::<()>().await;
                        drop(w);
                    });
                    tokio::spawn(async move {
                        let mut sink = Vec::new();
                        let _ = r.read_to_end(&mut sink).await;
                        std::future::pending::<()>().await;
                        drop(r);
                    });
                    return Ok(Box::new(a) as BoxCarrier);
                }
                tokio::spawn(async move {
                    let mut i = 0u64;
                    while i < DOWN {
                        let chunk: Vec<u8> = (i..(i + 4096).min(DOWN))
                            .map(|x| pattern_byte(x, 0))
                            .collect();
                        if w.write_all(&chunk).await.is_err() {
                            return;
                        }
                        i += chunk.len() as u64;
                    }
                    let _ = w.shutdown().await;
                });
                tokio::spawn(async move {
                    let mut at = 0u64;
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                for &x in &buf[..n] {
                                    assert_eq!(x, pattern_byte(at, 0x5a), "upload byte {at}");
                                    at += 1;
                                }
                                seen.store(at as usize, Ordering::SeqCst);
                            }
                        }
                    }
                    let _ = got_tx.send(at as usize);
                });
                let _ = connected_tx.send(());
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    let (accept_tx, accept_rx) = mpsc::channel(64);
    let table = RelayTable::new(
        segue_session::Config::default(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        9,
    );
    tokio::spawn(run_relay(table, accept_rx, site, None));

    // The slow sessions: default timing, the shared pool, each carrier a
    // throttled pipe to the relay.
    async fn pump(
        mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    ) {
        let mut buf = vec![0u8; SLOW_CHUNK];
        let mut tick = tokio::time::interval(SLOW_EVERY);
        loop {
            tick.tick().await;
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown().await;
    }
    let slow_dials = Arc::new(AtomicUsize::new(0));
    let slow_connector: Connector = {
        let (accept_tx, dials) = (accept_tx.clone(), slow_dials.clone());
        Arc::new(move || {
            let accept_tx = accept_tx.clone();
            dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let (client, ca) = tokio::io::duplex(SLOW_CHUNK);
                let (rb, relay) = tokio::io::duplex(SLOW_CHUNK);
                let (car, caw) = tokio::io::split(ca);
                let (rbr, rbw) = tokio::io::split(rb);
                tokio::spawn(pump(car, rbw));
                tokio::spawn(pump(rbr, caw));
                accept_tx
                    .send(Box::new(relay) as BoxCarrier)
                    .await
                    .map_err(|_| std::io::Error::other("gone"))?;
                Ok(Box::new(client) as BoxCarrier)
            })
        })
    };
    let mut slow = Vec::new();
    for i in 0..SLOW {
        let params = OpenParams {
            ticket: b"ticket".to_vec(),
            kind: Kind::Tcp,
            target: Target::Domain(format!("slow{i}.example"), 443),
            exit_class: 0,
            anchor_node_id: 1,
            instance_hint: 9,
        };
        let s = ClientSession::new(Default::default(), &pool, params, std::time::Instant::now())
            .expect("slow session admitted");
        let (mut app, far) = tokio::io::duplex(64 << 10);
        let client = tokio::spawn(run_client(s, far, slow_connector.clone()));
        slow.push(tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut app);
            let ((), down) = tokio::join!(
                async {
                    let _ = w.write_all(&[i as u8; 8 << 10]).await;
                    let _ = w.shutdown().await;
                },
                async {
                    let mut down = Vec::new();
                    let _ = r.read_to_end(&mut down).await;
                    down
                }
            );
            let reason = client.await.unwrap();
            (reason, down)
        }));
    }

    // The healthy flow: TUN → KernelDialer → a plain duplex carrier.
    let dialer = KernelDialer::new(
        Arc::new(RelayEngine { accept: accept_tx }),
        vec![Exit {
            name: "la".into(),
            carrier: "relay".into(),
            redundant_carrier: None,
            relay: "127.0.0.1:7443".parse().unwrap(),
            node_id: 1,
            egress_group: String::new(),
        }],
        [(
            "p1".to_string(),
            SegueRoute {
                ticket: b"ticket".to_vec(),
                exit_class: 0,
            },
        )]
        .into(),
        Default::default(),
    )
    .with_pool(pool.clone());
    let mut tun = TunStack::new(Arc::new(rules_proxy_default()), Arc::new(dialer));
    tun.config.shared_pool = Some(pool.clone());
    let mut h = Harness::run(tun);

    // Keep the elastic part spent, and record the peaks.
    let done = Arc::new(AtomicBool::new(false));
    let watch = tokio::spawn({
        let (pool, done) = (pool.clone(), done.clone());
        async move {
            // From the moment the healthy flow is admitted (a spent pool
            // refuses new flows).
            connected_rx.recv().await.expect("healthy site connected");
            let mut hog = Vec::new();
            let (mut peak, mut peak_transport) = (0, 0);
            while !done.load(Ordering::SeqCst) {
                while let Some(g) = Grant::fixed(&pool, BLOCK) {
                    hog.push(g);
                }
                assert!(pool.used_blocks() >= pool.limit(Tier::Elastic));
                peak = peak.max(pool.used_blocks() + pool.transport_used_blocks());
                peak_transport = peak_transport.max(pool.transport_used_blocks());
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            (hog.len(), peak, peak_transport)
        }
    });
    // Let the slow sessions open and start their downloads.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let started = Instant::now();
    let down = tokio::time::timeout(
        Duration::from_secs(60),
        raw_transfer(&mut h, CLIENT4, SITE4, UP, &site_got),
    )
    .await
    .expect("healthy TUN flow stalled behind the slow carriers");
    let healthy = started.elapsed();
    let slow_running = slow.iter().filter(|j| !j.is_finished()).count();
    assert_eq!(down.len() as u64, DOWN);
    for (i, &x) in down.iter().enumerate() {
        assert_eq!(x, pattern_byte(i as u64, 0), "download byte {i}");
    }
    let up = tokio::time::timeout(Duration::from_secs(10), got_rx.recv())
        .await
        .expect("site never saw the upload end")
        .unwrap();
    assert_eq!(up, UP);
    // The slow sessions finish too, with the pool still spent.
    let t_slow = Instant::now();
    for (i, j) in slow.into_iter().enumerate() {
        let (reason, d) = tokio::time::timeout(Duration::from_secs(90), j)
            .await
            .expect("slow session never finished")
            .unwrap();
        assert_eq!(reason, CloseReason::Clean, "slow session {i}");
        assert_eq!(d.len(), SLOW_DOWN, "slow session {i} download");
        for (k, &x) in d.iter().enumerate() {
            assert_eq!(x, pattern_byte(k as u64, 3), "slow {i} byte {k}");
        }
    }
    let slow_more = t_slow.elapsed();
    done.store(true, Ordering::SeqCst);
    let (hogged, peak, peak_transport) = watch.await.unwrap();
    let dials = slow_dials.load(Ordering::SeqCst);
    println!(
        "healthy {} KiB each way in {healthy:?} ({slow_running} of {SLOW} slow sessions still running), \
         slow done {slow_more:?} later; pool {} blocks, {hogged} hogged, peak {peak} used ({} elastic limit), \
         transport peak {peak_transport}/{}; slow dials {dials}",
        UP >> 10,
        pool.blocks(),
        pool.limit(Tier::Elastic),
        pool.transport_blocks(),
    );
    assert!(hogged > 100, "the pool was never spent ({hogged} blocks)");
    assert!(
        slow_running > 0,
        "the slow sessions ended before the healthy flow: no contention"
    );
    assert!(
        peak <= pool.blocks(),
        "peak {peak} of {} blocks",
        pool.blocks()
    );
    assert!(peak_transport <= pool.transport_blocks());
    assert!(dials <= 2 * SLOW, "{dials} dials for {SLOW} slow sessions");
}

/// The process's resident set in KiB, as the host reports it (`ps`).
fn host_rss_kib() -> Option<u64> {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

/// Engine stand-in that dials a real TCP listener on loopback: every
/// carrier is a kernel socket pair with its own buffers and syscalls.
struct LoopbackEngine {
    relay: SocketAddr,
}

#[async_trait]
impl Dialer for LoopbackEngine {
    async fn dial(
        &self,
        _tag: Option<&str>,
        _addr: &TargetAddr,
        _port: u16,
    ) -> Result<segue_kernel::dial::Stream, DialError> {
        let s = tokio::net::TcpStream::connect(self.relay)
            .await
            .map_err(|e| DialError(e.to_string()))?;
        let _ = s.set_nodelay(true);
        Ok(Box::new(s))
    }
}

/// r9 F7: the combined test over a real carrier. One TUN flow both ways
/// and many concurrent session flows (a burst each way, then idle, then
/// another burst) all go through `KernelDialer` over loopback TCP to
/// `run_relay`, on one shared 8 MiB pool. Records the pool's peak (all
/// regions and the transport region) and the process RSS sampled from the
/// host while it runs; everything must arrive intact with the pool
/// within its blocks and RSS growth bounded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tun_and_session_flows_over_a_loopback_tcp_carrier_with_pool_and_rss() {
    use segue_kernel::session::{Exit, KernelDialer, SegueRoute};
    use segue_session::codec::{Kind, Target};
    use segue_session::driver::{run_relay, BoxCarrier, SiteConnector};
    use segue_session::pool::Pool;
    use segue_session::relay::{AllowAll, RelayTable};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    const UP: usize = 256 << 10;
    const DOWN: u64 = 256 << 10;
    const SESSIONS: usize = 64;
    const BURST: usize = 64 << 10;
    const MIB: f64 = (1 << 20) as f64;

    let pool = Pool::new(8 << 20);
    let site_got = Arc::new(AtomicUsize::new(0));
    let site: SiteConnector = {
        let seen = site_got.clone();
        Arc::new(move |t: Target, _k: Kind| {
            let seen = seen.clone();
            Box::pin(async move {
                let (a, b) = tokio::io::duplex(64 << 10);
                let (mut r, mut w) = tokio::io::split(b);
                if matches!(t, Target::Domain(..)) {
                    // Session flows: an echo.
                    tokio::spawn(async move {
                        let _ = tokio::io::copy(&mut r, &mut w).await;
                        let _ = w.shutdown().await;
                    });
                    return Ok(Box::new(a) as BoxCarrier);
                }
                // The TUN flow: the download pattern, and the upload checked.
                tokio::spawn(async move {
                    let mut i = 0u64;
                    while i < DOWN {
                        let chunk: Vec<u8> = (i..(i + 4096).min(DOWN))
                            .map(|x| pattern_byte(x, 0))
                            .collect();
                        if w.write_all(&chunk).await.is_err() {
                            return;
                        }
                        i += chunk.len() as u64;
                    }
                    let _ = w.shutdown().await;
                });
                tokio::spawn(async move {
                    let mut at = 0u64;
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                for &x in &buf[..n] {
                                    assert_eq!(x, pattern_byte(at, 0x5a), "upload byte {at}");
                                    at += 1;
                                }
                                seen.store(at as usize, Ordering::SeqCst);
                            }
                        }
                    }
                });
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };
    // The relay behind a real loopback listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let carriers = Arc::new(AtomicUsize::new(0));
    let acceptor = tokio::spawn({
        let carriers = carriers.clone();
        async move {
            while let Ok((s, _)) = listener.accept().await {
                let _ = s.set_nodelay(true);
                carriers.fetch_add(1, Ordering::SeqCst);
                if accept_tx.send(Box::new(s)).await.is_err() {
                    return;
                }
            }
        }
    });
    let table = RelayTable::new(
        segue_session::Config::default(),
        Pool::new(64 << 20),
        Box::new(AllowAll),
        9,
    );
    let relay = tokio::spawn(run_relay(table, accept_rx, site, None));
    let dialer = Arc::new(
        KernelDialer::new(
            Arc::new(LoopbackEngine { relay: relay_addr }),
            vec![Exit {
                name: "la".into(),
                carrier: "relay".into(),
                redundant_carrier: None,
                relay: relay_addr,
                node_id: 1,
                egress_group: String::new(),
            }],
            [(
                "p1".to_string(),
                SegueRoute {
                    ticket: b"ticket".to_vec(),
                    exit_class: 0,
                },
            )]
            .into(),
            Default::default(),
        )
        .with_pool(pool.clone()),
    );

    // Sample the pool and the host's RSS for the whole run.
    let done = Arc::new(AtomicBool::new(false));
    let rss_base = host_rss_kib().expect("ps reports no RSS");
    let rss_peak = Arc::new(AtomicU64::new(rss_base));
    let sampler = std::thread::spawn({
        let (done, rss_peak) = (done.clone(), rss_peak.clone());
        move || {
            while !done.load(Ordering::SeqCst) {
                if let Some(k) = host_rss_kib() {
                    rss_peak.fetch_max(k, Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });
    let watch = tokio::spawn({
        let (pool, done) = (pool.clone(), done.clone());
        async move {
            let (mut peak, mut peak_transport) = (0, 0);
            while !done.load(Ordering::SeqCst) {
                peak = peak.max(pool.used_blocks() + pool.transport_used_blocks());
                peak_transport = peak_transport.max(pool.transport_used_blocks());
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            (peak, peak_transport)
        }
    });

    // Session flows: burst, idle, burst again; all at once.
    let mut jobs = Vec::new();
    for i in 0..SESSIONS {
        let d = dialer.clone();
        jobs.push(tokio::spawn(async move {
            let mut s = d
                .dial(Some("p1"), &TargetAddr::Domain(format!("s{i}.test")), 443)
                .await
                .unwrap_or_else(|e| panic!("session {i} refused: {e}"));
            for round in 0..2u8 {
                let up: Vec<u8> = (0..BURST as u64)
                    .map(|x| pattern_byte(x, i as u8 ^ round))
                    .collect();
                let (mut r, mut w) = tokio::io::split(&mut s);
                let (_, down) = tokio::join!(async { w.write_all(&up).await.unwrap() }, async {
                    let mut d = vec![0u8; BURST];
                    r.read_exact(&mut d).await.unwrap();
                    d
                });
                assert!(down == up, "session {i} round {round}: echo differs");
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }));
    }
    // The TUN flow, meanwhile.
    let mut tun = TunStack::new(Arc::new(rules_proxy_default()), dialer.clone());
    tun.config.shared_pool = Some(pool.clone());
    let mut h = Harness::run(tun);
    let started = Instant::now();
    let down = tokio::time::timeout(
        Duration::from_secs(60),
        raw_transfer(&mut h, CLIENT4, SITE4, UP, &site_got),
    )
    .await
    .expect("TUN flow stalled");
    let tun_took = started.elapsed();
    assert_eq!(down.len() as u64, DOWN);
    for (i, &x) in down.iter().enumerate() {
        assert_eq!(x, pattern_byte(i as u64, 0), "download byte {i}");
    }
    for (i, j) in jobs.into_iter().enumerate() {
        tokio::time::timeout(Duration::from_secs(60), j)
            .await
            .unwrap_or_else(|_| panic!("session {i} never finished"))
            .unwrap();
    }
    let all_took = started.elapsed();
    done.store(true, Ordering::SeqCst);
    let (peak, peak_transport) = watch.await.unwrap();
    sampler.join().unwrap();
    let rss_peak = rss_peak.load(Ordering::SeqCst);
    let n_carriers = carriers.load(Ordering::SeqCst);
    println!(
        "loopback TCP: TUN {} KiB each way in {tun_took:?}, {SESSIONS} sessions x 2 x {} KiB echo, all in {all_took:?}; \
         {n_carriers} carriers; pool {} blocks, peak {peak} used, transport peak {peak_transport}/{}; \
         RSS {:.1} MiB -> peak {:.1} MiB (+{:.1} MiB)",
        UP >> 10,
        BURST >> 10,
        pool.blocks(),
        pool.transport_blocks(),
        rss_base as f64 * 1024.0 / MIB,
        rss_peak as f64 * 1024.0 / MIB,
        (rss_peak - rss_base) as f64 * 1024.0 / MIB,
    );
    assert!(
        peak <= pool.blocks(),
        "peak {peak} of {} blocks",
        pool.blocks()
    );
    assert!(peak_transport <= pool.transport_blocks());
    // One carrier per session plus the control stream, a few redials at
    // most: loopback does not stall.
    assert!(
        n_carriers <= SESSIONS + 1 + 2 + 4,
        "{n_carriers} carriers for {} flows",
        SESSIONS + 1
    );
    // The client's own memory is the 8 MiB pool plus fixed costs; the
    // relay (64 MiB pool) and the test's buffers run in this process too,
    // so this bounds only gross leaks or per-flow blow-ups.
    let grew_mib = (rss_peak - rss_base) as f64 * 1024.0 / MIB;
    assert!(grew_mib < 128.0, "RSS grew {grew_mib:.1} MiB");
    relay.abort();
    acceptor.abort();
}

/// Process CPU time (user + system) and voluntary context switches (each
/// one a thread going to sleep: a proxy for wakeups).
fn process_cpu() -> (Duration, i64) {
    // SAFETY: valid out pointer.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    let r = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    assert_eq!(r, 0);
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    (tv(ru.ru_utime) + tv(ru.ru_stime), ru.ru_nvcsw as i64)
}

fn sha(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// r10 closing checklist item 4: everything at once over real loopback
/// TCP. Slow carriers (a throttling TCP proxy, 10 KB/s each way) carry
/// slow sessions on the client's shared 1 MiB pool, whose elastic part is
/// kept spent (full pool contention: the slow sessions send through the
/// transport region and wait on credit with ACKs due, r10 N4), while a
/// healthy TUN flow goes both ways through `KernelDialer` over a direct
/// loopback TCP carrier. Checks: every byte intact (SHA-256 of each
/// stream), reconnects bounded (slow dials and healthy carriers), CPU
/// and voluntary context switches per wall second bounded (no spinning
/// while blocked on credit), host RSS growth bounded. Before the N4 fix
/// the run took ~85% of a core here; now ~15%.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_tcp_carriers_full_pool_and_a_healthy_tun_flow_over_loopback() {
    // The CPU and wakeup budgets below are process-wide (getrusage), so the
    // sibling tests of this binary running in parallel would be billed to this
    // one: 5% of a core alone became 77% on a 4-core CI runner. Re-run this
    // test alone in a child process of the same binary and judge that run.
    const ISOLATED: &str = "SEGUE_KERNEL_ISOLATED_BUDGET_TEST";
    if std::env::var_os(ISOLATED).is_none() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "slow_tcp_carriers_full_pool_and_a_healthy_tun_flow_over_loopback",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(ISOLATED, "1")
            .status()
            .unwrap();
        assert!(status.success(), "isolated budget run failed: {status}");
        return;
    }
    use segue_kernel::session::{Exit, KernelDialer, SegueRoute};
    use segue_session::client::{ClientSession, CloseReason, OpenParams};
    use segue_session::codec::{Kind, Target};
    use segue_session::driver::{run_client, run_relay, BoxCarrier, Connector, SiteConnector};
    use segue_session::pool::{Grant, Pool, Tier};
    use segue_session::relay::{AllowAll, RelayTable};
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    const UP: usize = 192 << 10;
    const DOWN: u64 = 192 << 10;
    const SLOW: usize = 6;
    const SLOW_UP: usize = 8 << 10;
    const SLOW_DOWN: usize = 48 << 10;
    const SLOW_CHUNK: usize = 1000;
    const SLOW_EVERY: Duration = Duration::from_millis(100);
    const MIB: f64 = (1 << 20) as f64;

    let pool = Pool::new(1 << 20);
    let site_got = Arc::new(AtomicUsize::new(0));
    let (up_tx, mut up_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (connected_tx, mut connected_rx) = mpsc::unbounded_channel::<()>();
    let slow_up: Arc<Mutex<std::collections::HashMap<String, Vec<u8>>>> = Default::default();
    let site: SiteConnector = {
        let (seen, slow_up) = (site_got.clone(), slow_up.clone());
        Arc::new(move |t: Target, _k: Kind| {
            let (up_tx, connected_tx) = (up_tx.clone(), connected_tx.clone());
            let (seen, slow_up) = (seen.clone(), slow_up.clone());
            Box::pin(async move {
                let (a, b) = tokio::io::duplex(64 << 10);
                let (mut r, mut w) = tokio::io::split(b);
                if let Target::Domain(name, _) = t {
                    // Slow sessions: a large download in full frames; the
                    // upload kept for its hash.
                    tokio::spawn(async move {
                        let down: Vec<u8> =
                            (0..SLOW_DOWN as u64).map(|x| pattern_byte(x, 3)).collect();
                        let _ = w.write_all(&down).await;
                        let _ = w.shutdown().await;
                        std::future::pending::<()>().await;
                        drop(w);
                    });
                    tokio::spawn(async move {
                        let mut got = Vec::new();
                        let _ = r.read_to_end(&mut got).await;
                        slow_up.lock().unwrap().insert(name, got);
                        std::future::pending::<()>().await;
                        drop(r);
                    });
                    return Ok(Box::new(a) as BoxCarrier);
                }
                tokio::spawn(async move {
                    let mut i = 0u64;
                    while i < DOWN {
                        let chunk: Vec<u8> = (i..(i + 4096).min(DOWN))
                            .map(|x| pattern_byte(x, 0))
                            .collect();
                        if w.write_all(&chunk).await.is_err() {
                            return;
                        }
                        i += chunk.len() as u64;
                    }
                    let _ = w.shutdown().await;
                });
                tokio::spawn(async move {
                    let mut got = Vec::new();
                    let mut buf = vec![0u8; 4096];
                    loop {
                        match r.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                got.extend_from_slice(&buf[..n]);
                                seen.store(got.len(), Ordering::SeqCst);
                            }
                        }
                    }
                    let _ = up_tx.send(got);
                });
                let _ = connected_tx.send(());
                Ok(Box::new(a) as BoxCarrier)
            })
        })
    };

    // The relay behind a real loopback listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = listener.local_addr().unwrap();
    let (accept_tx, accept_rx) = mpsc::channel::<BoxCarrier>(64);
    let accepted = Arc::new(AtomicUsize::new(0));
    let acceptor = tokio::spawn({
        let accepted = accepted.clone();
        async move {
            while let Ok((s, _)) = listener.accept().await {
                let _ = s.set_nodelay(true);
                accepted.fetch_add(1, Ordering::SeqCst);
                if accept_tx.send(Box::new(s)).await.is_err() {
                    return;
                }
            }
        }
    });
    let table = RelayTable::new(
        segue_session::Config::default(),
        Pool::new(8 << 20),
        Box::new(AllowAll),
        9,
    );
    let relay = tokio::spawn(run_relay(table, accept_rx, site, None));

    // Slow carriers: a TCP proxy in front of the relay that moves at most
    // SLOW_CHUNK bytes per SLOW_EVERY each way, over small socket buffers.
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    async fn throttle(
        mut from: tokio::net::tcp::OwnedReadHalf,
        mut to: tokio::net::tcp::OwnedWriteHalf,
    ) {
        let mut buf = vec![0u8; SLOW_CHUNK];
        let mut tick = tokio::time::interval(SLOW_EVERY);
        loop {
            tick.tick().await;
            match from.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to.shutdown().await;
    }
    let proxy = tokio::spawn(async move {
        while let Ok((c, _)) = slow_listener.accept().await {
            let Ok(u) = tokio::net::TcpStream::connect(relay_addr).await else {
                continue;
            };
            let _ = (c.set_nodelay(true), u.set_nodelay(true));
            let (cr, cw) = c.into_split();
            let (ur, uw) = u.into_split();
            tokio::spawn(throttle(cr, uw));
            tokio::spawn(throttle(ur, cw));
        }
    });
    let slow_dials = Arc::new(AtomicUsize::new(0));
    let slow_connector: Connector = {
        let dials = slow_dials.clone();
        Arc::new(move || {
            dials.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                let s = tokio::net::TcpSocket::new_v4()?;
                s.set_recv_buffer_size(4096)?;
                s.set_send_buffer_size(4096)?;
                let s = s.connect(slow_addr).await?;
                let _ = s.set_nodelay(true);
                Ok(Box::new(s) as BoxCarrier)
            })
        })
    };

    // Sample the host's RSS for the whole run.
    let done = Arc::new(AtomicBool::new(false));
    let rss_base = host_rss_kib().expect("ps reports no RSS");
    let rss_peak = Arc::new(AtomicU64::new(rss_base));
    let sampler = std::thread::spawn({
        let (done, rss_peak) = (done.clone(), rss_peak.clone());
        move || {
            while !done.load(Ordering::SeqCst) {
                if let Some(k) = host_rss_kib() {
                    rss_peak.fetch_max(k, Ordering::SeqCst);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    });

    let mut slow = Vec::new();
    for i in 0..SLOW {
        let params = OpenParams {
            ticket: b"ticket".to_vec(),
            kind: Kind::Tcp,
            target: Target::Domain(format!("slow{i}.example"), 443),
            exit_class: 0,
            anchor_node_id: 1,
            instance_hint: 9,
        };
        let s = ClientSession::new(Default::default(), &pool, params, std::time::Instant::now())
            .expect("slow session admitted");
        let (mut app, far) = tokio::io::duplex(64 << 10);
        let client = tokio::spawn(run_client(s, far, slow_connector.clone()));
        slow.push(tokio::spawn(async move {
            let (mut r, mut w) = tokio::io::split(&mut app);
            let up: Vec<u8> = (0..SLOW_UP as u64)
                .map(|x| pattern_byte(x, i as u8 + 1))
                .collect();
            let ((), down) = tokio::join!(
                async {
                    let _ = w.write_all(&up).await;
                    let _ = w.shutdown().await;
                },
                async {
                    let mut down = Vec::new();
                    let _ = r.read_to_end(&mut down).await;
                    down
                }
            );
            (client.await.unwrap(), down)
        }));
    }

    // The healthy flow: TUN → KernelDialer → a direct loopback carrier.
    let dialer = KernelDialer::new(
        Arc::new(LoopbackEngine { relay: relay_addr }),
        vec![Exit {
            name: "la".into(),
            carrier: "relay".into(),
            redundant_carrier: None,
            relay: relay_addr,
            node_id: 1,
            egress_group: String::new(),
        }],
        [(
            "p1".to_string(),
            SegueRoute {
                ticket: b"ticket".to_vec(),
                exit_class: 0,
            },
        )]
        .into(),
        Default::default(),
    )
    .with_pool(pool.clone());
    let mut tun = TunStack::new(Arc::new(rules_proxy_default()), Arc::new(dialer));
    tun.config.shared_pool = Some(pool.clone());
    let mut h = Harness::run(tun);

    // Keep the elastic part spent once the healthy flow is admitted.
    let watch = tokio::spawn({
        let (pool, done) = (pool.clone(), done.clone());
        async move {
            connected_rx.recv().await.expect("healthy site connected");
            let mut hog = Vec::new();
            let (mut peak, mut peak_transport) = (0, 0);
            while !done.load(Ordering::SeqCst) {
                while let Some(g) = Grant::fixed(&pool, BLOCK) {
                    hog.push(g);
                }
                peak = peak.max(pool.used_blocks() + pool.transport_used_blocks());
                peak_transport = peak_transport.max(pool.transport_used_blocks());
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
            (hog.len(), peak, peak_transport)
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    let (cpu0, csw0) = process_cpu();
    let started = Instant::now();
    let down = tokio::time::timeout(
        Duration::from_secs(60),
        raw_transfer(&mut h, CLIENT4, SITE4, UP, &site_got),
    )
    .await
    .expect("healthy TUN flow stalled behind the slow carriers");
    let healthy = started.elapsed();
    let slow_running = slow.iter().filter(|j| !j.is_finished()).count();
    let want_down: Vec<u8> = (0..DOWN).map(|x| pattern_byte(x, 0)).collect();
    assert_eq!(down.len() as u64, DOWN);
    assert!(sha(&down) == sha(&want_down), "TUN download corrupted");
    let up = tokio::time::timeout(Duration::from_secs(10), up_rx.recv())
        .await
        .expect("site never saw the upload end")
        .unwrap();
    let want_up: Vec<u8> = (0..UP as u64).map(|x| pattern_byte(x, 0x5a)).collect();
    assert_eq!(up.len(), UP);
    assert!(sha(&up) == sha(&want_up), "TUN upload corrupted");
    // The slow sessions finish too, with the pool still spent.
    let want_slow_down: Vec<u8> = (0..SLOW_DOWN as u64).map(|x| pattern_byte(x, 3)).collect();
    for (i, j) in slow.into_iter().enumerate() {
        let (reason, d) = tokio::time::timeout(Duration::from_secs(120), j)
            .await
            .expect("slow session never finished")
            .unwrap();
        assert_eq!(reason, CloseReason::Clean, "slow session {i}");
        assert!(
            sha(&d) == sha(&want_slow_down),
            "slow session {i} download corrupted"
        );
    }
    let wall = started.elapsed();
    let (cpu1, csw1) = process_cpu();
    done.store(true, Ordering::SeqCst);
    let (hogged, peak, peak_transport) = watch.await.unwrap();
    sampler.join().unwrap();
    {
        let got = slow_up.lock().unwrap();
        for i in 0..SLOW {
            let want: Vec<u8> = (0..SLOW_UP as u64)
                .map(|x| pattern_byte(x, i as u8 + 1))
                .collect();
            let g = got
                .get(&format!("slow{i}.example"))
                .expect("slow upload missing");
            assert!(sha(g) == sha(&want), "slow session {i} upload corrupted");
        }
    }
    let cpu = cpu1 - cpu0;
    let csw = csw1 - csw0;
    let cpu_share = cpu.as_secs_f64() / wall.as_secs_f64();
    let csw_rate = csw as f64 / wall.as_secs_f64();
    let dials = slow_dials.load(Ordering::SeqCst);
    // Direct carriers: the healthy flow's and the control stream, plus
    // the slow sessions' proxied ones (the proxy dials the relay too).
    let direct = accepted.load(Ordering::SeqCst) - dials;
    let rss_peak = rss_peak.load(Ordering::SeqCst);
    let grew_mib = (rss_peak - rss_base) as f64 * 1024.0 / MIB;
    println!(
        "loopback: healthy {} KiB each way in {healthy:?} ({slow_running} of {SLOW} slow still running), all in {wall:?}; \
         pool {} blocks, {hogged} hogged, peak {peak} ({} elastic), transport peak {peak_transport}/{}; \
         slow dials {dials}, direct carriers {direct}; CPU {cpu:?} ({:.0}% of one core), {csw} voluntary switches ({csw_rate:.0}/s); \
         RSS {:.1} -> {:.1} MiB (+{grew_mib:.1})",
        UP >> 10,
        pool.blocks(),
        pool.limit(Tier::Elastic),
        pool.transport_blocks(),
        cpu_share * 100.0,
        rss_base as f64 * 1024.0 / MIB,
        rss_peak as f64 * 1024.0 / MIB,
    );
    assert!(hogged > 100, "the pool was never spent ({hogged} blocks)");
    assert!(
        slow_running > 0,
        "the slow sessions ended before the healthy flow: no contention"
    );
    assert!(
        peak <= pool.blocks(),
        "peak {peak} of {} blocks",
        pool.blocks()
    );
    assert!(peak_transport <= pool.transport_blocks());
    assert!(dials <= 2 * SLOW, "{dials} dials for {SLOW} slow sessions");
    assert!(
        direct <= 3,
        "{direct} direct carriers: the healthy flow redialled"
    );
    // Mostly waiting on 10 KB/s carriers: a session spinning on a
    // deadline it cannot serve burns a core on its own.
    assert!(
        cpu_share < 0.5,
        "CPU {:.0}% of a core over {wall:?}",
        cpu_share * 100.0
    );
    // A tight loop of timers that fire at once never sleeps, so it shows
    // as CPU, not as switches; this bounds the other kind (a timer that
    // wakes the thread every millisecond or so).
    assert!(csw_rate < 20_000.0, "{csw_rate:.0} wakeups/s");
    assert!(grew_mib < 128.0, "RSS grew {grew_mib:.1} MiB");
    relay.abort();
    acceptor.abort();
    proxy.abort();
}
