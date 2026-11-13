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
    hex, initial_for_test, QUIC_GO_CHATGPT_INITIAL, QUIC_GO_CHATGPT_INITIAL_2,
    RFC9001_CLIENT_INITIAL,
};
use segue_kernel::rules::{Action, Cidr, CidrTable, Matcher, Rule, RuleSet};
use segue_kernel::sniff::client_hello_for_test;
use segue_kernel::socks::{Kernel, SniffSettings};
use segue_kernel::tun::{
    mss_for, Event, FlowKey, Netstack, NetstackConfig, PacketIo, Proto, TunStack, UdpDatagram,
    Verdict, BLOCK,
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
    assert!(b.total < 16 * 1024 * 1024, "{b:?}");
    // The pool, not the flow count, bounds TCP buffering.
    let cfg = NetstackConfig::default();
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
    let h = Harness::run(TunStack::for_kernel(kernel, smart));
    Env { h, dialer, pool }
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

/// §5.2a.2 over TUN: a QUIC Initial's SNI routes the bare-IP flow by name.
#[tokio::test]
async fn tun_quic_sni_dials_by_name() {
    let e = kernel_env(inline(), false, true, false, false);
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
    e.h.send(udp(CLIENT4, dst, &hex(RFC9001_CLIENT_INITIAL)))
        .await;
    assert_eq!(
        udp_dials(&e).await,
        vec![(
            Some("p1".to_string()),
            TargetAddr::Domain("example.com".into()),
            443
        )]
    );
}

/// The AI name of a two-datagram ClientHello (real quic-go capture) is
/// refused: nothing dialled, the flow's next datagram gets ICMP.
#[tokio::test]
async fn tun_quic_ai_sni_split_hello_is_refused() {
    let mut e = kernel_env(inline(), false, true, false, false);
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
    let (a, b) = (hex(QUIC_GO_CHATGPT_INITIAL), hex(QUIC_GO_CHATGPT_INITIAL_2));
    e.h.send(udp(CLIENT4, dst, &a)).await;
    e.h.send(udp(CLIENT4, dst, &b)).await;
    let mut icmp = None;
    for _ in 0..50 {
        e.h.send(udp(CLIENT4, dst, &a)).await;
        if let Ok(Some(p)) =
            tokio::time::timeout(Duration::from_millis(100), e.h.from_stack.recv()).await
        {
            icmp = Some(p);
            break;
        }
    }
    let (t, code, _) = icmpv4(&icmp.expect("ICMP after refusal"));
    assert_eq!((t, code), (3, 13));
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
}

/// A split ClientHello with a non-AI policy: held until the name is known,
/// then dialled once, by that name.
#[tokio::test]
async fn tun_quic_split_hello_held_then_dialled_by_name() {
    let rules = RuleSet::new(Vec::new(), Action::Proxy("p1".into()));
    let e = kernel_env(
        Policy::inline(rules, CidrTable::default()),
        false,
        true,
        false,
        false,
    );
    let dst: SocketAddr = "8.8.8.8:443".parse().unwrap();
    e.h.send(udp(CLIENT4, dst, &hex(QUIC_GO_CHATGPT_INITIAL)))
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty(), "held");
    e.h.send(udp(CLIENT4, dst, &hex(QUIC_GO_CHATGPT_INITIAL_2)))
        .await;
    assert_eq!(
        udp_dials(&e).await,
        vec![(
            Some("p1".to_string()),
            TargetAddr::Domain("chatgpt.com".into()),
            443
        )]
    );
}

/// Unreadable QUIC on UDP/443 is refused at once with ICMP.
#[tokio::test]
async fn tun_unconfirmed_quic_is_refused() {
    let mut e = kernel_env(inline(), false, true, false, false);
    e.h.send(udp(CLIENT4, "8.8.8.8:443".parse().unwrap(), b"\x40short"))
        .await;
    let (t, code, _) = icmpv4(&e.h.next().await);
    assert_eq!((t, code), (3, 13));
    assert!(e.dialer.udp_dials.lock().unwrap().is_empty());
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

/// N7 over TUN: on one UDP tuple, an allowed QUIC connection, then a new
/// Initial (new DCID) naming an AI host. The AI connection's datagrams
/// never reach the flow's outbound; the first connection keeps flowing.
#[tokio::test]
async fn tun_second_quic_connection_on_same_tuple_is_classified() {
    for (dst, first) in [
        // UDP/443, first connection non-AI QUIC.
        ("8.8.8.8:443", hex(RFC9001_CLIENT_INITIAL)),
        // Another port, plain UDP first (routed by IP), then QUIC.
        ("8.8.8.8:8443", b"\x12\x34plain".to_vec()),
    ] {
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
        let dst: SocketAddr = dst.parse().unwrap();
        e.h.send(udp(CLIENT4, dst, &first)).await;
        assert_eq!(udp_sent(&e, 1).await, vec![first.clone()], "{dst}");
        let ai = initial_for_test(&[9; 8], "chatgpt.com");
        e.h.send(udp(CLIENT4, dst, &ai)).await;
        let (a, b) = (hex(QUIC_GO_CHATGPT_INITIAL), hex(QUIC_GO_CHATGPT_INITIAL_2));
        e.h.send(udp(CLIENT4, dst, &a)).await;
        e.h.send(udp(CLIENT4, dst, &b)).await;
        // The first connection still flows.
        let short = b"\x40short header".to_vec();
        e.h.send(udp(CLIENT4, dst, &short)).await;
        let sent = udp_sent(&e, 2).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let sent2 = e.dialer.udp_sent.lock().unwrap().clone();
        assert_eq!(sent, sent2);
        assert_eq!(
            sent,
            vec![first.clone(), short],
            "{dst}: AI Initials not sent"
        );
        assert_eq!(e.dialer.udp_dials.lock().unwrap().len(), 1);
    }
}

// ---------------------------------------------------------------------------
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
            relay: "127.0.0.1:7443".parse().unwrap(),
            node_id: 1,
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
