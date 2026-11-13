//! segue-relay end to end: tickets, SSRF guard, SOCKS5 Home dial, a real
//! segue-session client through the relay to local targets.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use segue_relay::cidr::Cidr;
use segue_relay::config::Config;
use segue_relay::dial::{Resolver, Route};
use segue_relay::guard::{is_forbidden, Guard};
use segue_relay::server::{serve, Relay};
use segue_relay::system_clock;
use segue_relay::ticket::{generate_pkcs8, grant_of, Claims, ExitClass, Signer, TicketAuth};
use segue_session::client::{ClientSession, CloseReason, OpenParams};
use segue_session::codec::{code, Frame, Kind, Open, Resume, Target, VERSION};
use segue_session::driver::{run_client, BoxCarrier, Connector};
use segue_session::pool::Pool;
use segue_session::relay::{Authorizer, RelayEvent, RelayTable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const USER: &str = "sub-node1";
const PASS: &str = "s3cret-pass";

fn now() -> u64 {
    system_clock()()
}

fn claims(device: u64, classes: Vec<ExitClass>) -> Claims {
    let t = now();
    Claims {
        v: 1,
        key_id: 0,
        device_id: device,
        account_id: 1,
        plan: "pro".into(),
        exit_classes: classes,
        ai_anchor_node_id: 0,
        not_before: t - 60,
        not_after: t + 3600,
    }
}

struct Env {
    relay: Arc<Relay>,
    signer: Signer,
    /// Private key the policy bundle is signed with (same format and
    /// verification as the client's `policy.bundle`).
    policy_key: String,
    _dir: TempDir,
}

/// Signed policy bundle in the client's format.
fn bundle(key: &str, version: u64, domains: &[&str], cidrs: &[&str]) -> String {
    let body = serde_json::json!({
        "version": version,
        "expires_at": now() + 3600,
        "ai_domains": domains,
        "ai_cidrs": cidrs,
        "default": {"type": "proxy", "outbound": "overseas"}
    });
    segue_policy::sign(key, 1, body.to_string().as_bytes()).unwrap()
}

/// Revocation file as the sync process writes it.
fn revocation_text(seq: u64, synced_at: u64, devices: &[u64]) -> String {
    let mut s = format!("seq {seq}\nsynced_at {synced_at}\n");
    for d in devices {
        s += &format!("{d}\n");
    }
    s + &format!("end {}\n", devices.len())
}

struct TempDir(std::path::PathBuf);
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn tempdir(tag: &str) -> TempDir {
    static N: AtomicUsize = AtomicUsize::new(0);
    let p = std::env::temp_dir().join(format!(
        "segue-relay-it-{}-{tag}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&p).unwrap();
    TempDir(p)
}

/// `echo.test` / `ai.test` → 127.0.0.1; `rebind.test` → public + private.
fn resolver() -> Resolver {
    Arc::new(|h: String| {
        Box::pin(async move {
            let v: Vec<IpAddr> = match h.as_str() {
                "echo.test" | "ai.test" | "api.ai.test" => vec!["127.0.0.1".parse().unwrap()],
                "rebind.test" => vec![
                    "93.184.216.34".parse().unwrap(),
                    "10.0.0.7".parse().unwrap(),
                ],
                "public.test" => vec!["93.184.216.34".parse().unwrap()],
                _ => return Err(std::io::Error::other("nxdomain")),
            };
            Ok(v)
        })
    })
}

fn env(home_server: &str, failover: bool, extra_ai_cidr: &str) -> Env {
    env_with(
        home_server,
        failover,
        extra_ai_cidr,
        resolver(),
        system_clock(),
    )
}

fn env_with(
    home_server: &str,
    failover: bool,
    extra_ai_cidr: &str,
    resolver: Resolver,
    clock: segue_relay::Clock,
) -> Env {
    let dir = tempdir("cfg");
    let signer = Signer::from_pkcs8(3, &generate_pkcs8()).unwrap();
    let pk = base64::engine::general_purpose::STANDARD.encode(signer.public_key());
    std::fs::write(dir.0.join("line.cred"), format!("{USER}:{PASS}\n")).unwrap();
    std::fs::write(dir.0.join("revoked.txt"), revocation_text(1, now(), &[])).unwrap();
    let (policy_key, policy_pub) = segue_policy::generate_key();
    let cidrs: Vec<&str> = [extra_ai_cidr]
        .into_iter()
        .filter(|c| !c.is_empty())
        .collect();
    std::fs::write(
        dir.0.join("policy.bundle"),
        bundle(&policy_key, 1, &["ai.test"], &cidrs),
    )
    .unwrap();
    let json = format!(
        r#"{{
        "listen": "127.0.0.1:7443",
        "node_id": 1,
        "ticket_keys": [{{"key_id": 3, "public_key": "{pk}"}}],
        "revocation_file": "revoked.txt",
        "policy": {{"public_keys": [{{"key_id": 1, "public_key": "{policy_pub}"}}], "bundle": "policy.bundle"}},
        "home_lines": [{{"id": "L1", "server": "{home_server}", "isp": "x", "credentials_file": "line.cred"}}],
        "home_auto_failover": {failover},
        "limits": {{"line_fail_threshold": 1, "connect_timeout_ms": 2000, "first_frame_timeout_ms": 2000}}
    }}"#
    );
    let cfg = Config::parse_in(&json, &dir.0).unwrap();
    // Targets in these tests live on loopback: open exactly 127.0.0.1.
    let guard = Guard {
        extra_blocked: vec![],
        exceptions: vec![Cidr::parse("127.0.0.1/32").unwrap()],
    };
    let relay = Arc::new(Relay::new(cfg, clock, Some(resolver), Some(guard)).unwrap());
    Env {
        relay,
        signer,
        policy_key,
        _dir: dir,
    }
}

fn auth(e: &Env) -> TicketAuth {
    TicketAuth {
        verifier: e.relay.verifier.clone(),
        revoked: e.relay.revoked.clone(),
        metrics: e.relay.metrics.clone(),
        clock: e.relay.clock.clone(),
    }
}

#[test]
fn ticket_accept_reject_expired_revoked() {
    let e = env("127.0.0.1:1", false, "198.51.100.0/24");
    let a = auth(&e);
    let t = Target::Domain("echo.test".into(), 80);
    let good = e.signer.sign(&claims(42, vec![ExitClass::Overseas]));
    let g = a.open(&good, &t, Kind::Tcp).unwrap();
    assert_eq!((g.device, g.exit_classes), (42, 1));
    // UDP sessions are never offered by this relay.
    assert_eq!(a.open(&good, &t, Kind::Udp), Err(code::EXIT_DENIED));
    // Garbage, tampered, wrong key.
    assert_eq!(a.open(b"nope", &t, Kind::Tcp), Err(code::AUTH));
    let mut bad = good.clone();
    let n = bad.len();
    bad[n - 5] ^= 0x01;
    assert_eq!(a.open(&bad, &t, Kind::Tcp), Err(code::AUTH));
    let other = Signer::from_pkcs8(3, &generate_pkcs8()).unwrap();
    assert_eq!(
        a.open(
            &other.sign(&claims(42, vec![ExitClass::Overseas])),
            &t,
            Kind::Tcp
        ),
        Err(code::AUTH)
    );
    // Expired: OPEN refused; RESUME gets the 1 h grace while the list is fresh.
    let mut c = claims(43, vec![ExitClass::Overseas]);
    c.not_before = now() - 7200;
    c.not_after = now() - 10;
    let exp = e.signer.sign(&c);
    assert_eq!(a.open(&exp, &t, Kind::Tcp), Err(code::EXPIRED));
    assert_eq!(a.resume(&exp), Ok(43));
    c.not_after = now() - 3700;
    assert_eq!(a.resume(&e.signer.sign(&c)), Err(code::EXPIRED));
    // Not yet valid.
    let mut f = claims(44, vec![ExitClass::Overseas]);
    f.not_before = now() + 600;
    f.not_after = now() + 7200;
    assert_eq!(a.open(&e.signer.sign(&f), &t, Kind::Tcp), Err(code::AUTH));
    // Revoked via the list file.
    let rev = e.relay.cfg.revocation_file.clone().unwrap();
    std::fs::write(&rev, revocation_text(2, now(), &[42])).unwrap();
    assert_eq!(e.relay.revoked.reload().unwrap(), vec![42]);
    assert_eq!(a.open(&good, &t, Kind::Tcp), Err(code::REVOKED));
    assert_eq!(a.resume(&good), Err(code::REVOKED));
}

fn open_frame(ticket: Vec<u8>, sid: [u8; 16], secret: [u8; 32]) -> Frame {
    Frame::Open(Open {
        version: VERSION,
        ticket,
        session_id: sid,
        resume_secret: secret,
        attach_gen: 0,
        retry: false,
        anchor_instance_id: 0,
        kind: Kind::Tcp,
        target: Target::Domain("echo.test".into(), 80),
        exit_class: 0,
        first_data: vec![],
    })
}

fn resume_frame(ticket: Vec<u8>, sid: [u8; 16], secret: [u8; 32], gen: u32) -> Frame {
    Frame::Resume(Resume {
        version: VERSION,
        ticket,
        anchor_node_id: 1,
        anchor_instance_id: 0,
        session_id: sid,
        resume_secret: secret,
        attach_gen: gen,
        recv_offset: 0,
        max_offset: 16 * 1024,
    })
}

#[test]
fn resume_with_other_devices_ticket_is_rejected() {
    let e = env("127.0.0.1:1", false, "198.51.100.0/24");
    let mut table = RelayTable::new(
        Default::default(),
        Pool::new(8 << 20),
        Box::new(auth(&e)),
        77,
    );
    let t = Instant::now();
    let (sid, secret) = ([1u8; 16], [2u8; 32]);
    table.add_carrier(1);
    table.on_frame(
        1,
        open_frame(
            e.signer.sign(&claims(10, vec![ExitClass::Overseas])),
            sid,
            secret,
        ),
        t,
    );
    while table.take_event().is_some() {}
    table.connect_done(&sid, Ok(()), t);
    while table.poll_transmit(1, t).is_some() {}
    // An expired-beyond-grace ticket of the owner is refused too.
    let mut old = claims(10, vec![ExitClass::Overseas]);
    old.not_before = now() - 9000;
    old.not_after = now() - 3700;
    table.add_carrier(9);
    table.on_frame(9, resume_frame(e.signer.sign(&old), sid, secret, 1), t);
    match table.poll_transmit(9, t) {
        Some(Frame::Reject(r)) => assert_eq!(r.code, code::EXPIRED),
        f => panic!("expected REJECT(expired), got {f:?}"),
    }
    // Device 11's valid ticket cannot take over device 10's session.
    table.add_carrier(2);
    table.on_frame(
        2,
        resume_frame(
            e.signer.sign(&claims(11, vec![ExitClass::Overseas])),
            sid,
            secret,
            1,
        ),
        t,
    );
    match table.poll_transmit(2, t) {
        Some(Frame::Reject(r)) => assert_eq!(r.code, code::AUTH),
        f => panic!("expected REJECT(auth), got {f:?}"),
    }
    // The owner's ticket resumes.
    table.add_carrier(3);
    table.on_frame(
        3,
        resume_frame(
            e.signer.sign(&claims(10, vec![ExitClass::Overseas])),
            sid,
            secret,
            2,
        ),
        t,
    );
    assert!(matches!(table.poll_transmit(3, t), Some(Frame::Resumed(_))));
}

#[test]
fn ssrf_guard_table() {
    let blocked = [
        "127.0.0.1",
        "127.255.255.254",
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.1.1",
        "100.64.0.1",
        "100.127.255.255",
        "169.254.169.254",
        "169.254.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fc00::1",
        "fd00:ec2::254",
        "ff02::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "64:ff9b::a00:1",
        "2002:7f00:1::",
        "2001:db8::1",
    ];
    let allowed = [
        "93.184.216.34",
        "1.1.1.1",
        "8.8.8.8",
        "172.32.0.1",
        "100.128.0.1",
        "2606:4700::1111",
        "::ffff:1.1.1.1",
    ];
    for s in blocked {
        assert!(is_forbidden(s.parse().unwrap()), "{s} should be blocked");
    }
    for s in allowed {
        assert!(!is_forbidden(s.parse().unwrap()), "{s} should be allowed");
    }
    let g = Guard::new(vec![Cidr::parse("203.0.114.0/24").unwrap()]);
    assert!(
        !g.allows("203.0.114.9".parse().unwrap()),
        "node's own range"
    );
    assert!(g.allows("1.1.1.1".parse().unwrap()));
}

#[tokio::test]
async fn routing_classifies_independently() {
    let e = env("127.0.0.1:1", false, "93.184.216.0/24");
    let d = &e.relay.dialer;
    let g1 = grant_of(&claims(1, vec![ExitClass::Overseas, ExitClass::Ai]));
    let g2 = grant_of(&claims(2, vec![ExitClass::Overseas]));
    let lo: SocketAddr = "127.0.0.1:80".parse().unwrap();
    // Overseas target with no hint.
    assert_eq!(
        d.route(&g1, &Target::Domain("echo.test".into(), 80), 0)
            .await,
        Ok(Route::Overseas(vec![lo]))
    );
    // An EXIT_AI hint the relay's policy cannot confirm is refused, never
    // downgraded to the data-centre exit (review r4 #1).
    assert_eq!(
        d.route(&g1, &Target::Domain("echo.test".into(), 80), 1)
            .await,
        Err(code::TARGET_DENIED)
    );
    // A hinted AI target the policy confirms goes Home.
    assert_eq!(
        d.route(&g1, &Target::Domain("ai.test".into(), 80), 1).await,
        Ok(Route::Home(lo))
    );
    // AI domain with an overseas hint → Home.
    assert_eq!(
        d.route(&g1, &Target::Domain("api.ai.test".into(), 80), 0)
            .await,
        Ok(Route::Home(lo))
    );
    // A name that resolves into the AI CIDR is AI too.
    let pubip: SocketAddr = "93.184.216.34:443".parse().unwrap();
    assert_eq!(
        d.route(&g1, &Target::Domain("public.test".into(), 443), 0)
            .await,
        Ok(Route::Home(pubip))
    );
    assert_eq!(
        d.route(&g1, &Target::Ip(pubip), 0).await,
        Ok(Route::Home(pubip))
    );
    // No AI grant → exit_denied, never direct.
    assert_eq!(
        d.route(&g2, &Target::Ip(pubip), 0).await,
        Err(code::EXIT_DENIED)
    );
    assert_eq!(
        d.route(&g2, &Target::Domain("ai.test".into(), 80), 0).await,
        Err(code::EXIT_DENIED)
    );
    // SSRF: literal and rebinding names refused.
    assert_eq!(
        d.route(&g2, &Target::Ip("10.0.0.1:80".parse().unwrap()), 0)
            .await,
        Err(code::TARGET_DENIED)
    );
    assert_eq!(
        d.route(
            &g2,
            &Target::Ip("[::ffff:169.254.169.254]:80".parse().unwrap()),
            0
        )
        .await,
        Err(code::TARGET_DENIED)
    );
    assert_eq!(
        d.route(&g2, &Target::Domain("rebind.test".into(), 80), 0)
            .await,
        Err(code::TARGET_DENIED)
    );
    // Rebinding into private space is refused for AI targets too.
    assert_eq!(
        d.route(&g1, &Target::Domain("rebind.test".into(), 80), 1)
            .await,
        Err(code::TARGET_DENIED)
    );
    assert_eq!(
        d.route(&g2, &Target::Domain("nx.test".into(), 80), 0).await,
        Err(code::DNS_FAILURE)
    );
    // A grant is per OPEN: device 1's AI grant does not leak into a
    // session opened with an overseas-only ticket for the same device.
    let g1_overseas = grant_of(&claims(1, vec![ExitClass::Overseas]));
    assert_eq!(
        d.route(&g1_overseas, &Target::Ip(pubip), 0).await,
        Err(code::EXIT_DENIED)
    );
    assert_eq!(
        d.route(&g1, &Target::Ip(pubip), 0).await,
        Ok(Route::Home(pubip))
    );
    let m = e.relay.metrics.render();
    assert!(!m.contains("segue_relay_reclassified 0\n"), "{m}");
}

/// Review r4 #2: the grant travels with each OPEN's own connect request.
/// Two sessions of one device opened with different tickets keep their own
/// exit classes; nothing is looked up per device later.
#[test]
fn grant_is_bound_to_each_open() {
    let e = env("127.0.0.1:1", false, "");
    let mut table = RelayTable::new(
        Default::default(),
        Pool::new(8 << 20),
        Box::new(auth(&e)),
        77,
    );
    let t = Instant::now();
    let both = e
        .signer
        .sign(&claims(10, vec![ExitClass::Overseas, ExitClass::Ai]));
    let overseas = e.signer.sign(&claims(10, vec![ExitClass::Overseas]));
    table.add_carrier(1);
    table.on_frame(1, open_frame(both, [1; 16], [2; 32]), t);
    table.add_carrier(2);
    table.on_frame(2, open_frame(overseas, [3; 16], [4; 32]), t);
    let mut grants = Vec::new();
    while let Some(ev) = table.take_event() {
        if let RelayEvent::Connect {
            session_id, grant, ..
        } = ev
        {
            grants.push((session_id, grant));
        }
    }
    grants.sort_by_key(|g| g.0);
    assert_eq!(grants.len(), 2);
    assert_eq!((grants[0].1.device, grants[0].1.exit_classes), (10, 3));
    assert_eq!((grants[1].1.device, grants[1].1.exit_classes), (10, 1));
}

/// Review r4 #1: the AI set comes from the signed policy bundle; it hot
/// reloads, and forged or rolled-back bundles keep the last good one.
#[tokio::test]
async fn policy_bundle_reload_forgery_rollback() {
    let e = env("127.0.0.1:1", false, "");
    let d = &e.relay.dialer;
    let g = grant_of(&claims(1, vec![ExitClass::Overseas, ExitClass::Ai]));
    let lo: SocketAddr = "127.0.0.1:80".parse().unwrap();
    let echo_ai = || Target::Domain("echo.test".into(), 80);
    assert_eq!(e.relay.ai.version(), Some(1));
    assert_eq!(d.route(&g, &echo_ai(), 1).await, Err(code::TARGET_DENIED));
    let path = e.relay.cfg.policy_bundle.clone();
    std::fs::write(
        &path,
        bundle(&e.policy_key, 2, &["ai.test", "echo.test"], &[]),
    )
    .unwrap();
    e.relay.reload_policy();
    assert_eq!(e.relay.ai.version(), Some(2));
    assert_eq!(d.route(&g, &echo_ai(), 1).await, Ok(Route::Home(lo)));
    // Forged (other key) and rolled back (lower version): ignored.
    let (other, _) = segue_policy::generate_key();
    std::fs::write(&path, bundle(&other, 9, &[], &[])).unwrap();
    e.relay.reload_policy();
    std::fs::write(
        &path,
        bundle(&e.policy_key, 1, &["ai.test"], &["10.9.9.0/24"]),
    )
    .unwrap();
    e.relay.reload_policy();
    assert_eq!(e.relay.ai.version(), Some(2));
    assert_eq!(d.route(&g, &echo_ai(), 1).await, Ok(Route::Home(lo)));
}

/// Review r5 N1: the policy is read after the DNS wait. A resolver held
/// open while v2 (which makes the name AI) is installed: the connect goes
/// Home on v2, not Overseas on the v1 snapshot. A bundle expiring during the
/// wait refuses the connect.
#[tokio::test]
async fn policy_change_during_dns_wait_applies() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let gate = Arc::new(tokio::sync::Notify::new());
    let (en, ga) = (entered.clone(), gate.clone());
    let skew = Arc::new(AtomicUsize::new(0));
    let sk = skew.clone();
    let res: Resolver = Arc::new(move |h: String| {
        let (en, ga) = (en.clone(), ga.clone());
        Box::pin(async move {
            if h == "slow.test" {
                en.notify_one();
                ga.notified().await;
            }
            Ok(vec!["93.184.216.34".parse().unwrap()])
        })
    });
    let clock: segue_relay::Clock = Arc::new(move || now() + sk.load(Ordering::SeqCst) as u64);
    let e = env_with("127.0.0.1:1", false, "", res, clock);
    let g = grant_of(&claims(1, vec![ExitClass::Overseas, ExitClass::Ai]));
    let ip: SocketAddr = "93.184.216.34:443".parse().unwrap();
    let slow = || Target::Domain("slow.test".into(), 443);
    let spawn = |relay: Arc<Relay>, g: segue_session::relay::Grant| {
        tokio::spawn(async move { relay.dialer.route(&g, &slow(), 0).await })
    };

    // v1: slow.test is plain overseas.
    let t = spawn(e.relay.clone(), g.clone());
    entered.notified().await;
    std::fs::write(
        &e.relay.cfg.policy_bundle,
        bundle(&e.policy_key, 2, &["ai.test", "slow.test"], &[]),
    )
    .unwrap();
    e.relay.reload_policy();
    assert_eq!(e.relay.ai.version(), Some(2));
    gate.notify_one();
    assert_eq!(
        t.await.unwrap(),
        Ok(Route::Home(ip)),
        "stale v1 snapshot used"
    );

    // The last bundle expires while the name resolves.
    let t = spawn(e.relay.clone(), g.clone());
    entered.notified().await;
    skew.store(7200, Ordering::SeqCst);
    gate.notify_one();
    assert_eq!(t.await.unwrap(), Err(code::TARGET_DENIED));
}

/// Review r6 R1: the policy is checked again before every further connect
/// attempt. `flip.test` resolves to [::1, 127.0.0.1]; nothing listens on
/// [::1] (refused), an echo server on 127.0.0.1. While the first address
/// fails, v2 makes the name AI (or the bundle expires): the second address
/// must not be dialed overseas on the stale Route.
///
/// The hook is the relay clock: the dialer reads it once per policy check
/// (before DNS, after DNS, then before each further attempt), so its third
/// read is the one after the first failed attempt.
#[tokio::test]
async fn policy_change_between_connect_attempts_applies() {
    use segue_session::driver::SiteRequest;
    for expire in [false, true] {
        let (echo_addr, echo_n) = echo().await;
        let res: Resolver = Arc::new(|_h: String| {
            Box::pin(async move { Ok(vec!["::1".parse().unwrap(), "127.0.0.1".parse().unwrap()]) })
        });
        let e = env("127.0.0.1:1", false, "");
        let reads = Arc::new(AtomicUsize::new(0));
        let ai = Arc::new(std::sync::OnceLock::<Arc<segue_relay::policy::AiPolicy>>::new());
        let v2 = bundle(&e.policy_key, 2, &["ai.test", "flip.test"], &[]).into_bytes();
        let (rd, ai2) = (reads.clone(), ai.clone());
        let clock: segue_relay::Clock = Arc::new(move || {
            let t = now();
            if rd.fetch_add(1, Ordering::SeqCst) < 2 {
                return t;
            }
            if expire {
                return t + 7200;
            }
            if let Some(p) = ai2.get() {
                let _ = p.install(&v2, t);
            }
            t
        });
        let guard = Guard {
            extra_blocked: vec![],
            exceptions: vec![
                Cidr::parse("127.0.0.1/32").unwrap(),
                Cidr::parse("::1/128").unwrap(),
            ],
        };
        let r = Relay::new(e.relay.cfg.clone(), clock, Some(res), Some(guard)).unwrap();
        let _ = ai.set(r.ai.clone());
        reads.store(0, Ordering::SeqCst);
        let got = r
            .dialer
            .connect(SiteRequest {
                session_id: [7; 16],
                grant: grant_of(&claims(1, vec![ExitClass::Overseas, ExitClass::Ai])),
                target: Target::Domain("flip.test".into(), echo_addr.port()),
                kind: Kind::Tcp,
                exit_class: 0,
            })
            .await;
        let code = got
            .err()
            .map(|e| segue_session::driver::SiteError::code_of(&e));
        assert_eq!(
            echo_n.load(Ordering::SeqCst),
            0,
            "dialed overseas on a stale route (expire={expire})"
        );
        assert!(reads.load(Ordering::SeqCst) >= 3, "policy not re-read");
        let want = if expire {
            code::TARGET_DENIED
        } else {
            code::HOME_UNAVAILABLE
        };
        assert_eq!(code, Some(want), "expire={expire}");
    }
}

/// Review r5 N2: the rollback floor survives a restart. v2 accepted, the
/// file replaced by a valid v1 while the relay is down: the new relay
/// keeps v2's AI set.
#[tokio::test]
async fn policy_rollback_refused_after_restart() {
    let e = env("127.0.0.1:1", false, "");
    let path = e.relay.cfg.policy_bundle.clone();
    std::fs::write(
        &path,
        bundle(&e.policy_key, 2, &["ai.test", "echo.test"], &[]),
    )
    .unwrap();
    e.relay.reload_policy();
    assert_eq!(e.relay.ai.version(), Some(2));
    std::fs::write(&path, bundle(&e.policy_key, 1, &["ai.test"], &[])).unwrap();
    let guard = Guard {
        extra_blocked: vec![],
        exceptions: vec![Cidr::parse("127.0.0.1/32").unwrap()],
    };
    let r = Relay::new(
        e.relay.cfg.clone(),
        system_clock(),
        Some(resolver()),
        Some(guard),
    )
    .unwrap();
    assert_eq!(r.ai.version(), Some(2), "restart accepted rollback to v1");
    let g = grant_of(&claims(1, vec![ExitClass::Overseas, ExitClass::Ai]));
    let lo: SocketAddr = "127.0.0.1:80".parse().unwrap();
    assert_eq!(
        r.dialer
            .route(&g, &Target::Domain("echo.test".into(), 80), 0)
            .await,
        Ok(Route::Home(lo))
    );
}

/// Review r6 R3: the accepted revocation state recorded seq 10 with device
/// 42; it is now corrupt and the input file is a complete, valid seq 9
/// without 42. The relay refuses to start instead of starting from an
/// empty floor and taking seq 9 (which would un-revoke 42).
#[test]
fn corrupt_revocation_state_refuses_start() {
    let e = env("127.0.0.1:1", false, "");
    let cfg = e.relay.cfg.clone();
    let state = cfg.revocation_state.clone().expect("state path");
    std::fs::write(
        cfg.revocation_file.as_ref().unwrap(),
        revocation_text(10, now(), &[42]),
    )
    .unwrap();
    e.relay.revoked.reload().unwrap();
    let full = std::fs::read_to_string(&state).unwrap();
    assert!(full.contains("seq 10"));
    std::fs::write(&state, &full[..full.len() - 3]).unwrap();
    std::fs::write(
        cfg.revocation_file.as_ref().unwrap(),
        revocation_text(9, now(), &[]),
    )
    .unwrap();
    let r = Relay::new(cfg, system_clock(), Some(resolver()), None);
    let err = r.err().expect("started over a corrupt revocation state");
    assert!(err.contains("revocation state"), "{err}");
}

/// Review r4 #1: with no usable bundle the relay cannot confirm anything
/// and refuses every target (fail closed), AI-hinted or not.
#[tokio::test]
async fn no_policy_bundle_fails_closed() {
    let e = env("127.0.0.1:1", false, "");
    std::fs::write(e.relay.cfg.policy_bundle.clone(), "garbage").unwrap();
    // A first start: no accepted state from an earlier run either (with
    // one, its unexpired bundle stays in force, review r5 N2).
    std::fs::remove_file(&e.relay.cfg.policy_state).unwrap();
    let cfg = e.relay.cfg.clone();
    let guard = Guard {
        extra_blocked: vec![],
        exceptions: vec![Cidr::parse("127.0.0.1/32").unwrap()],
    };
    let r = Relay::new(cfg, system_clock(), Some(resolver()), Some(guard)).unwrap();
    assert_eq!(r.ai.version(), None);
    let g = grant_of(&claims(1, vec![ExitClass::Overseas, ExitClass::Ai]));
    for hint in [0, 1] {
        assert_eq!(
            r.dialer
                .route(&g, &Target::Domain("ai.test".into(), 80), hint)
                .await,
            Err(code::TARGET_DENIED)
        );
        assert_eq!(
            r.dialer
                .route(&g, &Target::Domain("echo.test".into(), 80), hint)
                .await,
            Err(code::TARGET_DENIED)
        );
    }
    assert!(r
        .metrics
        .render()
        .contains("segue_relay_policy_unavailable 4\n"));
}

/// Review r4 #8: the sync process stops; the file stays readable and the
/// relay keeps re-reading it, but its own `synced_at` ages past 5 min, so
/// expired tickets lose the RESUME grace.
#[test]
fn stale_revocation_file_ends_resume_grace() {
    let e = env("127.0.0.1:1", false, "");
    let skew = Arc::new(AtomicUsize::new(0));
    let sk = skew.clone();
    let mut a = auth(&e);
    a.clock = Arc::new(move || now() + sk.load(Ordering::SeqCst) as u64);
    let mut c = claims(43, vec![ExitClass::Overseas]);
    c.not_before = now() - 7200;
    c.not_after = now() + 10;
    let exp = e.signer.sign(&c);
    // Ticket expires 10 s from now; the file was just synced.
    skew.store(60, Ordering::SeqCst);
    assert_eq!(a.resume(&exp), Ok(43));
    // The sync process dies: the file stays readable and is re-read every
    // poll, but six minutes later its synced_at is stale.
    skew.store(360, Ordering::SeqCst);
    for _ in 0..3 {
        e.relay.revoked.reload().unwrap();
        assert_eq!(a.resume(&exp), Err(code::EXPIRED));
    }
    // Rewriting the same stale content (touching it) does not help, and a
    // file moving synced_at backwards is refused.
    let rev = e.relay.cfg.revocation_file.clone().unwrap();
    let text = std::fs::read_to_string(&rev).unwrap();
    std::fs::write(&rev, format!("{text}# touched\n")).unwrap();
    e.relay.revoked.reload().unwrap();
    assert_eq!(a.resume(&exp), Err(code::EXPIRED));
    std::fs::write(&rev, revocation_text(9, now() - 1000, &[])).unwrap();
    assert!(e.relay.revoked.reload().is_err());
    // A real sync brings the grace back.
    std::fs::write(&rev, revocation_text(9, now() + 360, &[])).unwrap();
    e.relay.revoked.reload().unwrap();
    assert_eq!(a.resume(&exp), Ok(43));
}

/// Review r4 #13: one byte at a time does not extend the first-frame
/// deadline; the carrier is closed before its OPEN completes.
#[tokio::test]
async fn first_frame_slowloris_is_cut() {
    let e = env("127.0.0.1:1", false, "");
    let (addr, stop, _h) = start(&e).await;
    let mut bytes = Vec::new();
    open_frame(
        e.signer.sign(&claims(5, vec![ExitClass::Overseas])),
        [7; 16],
        [8; 32],
    )
    .encode(&mut bytes);
    assert!(bytes.len() > 60);
    let mut s = TcpStream::connect(addr).await.unwrap();
    let t0 = Instant::now();
    let mut cut = false;
    for b in &bytes {
        if s.write_all(&[*b]).await.is_err() {
            cut = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        if t0.elapsed() > Duration::from_secs(5) {
            break;
        }
    }
    if !cut {
        let mut buf = [0u8; 64];
        let r = tokio::time::timeout(Duration::from_secs(2), s.read(&mut buf)).await;
        assert!(
            matches!(r, Ok(Ok(0)) | Ok(Err(_))),
            "carrier still open: {r:?}"
        );
    }
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "deadline not enforced"
    );
    let m = e.relay.metrics.render();
    assert!(
        m.contains("segue_relay_carriers_first_frame_timeout 1\n"),
        "{m}"
    );
    assert!(m.contains("segue_relay_carriers_accepted 0\n"), "{m}");
    let _ = stop.send(true);
}

/// Echo server; counts accepted connections.
async fn echo() -> (SocketAddr, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            n2.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
                let _ = w.shutdown().await;
            });
        }
    });
    (a, n)
}

/// Minimal SOCKS5 server requiring RFC 1929 auth; records CONNECT targets.
async fn socks_server() -> (SocketAddr, Arc<Mutex<Vec<SocketAddr>>>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let seen = seen2.clone();
            tokio::spawn(async move {
                let mut g = [0u8; 3];
                s.read_exact(&mut g).await.unwrap();
                assert_eq!(g, [5, 1, 2], "offers user/pass only");
                s.write_all(&[5, 2]).await.unwrap();
                let mut h = [0u8; 2];
                s.read_exact(&mut h).await.unwrap();
                let mut u = vec![0u8; h[1] as usize];
                s.read_exact(&mut u).await.unwrap();
                let mut pl = [0u8; 1];
                s.read_exact(&mut pl).await.unwrap();
                let mut p = vec![0u8; pl[0] as usize];
                s.read_exact(&mut p).await.unwrap();
                let ok = u == USER.as_bytes() && p == PASS.as_bytes();
                s.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                if !ok {
                    return;
                }
                let mut req = [0u8; 4];
                if s.read_exact(&mut req).await.is_err() {
                    return; // probe: auth only
                }
                assert_eq!(&req[..3], &[5, 1, 0]);
                assert_eq!(req[3], 1, "relay sends IPv4 only, never a domain");
                let mut ip = [0u8; 6];
                s.read_exact(&mut ip).await.unwrap();
                let t = SocketAddr::from((
                    [ip[0], ip[1], ip[2], ip[3]],
                    u16::from_be_bytes([ip[4], ip[5]]),
                ));
                seen.lock().unwrap().push(t);
                match TcpStream::connect(t).await {
                    Ok(mut up) => {
                        s.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                        let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                    }
                    Err(_) => {
                        let _ = s.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
                    }
                }
            });
        }
    });
    (a, seen)
}

async fn start(
    e: &Env,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = l.local_addr().unwrap();
    let (tx, rx) = tokio::sync::watch::channel(false);
    let h = tokio::spawn(serve(e.relay.clone(), l, rx));
    (a, tx, h)
}

/// One client session through the relay; returns (downlink, close reason).
async fn client(
    relay: SocketAddr,
    ticket: Vec<u8>,
    target: Target,
    hint: u8,
    up: &[u8],
) -> (Vec<u8>, CloseReason) {
    let params = OpenParams {
        ticket,
        kind: Kind::Tcp,
        target,
        exit_class: hint,
        anchor_node_id: 1,
        instance_hint: 0,
    };
    let pool = Pool::new(8 << 20);
    let s = ClientSession::new(Default::default(), &pool, params, Instant::now()).unwrap();
    let connector: Connector = Arc::new(move || {
        Box::pin(async move { Ok(Box::new(TcpStream::connect(relay).await?) as BoxCarrier) })
    });
    let (app, far) = tokio::io::duplex(64 << 10);
    let c = tokio::spawn(run_client(s, far, connector));
    let (mut r, mut w) = tokio::io::split(app);
    let up = up.to_vec();
    tokio::spawn(async move {
        let _ = w.write_all(&up).await;
        let _ = w.shutdown().await;
    });
    let mut down = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), r.read_to_end(&mut down)).await;
    let reason = tokio::time::timeout(Duration::from_secs(10), c)
        .await
        .expect("client ended")
        .unwrap();
    (down, reason)
}

fn payload(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + (i >> 8)) as u8).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_through_relay_overseas_echo() {
    let e = env("127.0.0.1:1", false, "198.51.100.0/24");
    let (echo_addr, _) = echo().await;
    let (ra, stop, h) = start(&e).await;
    let t = e.signer.sign(&claims(5, vec![ExitClass::Overseas]));
    let up = payload(300_000);
    let (down, reason) = client(
        ra,
        t.clone(),
        Target::Domain("echo.test".into(), echo_addr.port()),
        0,
        &up,
    )
    .await;
    assert_eq!(reason, CloseReason::Clean);
    assert_eq!(down.len(), up.len());
    assert!(down == up);
    // Private target through a real relay: refused.
    let (_, reason) = client(
        ra,
        t.clone(),
        Target::Ip("10.0.0.1:80".parse().unwrap()),
        0,
        b"x",
    )
    .await;
    assert_eq!(reason, CloseReason::Reset(code::TARGET_DENIED));
    // Bad ticket.
    let (_, reason) = client(
        ra,
        b"SGT1.x.y".to_vec(),
        Target::Domain("echo.test".into(), echo_addr.port()),
        0,
        b"x",
    )
    .await;
    assert_eq!(reason, CloseReason::Reset(code::AUTH));
    let m = e.relay.metrics.render();
    assert!(m.contains("segue_relay_connects_overseas 1"), "{m}");
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_through_relay_home_socks() {
    let (socks, seen) = socks_server().await;
    let e = env(&socks.to_string(), false, "198.51.100.0/24");
    let (echo_addr, echo_n) = echo().await;
    let (ra, stop, h) = start(&e).await;
    let t = e
        .signer
        .sign(&claims(6, vec![ExitClass::Overseas, ExitClass::Ai]));
    let up = payload(100_000);
    // Hint says overseas; the relay classifies ai.test as AI → Home.
    let (down, reason) = client(
        ra,
        t,
        Target::Domain("ai.test".into(), echo_addr.port()),
        0,
        &up,
    )
    .await;
    assert_eq!(reason, CloseReason::Clean);
    assert!(down == up);
    assert_eq!(
        *seen.lock().unwrap(),
        vec![echo_addr],
        "CONNECT by resolved IP"
    );
    assert_eq!(echo_n.load(Ordering::SeqCst), 1);
    assert_eq!(e.relay.home.units("L1"), 1);
    let m = e.relay.metrics.render();
    assert!(m.contains("segue_relay_connects_home 1"), "{m}");
    assert!(!m.contains(PASS) && !m.contains(USER));
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn home_failure_is_refused_never_direct() {
    // Gateway port with nothing listening.
    let dead = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let e = env(&dead.to_string(), false, "198.51.100.0/24");
    let (echo_addr, echo_n) = echo().await;
    let (ra, stop, h) = start(&e).await;
    let t = e
        .signer
        .sign(&claims(7, vec![ExitClass::Overseas, ExitClass::Ai]));
    for _ in 0..2 {
        let (down, reason) = client(
            ra,
            t.clone(),
            Target::Domain("ai.test".into(), echo_addr.port()),
            1,
            b"hello",
        )
        .await;
        // OPEN was accepted and the site connect failed: the relay RSTs
        // the session with home_unavailable (never dials direct).
        assert!(
            matches!(
                reason,
                CloseReason::Refused(code::HOME_UNAVAILABLE)
                    | CloseReason::Reset(code::HOME_UNAVAILABLE)
            ),
            "{reason:?}"
        );
        assert!(down.is_empty());
    }
    assert_eq!(
        echo_n.load(Ordering::SeqCst),
        0,
        "AI target must never be dialed direct"
    );
    assert_eq!(
        e.relay.home.state("L1"),
        Some(segue_relay::home::LineState::Down)
    );
    let m = e.relay.metrics.render();
    assert!(m.contains("segue_relay_home_alerts 1"), "{m}");
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revocation_resets_live_sessions() {
    let e = env("127.0.0.1:1", false, "198.51.100.0/24");
    // Target that never answers: the session stays open.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let held = Arc::new(Mutex::new(Vec::new()));
    let held2 = held.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            held2.lock().unwrap().push(s);
        }
    });
    let (ra, stop, h) = start(&e).await;
    let t = e.signer.sign(&claims(8, vec![ExitClass::Overseas]));
    let params = OpenParams {
        ticket: t,
        kind: Kind::Tcp,
        target: Target::Domain("echo.test".into(), port),
        exit_class: 0,
        anchor_node_id: 1,
        instance_hint: 0,
    };
    let pool = Pool::new(8 << 20);
    let s = ClientSession::new(Default::default(), &pool, params, Instant::now()).unwrap();
    let connector: Connector = Arc::new(move || {
        Box::pin(async move { Ok(Box::new(TcpStream::connect(ra).await?) as BoxCarrier) })
    });
    let (_app, far) = tokio::io::duplex(64 << 10);
    let c = tokio::spawn(run_client(s, far, connector));
    for _ in 0..100 {
        if !held.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(held.lock().unwrap().len(), 1, "site connected");
    std::fs::write(
        e.relay.cfg.revocation_file.clone().unwrap(),
        revocation_text(2, now(), &[8]),
    )
    .unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(15), c)
        .await
        .expect("reset in time")
        .unwrap();
    assert_eq!(reason, CloseReason::Reset(code::REVOKED));
    let _ = stop.send(true);
    tokio::time::timeout(Duration::from_secs(10), h)
        .await
        .unwrap()
        .unwrap();
}

/// Review r6 (server.rs task ownership): cancelling `serve` (dropping or
/// aborting its future, as a hot restart or an embedder does) must take its
/// tasks with it. A live session's site socket and a carrier still in its
/// first-frame wait are closed at once; before, the driver and the
/// per-accept tasks ran on detached, holding both open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelling_serve_stops_its_tasks() {
    let e = env("127.0.0.1:1", false, "198.51.100.0/24");
    // A site that holds its connection and reports when it is closed.
    let site = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let site_port = site.local_addr().unwrap().port();
    let (closed_tx, mut closed_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = site.accept().await {
            let tx = closed_tx.clone();
            tokio::spawn(async move {
                let mut b = [0u8; 1024];
                while let Ok(n) = s.read(&mut b).await {
                    if n == 0 {
                        break;
                    }
                }
                let _ = tx.send(());
            });
        }
    });
    let (ra, _stop, h) = start(&e).await;
    let params = OpenParams {
        ticket: e.signer.sign(&claims(5, vec![ExitClass::Overseas])),
        kind: Kind::Tcp,
        target: Target::Domain("echo.test".into(), site_port),
        exit_class: 0,
        anchor_node_id: 1,
        instance_hint: 0,
    };
    let pool = Pool::new(8 << 20);
    let s = ClientSession::new(Default::default(), &pool, params, Instant::now()).unwrap();
    let connector: Connector = Arc::new(move || {
        Box::pin(async move { Ok(Box::new(TcpStream::connect(ra).await?) as BoxCarrier) })
    });
    let (mut app, far) = tokio::io::duplex(64 << 10);
    let client = tokio::spawn(run_client(s, far, connector));
    app.write_all(b"hello").await.unwrap();
    // A carrier that never sends its first frame.
    let mut idle = TcpStream::connect(ra).await.unwrap();
    // Wait for the site connection to be up, then cancel serve.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(closed_rx.try_recv().is_err(), "site closed early");
    h.abort();
    let _ = h.await;
    tokio::time::timeout(Duration::from_secs(3), closed_rx.recv())
        .await
        .expect("site socket outlived the cancelled serve");
    let mut b = [0u8; 16];
    let r = tokio::time::timeout(Duration::from_secs(3), idle.read(&mut b)).await;
    assert!(
        matches!(r, Ok(Ok(0)) | Ok(Err(_))),
        "first-frame task outlived the cancelled serve: {r:?}"
    );
    client.abort();
}

/// Review r7 #9: the upload drain bounds come from the relay config
/// (`limits.site_flush_idle_secs` / `site_flush_max_secs`) into every
/// session table, with the session defaults when unset; nonsense is
/// refused.
#[test]
fn site_flush_bounds_are_configurable() {
    let e = env("127.0.0.1:1", false, "");
    let d = segue_session::Timing::default();
    let t = e.relay.table();
    assert_eq!(t.timing().site_flush_idle, d.site_flush_idle);
    assert_eq!(t.timing().site_flush_max, d.site_flush_max);

    let pk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let (_, policy_pub) = segue_policy::generate_key();
    let dir = tempdir("flush");
    let json = |limits: &str| {
        format!(
            r#"{{
            "listen": "127.0.0.1:7443",
            "node_id": 1,
            "ticket_keys": [{{"key_id": 3, "public_key": "{pk}"}}],
            "policy": {{"public_keys": [{{"key_id": 1, "public_key": "{policy_pub}"}}], "bundle": "policy.bundle"}},
            "limits": {{{limits}}}
        }}"#
        )
    };
    let cfg = Config::parse_in(
        &json(r#""site_flush_idle_secs": 5, "site_flush_max_secs": 40"#),
        &dir.0,
    )
    .unwrap();
    assert_eq!(cfg.limits.site_flush_idle, Duration::from_secs(5));
    assert_eq!(cfg.limits.site_flush_max, Duration::from_secs(40));
    let relay = Relay::new(cfg, system_clock(), Some(resolver()), None).unwrap();
    let t = relay.table();
    assert_eq!(t.timing().site_flush_idle, Duration::from_secs(5));
    assert_eq!(t.timing().site_flush_max, Duration::from_secs(40));
    for bad in [
        r#""site_flush_idle_secs": 0"#,
        r#""site_flush_idle_secs": 50, "site_flush_max_secs": 40"#,
    ] {
        assert!(Config::parse_in(&json(bad), &dir.0).is_err(), "{bad}");
    }
}
