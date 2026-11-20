//! Kernel-side leak protection (KILLSWITCH.md L1, L5).
//!
//! While the session layer is connecting, reconnecting or in error, flows on
//! protected routes are refused, never sent direct. The tunnel is held in
//! every state except a user disconnect. The type is pure state; the shell
//! that owns the tunnel interface reads [`KillSwitch::hold_tunnel`].
//!
//! The dialer and the SOCKS/TUN admission ask [`KillSwitch::verdict`] (or
//! [`decide`] for the aggregate posture). [`Verdict::Wait`] holds a TCP flow
//! ([`wait_out`]) until the posture changes or [`WAIT_DEADLINE`] passes, and
//! then the caller refuses it the same way it refuses a failed dial. UDP is
//! not held: see [`admission`].
//!
//! The invariant is structural: [`KillSwitch::verdict`] for a proxied
//! action can only return [`Verdict::Proxy`], [`Verdict::Refuse`] or
//! [`Verdict::Wait`]; no state maps it to [`Verdict::Direct`].

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::rules::Action;

/// `exit_class` of an overseas session route (`session::EXIT_OVERSEAS`).
const EXIT_CLASS_OVERSEAS: u8 = 0;
/// `exit_class` of an AI / home session route (`session::EXIT_AI`).
const EXIT_CLASS_AI: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Posture {
    /// Kernel started, no working channel yet.
    Connecting,
    /// Channels / sessions healthy.
    Connected,
    /// Was connected; re-attaching after a network change or channel loss.
    Reconnecting,
    /// No channel can be established (all nodes down, policy failure...).
    Error,
    /// The user turned Segue off (L5): everything is released.
    Disconnected,
}

/// How a proxied route is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// AI routes: refuse whenever the path is not healthy.
    Strict,
    /// Overseas routes: may wait for a reconnect (§7) before refusing.
    Wait,
}

/// Protection for a session route's `exit_class`.
///
/// AI is [`Protection::Strict`]. Overseas is [`Protection::Wait`]. Any other
/// class is not a documented waitable route (the protocol only has those two),
/// so it fails closed as Strict: a proxied flow is refused rather than sent
/// direct or held.
pub fn protection_for_exit_class(exit_class: u8) -> Protection {
    match exit_class {
        EXIT_CLASS_OVERSEAS => Protection::Wait,
        EXIT_CLASS_AI => Protection::Strict,
        _ => Protection::Strict,
    }
}

/// How long one TCP flow may sit in [`Verdict::Wait`] before it is refused
/// the same way a failed dial is refused. One carrier dial is 10s; this is
/// that long plus a small margin, so a reconnect that succeeds on the next
/// attempt still delivers the flow, and one that does not does not pin the
/// accepted flow any longer than that.
pub const WAIT_DEADLINE: Duration = Duration::from_secs(12);

/// Most TCP flows held in [`Verdict::Wait`] at once. A reconnect burst past
/// this is refused immediately, so the wait queue cannot grow with SYNs.
pub const WAIT_CAP: usize = 64;

/// How often a held flow re-reads the posture.
const WAIT_POLL: Duration = Duration::from_millis(50);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Dial through the named outbound.
    Proxy(String),
    /// Connect from this device (domestic only).
    Direct,
    /// Refuse now (RST / ICMP unreachable).
    Refuse,
    /// Hold the flow until the posture changes, then decide again; the
    /// caller refuses when its own wait deadline passes.
    Wait,
    /// Not handled by Segue (user disconnected): the OS routes it.
    Release,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    ChannelUp,
    /// Channel lost / network changed while connected.
    ChannelLost,
    /// Giving up for now (all attempts failed).
    Failed,
    /// Retrying after an error.
    Retry,
    UserConnect,
    UserDisconnect,
}

#[derive(Clone, Debug)]
pub struct KillSwitch {
    posture: Posture,
}

impl Default for KillSwitch {
    fn default() -> Self {
        Self::new()
    }
}

impl KillSwitch {
    pub fn new() -> Self {
        Self {
            posture: Posture::Connecting,
        }
    }

    pub fn posture(&self) -> Posture {
        self.posture
    }

    /// The tunnel interface must stay up: true in every state except a
    /// user disconnect (L1: never torn down on reconnect or error).
    pub fn hold_tunnel(&self) -> bool {
        self.posture != Posture::Disconnected
    }

    pub fn on_event(&mut self, ev: Event) -> Posture {
        use Posture::*;
        self.posture = match (self.posture, ev) {
            (_, Event::UserDisconnect) => Disconnected,
            (Disconnected, Event::UserConnect) => Connecting,
            (Disconnected, _) => Disconnected,
            (_, Event::ChannelUp) => Connected,
            (Connected, Event::ChannelLost) => Reconnecting,
            (Connecting | Reconnecting, Event::Failed) => Error,
            (Error, Event::Retry) => Reconnecting,
            (p, _) => p,
        };
        self.posture
    }

    /// What to do with a new flow whose rule matched `action`.
    pub fn verdict(&self, action: &Action, protection: Protection) -> Verdict {
        decide(self.posture, action, protection)
    }
}

/// [`KillSwitch::verdict`] for an explicit posture. Admission uses the
/// aggregate posture (user off, device revoked), which is not always one
/// exit's own switch.
pub fn decide(posture: Posture, action: &Action, protection: Protection) -> Verdict {
    match action {
        Action::Reject => {
            if posture == Posture::Disconnected {
                Verdict::Release
            } else {
                Verdict::Refuse
            }
        }
        // Domestic direct keeps working in every state (L1).
        Action::Direct => {
            if posture == Posture::Disconnected {
                Verdict::Release
            } else {
                Verdict::Direct
            }
        }
        Action::Proxy(tag) => match (posture, protection) {
            (Posture::Connected, _) => Verdict::Proxy(tag.clone()),
            // Segue is off: the flow never reaches the kernel.
            (Posture::Disconnected, _) => Verdict::Release,
            (Posture::Connecting | Posture::Reconnecting, Protection::Wait) => Verdict::Wait,
            _ => Verdict::Refuse,
        },
    }
}

/// What admission should do with [`decide`]'s answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Dial now.
    Proceed,
    /// RST, drop, or a SOCKS refusal, the same as a failed dial today.
    Refuse,
    /// TCP only: hold one [`HoldGuard`] until [`wait_out`] returns.
    Hold,
}

/// Map a verdict onto admission.
///
/// UDP is never held. A datagram flow has no handshake the application is
/// blocked on, and queueing datagrams until the tunnel returns would pin
/// memory for a flow most apps have already abandoned (they time out and
/// retry). [`Verdict::Wait`] on UDP is a refusal, the same as a down strict
/// route. [`Verdict::Release`] of a direct flow still proceeds: domestic
/// direct is dialled as before, and the shell is what stops capturing when
/// the user disconnects. A released proxy or reject is refused.
pub fn admission(verdict: Verdict, action: &Action, udp: bool) -> Admission {
    match verdict {
        Verdict::Proxy(_) | Verdict::Direct => Admission::Proceed,
        Verdict::Release => match action {
            Action::Direct => Admission::Proceed,
            _ => Admission::Refuse,
        },
        Verdict::Wait if udp => Admission::Refuse,
        Verdict::Wait => Admission::Hold,
        Verdict::Refuse => Admission::Refuse,
    }
}

/// One held TCP flow, counting against [`WAIT_CAP`]. Dropped when the wait
/// ends (dial, refuse, or the flow is gone).
pub struct HoldGuard {
    count: Arc<AtomicUsize>,
}

impl HoldGuard {
    /// `None` when `cap` flows are already held.
    pub fn try_acquire(count: &Arc<AtomicUsize>, cap: usize) -> Option<Self> {
        let mut cur = count.load(Ordering::Relaxed);
        loop {
            if cur >= cap {
                return None;
            }
            match count.compare_exchange_weak(cur, cur + 1, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => {
                    return Some(Self {
                        count: count.clone(),
                    })
                }
                Err(observed) => cur = observed,
            }
        }
    }
}

impl Drop for HoldGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Re-read `current` until it is no longer [`Verdict::Wait`], or
/// [`WAIT_DEADLINE`] has passed (then [`Verdict::Refuse`]).
pub async fn wait_out(current: impl FnMut() -> Verdict) -> Verdict {
    wait_out_notified(None, current).await
}

/// Like [`wait_out`], waking immediately when `notify` signals a posture change
/// instead of waiting for the fallback polling interval.
pub async fn wait_out_notified(
    notify: Option<&tokio::sync::Notify>,
    mut current: impl FnMut() -> Verdict,
) -> Verdict {
    let deadline = tokio::time::Instant::now() + WAIT_DEADLINE;
    loop {
        if let Some(n) = notify {
            let notified = n.notified();
            tokio::pin!(notified);
            // Register before sampling `current()` so a concurrent posture update
            // cannot fire between the check and awaiting `notified`.
            notified.as_mut().enable();
            let verdict = current();
            if !matches!(verdict, Verdict::Wait) {
                return verdict;
            }
            if tokio::time::Instant::now() >= deadline {
                return Verdict::Refuse;
            }
            tokio::select! {
                () = &mut notified => {}
                () = tokio::time::sleep_until(deadline) => return Verdict::Refuse,
            }
        } else {
            let verdict = current();
            if !matches!(verdict, Verdict::Wait) {
                return verdict;
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return Verdict::Refuse;
            }
            tokio::time::sleep(WAIT_POLL.min(deadline - now)).await;
        }
    }
}

/// Posture and per-tag protection the SOCKS/TUN front ends read. Implemented
/// by the session dialer; absent on a kernel whose dialer has no kill switch.
pub trait FlowPosture: Send + Sync {
    fn posture(&self) -> Posture;
    /// `None`: `tag` is not a session route (an engine outbound).
    fn protection(&self, tag: &str) -> Option<Protection>;
    fn try_hold(&self) -> Option<HoldGuard>;
    fn posture_notify(&self) -> Option<Arc<tokio::sync::Notify>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    const ALL: [Posture; 5] = [
        Posture::Connecting,
        Posture::Connected,
        Posture::Reconnecting,
        Posture::Error,
        Posture::Disconnected,
    ];
    const EVENTS: [Event; 6] = [
        Event::ChannelUp,
        Event::ChannelLost,
        Event::Failed,
        Event::Retry,
        Event::UserConnect,
        Event::UserDisconnect,
    ];

    fn at(p: Posture) -> KillSwitch {
        KillSwitch { posture: p }
    }

    #[test]
    fn proxied_flow_never_goes_direct_in_any_state() {
        let a = Action::Proxy("ai".into());
        for p in ALL {
            for prot in [Protection::Strict, Protection::Wait] {
                let v = at(p).verdict(&a, prot);
                assert_ne!(v, Verdict::Direct, "{p:?} {prot:?}");
                let expected = match (p, prot) {
                    (Posture::Connected, _) => Verdict::Proxy("ai".into()),
                    (Posture::Disconnected, _) => Verdict::Release,
                    (Posture::Connecting | Posture::Reconnecting, Protection::Wait) => {
                        Verdict::Wait
                    }
                    _ => Verdict::Refuse,
                };
                assert_eq!(v, expected, "{p:?} {prot:?}");
            }
        }
    }

    #[test]
    fn ai_refused_while_reconnecting_domestic_keeps_working() {
        let k = at(Posture::Reconnecting);
        assert_eq!(
            k.verdict(&Action::Proxy("ai".into()), Protection::Strict),
            Verdict::Refuse
        );
        assert_eq!(
            k.verdict(&Action::Direct, Protection::Strict),
            Verdict::Direct
        );
        assert_eq!(
            k.verdict(&Action::Reject, Protection::Wait),
            Verdict::Refuse
        );
        assert!(k.hold_tunnel());
    }

    #[test]
    fn only_user_disconnect_releases_the_tunnel() {
        for p in ALL {
            for ev in EVENTS {
                let mut k = at(p);
                let next = k.on_event(ev);
                let released = !k.hold_tunnel();
                assert_eq!(released, next == Posture::Disconnected);
                if p != Posture::Disconnected {
                    assert_eq!(released, ev == Event::UserDisconnect, "{p:?} {ev:?}");
                }
            }
        }
    }

    #[test]
    fn lifecycle() {
        let mut k = KillSwitch::new();
        assert_eq!(k.posture(), Posture::Connecting);
        assert!(k.hold_tunnel());
        assert_eq!(k.on_event(Event::ChannelUp), Posture::Connected);
        assert_eq!(k.on_event(Event::ChannelLost), Posture::Reconnecting);
        assert_eq!(k.on_event(Event::Failed), Posture::Error);
        assert_eq!(k.on_event(Event::ChannelLost), Posture::Error);
        assert_eq!(k.on_event(Event::Retry), Posture::Reconnecting);
        assert_eq!(k.on_event(Event::ChannelUp), Posture::Connected);
        assert_eq!(k.on_event(Event::UserDisconnect), Posture::Disconnected);
        assert_eq!(
            k.on_event(Event::ChannelUp),
            Posture::Disconnected,
            "stays off until the user connects"
        );
        assert_eq!(k.on_event(Event::UserConnect), Posture::Connecting);
    }

    #[test]
    fn protection_follows_exit_class() {
        use crate::session::{EXIT_AI, EXIT_OVERSEAS};
        assert_eq!(protection_for_exit_class(EXIT_AI), Protection::Strict);
        assert_eq!(protection_for_exit_class(EXIT_OVERSEAS), Protection::Wait);
        // Not a documented class: fail closed, never Wait.
        assert_eq!(protection_for_exit_class(2), Protection::Strict);
        assert_eq!(protection_for_exit_class(255), Protection::Strict);
        assert_eq!(EXIT_OVERSEAS, 0);
        assert_eq!(EXIT_AI, 1);
    }

    #[test]
    fn admission_holds_tcp_wait_and_refuses_udp() {
        let action = Action::Proxy("overseas".into());
        let wait = decide(Posture::Reconnecting, &action, Protection::Wait);
        assert_eq!(wait, Verdict::Wait);
        assert_eq!(admission(wait.clone(), &action, false), Admission::Hold);
        assert_eq!(
            admission(wait, &action, true),
            Admission::Refuse,
            "UDP is not held"
        );
        let ai = Action::Proxy("ai".into());
        let refused = decide(Posture::Reconnecting, &ai, Protection::Strict);
        assert_eq!(refused, Verdict::Refuse);
        assert_eq!(admission(refused, &ai, false), Admission::Refuse);
        let direct = Action::Direct;
        let released = decide(Posture::Disconnected, &direct, Protection::Wait);
        assert_eq!(released, Verdict::Release);
        assert_eq!(admission(released, &direct, false), Admission::Proceed);
        let proxy = Action::Proxy("overseas".into());
        let off = decide(Posture::Disconnected, &proxy, Protection::Wait);
        assert_eq!(admission(off, &proxy, false), Admission::Refuse);
    }

    #[test]
    fn hold_cap_refuses_past_the_bound() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut held = Vec::new();
        for _ in 0..WAIT_CAP {
            held.push(HoldGuard::try_acquire(&count, WAIT_CAP).expect("under the cap"));
        }
        assert!(HoldGuard::try_acquire(&count, WAIT_CAP).is_none());
        held.pop();
        assert!(HoldGuard::try_acquire(&count, WAIT_CAP).is_some());
    }

    /// Yield until `flag` is set. The setter runs before [`wait_out`]'s sleep,
    /// and a current-thread task runs until that await, so the hold is parked
    /// before the clock jumps. Jumping first would start the deadline late and
    /// the test would wait forever.
    async fn parked(flag: &AtomicBool) {
        while !flag.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn wait_holds_until_connected_then_proxies() {
        tokio::time::pause();
        let posture = Arc::new(std::sync::Mutex::new(Posture::Reconnecting));
        let watch = posture.clone();
        let started = Arc::new(AtomicBool::new(false));
        let flag = started.clone();
        let handle = tokio::spawn(async move {
            flag.store(true, Ordering::SeqCst);
            let action = Action::Proxy("overseas".into());
            wait_out(|| decide(*watch.lock().unwrap(), &action, Protection::Wait)).await
        });
        parked(&started).await;
        assert!(!handle.is_finished(), "overseas flow was not held");
        tokio::time::advance(WAIT_POLL).await;
        assert!(
            !handle.is_finished(),
            "held flow completed before Connected"
        );
        *posture.lock().unwrap() = Posture::Connected;
        tokio::time::advance(WAIT_POLL).await;
        let verdict = handle.await.expect("hold task");
        assert_eq!(verdict, Verdict::Proxy("overseas".into()));
    }

    #[tokio::test]
    async fn wait_refuses_when_the_deadline_passes() {
        tokio::time::pause();
        let started = Arc::new(AtomicBool::new(false));
        let flag = started.clone();
        let handle = tokio::spawn(async move {
            flag.store(true, Ordering::SeqCst);
            let action = Action::Proxy("overseas".into());
            wait_out(|| decide(Posture::Reconnecting, &action, Protection::Wait)).await
        });
        parked(&started).await;
        assert!(!handle.is_finished(), "flow was not held");
        tokio::time::advance(WAIT_DEADLINE).await;
        let verdict = handle.await.expect("hold task");
        assert_eq!(verdict, Verdict::Refuse);
    }

    #[tokio::test]
    async fn ai_while_reconnecting_is_refused_immediately() {
        tokio::time::pause();
        let started = tokio::time::Instant::now();
        let verdict = wait_out(|| {
            decide(
                Posture::Reconnecting,
                &Action::Proxy("ai".into()),
                Protection::Strict,
            )
        })
        .await;
        assert_eq!(verdict, Verdict::Refuse);
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// Posture × flow class. An AI-class flow is never Direct, and never a
    /// different exit's proxy, except `Disconnected` (the user turned Segue
    /// off; the kernel is not on the path). QUIC to the AI route is refused
    /// even while Connected: the home exit carries no UDP, so the client
    /// falls back to TCP. The egress-group half of the invariant is
    /// `session::tests::ai_auto_does_not_leave_its_egress_group`.
    #[test]
    fn posture_matrix_ai_never_goes_direct() {
        use std::net::SocketAddr;

        use segue_routing::TargetAddr;

        use crate::dns::{classify, proxied_answer, Class, ProxiedAnswer, TYPE_A, TYPE_AAAA};
        use crate::policy::Policy;
        use crate::rules::{builtin_ai_list, Action, Cidr, CidrTable, Matcher, Rule, RuleSet};
        use crate::sniff::Sniff;
        use crate::socks::{sniffed_route, HiddenRefusals};
        use crate::udp::{finish, UdpSettings};

        let (suffixes, mut cidrs) = builtin_ai_list();
        let ai_net = Cidr::parse("203.0.113.0/24").unwrap();
        cidrs.push(ai_net);
        let rules = RuleSet::new(
            vec![
                Rule {
                    matcher: Matcher::DomainSuffix("claude.ai".into()),
                    action: Action::Direct,
                },
                Rule {
                    matcher: Matcher::Cidr(ai_net),
                    action: Action::Direct,
                },
                Rule {
                    matcher: Matcher::DomainSuffix("cdn.example".into()),
                    action: Action::Proxy("overseas".into()),
                },
                Rule {
                    matcher: Matcher::Cidr(Cidr::parse("10.0.0.0/8").unwrap()),
                    action: Action::Direct,
                },
            ],
            Action::Proxy("overseas".into()),
        )
        .with_ai(suffixes, &cidrs, Action::Proxy("ai".into()));
        let policy = Policy::inline(rules, CidrTable::default());
        let hidden = HiddenRefusals::default();
        let mut udp = UdpSettings::default();
        udp.refuse.insert("ai".to_string());

        let ai = Action::Proxy("ai".into());
        let overseas = Action::Proxy("overseas".into());
        let direct = Action::Direct;
        let direct_ip: std::net::IpAddr = "10.1.2.3".parse().unwrap();
        let ai_ip: std::net::IpAddr = "203.0.113.8".parse().unwrap();

        #[derive(Clone, Copy)]
        enum ClassKind {
            AiDomain,
            AiIp,
            AiSni,
            AiDnsA,
            AiDnsAaaa,
            AiQuic,
            Direct,
            Overseas,
        }
        let kinds = [
            ClassKind::AiDomain,
            ClassKind::AiIp,
            ClassKind::AiSni,
            ClassKind::AiDnsA,
            ClassKind::AiDnsAaaa,
            ClassKind::AiQuic,
            ClassKind::Direct,
            ClassKind::Overseas,
        ];

        for posture in ALL {
            for kind in kinds {
                let (action, protection, label): (&Action, Protection, &str) = match kind {
                    ClassKind::AiDomain => {
                        assert_eq!(
                            policy
                                .rules
                                .decide(&TargetAddr::Domain("api.claude.ai".into())),
                            &ai
                        );
                        (&ai, Protection::Strict, "ai domain")
                    }
                    ClassKind::AiIp => {
                        assert_eq!(policy.rules.decide(&TargetAddr::Ip(ai_ip)), &ai);
                        (&ai, Protection::Strict, "ai ip")
                    }
                    ClassKind::AiSni => {
                        let dst: SocketAddr = "1.2.3.4:443".parse().unwrap();
                        let (tag, _) = sniffed_route(
                            &policy,
                            dst,
                            &Sniff::Domain("api.anthropic.com".into()),
                            &hidden,
                        )
                        .unwrap_or_else(|| panic!("{posture:?}: SNI not routed"));
                        assert_eq!(tag.as_deref(), Some("ai"), "{posture:?}");
                        (&ai, Protection::Strict, "ai sni")
                    }
                    ClassKind::AiDnsA => {
                        assert!(
                            matches!(classify(&policy, "claude.ai"), Class::Fake),
                            "{posture:?}: AI A would be resolved direct"
                        );
                        assert!(matches!(proxied_answer(TYPE_A), ProxiedAnswer::FakeV4));
                        (&ai, Protection::Strict, "ai dns A")
                    }
                    ClassKind::AiDnsAaaa => {
                        assert!(matches!(classify(&policy, "api.openai.com"), Class::Fake));
                        assert!(
                            matches!(proxied_answer(TYPE_AAAA), ProxiedAnswer::Empty),
                            "AAAA must not be a real address"
                        );
                        (&ai, Protection::Strict, "ai dns AAAA")
                    }
                    ClassKind::AiQuic => {
                        assert!(
                            finish(
                                &udp,
                                ai.clone(),
                                TargetAddr::Domain("claude.ai".into()),
                                443,
                            )
                            .is_none(),
                            "{posture:?}: QUIC to the AI exit was dialled"
                        );
                        (&ai, Protection::Strict, "ai quic")
                    }
                    ClassKind::Direct => {
                        assert_eq!(
                            policy.rules.decide(&TargetAddr::Ip(direct_ip)),
                            &Action::Direct
                        );
                        (&direct, Protection::Wait, "direct")
                    }
                    ClassKind::Overseas => {
                        assert_eq!(
                            policy
                                .rules
                                .decide(&TargetAddr::Domain("static.cdn.example".into())),
                            &overseas
                        );
                        (&overseas, Protection::Wait, "overseas")
                    }
                };
                let verdict = decide(posture, action, protection);
                let ai_class = !matches!(kind, ClassKind::Direct | ClassKind::Overseas);
                if ai_class && posture != Posture::Disconnected {
                    assert_ne!(verdict, Verdict::Direct, "{posture:?} {label}");
                    assert_ne!(
                        verdict,
                        Verdict::Proxy("overseas".into()),
                        "{posture:?} {label} left via another exit"
                    );
                }
                let expected = match (kind, posture) {
                    (ClassKind::Direct, Posture::Disconnected) => Verdict::Release,
                    (ClassKind::Direct, _) => Verdict::Direct,
                    (ClassKind::Overseas, Posture::Connected) => Verdict::Proxy("overseas".into()),
                    (ClassKind::Overseas, Posture::Connecting | Posture::Reconnecting) => {
                        Verdict::Wait
                    }
                    (ClassKind::Overseas, Posture::Error) => Verdict::Refuse,
                    (ClassKind::Overseas, Posture::Disconnected) => Verdict::Release,
                    // QUIC is refused by the UDP layer even when the posture
                    // would proxy a TCP flow. The kill-switch verdict is still
                    // the strict one; admission of a proxy Release refuses.
                    (ClassKind::AiQuic, Posture::Connected) => Verdict::Proxy("ai".into()),
                    (ClassKind::AiQuic, Posture::Disconnected) => Verdict::Release,
                    (_, Posture::Connected) => Verdict::Proxy("ai".into()),
                    (_, Posture::Disconnected) => Verdict::Release,
                    _ => Verdict::Refuse,
                };
                assert_eq!(verdict, expected, "{posture:?} {label}");
                if matches!(kind, ClassKind::AiQuic) && !matches!(verdict, Verdict::Proxy(_)) {
                    // Connected is Proxy at the kill switch and Refuse in
                    // `udp::finish` (asserted above): home carries no UDP.
                    // Every other posture refuses the datagram as well.
                    assert_eq!(
                        admission(verdict, action, true),
                        Admission::Refuse,
                        "{posture:?}: AI QUIC was not refused"
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn wait_out_notified_wakes_before_poll_interval() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let ready = Arc::new(AtomicBool::new(false));

        let n2 = notify.clone();
        let r2 = ready.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(2)).await;
            r2.store(true, Ordering::Release);
            n2.notify_waiters();
        });

        let started = tokio::time::Instant::now();
        let verdict = tokio::time::timeout(
            Duration::from_millis(25),
            wait_out_notified(Some(&notify), || {
                if ready.load(Ordering::Acquire) {
                    Verdict::Proxy("overseas".into())
                } else {
                    Verdict::Wait
                }
            }),
        )
        .await
        .expect("wait_out_notified should wake immediately without waiting WAIT_POLL");
        assert_eq!(verdict, Verdict::Proxy("overseas".into()));
        assert!(started.elapsed() < Duration::from_millis(25));
    }
}
