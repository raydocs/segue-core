//! Kernel-side leak protection (KILLSWITCH.md L1, L5).
//!
//! While the session layer is connecting, reconnecting or in error, flows on
//! protected routes are refused, never sent direct. The tunnel is held in
//! every state except a user disconnect. The type is pure state; the shell
//! that owns the tunnel interface reads [`KillSwitch::hold_tunnel`].
//!
//! The invariant is structural: [`KillSwitch::verdict`] for a proxied
//! action can only return [`Verdict::Proxy`], [`Verdict::Refuse`] or
//! [`Verdict::Wait`]; no state maps it to [`Verdict::Direct`].

use crate::rules::Action;

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
        match action {
            Action::Reject => {
                if self.posture == Posture::Disconnected {
                    Verdict::Release
                } else {
                    Verdict::Refuse
                }
            }
            // Domestic direct keeps working in every state (L1).
            Action::Direct => {
                if self.posture == Posture::Disconnected {
                    Verdict::Release
                } else {
                    Verdict::Direct
                }
            }
            Action::Proxy(tag) => match (self.posture, protection) {
                (Posture::Connected, _) => Verdict::Proxy(tag.clone()),
                // Segue is off: the flow never reaches the kernel.
                (Posture::Disconnected, _) => Verdict::Release,
                (Posture::Connecting | Posture::Reconnecting, Protection::Wait) => Verdict::Wait,
                _ => Verdict::Refuse,
            },
        }
    }
}

#[cfg(test)]
mod tests {
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
}
