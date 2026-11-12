//! Segue client kernel (prototype): local SOCKS5 → rule table → outer engine,
//! with a loopback smart DNS (fake-IP for proxied names) and TLS SNI / HTTP
//! Host sniffing for bare-IP flows (KERNEL_SPEC §5.2, §5.2a).
//!
//! Not here yet: UDP, TUN, QUIC Initial sniffing, the session layer and the
//! kill-switch (specified in tono-next/spec).

pub mod config;
pub mod dial;
pub mod dns;
pub mod fakeip;
pub mod rules;
pub mod sniff;
pub mod socks;
