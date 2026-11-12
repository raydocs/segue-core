//! Segue client kernel (prototype): local SOCKS5 → rule table → outer engine,
//! with a loopback smart DNS (fake-IP for proxied names) and TLS SNI / HTTP
//! Host sniffing for bare-IP flows (KERNEL_SPEC §5.2, §5.2a).
//!
//! SOCKS5 UDP ASSOCIATE is routed per destination (KERNEL_SPEC §4.3).
//! The session layer lives in the `segue-session` crate; [`killswitch`] holds
//! the posture and per-flow verdicts (KILLSWITCH.md).

pub mod config;
pub mod dial;
pub mod dns;
pub mod fakeip;
pub mod killswitch;
pub mod rules;
pub mod sniff;
pub mod socks;
pub mod udp;
