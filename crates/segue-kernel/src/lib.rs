//! Segue client kernel (prototype): local SOCKS5 / TUN → rule table → outer
//! engine, with a loopback smart DNS (fake-IP for proxied names) and TLS SNI /
//! HTTP Host sniffing for bare-IP flows (KERNEL_SPEC §5.2, §5.2a).
//!
//! Entry points: SOCKS5 CONNECT / UDP ASSOCIATE ([`socks`], [`udp`]) and TUN
//! packets ([`tun`]). The session layer lives in the `segue-session` crate;
//! [`killswitch`] holds the posture and per-flow verdicts (KILLSWITCH.md).

pub mod config;
pub mod control;
pub mod dial;
pub mod dns;
pub mod fakeip;
pub mod killswitch;
pub mod policy;
pub mod quic;
pub mod rules;
pub mod session;
pub mod sniff;
pub mod socks;
pub mod tun;
pub mod udp;
