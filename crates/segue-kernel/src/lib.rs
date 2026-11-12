//! Segue client kernel (prototype): local SOCKS5 → rule table → outer engine.
//!
//! Scope of this slice: TCP CONNECT only. UDP, TUN, smart DNS and SNI sniffing
//! are specified in tono-next/spec and not implemented here yet. The session
//! layer lives in the `segue-session` crate; [`killswitch`] holds the posture
//! and per-flow verdicts (KILLSWITCH.md) but is not yet wired into `socks`.

pub mod config;
pub mod dial;
pub mod killswitch;
pub mod rules;
pub mod socks;
