//! Segue client kernel (prototype): local SOCKS5 → rule table → outer engine.
//!
//! Scope of this slice: TCP CONNECT only. UDP, TUN, smart DNS, SNI sniffing,
//! the session layer and the kill-switch are specified in tono-next/spec and
//! not implemented here yet.

pub mod config;
pub mod dial;
pub mod rules;
pub mod socks;
