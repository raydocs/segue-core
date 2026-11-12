//! Segue client kernel (prototype): local SOCKS5 / TUN → rule table → outer engine.
//!
//! Entry points: SOCKS5 CONNECT ([`socks`]) and TUN packets ([`tun`]). UDP
//! relaying, smart DNS, SNI sniffing, the session layer and the kill-switch
//! are specified in tono-next/spec and not implemented here yet.

pub mod config;
pub mod dial;
pub mod rules;
pub mod socks;
pub mod tun;
