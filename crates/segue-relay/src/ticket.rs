//! Device tickets (SESSION_PROTOCOL §3/§6, CONTROL_PLANE_SPEC §3.3).
//!
//! Wire form (the OPEN / RESUME `ticket` bytes):
//! `SGT1.` base64url(payload JSON) `.` base64url(Ed25519 signature)`, no
//! padding. The signature covers `"segue-ticket-v1\n" || payload`. The relay
//! holds only public keys and verifies offline. A ticket is a bearer secret:
//! it is never logged, and [`Claims`] carries nothing that grants access.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{self, KeyPair as _};
use segue_session::codec::{code, Kind, Target};
use segue_session::relay::Authorizer;
use serde::{Deserialize, Serialize};

use crate::metrics::Metrics;
use crate::revoke::Revocations;
use crate::Clock;

const PREFIX: &str = "SGT1.";
const DOMAIN: &[u8] = b"segue-ticket-v1\n";
/// Longest ticket accepted; larger ones are rejected before decoding.
pub const MAX_TICKET: usize = 2048;
/// RESUME grace after `not_after` (SESSION_PROTOCOL §6), only while the
/// revocation list is fresh.
pub const RESUME_GRACE_SECS: u64 = 3600;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExitClass {
    Overseas,
    Ai,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub v: u32,
    pub key_id: u32,
    pub device_id: u64,
    #[serde(default)]
    pub account_id: u64,
    #[serde(default)]
    pub plan: String,
    pub exit_classes: Vec<ExitClass>,
    /// Node allowed to anchor this device's AI sessions; 0 = any.
    #[serde(default)]
    pub ai_anchor_node_id: u64,
    pub not_before: u64,
    pub not_after: u64,
}

impl Claims {
    pub fn allows(&self, c: ExitClass) -> bool {
        self.exit_classes.contains(&c)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketError {
    /// Malformed, unknown key, bad signature, not yet valid.
    Bad,
    Expired,
}

/// Signs tickets (dev CLI and tests; production keys live in the control
/// plane).
pub struct Signer {
    key_id: u32,
    pair: signature::Ed25519KeyPair,
}

impl Signer {
    /// From a PKCS#8 v2 document (as written by [`generate_pkcs8`]).
    pub fn from_pkcs8(key_id: u32, pkcs8: &[u8]) -> Result<Self, String> {
        let pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| "not an Ed25519 PKCS#8 key".to_string())?;
        Ok(Self { key_id, pair })
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.pair.public_key().as_ref().try_into().unwrap()
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    /// `claims.key_id` is overwritten with this signer's.
    pub fn sign(&self, claims: &Claims) -> Vec<u8> {
        let mut c = claims.clone();
        c.key_id = self.key_id;
        let payload = serde_json::to_vec(&c).unwrap();
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&payload);
        let sig = self.pair.sign(&msg);
        format!(
            "{PREFIX}{}.{}",
            URL_SAFE_NO_PAD.encode(&payload),
            URL_SAFE_NO_PAD.encode(sig.as_ref())
        )
        .into_bytes()
    }
}

pub fn generate_pkcs8() -> Vec<u8> {
    let rng = ring::rand::SystemRandom::new();
    signature::Ed25519KeyPair::generate_pkcs8(&rng)
        .expect("system RNG")
        .as_ref()
        .to_vec()
}

/// Offline ticket verification against the configured public keys.
pub struct Verifier {
    keys: Vec<(u32, [u8; 32])>,
}

impl Verifier {
    pub fn new(keys: Vec<(u32, [u8; 32])>) -> Self {
        Self { keys }
    }

    /// Signature and shape only; validity window is checked by the caller.
    pub fn decode(&self, ticket: &[u8]) -> Result<Claims, TicketError> {
        if ticket.len() > MAX_TICKET {
            return Err(TicketError::Bad);
        }
        let s = std::str::from_utf8(ticket).map_err(|_| TicketError::Bad)?;
        let rest = s.strip_prefix(PREFIX).ok_or(TicketError::Bad)?;
        let (p, sig) = rest.split_once('.').ok_or(TicketError::Bad)?;
        let payload = URL_SAFE_NO_PAD.decode(p).map_err(|_| TicketError::Bad)?;
        let sig = URL_SAFE_NO_PAD.decode(sig).map_err(|_| TicketError::Bad)?;
        // key_id is read before the signature is checked only to pick the
        // key; nothing else is trusted until verification passes.
        #[derive(Deserialize)]
        struct KeyOnly {
            key_id: u32,
        }
        let k: KeyOnly = serde_json::from_slice(&payload).map_err(|_| TicketError::Bad)?;
        let key = self
            .keys
            .iter()
            .find(|(id, _)| *id == k.key_id)
            .ok_or(TicketError::Bad)?;
        let mut msg = DOMAIN.to_vec();
        msg.extend_from_slice(&payload);
        signature::UnparsedPublicKey::new(&signature::ED25519, &key.1)
            .verify(&msg, &sig)
            .map_err(|_| TicketError::Bad)?;
        let c: Claims = serde_json::from_slice(&payload).map_err(|_| TicketError::Bad)?;
        if c.v != 1 || c.not_after <= c.not_before {
            return Err(TicketError::Bad);
        }
        Ok(c)
    }

    /// Decode and check the validity window at `now` (unix seconds).
    pub fn verify(&self, ticket: &[u8], now: u64) -> Result<Claims, TicketError> {
        let c = self.decode(ticket)?;
        if now < c.not_before {
            return Err(TicketError::Bad);
        }
        if now >= c.not_after {
            return Err(TicketError::Expired);
        }
        Ok(c)
    }
}

/// Latest claims per device, for the site connector (which only learns the
/// device id from the session table). Bounded.
#[derive(Default)]
pub struct ClaimsCache {
    map: Mutex<HashMap<u64, Claims>>,
}

const MAX_CLAIMS: usize = 65_536;

impl ClaimsCache {
    pub fn put(&self, c: Claims) {
        let mut m = self.map.lock().unwrap();
        if m.len() >= MAX_CLAIMS && !m.contains_key(&c.device_id) {
            // Drop expired entries first; if none, an arbitrary one. A
            // device whose entry is gone is refused (`auth`) at dial time.
            let now_min = c.not_before;
            m.retain(|_, x| x.not_after > now_min);
            if m.len() >= MAX_CLAIMS {
                if let Some(&k) = m.keys().next() {
                    m.remove(&k);
                }
            }
        }
        m.insert(c.device_id, c);
    }

    pub fn get(&self, device: u64) -> Option<Claims> {
        self.map.lock().unwrap().get(&device).cloned()
    }

    pub fn remove(&self, device: u64) {
        self.map.lock().unwrap().remove(&device);
    }
}

/// [`Authorizer`] over tickets and the revocation list.
pub struct TicketAuth {
    pub verifier: Arc<Verifier>,
    pub revoked: Arc<Revocations>,
    pub claims: Arc<ClaimsCache>,
    pub metrics: Arc<Metrics>,
    pub clock: Clock,
}

impl TicketAuth {
    fn check(&self, ticket: &[u8], resume: bool) -> Result<Claims, u8> {
        let now = (self.clock)();
        let c = match self.verifier.verify(ticket, now) {
            Ok(c) => c,
            Err(TicketError::Expired) => {
                let c = self.verifier.decode(ticket).map_err(|_| code::AUTH)?;
                let grace = resume
                    && now < c.not_after.saturating_add(RESUME_GRACE_SECS)
                    && self.revoked.is_fresh();
                if !grace {
                    Metrics::inc(&self.metrics.tickets_expired);
                    return Err(code::EXPIRED);
                }
                c
            }
            Err(TicketError::Bad) => {
                Metrics::inc(&self.metrics.tickets_bad);
                return Err(code::AUTH);
            }
        };
        if self.revoked.contains(c.device_id) {
            Metrics::inc(&self.metrics.tickets_revoked);
            return Err(code::REVOKED);
        }
        Metrics::inc(&self.metrics.tickets_ok);
        Ok(c)
    }
}

impl Authorizer for TicketAuth {
    fn open(&self, ticket: &[u8], _target: &Target, kind: Kind) -> Result<u64, u8> {
        let c = self.check(ticket, false)?;
        // This relay carries TCP only; Home UDP is never offered (§5.5.5).
        if kind == Kind::Udp || c.exit_classes.is_empty() {
            Metrics::inc(&self.metrics.exit_denied);
            return Err(code::EXIT_DENIED);
        }
        let d = c.device_id;
        self.claims.put(c);
        Ok(d)
    }

    fn resume(&self, ticket: &[u8]) -> Result<u64, u8> {
        let c = self.check(ticket, true)?;
        let d = c.device_id;
        self.claims.put(c);
        Ok(d)
    }
}

/// Parse a dev key file: base64 PKCS#8.
pub fn read_signer(key_id: u32, text: &str) -> Result<Signer, String> {
    let der = base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .map_err(|_| "key file: bad base64".to_string())?;
    Signer::from_pkcs8(key_id, &der)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn claims(device: u64, now: u64) -> Claims {
        Claims {
            v: 1,
            key_id: 0,
            device_id: device,
            account_id: 9,
            plan: "pro".into(),
            exit_classes: vec![ExitClass::Overseas, ExitClass::Ai],
            ai_anchor_node_id: 0,
            not_before: now - 10,
            not_after: now + 100,
        }
    }

    #[test]
    fn sign_verify_and_tamper() {
        let s = Signer::from_pkcs8(7, &generate_pkcs8()).unwrap();
        let v = Verifier::new(vec![(7, s.public_key())]);
        let t = s.sign(&claims(42, 1000));
        let c = v.verify(&t, 1000).unwrap();
        assert_eq!((c.device_id, c.key_id), (42, 7));
        assert_eq!(v.verify(&t, 1100), Err(TicketError::Expired));
        assert_eq!(v.verify(&t, 980), Err(TicketError::Bad));
        // Flip one payload byte.
        let mut bad = t.clone();
        bad[PREFIX.len() + 3] ^= 1;
        assert_eq!(v.verify(&bad, 1000), Err(TicketError::Bad));
        // Unknown key id / other key.
        let other = Signer::from_pkcs8(7, &generate_pkcs8()).unwrap();
        assert_eq!(
            v.verify(&other.sign(&claims(42, 1000)), 1000),
            Err(TicketError::Bad)
        );
        let v2 = Verifier::new(vec![(8, s.public_key())]);
        assert_eq!(v2.verify(&t, 1000), Err(TicketError::Bad));
        assert_eq!(v.verify(b"junk", 1000), Err(TicketError::Bad));
        assert_eq!(
            v.verify(&vec![b'S'; MAX_TICKET + 1], 1000),
            Err(TicketError::Bad)
        );
    }
}
