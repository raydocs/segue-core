//! Signed policy bundle envelope (KERNEL_SPEC §5.3, §5.5 items 3 and 7;
//! CONTROL_PLANE_SPEC §6), shared by the client kernel and the relay so
//! both read the AI set from the same signed bytes.
//!
//! Envelope (JSON): `{"key_id": 1, "body": "<base64 body>", "sig": "<base64>"}`.
//! The signature covers [`SIG_CONTEXT`] followed by the raw body bytes, so a
//! signature made for anything else (a ticket, an older format) never
//! verifies as a policy.
//!
//! The body is JSON. Each consumer parses the fields it uses; the kernel
//! parses all of it strictly. [`AiView`] is the relay's view: version,
//! expiry and the AI set (`ai_domains` suffixes, `ai_cidrs`).

use std::collections::BTreeMap;
use std::net::IpAddr;

use base64::Engine as _;
use ring::signature::{self, KeyPair as _};
use serde::{Deserialize, Serialize};

pub mod cidr;
use cidr::any_contains;
pub use cidr::Cidr;

/// Domain separation for policy signatures.
pub const SIG_CONTEXT: &[u8] = b"segue-policy-v1\0";
/// Largest envelope accepted (the AI / chnroute lists are a few thousand
/// entries; this leaves room without letting a bad file eat memory).
pub const MAX_BUNDLE_BYTES: usize = 8 << 20;

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub key_id: u32,
    /// Base64 of the body JSON.
    pub body: String,
    /// Base64 Ed25519 signature over `SIG_CONTEXT || body bytes`.
    pub sig: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    Malformed(String),
    UnknownKey(u32),
    BadSignature,
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "policy bundle malformed: {e}"),
            Self::UnknownKey(k) => write!(f, "policy bundle signed with unknown key_id {k}"),
            Self::BadSignature => f.write_str("policy bundle signature invalid"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// Check the envelope's signature under `keys` (key id → raw 32-byte
/// Ed25519 public key). Returns the signed body bytes; nothing unsigned is
/// parsed past the envelope.
pub fn open(keys: &BTreeMap<u32, Vec<u8>>, bytes: &[u8]) -> Result<Vec<u8>, EnvelopeError> {
    if bytes.len() > MAX_BUNDLE_BYTES {
        return Err(EnvelopeError::Malformed(format!(
            "{} bytes > {MAX_BUNDLE_BYTES}",
            bytes.len()
        )));
    }
    let env: Envelope =
        serde_json::from_slice(bytes).map_err(|e| EnvelopeError::Malformed(e.to_string()))?;
    let key = keys
        .get(&env.key_id)
        .ok_or(EnvelopeError::UnknownKey(env.key_id))?;
    let body = b64()
        .decode(env.body.trim())
        .map_err(|_| EnvelopeError::Malformed("body: bad base64".into()))?;
    let sig = b64()
        .decode(env.sig.trim())
        .map_err(|_| EnvelopeError::Malformed("sig: bad base64".into()))?;
    let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + body.len());
    msg.extend_from_slice(SIG_CONTEXT);
    msg.extend_from_slice(&body);
    signature::UnparsedPublicKey::new(&signature::ED25519, key)
        .verify(&msg, &sig)
        .map_err(|_| EnvelopeError::BadSignature)?;
    Ok(body)
}

/// Sign `body` into an envelope (dev signing tool and tests; the control
/// plane does this in production). `key_b64` is base64 PKCS#8.
pub fn sign(key_b64: &str, key_id: u32, body: &[u8]) -> Result<String, String> {
    let der = b64()
        .decode(key_b64.trim())
        .map_err(|_| "key: bad base64".to_string())?;
    let pair = signature::Ed25519KeyPair::from_pkcs8(&der).map_err(|_| "key: bad PKCS#8")?;
    let mut msg = Vec::with_capacity(SIG_CONTEXT.len() + body.len());
    msg.extend_from_slice(SIG_CONTEXT);
    msg.extend_from_slice(body);
    let sig = pair.sign(&msg);
    let env = Envelope {
        key_id,
        body: b64().encode(body),
        sig: b64().encode(sig.as_ref()),
    };
    Ok(serde_json::to_string(&env).expect("envelope"))
}

/// A fresh Ed25519 key: (base64 PKCS#8 private, base64 raw public).
pub fn generate_key() -> (String, String) {
    let rng = ring::rand::SystemRandom::new();
    let der = signature::Ed25519KeyPair::generate_pkcs8(&rng).expect("ed25519 keygen");
    let pair = signature::Ed25519KeyPair::from_pkcs8(der.as_ref()).expect("fresh key");
    (
        b64().encode(der.as_ref()),
        b64().encode(pair.public_key().as_ref()),
    )
}

/// Parse a base64 Ed25519 public key.
pub fn parse_public_key(text: &str) -> Result<Vec<u8>, String> {
    let k = b64()
        .decode(text.trim())
        .map_err(|_| "public key: bad base64".to_string())?;
    if k.len() != 32 {
        return Err("public key: must be 32 bytes".into());
    }
    Ok(k)
}

/// The AI part of a bundle body (other fields are ignored here; the kernel
/// checks them).
#[derive(Debug, Clone, Deserialize)]
pub struct AiView {
    pub version: u64,
    /// Unix seconds; the bundle is invalid at and after this time.
    pub expires_at: u64,
    #[serde(default)]
    pub ai_domains: Vec<String>,
    #[serde(default)]
    pub ai_cidrs: Vec<String>,
}

impl AiView {
    pub fn parse(body: &[u8]) -> Result<Self, EnvelopeError> {
        serde_json::from_slice(body).map_err(|e| EnvelopeError::Malformed(format!("body: {e}")))
    }
}

/// Lowercased, trailing dot removed: the form names are matched in.
pub fn normalize_domain(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The canonical form of a DNS name, or `None` if it is not one: lowercase,
/// one optional trailing dot removed, 1..=253 bytes, labels of 1..=63 bytes
/// from `[a-z0-9_-]`. A leading dot, an empty label or whitespace is
/// rejected, not repaired: a signed list means the same to every consumer.
pub fn canonical_domain(name: &str) -> Option<String> {
    let n = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let ok = !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    ok.then_some(n)
}

/// `name` equals `suffix` or ends with `.suffix` (both normalized).
pub fn suffix_match(name: &str, suffix: &str) -> bool {
    name == suffix
        || (name.len() > suffix.len()
            && name.ends_with(suffix)
            && name.as_bytes()[name.len() - suffix.len() - 1] == b'.')
}

/// The AI set of one bundle: the single classification both the client
/// kernel and the relay use (KERNEL_SPEC §5.5 item 7), so the same signed
/// bytes are accepted or refused, and match, identically on both ends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AiSet {
    suffixes: Vec<String>,
    cidrs: Vec<Cidr>,
}

impl AiSet {
    /// Every entry must already be canonical ([`canonical_domain`],
    /// [`Cidr::parse`]); one bad entry refuses the whole bundle.
    pub fn parse(domains: &[String], cidrs: &[String]) -> Result<Self, String> {
        let suffixes = domains
            .iter()
            .enumerate()
            .map(|(i, d)| {
                canonical_domain(d).ok_or_else(|| format!("ai_domains[{i}]: bad domain {d:?}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let cidrs = cidrs
            .iter()
            .enumerate()
            .map(|(i, c)| Cidr::parse(c).map_err(|e| format!("ai_cidrs[{i}]: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { suffixes, cidrs })
    }

    pub fn from_view(v: &AiView) -> Result<Self, String> {
        Self::parse(&v.ai_domains, &v.ai_cidrs)
    }

    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty() && self.cidrs.is_empty()
    }

    /// `name` (any case, trailing dot allowed) is an AI domain.
    pub fn is_ai_domain(&self, name: &str) -> bool {
        let n = normalize_domain(name);
        self.suffixes.iter().any(|s| suffix_match(&n, s))
    }

    /// `ip` (IPv4-mapped IPv6 as IPv4) is in an AI range.
    pub fn is_ai_ip(&self, ip: IpAddr) -> bool {
        any_contains(&self.cidrs, ip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_open_tamper() {
        let (k, p) = generate_key();
        let keys: BTreeMap<u32, Vec<u8>> = [(1, parse_public_key(&p).unwrap())].into();
        let body = br#"{"version":3,"expires_at":9,"ai_domains":["openai.com"],"ai_cidrs":["1.2.3.0/24"],"rules":[]}"#;
        let env = sign(&k, 1, body).unwrap();
        assert_eq!(open(&keys, env.as_bytes()).unwrap(), body.to_vec());
        let v = AiView::parse(body).unwrap();
        assert_eq!((v.version, v.ai_domains.len(), v.ai_cidrs.len()), (3, 1, 1));
        assert_eq!(
            open(&keys, sign(&k, 2, body).unwrap().as_bytes()),
            Err(EnvelopeError::UnknownKey(2))
        );
        let (other, _) = generate_key();
        assert_eq!(
            open(&keys, sign(&other, 1, body).unwrap().as_bytes()),
            Err(EnvelopeError::BadSignature)
        );
        assert!(suffix_match("api.openai.com", "openai.com"));
        assert!(!suffix_match("notopenai.com", "openai.com"));
    }

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Review r5 N3: non-canonical entries are refused, never repaired
    /// differently by each consumer.
    #[test]
    fn ai_set_is_strict() {
        for bad in [
            ".openai.com",
            " openai.com",
            "openai.com ",
            "a..b",
            "",
            ".",
            "a/b",
            "x.com..",
        ] {
            assert!(
                AiSet::parse(&strs(&[bad]), &[]).is_err(),
                "{bad:?} accepted"
            );
        }
        for bad in [" 1.2.3.0/24", "1.2.3.0/33", "1.2.3.0/"] {
            assert!(
                AiSet::parse(&[], &strs(&[bad])).is_err(),
                "{bad:?} accepted"
            );
        }
        let s = AiSet::parse(
            &strs(&["OpenAI.com.", "ai.test"]),
            &strs(&["203.0.113.0/24"]),
        )
        .unwrap();
        assert!(s.is_ai_domain("api.openai.com") && s.is_ai_domain("API.OpenAI.Com."));
        assert!(!s.is_ai_domain("notopenai.com") && !s.is_ai_domain("openai.com.evil"));
        assert!(s.is_ai_ip("203.0.113.9".parse().unwrap()));
        assert!(s.is_ai_ip("::ffff:203.0.113.9".parse().unwrap()));
        assert!(!s.is_ai_ip("203.0.114.9".parse().unwrap()));
    }
}
