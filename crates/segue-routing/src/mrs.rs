//! Reader for mihomo binary rule-sets (`.mrs`, format version 1).
//!
//! The file is one zstd frame. Inflated, it is `MRS`, a version byte (1), a
//! behaviour byte, an int64 rule count, an int64 extra length and that many
//! reserved bytes, then the behaviour payload. `domain` (0) is a succinct
//! domain set (`component/trie/domain_set_bin.go`): version 1, then big-endian
//! int64 lengths for the leaf bitmap, the label bitmap and the label bytes.
//! `ipcidr` (1) is sorted inclusive ranges (`component/cidr/ipcidr_set_bin.go`),
//! each endpoint 16 bytes, IPv4 stored IPv4-mapped and unmapped on read.
//! `classical` is not stored in this format and is rejected.
//!
//! mihomo's domain set is the same succinct trie as sing-box, addressed by
//! bytes of the rune-reversed pattern. A trailing `+` in that key is the
//! leading-dot suffix wildcard. `*` is one label. Those become
//! [`crate::DomainMatcher`] values on one [`crate::srs::FlatRule`], so a
//! routing rule can OR them the way it ORs a sing-box rule-set. An exact name
//! and its dot-suffix together are one [`DomainMatcher::Suffix`].
//!
//! zstd is decoded with `ruzstd` rather than the workspace's `zstd` crate.
//! `zstd` links libzstd, and a C library is the wrong dependency for the iOS
//! and Android cross builds; this path only needs a decoder. The frame and
//! the inflated bytes are both size-capped.

use std::collections::BTreeSet;
use std::io::{self, ErrorKind, Read};

use ruzstd::decoding::errors::FrameDecoderError;
use ruzstd::decoding::{FrameDecoder, StreamingDecoder};
use thiserror::Error;

use crate::srs::{cidrs_for_range, succinct_keys, FlatRule, IpBytes};
use crate::{DomainMatcher, RegexMatcher};

/// Largest `.mrs` file accepted on disk. Same cap as a geodata file.
pub const MAX_MRS_FILE_BYTES: u64 = 128 * 1024 * 1024;
/// Largest inflated rule-set. A small frame cannot expand without bound.
pub const MAX_MRS_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

const MRS_VERSION: u8 = 1;
const BEHAVIOR_DOMAIN: u8 = 0;
const BEHAVIOR_IPCIDR: u8 = 1;
const BEHAVIOR_CLASSICAL: u8 = 2;
const SET_VERSION: u8 = 1;
const MAX_BITMAP_WORDS: usize = 1_048_576;
const MAX_LABELS: usize = 8_000_000;
const MAX_DOMAINS: usize = 200_000;
const MAX_IP_CIDRS: usize = 500_000;

const LIMIT_MESSAGE: &str = "inflated rule-set exceeds the size limit";

/// Caps for one decode. [`Default`] matches the constants above.
#[derive(Debug, Clone, Copy)]
pub struct MrsLimits {
    pub max_decompressed_bytes: u64,
    pub max_domains: usize,
    pub max_ip_cidrs: usize,
}

impl Default for MrsLimits {
    fn default() -> Self {
        Self {
            max_decompressed_bytes: MAX_MRS_DECOMPRESSED_BYTES,
            max_domains: MAX_DOMAINS,
            max_ip_cidrs: MAX_IP_CIDRS,
        }
    }
}

/// Which payload follows the header. Classical is a behaviour mihomo knows
/// but does not write into `.mrs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Domain,
    IpCidr,
}

#[derive(Debug, Error)]
pub enum MrsError {
    #[error("invalid mihomo rule-set file")]
    BadMagic,
    #[error("unsupported rule-set version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported rule-set behavior {0}")]
    UnsupportedBehavior(u8),
    #[error("rule-set is truncated")]
    Truncated,
    #[error("inflated rule-set exceeds {0} bytes")]
    TooLarge(u64),
    #[error("invalid rule-set: {0}")]
    Invalid(String),
    #[error("failed to read rule-set: {0}")]
    Io(io::Error),
}

/// A rule that was not applied. `rule_index` is always 0: a `.mrs` file is one set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrsWarning {
    pub rule_index: usize,
    pub message: String,
}

impl std::fmt::Display for MrsWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "rule[{}]: {}", self.rule_index, self.message)
    }
}

/// A decoded rule-set. `rules` has at most one entry and is OR'd by the routing
/// rule that named the file. `count` is mihomo's insertion count, which is not
/// the number of trie keys or merged ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MrsRuleSet {
    pub version: u8,
    pub behavior: Behavior,
    pub count: u64,
    pub rules: Vec<FlatRule>,
    pub warnings: Vec<MrsWarning>,
}

/// Reads a `.mrs` file from the start of `input` using [`MrsLimits::default`].
pub fn read_rule_set(input: impl Read) -> Result<MrsRuleSet, MrsError> {
    read_rule_set_with_limits(input, MrsLimits::default())
}

/// Reads a `.mrs` file, stopping if the frame, the inflated stream or a count
/// exceeds `limits`.
pub fn read_rule_set_with_limits(
    input: impl Read,
    limits: MrsLimits,
) -> Result<MrsRuleSet, MrsError> {
    let decoder = StreamingDecoder::new_with_max_window_size(input, limits.max_decompressed_bytes)
        .map_err(|error| map_zstd(error, limits.max_decompressed_bytes))?;
    let mut reader = Reader {
        inner: BoundedRead {
            inner: decoder,
            remaining: limits.max_decompressed_bytes,
            limit: limits.max_decompressed_bytes,
        },
        limits,
        domains: 0,
        ip_cidrs: 0,
    };

    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    if &header[..3] != b"MRS" {
        return Err(MrsError::BadMagic);
    }
    if header[3] != MRS_VERSION {
        return Err(MrsError::UnsupportedVersion(header[3]));
    }

    let behavior = match reader.read_u8()? {
        BEHAVIOR_DOMAIN => Behavior::Domain,
        BEHAVIOR_IPCIDR => Behavior::IpCidr,
        BEHAVIOR_CLASSICAL => {
            return Err(MrsError::Invalid(
                "classical behavior is not stored as .mrs".to_owned(),
            ));
        }
        other => return Err(MrsError::UnsupportedBehavior(other)),
    };
    let max_count = match behavior {
        Behavior::Domain => limits.max_domains,
        Behavior::IpCidr => limits.max_ip_cidrs,
    };
    let count = reader.read_header_count(max_count)?;
    reader.skip_extra()?;

    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    match behavior {
        Behavior::Domain => reader.read_domain_set(&mut rules, &mut warnings)?,
        Behavior::IpCidr => reader.read_ipcidr_set(&mut rules, &mut warnings)?,
    }
    Ok(MrsRuleSet {
        version: MRS_VERSION,
        behavior,
        count,
        rules,
        warnings,
    })
}

struct BoundedRead<R> {
    inner: R,
    remaining: u64,
    limit: u64,
}

impl<R: Read> Read for BoundedRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::new(ErrorKind::InvalidData, LIMIT_MESSAGE));
        }
        let max = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let end = buf.len().min(max);
        let read = self.inner.read(&mut buf[..end])?;
        self.remaining -= u64::try_from(read).unwrap_or(u64::MAX);
        Ok(read)
    }
}

struct Reader<R: Read> {
    inner: BoundedRead<StreamingDecoder<R, FrameDecoder>>,
    limits: MrsLimits,
    domains: usize,
    ip_cidrs: usize,
}

impl<R: Read> Reader<R> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), MrsError> {
        self.inner
            .read_exact(buf)
            .map_err(map_bounded_io(self.inner.limit))
    }

    fn read_u8(&mut self) -> Result<u8, MrsError> {
        let mut byte = [0u8; 1];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    fn read_i64(&mut self) -> Result<i64, MrsError> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(i64::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, MrsError> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, MrsError> {
        let mut bytes = vec![0u8; len];
        if len > 0 {
            self.read_exact(&mut bytes)?;
        }
        Ok(bytes)
    }

    fn read_header_count(&mut self, max: usize) -> Result<u64, MrsError> {
        let count = self.read_i64()?;
        if count < 0 {
            return Err(MrsError::Invalid("rule count is invalid".to_owned()));
        }
        let as_usize = usize::try_from(count)
            .map_err(|_| MrsError::Invalid("rule count does not fit".to_owned()))?;
        if as_usize > max {
            return Err(MrsError::Invalid(format!(
                "rule count {as_usize} exceeds {max}"
            )));
        }
        u64::try_from(count).map_err(|_| MrsError::Invalid("rule count does not fit".to_owned()))
    }

    /// mihomo rejects a negative extra length and skips a non-negative one.
    fn skip_extra(&mut self) -> Result<(), MrsError> {
        let length = self.read_i64()?;
        if length < 0 {
            return Err(MrsError::Invalid("extra length is invalid".to_owned()));
        }
        let length = usize::try_from(length)
            .map_err(|_| MrsError::Invalid("extra length does not fit".to_owned()))?;
        if u64::try_from(length).unwrap_or(u64::MAX) > self.limits.max_decompressed_bytes {
            return Err(MrsError::TooLarge(self.limits.max_decompressed_bytes));
        }
        self.skip_exact(length)
    }

    fn skip_exact(&mut self, len: usize) -> Result<(), MrsError> {
        let mut skipped = 0;
        let mut buf = [0u8; 4096];
        while skipped < len {
            let chunk = (len - skipped).min(buf.len());
            self.read_exact(&mut buf[..chunk])?;
            skipped += chunk;
        }
        Ok(())
    }

    /// A section length mihomo stores as a positive int64.
    fn read_section_len(&mut self, max: usize, what: &str) -> Result<usize, MrsError> {
        let length = self.read_i64()?;
        if length < 1 {
            return Err(MrsError::Invalid(format!("{what} length is invalid")));
        }
        let count = usize::try_from(length)
            .map_err(|_| MrsError::Invalid(format!("{what} length does not fit")))?;
        if count > max {
            return Err(MrsError::Invalid(format!(
                "{what} count {count} exceeds {max}"
            )));
        }
        Ok(count)
    }

    fn read_u64_words(&mut self, max: usize, what: &str) -> Result<Vec<u64>, MrsError> {
        let count = self.read_section_len(max, what)?;
        let mut words = Vec::with_capacity(count);
        for _ in 0..count {
            words.push(self.read_u64()?);
        }
        Ok(words)
    }

    fn read_domain_set(
        &mut self,
        rules: &mut Vec<FlatRule>,
        warnings: &mut Vec<MrsWarning>,
    ) -> Result<(), MrsError> {
        let version = self.read_u8()?;
        if version != SET_VERSION {
            return Err(MrsError::Invalid(format!("domain set version {version}")));
        }
        let leaves = self.read_u64_words(MAX_BITMAP_WORDS, "domain leaf bitmap")?;
        let label_bitmap = self.read_u64_words(MAX_BITMAP_WORDS, "domain label bitmap")?;
        let label_len = self.read_section_len(MAX_LABELS, "domain label")?;
        let labels = self.read_vec(label_len)?;
        let keys = succinct_keys(leaves, label_bitmap, labels)
            .map_err(|error| MrsError::Invalid(error.to_string()))?;
        if keys.is_empty() {
            warnings.push(nothing("domain set"));
            return Ok(());
        }
        let matchers = matchers_from_keys(&keys)?;
        // A `+.` pattern is two trie keys and one suffix matcher. Count the
        // larger of the two so neither the trie nor the lowered list can pass
        // the cap by hiding in the other.
        self.account_domains(keys.len().max(matchers.len()))?;
        if matchers.is_empty() {
            warnings.push(nothing("domain set"));
            return Ok(());
        }
        rules.push(flat_rule(matchers, Vec::new()));
        Ok(())
    }

    fn read_ipcidr_set(
        &mut self,
        rules: &mut Vec<FlatRule>,
        warnings: &mut Vec<MrsWarning>,
    ) -> Result<(), MrsError> {
        let version = self.read_u8()?;
        if version != SET_VERSION {
            return Err(MrsError::Invalid(format!("IP set version {version}")));
        }
        let count = self.read_section_len(self.limits.max_ip_cidrs, "IP range")?;
        let mut cidrs = Vec::new();
        for _ in 0..count {
            let mut start = [0u8; 16];
            let mut end = [0u8; 16];
            self.read_exact(&mut start)?;
            self.read_exact(&mut end)?;
            let start = unmap_endpoint(start);
            let end = unmap_endpoint(end);
            if start.as_slice().len() != end.as_slice().len() {
                return Err(MrsError::Invalid(
                    "IP range endpoints have different families".to_owned(),
                ));
            }
            if start.as_slice() > end.as_slice() {
                continue;
            }
            let split = cidrs_for_range(start.as_slice(), end.as_slice())
                .map_err(|error| MrsError::Invalid(error.to_string()))?;
            cidrs.extend(split);
            self.account_cidrs(cidrs.len())?;
        }
        if cidrs.is_empty() {
            warnings.push(nothing("ipcidr"));
            return Ok(());
        }
        rules.push(flat_rule(Vec::new(), cidrs));
        Ok(())
    }

    fn account_domains(&mut self, count: usize) -> Result<(), MrsError> {
        self.domains = self.domains.saturating_add(count);
        if self.domains > self.limits.max_domains {
            return Err(MrsError::Invalid(format!(
                "rule-set contains more than {} domains",
                self.limits.max_domains
            )));
        }
        Ok(())
    }

    fn account_cidrs(&mut self, total: usize) -> Result<(), MrsError> {
        // `total` is the running size, not a delta: splitting one range can
        // jump by more than one, and the check has to see that jump once.
        self.ip_cidrs = total;
        if self.ip_cidrs > self.limits.max_ip_cidrs {
            return Err(MrsError::Invalid(format!(
                "rule-set contains more than {} IP CIDRs",
                self.limits.max_ip_cidrs
            )));
        }
        Ok(())
    }
}

fn nothing(what: &str) -> MrsWarning {
    MrsWarning {
        rule_index: 0,
        message: format!("{what} matches nothing"),
    }
}

fn flat_rule(domains: Vec<DomainMatcher>, ip_cidrs: Vec<crate::Cidr>) -> FlatRule {
    FlatRule {
        domains,
        ip_cidrs,
        source_ip_cidrs: Vec::new(),
        ports: Vec::new(),
        source_ports: Vec::new(),
        networks: None,
    }
}

fn unmap_endpoint(bytes: [u8; 16]) -> IpBytes {
    IpBytes::unmap_v6(bytes)
}

enum Class {
    Exact(String),
    /// `.example.com`: subdomains only, not the apex.
    DotSuffix(String),
    Regex(String),
}

fn matchers_from_keys(keys: &[String]) -> Result<Vec<DomainMatcher>, MrsError> {
    let mut exact = BTreeSet::new();
    let mut dots = BTreeSet::new();
    let mut regexes = BTreeSet::new();
    for key in keys {
        match classify(key)? {
            Class::Exact(domain) => {
                exact.insert(domain);
            }
            Class::DotSuffix(domain) => {
                dots.insert(domain);
            }
            Class::Regex(pattern) => {
                regexes.insert(pattern);
            }
        }
    }

    let mut matchers = Vec::new();
    for domain in exact.intersection(&dots) {
        matchers.push(DomainMatcher::Suffix(domain.clone()));
    }
    for domain in exact.difference(&dots) {
        matchers.push(DomainMatcher::Full(domain.clone()));
    }
    for domain in dots.difference(&exact) {
        matchers.push(DomainMatcher::Subdomain(domain.clone()));
    }
    for pattern in regexes {
        matchers.push(compile_regex(pattern)?);
    }
    Ok(matchers)
}

fn classify(key: &str) -> Result<Class, MrsError> {
    let suffix_wildcard = key.ends_with('+');
    let body = if suffix_wildcard {
        &key[..key.len() - 1]
    } else {
        key
    };
    if body.contains('+') {
        return Err(MrsError::Invalid(
            "'+' wildcard is not at the end of a domain key".to_owned(),
        ));
    }
    let pattern: String = body.chars().rev().collect();
    if pattern.is_empty() {
        return Err(MrsError::Invalid("empty domain".to_owned()));
    }
    if suffix_wildcard && !pattern.starts_with('.') {
        return Err(MrsError::Invalid(
            "'+' domain wildcard is not a leading-dot suffix".to_owned(),
        ));
    }
    let starred = pattern.contains('*');
    if suffix_wildcard && !starred {
        if let Some(domain) = pattern.strip_prefix('.') {
            if plain_domain(domain) {
                return Ok(Class::DotSuffix(domain.to_owned()));
            }
        }
    }
    if !suffix_wildcard && !starred {
        if plain_domain(&pattern) {
            return Ok(Class::Exact(pattern));
        }
        return Err(MrsError::Invalid(format!(
            "domain `{pattern}` is not a mihomo domain pattern"
        )));
    }
    Ok(Class::Regex(wildcard_regex(&pattern, suffix_wildcard)?))
}

fn plain_domain(domain: &str) -> bool {
    if domain.is_empty()
        || domain.starts_with('.')
        || domain.ends_with('.')
        || domain.contains("..")
    {
        return false;
    }
    !domain
        .chars()
        .any(|character| character == '*' || character == '+')
}

fn wildcard_regex(pattern: &str, suffix_wildcard: bool) -> Result<String, MrsError> {
    let labels: Vec<&str> = pattern.split('.').collect();
    let mut body = String::new();
    for (index, label) in labels.iter().enumerate() {
        if index > 0 {
            body.push_str(r"\.");
        }
        if label.is_empty() {
            if index != 0 {
                return Err(MrsError::Invalid("empty domain label".to_owned()));
            }
            continue;
        }
        if *label == "*" {
            body.push_str("[^.]+");
            continue;
        }
        if label.contains('*') || label.contains('+') {
            return Err(MrsError::Invalid(
                "partial wildcard is not a mihomo domain label".to_owned(),
            ));
        }
        body.push_str(&regex_escape(label));
    }
    if body.is_empty() {
        return Err(MrsError::Invalid("empty domain".to_owned()));
    }
    if suffix_wildcard {
        Ok(format!(".+{body}$"))
    } else {
        Ok(format!("^{body}$"))
    }
}

fn compile_regex(pattern: String) -> Result<DomainMatcher, MrsError> {
    let matcher =
        RegexMatcher::new(pattern).map_err(|error| MrsError::Invalid(error.to_string()))?;
    Ok(DomainMatcher::Regex(matcher))
}

fn regex_escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if matches!(
            character,
            '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$' | '\\'
        ) {
            escaped.push('\\');
        }
        escaped.push(character);
    }
    escaped
}

fn map_zstd(error: FrameDecoderError, limit: u64) -> MrsError {
    let text = error.to_string();
    if text.contains("window_size is too big") {
        MrsError::TooLarge(limit)
    } else {
        MrsError::Invalid(format!("invalid zstd frame: {text}"))
    }
}

fn map_bounded_io(limit: u64) -> impl Fn(io::Error) -> MrsError {
    move |error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            MrsError::Truncated
        } else if error.to_string().contains(LIMIT_MESSAGE) {
            MrsError::TooLarge(limit)
        } else if error.kind() == ErrorKind::Other {
            MrsError::Invalid(format!("invalid zstd frame: {error}"))
        } else {
            MrsError::Io(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::{
        read_rule_set, read_rule_set_with_limits, Behavior, MrsError, MrsLimits, MAX_BITMAP_WORDS,
        MAX_IP_CIDRS,
    };
    use crate::srs::FlatRule;
    use crate::{Cidr, DomainMatcher};

    fn zstd_raw_frame(payload: &[u8]) -> Vec<u8> {
        assert!(!payload.is_empty());
        assert!(payload.len() < 256);
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x20, payload.len() as u8];
        let header = (payload.len() << 3) | 1;
        frame.extend((header as u32).to_le_bytes()[..3].iter().copied());
        frame.extend(payload);
        frame
    }

    fn mrs(behavior: u8, count: i64, extra: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut body = vec![b'M', b'R', b'S', 1, behavior];
        body.extend(count.to_be_bytes());
        body.extend((extra.len() as i64).to_be_bytes());
        body.extend(extra);
        body.extend(payload);
        zstd_raw_frame(&body)
    }

    /// Succinct set of reverse("ab") = "ba". Same bitmap the sing-box tests use.
    fn domain_set_ab() -> Vec<u8> {
        let mut body = vec![1u8];
        body.extend(1i64.to_be_bytes());
        body.extend(4u64.to_be_bytes());
        body.extend(1i64.to_be_bytes());
        body.extend(26u64.to_be_bytes());
        body.extend(2i64.to_be_bytes());
        body.extend(b"ba");
        body
    }

    fn matches_domain(rule: &FlatRule, domain: &str) -> bool {
        rule.domains.iter().any(|matcher| matcher.matches(domain))
    }

    fn covers_v4(cidrs: &[Cidr], octets: [u8; 4]) -> bool {
        let address = IpAddr::V4(Ipv4Addr::from(octets));
        cidrs.iter().any(|cidr| cidr.contains(address))
    }

    fn covers_v6(cidrs: &[Cidr], segments: [u16; 8]) -> bool {
        let address = IpAddr::V6(Ipv6Addr::from(segments));
        cidrs.iter().any(|cidr| cidr.contains(address))
    }

    fn load_fixture(name: &str) -> super::MrsRuleSet {
        let bytes: &[u8] = match name {
            "domain.mrs" => include_bytes!("../fixtures/domain.mrs"),
            "ipcidr.mrs" => include_bytes!("../fixtures/ipcidr.mrs"),
            other => panic!("unknown fixture {other}"),
        };
        read_rule_set(bytes).unwrap()
    }

    #[test]
    fn hand_built_chain_recovers_a_full_domain() {
        let set = read_rule_set(mrs(0, 1, b"xyz", &domain_set_ab()).as_slice()).unwrap();
        assert_eq!(set.behavior, Behavior::Domain);
        assert_eq!(set.count, 1);
        assert!(set.warnings.is_empty());
        assert!(matches_domain(&set.rules[0], "ab"));
        assert!(matches_domain(&set.rules[0], "AB"));
        assert!(!matches_domain(&set.rules[0], "a"));
        assert!(!matches_domain(&set.rules[0], "bab"));
        assert!(matches!(set.rules[0].domains[0], DomainMatcher::Full(_)));
    }

    #[test]
    fn fixtures_round_trip_domains_and_ip_ranges() {
        let domains = load_fixture("domain.mrs");
        assert_eq!(domains.version, 1);
        assert_eq!(domains.behavior, Behavior::Domain);
        assert_eq!(domains.count, 8);
        assert!(domains.warnings.is_empty(), "{:?}", domains.warnings);
        let rule = &domains.rules[0];
        assert!(matches_domain(rule, "example.com"));
        assert!(matches_domain(rule, "EXAMPLE.COM"));
        assert!(!matches_domain(rule, "www.example.com"));
        assert!(matches_domain(rule, "sagernet.org"));
        assert!(matches_domain(rule, "sing-box.sagernet.org"));
        assert!(!matches_domain(rule, "notsagernet.org"));
        assert!(matches_domain(rule, "example.com.cn"));
        assert!(matches_domain(rule, "a.b.com.cn"));
        assert!(!matches_domain(rule, "com.cn"));
        assert!(matches_domain(rule, "www.qq.com"));
        assert!(!matches_domain(rule, "qq.com"));
        assert!(!matches_domain(rule, "a.b.qq.com"));
        assert!(matches_domain(rule, "a.b.baidu.com"));
        assert!(!matches_domain(rule, "b.baidu.com"));
        assert!(!matches_domain(rule, "a.b.c.baidu.com"));
        assert!(matches_domain(rule, "www.baidu.com"));
        // `.com.cn` is the dot wildcard, which mihomo stores as `+.com.cn`
        // (`DomainSetBuilder.insert` rewrites the empty first label to `+`) and
        // whose `Has` returns true at the `+` node for any remaining labels
        // (mihomo `component/trie/domain_set.go`). So a deeper name under
        // com.cn matches too.
        assert!(matches_domain(rule, "www.baidu.com.cn"));
        // `www.baidu.*` is one label only, so a two-label TLD under baidu is
        // not matched by it.
        assert!(!matches_domain(rule, "www.baidu.co.uk"));
        assert!(matches_domain(rule, "пример.рф"));
        assert!(!matches_domain(rule, "www.пример.рф"));
        assert!(matches_domain(rule, "Mijia Cloud"));
        assert!(matches_domain(rule, "mijia cloud"));
        assert!(!matches_domain(rule, "Mijia"));

        let ips = load_fixture("ipcidr.mrs");
        assert_eq!(ips.behavior, Behavior::IpCidr);
        assert_eq!(ips.count, 4);
        assert!(ips.warnings.is_empty(), "{:?}", ips.warnings);
        let ip_rule = &ips.rules[0];
        assert!(ip_rule.domains.is_empty());
        assert!(covers_v4(&ip_rule.ip_cidrs, [10, 1, 2, 3]));
        assert!(!covers_v4(&ip_rule.ip_cidrs, [11, 0, 0, 1]));
        assert!(covers_v4(&ip_rule.ip_cidrs, [192, 0, 2, 10]));
        assert!(!covers_v4(&ip_rule.ip_cidrs, [192, 0, 3, 1]));
        assert!(covers_v4(&ip_rule.ip_cidrs, [203, 0, 113, 1]));
        assert!(covers_v4(&ip_rule.ip_cidrs, [203, 0, 113, 2]));
        assert!(!covers_v4(&ip_rule.ip_cidrs, [203, 0, 113, 0]));
        assert!(!covers_v4(&ip_rule.ip_cidrs, [203, 0, 113, 3]));
        assert!(covers_v6(
            &ip_rule.ip_cidrs,
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]
        ));
        assert!(!covers_v6(
            &ip_rule.ip_cidrs,
            [0x2001, 0x0db9, 0, 0, 0, 0, 0, 1]
        ));
    }

    #[test]
    fn bad_magic_version_behavior_and_truncated_input_fail() {
        assert!(matches!(
            read_rule_set(zstd_raw_frame(b"NOPE").as_slice()).unwrap_err(),
            MrsError::BadMagic
        ));
        assert!(matches!(
            read_rule_set(zstd_raw_frame(b"MRS\x02").as_slice()).unwrap_err(),
            MrsError::UnsupportedVersion(2)
        ));
        assert!(matches!(
            read_rule_set(zstd_raw_frame(b"MRS\x01\x02").as_slice()).unwrap_err(),
            MrsError::Invalid(message) if message.contains("classical")
        ));
        assert!(matches!(
            read_rule_set(zstd_raw_frame(b"MRS\x01\x09").as_slice()).unwrap_err(),
            MrsError::UnsupportedBehavior(9)
        ));
        assert!(matches!(
            read_rule_set(zstd_raw_frame(b"MRS").as_slice()).unwrap_err(),
            MrsError::Truncated
        ));
        let frame = zstd_raw_frame(b"MRS\x01");
        assert!(matches!(
            read_rule_set(&frame[..frame.len() / 2]).unwrap_err(),
            MrsError::Invalid(_) | MrsError::Truncated
        ));
        assert!(matches!(
            read_rule_set(&b"not zstd"[..]).unwrap_err(),
            MrsError::Invalid(_)
        ));
    }

    #[test]
    fn oversized_counts_and_negative_lengths_fail() {
        let limits = MrsLimits {
            max_domains: 4,
            ..MrsLimits::default()
        };
        let error = read_rule_set_with_limits(mrs(0, 5, b"", b"").as_slice(), limits).unwrap_err();
        assert!(
            matches!(error, MrsError::Invalid(ref message) if message.contains("exceeds 4")),
            "{error}"
        );

        let mut ip = vec![1u8];
        ip.extend((i64::try_from(MAX_IP_CIDRS).unwrap() + 1).to_be_bytes());
        let error = read_rule_set(mrs(1, 1, b"", &ip).as_slice()).unwrap_err();
        assert!(
            matches!(error, MrsError::Invalid(ref message) if message.contains("exceeds")),
            "{error}"
        );

        let mut leaves = vec![1u8];
        leaves.extend((i64::try_from(MAX_BITMAP_WORDS).unwrap() + 1).to_be_bytes());
        let error = read_rule_set(mrs(0, 1, b"", &leaves).as_slice()).unwrap_err();
        assert!(
            matches!(error, MrsError::Invalid(ref message) if message.contains("exceeds")),
            "{error}"
        );

        let error = read_rule_set(mrs(0, -1, b"", b"").as_slice()).unwrap_err();
        assert!(
            matches!(error, MrsError::Invalid(ref message) if message.contains("rule count")),
            "{error}"
        );

        let mut negative_extra = vec![b'M', b'R', b'S', 1, 0];
        negative_extra.extend(1i64.to_be_bytes());
        negative_extra.extend((-1i64).to_be_bytes());
        let error = read_rule_set(zstd_raw_frame(&negative_extra).as_slice()).unwrap_err();
        assert!(
            matches!(error, MrsError::Invalid(ref message) if message.contains("extra")),
            "{error}"
        );

        let error =
            read_rule_set(mrs(0, 1, b"", &[1, 0, 0, 0, 0, 0, 0, 0, 0]).as_slice()).unwrap_err();
        assert!(
            matches!(
                error,
                MrsError::Invalid(ref message) if message.contains("length is invalid")
            ),
            "{error}"
        );
    }

    #[test]
    fn inflated_stream_is_capped() {
        let limits = MrsLimits {
            max_decompressed_bytes: 8,
            ..MrsLimits::default()
        };
        let error =
            read_rule_set_with_limits(zstd_raw_frame(&[0u8; 64]).as_slice(), limits).unwrap_err();
        assert!(matches!(error, MrsError::TooLarge(8)), "{error}");
    }

    #[test]
    fn inverted_ip_range_matches_nothing() {
        let mut payload = vec![1u8];
        payload.extend(1i64.to_be_bytes());
        payload.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2]);
        payload.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1]);
        let set = read_rule_set(mrs(1, 1, b"", &payload).as_slice()).unwrap();
        assert!(set.rules.is_empty());
        assert!(set.warnings[0].message.contains("matches nothing"));
    }

    #[test]
    fn domain_set_version_must_be_one() {
        let mut payload = domain_set_ab();
        payload[0] = 2;
        let error = read_rule_set(mrs(0, 1, b"", &payload).as_slice()).unwrap_err();
        assert!(
            matches!(
                error,
                MrsError::Invalid(ref message) if message.contains("domain set version")
            ),
            "{error}"
        );
    }
}
