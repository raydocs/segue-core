//! Reader for sing-box binary rule-sets (`.srs`, format versions 1–5).
//!
//! The file is `SRS`, a version byte, then a zlib stream. Inside, a uvarint
//! rule count and that many headless rules, in the layout of
//! `sing-box/common/srs/binary.go`. A default rule's items are AND'd across
//! groups, except destination domains and destination IP CIDRs, which sing-box
//! OR's into one destination group. Logical `or` flattens to that same OR.
//! Logical `and` is merged when each field is constrained by only one side.
//!
//! Items Segue cannot match (process, package, wifi, AdGuard, network type,
//! invert, and the rest) are reported and that rule matches nothing. An empty
//! rule, which sing-box would treat as matching every connection, is also
//! reported and matches nothing: a missing item must not become a match-all.
//!
//! The zlib stream is decoded as it is read. The compressed bytes are not
//! buffered beside the decompressed ones, and both the file and the
//! decompressed stream are size-capped.

use std::io::{self, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use flate2::read::ZlibDecoder;
use thiserror::Error;

use crate::{Cidr, DomainMatcher, Network, RegexMatcher};

/// Largest `.srs` file accepted on disk. Same cap as a geodata file.
pub const MAX_SRS_FILE_BYTES: u64 = 128 * 1024 * 1024;
/// Largest decompressed rule-set. A small compressed file cannot expand without bound.
pub const MAX_SRS_DECOMPRESSED_BYTES: u64 = 128 * 1024 * 1024;

const SRS_VERSION_MIN: u8 = 1;
const SRS_VERSION_MAX: u8 = 5;
const MAX_RULES: usize = 65_536;
const MAX_DOMAINS: usize = 200_000;
const MAX_IP_CIDRS: usize = 500_000;
const MAX_STRING_BYTES: usize = 4 * 1024;
const MAX_BITMAP_WORDS: usize = 1_048_576;
const MAX_LABELS: usize = 8_000_000;
const MAX_LOGICAL_DEPTH: usize = 100;
const MAX_PORT_VALUES: usize = 65_536;
const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xFF;

const LIMIT_MESSAGE: &str = "decompressed rule-set exceeds the size limit";

/// Caps for one decode. [`Default`] matches the constants above.
#[derive(Debug, Clone, Copy)]
pub struct SrsLimits {
    pub max_decompressed_bytes: u64,
    pub max_rules: usize,
    pub max_domains: usize,
    pub max_ip_cidrs: usize,
}

impl Default for SrsLimits {
    fn default() -> Self {
        Self {
            max_decompressed_bytes: MAX_SRS_DECOMPRESSED_BYTES,
            max_rules: MAX_RULES,
            max_domains: MAX_DOMAINS,
            max_ip_cidrs: MAX_IP_CIDRS,
        }
    }
}

#[derive(Debug, Error)]
pub enum SrsError {
    #[error("invalid sing-box rule-set file")]
    BadMagic,
    #[error("unsupported rule-set version {0}")]
    UnsupportedVersion(u8),
    #[error("rule-set is truncated")]
    Truncated,
    #[error("decompressed rule-set exceeds {0} bytes")]
    TooLarge(u64),
    #[error("invalid rule-set: {0}")]
    Invalid(String),
    #[error("failed to read rule-set: {0}")]
    Io(io::Error),
}

/// One inclusive port span. `start` is never greater than `end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SrsPortRange {
    pub start: u16,
    pub end: u16,
}

/// A default rule Segue can match, or one branch of a logical `or` / `and`.
///
/// Empty `domains`, `ip_cidrs`, `source_ip_cidrs`, `ports` or `source_ports`
/// means that field is not constrained. `networks` is `None` when the rule
/// does not care, and never an empty list.
///
/// When a sing-box rule sets both domains and destination IPs, they are OR'd.
/// That arrives here as two [`FlatRule`]s that share the other fields, because
/// a Segue routing rule AND's its domain set with its IP set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlatRule {
    pub domains: Vec<DomainMatcher>,
    pub ip_cidrs: Vec<Cidr>,
    pub source_ip_cidrs: Vec<Cidr>,
    pub ports: Vec<SrsPortRange>,
    pub source_ports: Vec<SrsPortRange>,
    pub networks: Option<Vec<Network>>,
}

/// A rule that was not applied. `rule_index` is the top-level rule in the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsWarning {
    pub rule_index: usize,
    pub message: String,
}

impl std::fmt::Display for SrsWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "rule[{}]: {}", self.rule_index, self.message)
    }
}

/// A decoded rule-set. `rules` are OR'd. `warnings` are rules (or pieces of
/// rules) that were dropped instead of being widened into a match-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrsRuleSet {
    pub version: u8,
    pub rules: Vec<FlatRule>,
    pub warnings: Vec<SrsWarning>,
}

/// Reads a `.srs` file from the start of `input` using [`SrsLimits::default`].
pub fn read_rule_set(input: impl Read) -> Result<SrsRuleSet, SrsError> {
    read_rule_set_with_limits(input, SrsLimits::default())
}

/// Reads a `.srs` file, stopping if the decompressed stream or a count exceeds `limits`.
pub fn read_rule_set_with_limits(
    mut input: impl Read,
    limits: SrsLimits,
) -> Result<SrsRuleSet, SrsError> {
    let mut header = [0u8; 4];
    input.read_exact(&mut header).map_err(map_io)?;
    if &header[..3] != b"SRS" {
        return Err(SrsError::BadMagic);
    }
    let version = header[3];
    if !(SRS_VERSION_MIN..=SRS_VERSION_MAX).contains(&version) {
        return Err(SrsError::UnsupportedVersion(version));
    }

    let decoder = ZlibDecoder::new(input);
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
    let rule_count = reader.read_count(limits.max_rules, "rule")?;
    let mut raw = Vec::with_capacity(rule_count);
    for _ in 0..rule_count {
        raw.push(reader.read_rule(0)?);
    }

    let mut rules = Vec::new();
    let mut warnings = Vec::new();
    for (index, rule) in raw.into_iter().enumerate() {
        lower(rule, index, &limits, &mut warnings, &mut rules);
    }
    Ok(SrsRuleSet {
        version,
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

struct Reader<R> {
    inner: BoundedRead<R>,
    limits: SrsLimits,
    domains: usize,
    ip_cidrs: usize,
}

impl<R: Read> Reader<R> {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), SrsError> {
        self.inner
            .read_exact(buf)
            .map_err(map_bounded_io(self.inner.limit))
    }

    fn read_u8(&mut self) -> Result<u8, SrsError> {
        let mut byte = [0u8; 1];
        self.read_exact(&mut byte)?;
        Ok(byte[0])
    }

    fn read_bool(&mut self) -> Result<bool, SrsError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(SrsError::Invalid(format!("invalid boolean byte {other}"))),
        }
    }

    fn read_u16(&mut self) -> Result<u16, SrsError> {
        let mut bytes = [0u8; 2];
        self.read_exact(&mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn read_u64(&mut self) -> Result<u64, SrsError> {
        let mut bytes = [0u8; 8];
        self.read_exact(&mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, SrsError> {
        let mut bytes = vec![0u8; len];
        if len > 0 {
            self.read_exact(&mut bytes)?;
        }
        Ok(bytes)
    }

    /// `encoding/binary.ReadUvarint`: at most ten bytes, and the tenth may only be 0 or 1.
    fn read_uvarint(&mut self) -> Result<u64, SrsError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.read_u8()?;
            if shift == 63 && byte > 1 {
                return Err(SrsError::Invalid("uvarint overflows".to_owned()));
            }
            if byte < 0x80 {
                return Ok(value | (u64::from(byte) << shift));
            }
            value |= u64::from(byte & 0x7f) << shift;
        }
        Err(SrsError::Invalid("uvarint overflows".to_owned()))
    }

    fn read_count(&mut self, max: usize, what: &str) -> Result<usize, SrsError> {
        let value = self.read_uvarint()?;
        let count = usize::try_from(value)
            .map_err(|_| SrsError::Invalid(format!("{what} count does not fit")))?;
        if count > max {
            return Err(SrsError::Invalid(format!(
                "{what} count {count} exceeds {max}"
            )));
        }
        Ok(count)
    }

    fn read_bytes_counted(&mut self, max: usize, what: &str) -> Result<Vec<u8>, SrsError> {
        let len = self.read_count(max, what)?;
        self.read_vec(len)
    }

    fn read_text(&mut self) -> Result<String, SrsError> {
        let bytes = self.read_bytes_counted(MAX_STRING_BYTES, "string")?;
        String::from_utf8(bytes).map_err(|_| SrsError::Invalid("string is not utf-8".to_owned()))
    }

    fn read_strings(&mut self) -> Result<Vec<String>, SrsError> {
        let count = self.read_count(self.limits.max_domains, "string")?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.read_text()?);
        }
        Ok(values)
    }

    fn skip_exact(&mut self, len: usize) -> Result<(), SrsError> {
        let mut skipped = 0;
        let mut buf = [0u8; 4096];
        while skipped < len {
            let chunk = (len - skipped).min(buf.len());
            self.read_exact(&mut buf[..chunk])?;
            skipped += chunk;
        }
        Ok(())
    }

    fn skip_u16s(&mut self) -> Result<(), SrsError> {
        let count = self.read_count(MAX_PORT_VALUES, "uint16")?;
        self.skip_exact(count.saturating_mul(2))
    }

    fn read_u16s(&mut self) -> Result<Vec<u16>, SrsError> {
        let count = self.read_count(MAX_PORT_VALUES, "port")?;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(self.read_u16()?);
        }
        Ok(values)
    }

    fn read_rule(&mut self, depth: usize) -> Result<RawRule, SrsError> {
        if depth > MAX_LOGICAL_DEPTH {
            return Err(SrsError::Invalid("logical rule nested too deep".to_owned()));
        }
        match self.read_u8()? {
            0 => Ok(RawRule::Default(Box::new(self.read_default()?))),
            1 => self.read_logical(depth),
            other => Err(SrsError::Invalid(format!("unknown rule type {other}"))),
        }
    }

    fn read_logical(&mut self, depth: usize) -> Result<RawRule, SrsError> {
        let mode = match self.read_u8()? {
            0 => LogicalMode::And,
            1 => LogicalMode::Or,
            other => {
                return Err(SrsError::Invalid(format!("unknown logical mode {other}")));
            }
        };
        let count = self.read_count(self.limits.max_rules, "logical rule")?;
        let mut rules = Vec::with_capacity(count);
        for _ in 0..count {
            rules.push(self.read_rule(depth + 1)?);
        }
        let invert = self.read_bool()?;
        Ok(RawRule::Logical {
            mode,
            rules,
            invert,
        })
    }

    fn read_default(&mut self) -> Result<RawDefault, SrsError> {
        let mut rule = RawDefault::default();
        loop {
            match self.read_u8()? {
                ITEM_QUERY_TYPE => {
                    self.skip_u16s()?;
                    rule.mark("query_type");
                }
                ITEM_NETWORK => rule.network = Some(self.read_strings()?),
                ITEM_DOMAIN => rule.trie = self.read_domain_trie()?,
                ITEM_DOMAIN_KEYWORD => {
                    rule.keywords = self.read_strings()?;
                    self.account_domains(rule.keywords.len())?;
                }
                ITEM_DOMAIN_REGEX => {
                    rule.regexes = self.read_strings()?;
                    self.account_domains(rule.regexes.len())?;
                }
                ITEM_SOURCE_IP_CIDR => {
                    rule.source_ips = self.read_ip_set()?;
                    rule.saw_source_ip = true;
                }
                ITEM_IP_CIDR => {
                    rule.ips = self.read_ip_set()?;
                    rule.saw_ip = true;
                }
                ITEM_SOURCE_PORT => rule.source_exact = self.read_u16s()?,
                ITEM_SOURCE_PORT_RANGE => rule.source_ranges = self.read_strings()?,
                ITEM_PORT => rule.exact = self.read_u16s()?,
                ITEM_PORT_RANGE => rule.ranges = self.read_strings()?,
                ITEM_PROCESS_NAME => {
                    self.read_strings()?;
                    rule.mark("process_name");
                }
                ITEM_PROCESS_PATH => {
                    self.read_strings()?;
                    rule.mark("process_path");
                }
                ITEM_PROCESS_PATH_REGEX => {
                    self.read_strings()?;
                    rule.mark("process_path_regex");
                }
                ITEM_PACKAGE_NAME => {
                    self.read_strings()?;
                    rule.mark("package_name");
                }
                ITEM_PACKAGE_NAME_REGEX => {
                    self.read_strings()?;
                    rule.mark("package_name_regex");
                }
                ITEM_WIFI_SSID => {
                    self.read_strings()?;
                    rule.mark("wifi_ssid");
                }
                ITEM_WIFI_BSSID => {
                    self.read_strings()?;
                    rule.mark("wifi_bssid");
                }
                ITEM_ADGUARD => {
                    self.read_succinct()?;
                    rule.mark("adguard_domain");
                }
                ITEM_NETWORK_TYPE => {
                    let count = self.read_count(256, "network_type")?;
                    self.skip_exact(count)?;
                    rule.mark("network_type");
                }
                ITEM_NETWORK_IS_EXPENSIVE => rule.mark("network_is_expensive"),
                ITEM_NETWORK_IS_CONSTRAINED => rule.mark("network_is_constrained"),
                ITEM_NETWORK_INTERFACE_ADDRESS => {
                    self.skip_interface_map()?;
                    rule.mark("network_interface_address");
                }
                ITEM_DEFAULT_INTERFACE_ADDRESS => {
                    self.skip_prefixes()?;
                    rule.mark("default_interface_address");
                }
                ITEM_FINAL => {
                    rule.invert = self.read_bool()?;
                    return Ok(rule);
                }
                other => {
                    return Err(SrsError::Invalid(format!("unknown rule item type {other}")));
                }
            }
        }
    }

    fn read_domain_trie(&mut self) -> Result<Vec<DomainMatcher>, SrsError> {
        let succinct = self.read_succinct()?;
        let keys = succinct.keys()?;
        let (domains, suffixes) = dump_domains(keys)?;
        let matchers = matchers_from_dump(domains, suffixes)?;
        self.account_domains(matchers.len())?;
        Ok(matchers)
    }

    fn account_domains(&mut self, count: usize) -> Result<(), SrsError> {
        self.domains = self.domains.saturating_add(count);
        if self.domains > self.limits.max_domains {
            return Err(SrsError::Invalid(format!(
                "rule-set contains more than {} domains",
                self.limits.max_domains
            )));
        }
        Ok(())
    }

    fn account_cidrs(&mut self, count: usize) -> Result<(), SrsError> {
        self.ip_cidrs = self.ip_cidrs.saturating_add(count);
        if self.ip_cidrs > self.limits.max_ip_cidrs {
            return Err(SrsError::Invalid(format!(
                "rule-set contains more than {} IP CIDRs",
                self.limits.max_ip_cidrs
            )));
        }
        Ok(())
    }

    fn read_ip_set(&mut self) -> Result<Vec<Cidr>, SrsError> {
        let version = self.read_u8()?;
        if version != 1 {
            return Err(SrsError::Invalid(format!(
                "unknown IP set version {version}"
            )));
        }
        let count = self.read_u64()?;
        let count = usize::try_from(count)
            .map_err(|_| SrsError::Invalid("IP set length does not fit".to_owned()))?;
        if count > self.limits.max_ip_cidrs {
            return Err(SrsError::Invalid(format!(
                "IP set length {count} exceeds {}",
                self.limits.max_ip_cidrs
            )));
        }
        let mut cidrs = Vec::new();
        for _ in 0..count {
            let start = self.read_ip_addr()?;
            let end = self.read_ip_addr()?;
            if start.len() != end.len() {
                return Err(SrsError::Invalid(
                    "IP range endpoints have different lengths".to_owned(),
                ));
            }
            if start.as_slice() > end.as_slice() {
                // An inverted range matches nothing. Leave it out; the caller
                // notices when a present item produced no address.
                continue;
            }
            cidrs.extend(cidrs_for_range(&start, &end)?);
        }
        self.account_cidrs(cidrs.len())?;
        Ok(cidrs)
    }

    fn read_ip_addr(&mut self) -> Result<Vec<u8>, SrsError> {
        let len = self.read_count(16, "IP address")?;
        if len != 4 && len != 16 {
            return Err(SrsError::Invalid(format!("IP address length {len}")));
        }
        self.read_vec(len)
    }

    fn read_succinct(&mut self) -> Result<Succinct, SrsError> {
        // sing-box reads a version byte and ignores it.
        let _version = self.read_u8()?;
        let leaves = self.read_u64_words()?;
        let label_bitmap = self.read_u64_words()?;
        let labels = self.read_bytes_counted(MAX_LABELS, "label")?;
        let mut succinct = Succinct {
            leaves,
            label_bitmap,
            labels,
        };
        succinct.validate()?;
        Ok(succinct)
    }

    fn read_u64_words(&mut self) -> Result<Vec<u64>, SrsError> {
        let count = self.read_count(MAX_BITMAP_WORDS, "bitmap")?;
        let mut words = Vec::with_capacity(count);
        for _ in 0..count {
            words.push(self.read_u64()?);
        }
        Ok(words)
    }

    fn skip_prefixes(&mut self) -> Result<(), SrsError> {
        let count = self.read_count(self.limits.max_ip_cidrs, "prefix")?;
        for _ in 0..count {
            self.skip_one_prefix()?;
        }
        Ok(())
    }

    fn skip_one_prefix(&mut self) -> Result<(), SrsError> {
        let len = self.read_count(16, "prefix address")?;
        if len != 4 && len != 16 {
            return Err(SrsError::Invalid(format!("prefix address length {len}")));
        }
        self.skip_exact(len)?;
        let _bits = self.read_u8()?;
        Ok(())
    }

    fn skip_interface_map(&mut self) -> Result<(), SrsError> {
        let entries = self.read_count(256, "network interface")?;
        for _ in 0..entries {
            let _key = self.read_u8()?;
            self.skip_prefixes()?;
        }
        Ok(())
    }
}

fn map_io(error: io::Error) -> SrsError {
    if error.kind() == ErrorKind::UnexpectedEof {
        SrsError::Truncated
    } else {
        SrsError::Io(error)
    }
}

fn map_bounded_io(limit: u64) -> impl Fn(io::Error) -> SrsError {
    move |error| {
        if error.kind() == ErrorKind::UnexpectedEof {
            SrsError::Truncated
        } else if error.to_string().contains(LIMIT_MESSAGE) {
            SrsError::TooLarge(limit)
        } else {
            SrsError::Io(error)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LogicalMode {
    And,
    Or,
}

enum RawRule {
    Default(Box<RawDefault>),
    Logical {
        mode: LogicalMode,
        rules: Vec<RawRule>,
        invert: bool,
    },
}

#[derive(Debug, Default)]
struct RawDefault {
    trie: Vec<DomainMatcher>,
    keywords: Vec<String>,
    regexes: Vec<String>,
    ips: Vec<Cidr>,
    source_ips: Vec<Cidr>,
    exact: Vec<u16>,
    ranges: Vec<String>,
    source_exact: Vec<u16>,
    source_ranges: Vec<String>,
    network: Option<Vec<String>>,
    unsupported: Vec<&'static str>,
    saw_ip: bool,
    saw_source_ip: bool,
    invert: bool,
}

impl RawDefault {
    fn mark(&mut self, name: &'static str) {
        if !self.unsupported.contains(&name) {
            self.unsupported.push(name);
        }
    }
}

struct Succinct {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
}

impl Succinct {
    fn validate(&mut self) -> Result<(), SrsError> {
        let (ones, zeros) = count_label_bitmap(&self.label_bitmap)?;
        if ones != zeros + 1 || self.labels.len() != zeros {
            return Err(SrsError::Invalid("malformed succinct set".to_owned()));
        }
        let words = (ones + 63) >> 6;
        if self.leaves.len() < words {
            self.leaves.resize(words, 0);
        }
        Ok(())
    }

    fn keys(&self) -> Result<Vec<String>, SrsError> {
        let ranks = ranks_of(&self.label_bitmap)?;
        let selects = selects_of(&self.label_bitmap)?;
        let mut result = Vec::new();
        let mut current = Vec::new();
        if bit(&self.leaves, 0)? == 1 {
            result.push(String::new());
        }
        let mut stack = vec![(0usize, 0usize)];
        let step_limit = self.labels.len().saturating_mul(4).saturating_add(8);
        let mut steps = 0usize;
        while let Some(&(node_id, bitmap_index)) = stack.last() {
            steps += 1;
            if steps > step_limit {
                return Err(SrsError::Invalid(
                    "succinct set walk did not finish".to_owned(),
                ));
            }
            if bit(&self.label_bitmap, bitmap_index)? == 1 {
                stack.pop();
                if !stack.is_empty() {
                    current.pop();
                    let last = stack.len() - 1;
                    stack[last].1 = stack[last].1.saturating_add(1);
                }
                continue;
            }
            let label_index = bitmap_index
                .checked_sub(node_id)
                .ok_or_else(|| SrsError::Invalid("succinct label index underflows".to_owned()))?;
            let label = *self.labels.get(label_index).ok_or_else(|| {
                SrsError::Invalid("succinct label index is out of range".to_owned())
            })?;
            current.push(label);
            let next_node = count_zeros(&self.label_bitmap, &ranks, bitmap_index + 1)?;
            if next_node == 0 {
                return Err(SrsError::Invalid(
                    "succinct child node is the root".to_owned(),
                ));
            }
            let next_bitmap = select_ith_one(
                &self.label_bitmap,
                &ranks,
                &selects,
                i32::try_from(next_node - 1)
                    .map_err(|_| SrsError::Invalid("succinct node id overflows".to_owned()))?,
            )? + 1;
            if bit(&self.leaves, next_node)? == 1 {
                let text = String::from_utf8(current.clone())
                    .map_err(|_| SrsError::Invalid("domain is not utf-8".to_owned()))?;
                result.push(text);
            }
            stack.push((next_node, next_bitmap));
        }
        Ok(result)
    }
}

/// Walk a succinct set already loaded the way sing-box and mihomo store it
/// (`leaves`, `labelBitmap`, `labels`). The wire length prefixes differ; the
/// bitmap does not.
pub(crate) fn succinct_keys(
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
) -> Result<Vec<String>, SrsError> {
    let mut succinct = Succinct {
        leaves,
        label_bitmap,
        labels,
    };
    succinct.validate()?;
    succinct.keys()
}

fn bit(words: &[u64], index: usize) -> Result<u64, SrsError> {
    let word = words
        .get(index >> 6)
        .copied()
        .ok_or_else(|| SrsError::Invalid("succinct set bit is out of range".to_owned()))?;
    Ok((word >> (index & 63)) & 1)
}

fn count_label_bitmap(words: &[u64]) -> Result<(usize, usize), SrsError> {
    let mut ones = 0usize;
    let mut last_one = None;
    for (word_index, word) in words.iter().copied().enumerate() {
        ones += word.count_ones() as usize;
        if word != 0 {
            let highest = 63 - word.leading_zeros() as usize;
            last_one = Some((word_index << 6) | highest);
        }
    }
    let Some(last_one) = last_one else {
        return Err(SrsError::Invalid("malformed succinct set".to_owned()));
    };
    if last_one + 1 < ones {
        return Err(SrsError::Invalid("malformed succinct set".to_owned()));
    }
    Ok((ones, last_one + 1 - ones))
}

fn ranks_of(words: &[u64]) -> Result<Vec<i32>, SrsError> {
    let mut ranks = Vec::with_capacity(words.len() + 1);
    let mut total = 0i32;
    ranks.push(0);
    for word in words {
        total = total
            .checked_add(word.count_ones() as i32)
            .ok_or_else(|| SrsError::Invalid("succinct rank overflows".to_owned()))?;
        ranks.push(total);
    }
    Ok(ranks)
}

fn selects_of(words: &[u64]) -> Result<Vec<i32>, SrsError> {
    let mut selects = Vec::new();
    let mut ith = -1i64;
    let limit = words.len().saturating_mul(64);
    for index in 0..limit {
        if words[index >> 6] & (1u64 << (index & 63)) != 0 {
            ith += 1;
            if ith & 31 == 0 {
                selects.push(
                    i32::try_from(index)
                        .map_err(|_| SrsError::Invalid("succinct select overflows".to_owned()))?,
                );
            }
        }
    }
    Ok(selects)
}

fn count_ones_before(words: &[u64], ranks: &[i32], index: usize) -> Result<i32, SrsError> {
    let word_index = index >> 6;
    let bit_index = (index & 63) as u32;
    if word_index == words.len() {
        if bit_index != 0 {
            return Err(SrsError::Invalid(
                "succinct rank is out of range".to_owned(),
            ));
        }
        return ranks
            .last()
            .copied()
            .ok_or_else(|| SrsError::Invalid("succinct rank is out of range".to_owned()));
    }
    let base = *ranks
        .get(word_index)
        .ok_or_else(|| SrsError::Invalid("succinct rank is out of range".to_owned()))?;
    let word = *words
        .get(word_index)
        .ok_or_else(|| SrsError::Invalid("succinct bitmap is out of range".to_owned()))?;
    let low = if bit_index == 0 {
        0
    } else {
        (word & ((1u64 << bit_index) - 1)).count_ones()
    };
    base.checked_add(low as i32)
        .ok_or_else(|| SrsError::Invalid("succinct rank overflows".to_owned()))
}

fn count_zeros(words: &[u64], ranks: &[i32], index: usize) -> Result<usize, SrsError> {
    let ones = count_ones_before(words, ranks, index)? as usize;
    if index < ones {
        return Err(SrsError::Invalid(
            "succinct zero count underflows".to_owned(),
        ));
    }
    Ok(index - ones)
}

fn select8_table() -> &'static [u8; 2048] {
    static TABLE: OnceLock<[u8; 2048]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut table = [0u8; 2048];
        for byte in 0..256 {
            let mut cursor = byte as u8;
            for nth in 0..8 {
                table[byte * 8 + nth] = if cursor == 0 {
                    8
                } else {
                    cursor.trailing_zeros() as u8
                };
                cursor &= cursor.wrapping_sub(1);
            }
        }
        table
    })
}

/// Position of the `ith` 1-bit (0-based), ported from `domain.select32R64`.
fn select_ith_one(
    words: &[u64],
    ranks: &[i32],
    selects: &[i32],
    ith: i32,
) -> Result<usize, SrsError> {
    if ith < 0 {
        return Err(SrsError::Invalid("select of a negative bit".to_owned()));
    }
    let bucket = (ith as usize) >> 5;
    let mut word_index = (*selects
        .get(bucket)
        .ok_or_else(|| SrsError::Invalid("succinct select index is out of range".to_owned()))?
        as usize)
        >> 6;
    loop {
        let next = ranks
            .get(word_index + 1)
            .copied()
            .ok_or_else(|| SrsError::Invalid("succinct select rank is out of range".to_owned()))?;
        if next > ith {
            break;
        }
        word_index += 1;
        if word_index >= words.len() {
            return Err(SrsError::Invalid("select walked off the bitmap".to_owned()));
        }
    }
    let mut window = words[word_index];
    let base = word_index << 6;
    let mut find = u32::try_from(ith - ranks[word_index])
        .map_err(|_| SrsError::Invalid("succinct select offset underflows".to_owned()))?;
    let mut offset = 0u32;
    let mut ones = (window as u32).count_ones();
    if ones <= find {
        find -= ones;
        offset |= 32;
        window >>= 32;
    }
    ones = u32::from(window as u16).count_ones();
    if ones <= find {
        find -= ones;
        offset |= 16;
        window >>= 16;
    }
    ones = u32::from(window as u8).count_ones();
    let table = select8_table();
    let position = if ones <= find {
        let index = (((window >> 5) as usize) & 0x7f8) | (find - ones) as usize;
        u32::from(
            *table
                .get(index)
                .ok_or_else(|| SrsError::Invalid("select lookup is out of range".to_owned()))?,
        ) + offset
            + 8
    } else {
        let index = ((window as u8 as usize) << 3) | find as usize;
        u32::from(
            *table
                .get(index)
                .ok_or_else(|| SrsError::Invalid("select lookup is out of range".to_owned()))?,
        ) + offset
    };
    Ok(base + position as usize)
}

fn dump_domains(keys: Vec<String>) -> Result<(Vec<String>, Vec<String>), SrsError> {
    let mut domains = Vec::new();
    let mut prefixes = Vec::new();
    let mut dotted = Vec::new();
    for key in keys {
        let restored = reverse_domain(&key);
        let bytes = restored.as_bytes();
        if bytes.is_empty() {
            domains.push(String::new());
            continue;
        }
        match bytes[0] {
            PREFIX_LABEL => dotted.push(restored[1..].to_owned()),
            ROOT_LABEL => prefixes.push(restored[1..].to_owned()),
            _ => domains.push(restored),
        }
    }
    for raw in dotted {
        if let Some(apex) = raw.strip_prefix('.') {
            if let Some(position) = domains.iter().position(|domain| domain == apex) {
                domains.remove(position);
                prefixes.push(apex.to_owned());
                continue;
            }
        }
        prefixes.push(raw);
    }
    domains.sort();
    prefixes.sort();
    Ok((domains, prefixes))
}

fn reverse_domain(domain: &str) -> String {
    domain.chars().rev().collect()
}

fn matchers_from_dump(
    domains: Vec<String>,
    suffixes: Vec<String>,
) -> Result<Vec<DomainMatcher>, SrsError> {
    let mut matchers = Vec::with_capacity(domains.len() + suffixes.len());
    for domain in domains {
        if domain.is_empty() {
            return Err(SrsError::Invalid("empty domain".to_owned()));
        }
        matchers.push(DomainMatcher::Full(domain));
    }
    for suffix in suffixes {
        matchers.push(suffix_matcher(&suffix)?);
    }
    Ok(matchers)
}

fn suffix_matcher(suffix: &str) -> Result<DomainMatcher, SrsError> {
    if suffix.is_empty() {
        return Err(SrsError::Invalid("empty domain suffix".to_owned()));
    }
    // A leading dot is sing-box's "ends with this, but not the apex" form:
    // `.com.cn` matches `example.com.cn` and not `com.cn`. [`DomainMatcher::Suffix`]
    // also matches the apex, so this shape is a anchored regex instead.
    if suffix.starts_with('.') {
        if suffix == "." {
            return Err(SrsError::Invalid("empty domain suffix".to_owned()));
        }
        let pattern = format!("{}$", regex_escape(&suffix.to_ascii_lowercase()));
        let matcher =
            RegexMatcher::new(pattern).map_err(|error| SrsError::Invalid(error.to_string()))?;
        return Ok(DomainMatcher::Regex(matcher));
    }
    Ok(DomainMatcher::Suffix(suffix.to_owned()))
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

pub(crate) fn cidrs_for_range(start: &[u8], end: &[u8]) -> Result<Vec<Cidr>, SrsError> {
    let bad_length = || SrsError::Invalid("IP address length".to_owned());
    match start.len() {
        4 => {
            let start = u32::from_be_bytes(start.try_into().map_err(|_| bad_length())?);
            let end = u32::from_be_bytes(end.try_into().map_err(|_| bad_length())?);
            ints_to_cidrs(u128::from(start), u128::from(end), 32)
        }
        16 => {
            let start_bytes: [u8; 16] = start.try_into().map_err(|_| bad_length())?;
            let end_bytes: [u8; 16] = end.try_into().map_err(|_| bad_length())?;
            let start_v6 = Ipv6Addr::from(start_bytes);
            let end_v6 = Ipv6Addr::from(end_bytes);
            if let (Some(start_v4), Some(end_v4)) =
                (start_v6.to_ipv4_mapped(), end_v6.to_ipv4_mapped())
            {
                return ints_to_cidrs(
                    u128::from(u32::from(start_v4)),
                    u128::from(u32::from(end_v4)),
                    32,
                );
            }
            ints_to_cidrs(
                u128::from_be_bytes(start_bytes),
                u128::from_be_bytes(end_bytes),
                128,
            )
        }
        other => Err(SrsError::Invalid(format!("IP address length {other}"))),
    }
}

/// Splits an inclusive address span into the CIDRs that cover it exactly.
fn ints_to_cidrs(mut start: u128, end: u128, bits: u32) -> Result<Vec<Cidr>, SrsError> {
    if start > end {
        return Ok(Vec::new());
    }
    let mut cidrs = Vec::new();
    let mut guard = 0u32;
    while start <= end {
        guard += 1;
        // An inclusive range splits into at most two CIDRs per bit.
        if guard > bits.saturating_mul(2).saturating_add(2) {
            return Err(SrsError::Invalid("IP range did not split".to_owned()));
        }
        let align = if start == 0 {
            bits
        } else {
            start.trailing_zeros().min(bits)
        };
        let mut size = align;
        loop {
            let span = if size >= 128 {
                u128::MAX
            } else {
                (1u128 << size) - 1
            };
            let span_end = start.saturating_add(span);
            if span_end >= start && span_end <= end {
                break;
            }
            if size == 0 {
                break;
            }
            size -= 1;
        }
        let prefix_len = u8::try_from(bits - size)
            .map_err(|_| SrsError::Invalid("IP prefix length overflows".to_owned()))?;
        let address = int_to_ip(start, bits)?;
        let cidr =
            Cidr::new(address, prefix_len).map_err(|error| SrsError::Invalid(error.to_string()))?;
        cidrs.push(cidr);
        if size >= 128 {
            break;
        }
        let step = 1u128 << size;
        let next = start.saturating_add(step);
        if next <= start {
            break;
        }
        start = next;
    }
    Ok(cidrs)
}

fn int_to_ip(value: u128, bits: u32) -> Result<IpAddr, SrsError> {
    if bits == 32 {
        let value = u32::try_from(value)
            .map_err(|_| SrsError::Invalid("IPv4 range does not fit".to_owned()))?;
        Ok(IpAddr::V4(Ipv4Addr::from(value)))
    } else {
        Ok(IpAddr::V6(Ipv6Addr::from(value)))
    }
}

fn parse_port_range(text: &str) -> Result<(u16, u16), ()> {
    let Some(split) = text.find(':') else {
        return Err(());
    };
    let (start_text, end_text) = text.split_at(split);
    let end_text = &end_text[1..];
    let start = if start_text.is_empty() {
        0
    } else {
        start_text.parse().map_err(|_| ())?
    };
    let end = if end_text.is_empty() {
        u16::MAX
    } else {
        end_text.parse().map_err(|_| ())?
    };
    Ok((start, end))
}

fn ports_from(exact: &[u16], ranges: &[String]) -> Result<Vec<SrsPortRange>, String> {
    let mut ports = Vec::with_capacity(exact.len() + ranges.len());
    for port in exact {
        ports.push(SrsPortRange {
            start: *port,
            end: *port,
        });
    }
    for text in ranges {
        let (start, end) = parse_port_range(text)
            .map_err(|_| format!("port range `{text}` is invalid and the rule matches nothing"))?;
        if start <= end {
            ports.push(SrsPortRange { start, end });
        }
    }
    Ok(ports)
}

fn networks_from(names: &[String]) -> (Option<Vec<Network>>, Vec<String>, bool) {
    let mut known = Vec::new();
    let mut notes = Vec::new();
    for name in names {
        let network = match name.as_str() {
            "tcp" => Some(Network::Tcp),
            "udp" => Some(Network::Udp),
            _ => None,
        };
        match network {
            Some(network) if !known.contains(&network) => known.push(network),
            Some(_) => {}
            None => notes.push(format!(
                "network `{name}` is not tcp or udp and matches nothing"
            )),
        }
    }
    if known.is_empty() {
        (None, notes, true)
    } else {
        (Some(known), notes, false)
    }
}

enum MergeFail {
    Unsatisfiable,
    Unsupported(&'static str),
}

fn lower(
    rule: RawRule,
    index: usize,
    limits: &SrsLimits,
    warnings: &mut Vec<SrsWarning>,
    out: &mut Vec<FlatRule>,
) {
    match rule {
        RawRule::Default(rule) => lower_default(*rule, index, limits, warnings, out),
        RawRule::Logical {
            mode,
            rules,
            invert,
        } => {
            if invert {
                warnings.push(SrsWarning {
                    rule_index: index,
                    message: "inverted logical rules are not supported and match nothing"
                        .to_owned(),
                });
                return;
            }
            match mode {
                LogicalMode::Or => {
                    for rule in rules {
                        lower(rule, index, limits, warnings, out);
                    }
                }
                LogicalMode::And => lower_and(rules, index, limits, warnings, out),
            }
        }
    }
}

fn lower_default(
    rule: RawDefault,
    index: usize,
    limits: &SrsLimits,
    warnings: &mut Vec<SrsWarning>,
    out: &mut Vec<FlatRule>,
) {
    if rule.invert {
        warnings.push(SrsWarning {
            rule_index: index,
            message: "inverted rules are not supported and match nothing".to_owned(),
        });
        return;
    }
    if !rule.unsupported.is_empty() {
        warnings.push(SrsWarning {
            rule_index: index,
            message: format!(
                "{} not supported and the rule matches nothing",
                rule.unsupported.join(", ")
            ),
        });
        return;
    }

    let mut domains = rule.trie;
    for keyword in rule.keywords {
        domains.push(DomainMatcher::Keyword(keyword));
    }
    for pattern in rule.regexes {
        match RegexMatcher::new(pattern) {
            Ok(matcher) => domains.push(DomainMatcher::Regex(matcher)),
            Err(error) => warnings.push(SrsWarning {
                rule_index: index,
                message: format!("{error}; the pattern was ignored"),
            }),
        }
    }

    let ports = match ports_from(&rule.exact, &rule.ranges) {
        Ok(ports) => ports,
        Err(message) => {
            warnings.push(SrsWarning {
                rule_index: index,
                message,
            });
            return;
        }
    };
    let source_ports = match ports_from(&rule.source_exact, &rule.source_ranges) {
        Ok(ports) => ports,
        Err(message) => {
            warnings.push(SrsWarning {
                rule_index: index,
                message,
            });
            return;
        }
    };
    let saw_port = !rule.exact.is_empty() || !rule.ranges.is_empty();
    let saw_source_port = !rule.source_exact.is_empty() || !rule.source_ranges.is_empty();
    if (saw_port && ports.is_empty()) || (saw_source_port && source_ports.is_empty()) {
        warnings.push(SrsWarning {
            rule_index: index,
            message: "port range matches nothing".to_owned(),
        });
        return;
    }

    let (networks, network_notes, network_unsatisfiable) = match &rule.network {
        Some(names) => networks_from(names),
        None => (None, Vec::new(), false),
    };
    for note in network_notes {
        warnings.push(SrsWarning {
            rule_index: index,
            message: note,
        });
    }
    if network_unsatisfiable {
        warnings.push(SrsWarning {
            rule_index: index,
            message: "network matches nothing".to_owned(),
        });
        return;
    }
    // A present IP item with no surviving range matches nothing. Dropping it
    // and keeping the other fields would widen the rule.
    if (rule.saw_ip && rule.ips.is_empty()) || (rule.saw_source_ip && rule.source_ips.is_empty()) {
        warnings.push(SrsWarning {
            rule_index: index,
            message: "ip_cidr matches nothing".to_owned(),
        });
        return;
    }

    let has_condition = !domains.is_empty()
        || !rule.ips.is_empty()
        || !rule.source_ips.is_empty()
        || !ports.is_empty()
        || !source_ports.is_empty()
        || networks.is_some();
    if !has_condition {
        warnings.push(SrsWarning {
            rule_index: index,
            message: "rule has no supported condition and matches nothing".to_owned(),
        });
        return;
    }

    if !domains.is_empty() && !rule.ips.is_empty() {
        // Destination domains and destination IPs share one sing-box group
        // and either one satisfies it. Two Segue rules preserve that OR.
        let domain_rule = FlatRule {
            domains,
            ip_cidrs: Vec::new(),
            source_ip_cidrs: rule.source_ips.clone(),
            ports: ports.clone(),
            source_ports: source_ports.clone(),
            networks: networks.clone(),
        };
        let ip_rule = FlatRule {
            domains: Vec::new(),
            ip_cidrs: rule.ips,
            source_ip_cidrs: rule.source_ips,
            ports,
            source_ports,
            networks,
        };
        push_rule(domain_rule, index, limits, warnings, out);
        push_rule(ip_rule, index, limits, warnings, out);
        return;
    }

    push_rule(
        FlatRule {
            domains,
            ip_cidrs: rule.ips,
            source_ip_cidrs: rule.source_ips,
            ports,
            source_ports,
            networks,
        },
        index,
        limits,
        warnings,
        out,
    );
}

fn push_rule(
    rule: FlatRule,
    index: usize,
    limits: &SrsLimits,
    warnings: &mut Vec<SrsWarning>,
    out: &mut Vec<FlatRule>,
) {
    if out.len() >= limits.max_rules {
        let message = format!(
            "rule-set expands past {} rules; later rules match nothing",
            limits.max_rules
        );
        if warnings
            .last()
            .is_none_or(|warning| warning.message != message)
        {
            warnings.push(SrsWarning {
                rule_index: index,
                message,
            });
        }
        return;
    }
    out.push(rule);
}

fn lower_and(
    rules: Vec<RawRule>,
    index: usize,
    limits: &SrsLimits,
    warnings: &mut Vec<SrsWarning>,
    out: &mut Vec<FlatRule>,
) {
    if rules.is_empty() {
        warnings.push(SrsWarning {
            rule_index: index,
            message: "logical and with no rules would match everything and matches nothing"
                .to_owned(),
        });
        return;
    }
    let mut parts = Vec::with_capacity(rules.len());
    for rule in rules {
        let mut lowered = Vec::new();
        lower(rule, index, limits, warnings, &mut lowered);
        if lowered.is_empty() {
            warnings.push(SrsWarning {
                rule_index: index,
                message: "logical and matches nothing because one branch matches nothing"
                    .to_owned(),
            });
            return;
        }
        parts.push(lowered);
    }
    let mut combined = parts.remove(0);
    for next in parts {
        let mut product = Vec::new();
        let mut unsupported = false;
        for left in &combined {
            for right in &next {
                match and_merge(left, right) {
                    Ok(rule) => {
                        if product.len() >= limits.max_rules {
                            warnings.push(SrsWarning {
                                rule_index: index,
                                message: format!(
                                    "logical and expands past {} rules; the rest match nothing",
                                    limits.max_rules
                                ),
                            });
                            break;
                        }
                        product.push(rule);
                    }
                    Err(MergeFail::Unsatisfiable) => {}
                    Err(MergeFail::Unsupported(field)) => {
                        unsupported = true;
                        let message = format!(
                            "logical and of two {field} lists is not supported and that combination matches nothing"
                        );
                        if warnings
                            .last()
                            .is_none_or(|warning| warning.message != message)
                        {
                            warnings.push(SrsWarning {
                                rule_index: index,
                                message,
                            });
                        }
                    }
                }
            }
        }
        if product.is_empty() {
            if !unsupported {
                warnings.push(SrsWarning {
                    rule_index: index,
                    message: "logical and matches nothing".to_owned(),
                });
            }
            return;
        }
        combined = product;
    }
    for rule in combined {
        push_rule(rule, index, limits, warnings, out);
    }
}

fn and_merge(left: &FlatRule, right: &FlatRule) -> Result<FlatRule, MergeFail> {
    Ok(FlatRule {
        domains: merge_owned(&left.domains, &right.domains, "domain")?,
        ip_cidrs: merge_owned(&left.ip_cidrs, &right.ip_cidrs, "ip_cidr")?,
        source_ip_cidrs: merge_owned(
            &left.source_ip_cidrs,
            &right.source_ip_cidrs,
            "source_ip_cidr",
        )?,
        ports: intersect_ports(&left.ports, &right.ports)?,
        source_ports: intersect_ports(&left.source_ports, &right.source_ports)?,
        networks: merge_networks(&left.networks, &right.networks)?,
    })
}

fn merge_owned<T: Clone>(
    left: &[T],
    right: &[T],
    field: &'static str,
) -> Result<Vec<T>, MergeFail> {
    if left.is_empty() {
        return Ok(right.to_vec());
    }
    if right.is_empty() {
        return Ok(left.to_vec());
    }
    Err(MergeFail::Unsupported(field))
}

fn intersect_ports(
    left: &[SrsPortRange],
    right: &[SrsPortRange],
) -> Result<Vec<SrsPortRange>, MergeFail> {
    if left.is_empty() {
        return Ok(right.to_vec());
    }
    if right.is_empty() {
        return Ok(left.to_vec());
    }
    let mut ports = Vec::new();
    for left in left {
        for right in right {
            let start = left.start.max(right.start);
            let end = left.end.min(right.end);
            if start <= end {
                ports.push(SrsPortRange { start, end });
            }
        }
    }
    if ports.is_empty() {
        Err(MergeFail::Unsatisfiable)
    } else {
        Ok(ports)
    }
}

fn merge_networks(
    left: &Option<Vec<Network>>,
    right: &Option<Vec<Network>>,
) -> Result<Option<Vec<Network>>, MergeFail> {
    match (left, right) {
        (None, other) => Ok(other.clone()),
        (Some(list), None) => Ok(Some(list.clone())),
        (Some(left), Some(right)) => {
            let intersection = left
                .iter()
                .copied()
                .filter(|network| right.contains(network))
                .collect::<Vec<_>>();
            if intersection.is_empty() {
                Err(MergeFail::Unsatisfiable)
            } else {
                Ok(Some(intersection))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use flate2::{write::ZlibEncoder, Compression};

    use super::{
        ints_to_cidrs, read_rule_set, read_rule_set_with_limits, Cidr, FlatRule, Network, SrsError,
        SrsLimits, SrsPortRange, SrsRuleSet, ITEM_DOMAIN, ITEM_FINAL, ITEM_IP_CIDR, ITEM_NETWORK,
        ITEM_PORT, ITEM_PORT_RANGE,
    };

    fn uvarint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
    }

    fn wrap(version: u8, payload: &[u8]) -> Vec<u8> {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(payload).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut bytes = vec![b'S', b'R', b'S', version];
        bytes.extend(compressed);
        bytes
    }

    fn succinct(leaves: u64, bitmap: u64, labels: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8];
        body.extend(uvarint(1));
        body.extend(leaves.to_be_bytes());
        body.extend(uvarint(1));
        body.extend(bitmap.to_be_bytes());
        body.extend(uvarint(labels.len() as u64));
        body.extend(labels);
        body
    }

    fn default_rule(items: &[u8]) -> Vec<u8> {
        let mut rule = vec![0u8];
        rule.extend(items);
        rule.push(ITEM_FINAL);
        rule.push(0);
        rule
    }

    fn one_rule(items: &[u8]) -> Vec<u8> {
        let mut payload = uvarint(1);
        payload.extend(default_rule(items));
        payload
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

    fn load_fixture(name: &str) -> SrsRuleSet {
        match name {
            "domain-v1.srs" => {
                read_rule_set(include_bytes!("../fixtures/domain-v1.srs").as_slice())
            }
            "domain-v2.srs" => {
                read_rule_set(include_bytes!("../fixtures/domain-v2.srs").as_slice())
            }
            "ip-v2.srs" => read_rule_set(include_bytes!("../fixtures/ip-v2.srs").as_slice()),
            "mixed-v2.srs" => read_rule_set(include_bytes!("../fixtures/mixed-v2.srs").as_slice()),
            "logical-or-v2.srs" => {
                read_rule_set(include_bytes!("../fixtures/logical-or-v2.srs").as_slice())
            }
            "unsupported-v3.srs" => {
                read_rule_set(include_bytes!("../fixtures/unsupported-v3.srs").as_slice())
            }
            "unsupported-v4.srs" => {
                read_rule_set(include_bytes!("../fixtures/unsupported-v4.srs").as_slice())
            }
            "unsupported-v5.srs" => {
                read_rule_set(include_bytes!("../fixtures/unsupported-v5.srs").as_slice())
            }
            "invert-v2.srs" => {
                read_rule_set(include_bytes!("../fixtures/invert-v2.srs").as_slice())
            }
            "process-v2.srs" => {
                read_rule_set(include_bytes!("../fixtures/process-v2.srs").as_slice())
            }
            other => panic!("unknown fixture {other}"),
        }
        .unwrap()
    }

    #[test]
    fn hand_built_chain_recovers_a_full_domain() {
        // Succinct set of reverse("ab") = "ba", checked against newSuccinctSet.
        let mut items = vec![ITEM_DOMAIN];
        items.extend(succinct(4, 26, b"ba"));
        let set = read_rule_set(wrap(2, &one_rule(&items)).as_slice()).unwrap();
        assert!(set.warnings.is_empty());
        assert_eq!(set.rules.len(), 1);
        assert!(matches_domain(&set.rules[0], "ab"));
        assert!(!matches_domain(&set.rules[0], "a"));
        assert!(!matches_domain(&set.rules[0], "bab"));
    }

    #[test]
    fn hand_built_branch_recovers_both_leaves() {
        // Keys "a" and "b": leaves bits 1 and 2, label bits 2, 3 and 4.
        let mut items = vec![ITEM_DOMAIN];
        items.extend(succinct(6, 28, b"ab"));
        let set = read_rule_set(wrap(2, &one_rule(&items)).as_slice()).unwrap();
        assert!(set.warnings.is_empty());
        assert!(matches_domain(&set.rules[0], "a"));
        assert!(matches_domain(&set.rules[0], "b"));
        assert!(!matches_domain(&set.rules[0], "c"));
    }

    #[test]
    fn ipv4_range_that_is_not_one_prefix_splits() {
        let mut items = vec![ITEM_IP_CIDR, 1];
        items.extend(1u64.to_be_bytes());
        items.extend(uvarint(4));
        items.extend([10, 0, 0, 1]);
        items.extend(uvarint(4));
        items.extend([10, 0, 0, 2]);
        let set = read_rule_set(wrap(2, &one_rule(&items)).as_slice()).unwrap();
        let rule = &set.rules[0];
        assert_eq!(rule.ip_cidrs.len(), 2);
        assert!(covers_v4(&rule.ip_cidrs, [10, 0, 0, 1]));
        assert!(covers_v4(&rule.ip_cidrs, [10, 0, 0, 2]));
        assert!(!covers_v4(&rule.ip_cidrs, [10, 0, 0, 0]));
        assert!(!covers_v4(&rule.ip_cidrs, [10, 0, 0, 3]));
    }

    #[test]
    fn port_network_and_open_range_combine() {
        // port_range "80:" is 80..=65535, network tcp, exact port is OR'd in
        // the same group so 53 alone also matches.
        let mut items = vec![ITEM_NETWORK];
        items.extend(uvarint(1));
        items.extend(uvarint(3));
        items.extend(b"tcp");
        items.push(ITEM_PORT);
        items.extend(uvarint(1));
        items.extend(53u16.to_be_bytes());
        items.push(ITEM_PORT_RANGE);
        items.extend(uvarint(1));
        items.extend(uvarint(3));
        items.extend(b"80:");
        let set = read_rule_set(wrap(3, &one_rule(&items)).as_slice()).unwrap();
        let rule = &set.rules[0];
        assert_eq!(rule.networks.as_deref(), Some(&[Network::Tcp][..]));
        assert!(rule
            .ports
            .iter()
            .any(|range| range.start == 53 && range.end == 53));
        assert!(rule
            .ports
            .iter()
            .any(|range| range.start == 80 && range.end == u16::MAX));
    }

    #[test]
    fn reversed_port_range_matches_nothing() {
        let mut items = vec![ITEM_PORT_RANGE];
        items.extend(uvarint(1));
        items.extend(uvarint(6));
        items.extend(b"500:80");
        let set = read_rule_set(wrap(2, &one_rule(&items)).as_slice()).unwrap();
        assert!(set.rules.is_empty());
        assert!(set.warnings[0].message.contains("matches nothing"));
    }

    #[test]
    fn logical_and_merges_port_and_network() {
        let mut port_rule = vec![0u8, ITEM_PORT];
        port_rule.extend(uvarint(1));
        port_rule.extend(443u16.to_be_bytes());
        port_rule.push(ITEM_FINAL);
        port_rule.push(0);
        let mut network_rule = vec![0u8, ITEM_NETWORK];
        network_rule.extend(uvarint(1));
        network_rule.extend(uvarint(3));
        network_rule.extend(b"tcp");
        network_rule.push(ITEM_FINAL);
        network_rule.push(0);
        let mut payload = uvarint(1);
        payload.push(1); // logical
        payload.push(0); // and
        payload.extend(uvarint(2));
        payload.extend(port_rule);
        payload.extend(network_rule);
        payload.push(0); // invert
        let set = read_rule_set(wrap(2, &payload).as_slice()).unwrap();
        assert!(set.warnings.is_empty(), "{:?}", set.warnings);
        assert_eq!(set.rules.len(), 1);
        assert_eq!(
            set.rules[0].ports,
            vec![SrsPortRange {
                start: 443,
                end: 443
            }]
        );
        assert_eq!(set.rules[0].networks.as_deref(), Some(&[Network::Tcp][..]));
    }

    #[test]
    fn empty_logical_and_is_not_a_match_all() {
        let mut payload = uvarint(1);
        payload.extend([1, 0]);
        payload.extend(uvarint(0));
        payload.push(0);
        let set = read_rule_set(wrap(2, &payload).as_slice()).unwrap();
        assert!(set.rules.is_empty());
        // The warning reads "…would match everything and matches nothing".
        assert!(set.warnings[0].message.contains("matches nothing"));
    }

    #[test]
    fn bad_magic_version_and_truncated_stream_fail() {
        assert!(matches!(
            read_rule_set(&b"NOPE"[..]).unwrap_err(),
            SrsError::BadMagic
        ));
        assert!(matches!(
            read_rule_set(&b"SRS\x00"[..]).unwrap_err(),
            SrsError::UnsupportedVersion(0)
        ));
        assert!(matches!(
            read_rule_set(&b"SRS\x06"[..]).unwrap_err(),
            SrsError::UnsupportedVersion(6)
        ));
        assert!(matches!(
            read_rule_set(&b"SRS\x02\x78"[..]).unwrap_err(),
            SrsError::Truncated | SrsError::Io(_)
        ));
    }

    #[test]
    fn decompressed_stream_is_capped() {
        let limits = SrsLimits {
            max_decompressed_bytes: 8,
            ..SrsLimits::default()
        };
        // A non-zero rule count forces the reader past the decompressed cap.
        let mut payload = vec![1u8];
        payload.extend(std::iter::repeat_n(0u8, 64));
        let error = read_rule_set_with_limits(wrap(2, &payload).as_slice(), limits).unwrap_err();
        assert!(matches!(error, SrsError::TooLarge(8)), "{error}");
    }

    #[test]
    fn ten_dot_slash_eight_is_one_prefix() {
        let start = u128::from(u32::from(Ipv4Addr::new(10, 0, 0, 0)));
        let end = u128::from(u32::from(Ipv4Addr::new(10, 255, 255, 255)));
        let cidrs = ints_to_cidrs(start, end, 32).unwrap();
        assert_eq!(cidrs.len(), 1);
        assert_eq!(cidrs[0].prefix_len(), 8);
        assert!(cidrs[0].contains(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!cidrs[0].contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 0))));
    }

    #[test]
    fn fixtures_round_trip_domains_ips_and_skipped_items() {
        let domain_v2 = load_fixture("domain-v2.srs");
        assert_eq!(domain_v2.version, 2);
        assert!(domain_v2.warnings.is_empty());
        let rule = &domain_v2.rules[0];
        assert!(matches_domain(rule, "example.com"));
        assert!(matches_domain(rule, "www.example.com"));
        assert!(!matches_domain(rule, "other.example.com"));
        assert!(matches_domain(rule, "sagernet.org"));
        assert!(matches_domain(rule, "sing-box.sagernet.org"));
        assert!(matches_domain(rule, "example.com.cn"));
        assert!(!matches_domain(rule, "com.cn"));
        assert!(matches_domain(rule, "ads.tracker.test"));
        assert!(matches_domain(rule, "ads.example"));
        // `ads` is a keyword, so it matches anywhere; this name has neither.
        assert!(!matches_domain(rule, "tracker.test"));

        let domain_v1 = load_fixture("domain-v1.srs");
        assert_eq!(domain_v1.version, 1);
        let legacy = &domain_v1.rules[0];
        assert!(matches_domain(legacy, "example.com"));
        assert!(matches_domain(legacy, "example.com.cn"));
        assert!(!matches_domain(legacy, "com.cn"));
        assert!(matches_domain(legacy, "sing-box.sagernet.org"));

        let ips = load_fixture("ip-v2.srs");
        let ip_rule = &ips.rules[0];
        assert!(covers_v4(&ip_rule.ip_cidrs, [10, 1, 2, 3]));
        assert!(!covers_v4(&ip_rule.ip_cidrs, [11, 0, 0, 1]));
        assert!(covers_v6(
            &ip_rule.ip_cidrs,
            [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1]
        ));
        assert!(!covers_v6(
            &ip_rule.ip_cidrs,
            [0x2001, 0x0db9, 0, 0, 0, 0, 0, 1]
        ));
        assert!(covers_v4(&ip_rule.source_ip_cidrs, [192, 0, 2, 1]));
        assert!(!covers_v4(&ip_rule.source_ip_cidrs, [192, 0, 2, 2]));

        let mixed = load_fixture("mixed-v2.srs");
        assert_eq!(mixed.rules.len(), 2);
        assert!(mixed.rules.iter().all(|rule| {
            rule.networks.as_deref() == Some(&[Network::Tcp][..])
                && rule.ports
                    == vec![SrsPortRange {
                        start: 80,
                        end: 443,
                    }]
                && rule.source_ports == vec![SrsPortRange { start: 53, end: 53 }]
        }));
        assert!(mixed
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "example.com") && rule.ip_cidrs.is_empty()));
        assert!(mixed
            .rules
            .iter()
            .any(|rule| { rule.domains.is_empty() && covers_v4(&rule.ip_cidrs, [192, 0, 2, 10]) }));

        let logical = load_fixture("logical-or-v2.srs");
        assert_eq!(logical.rules.len(), 2);
        assert!(logical
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "www.a.test")));
        assert!(logical
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "b.test")));
        assert!(!logical
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "c.test")));

        let skipped = load_fixture("unsupported-v3.srs");
        assert_eq!(skipped.rules.len(), 1);
        assert!(matches_domain(&skipped.rules[0], "keep.example"));
        assert!(!skipped
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "nope.example")));
        assert!(skipped
            .warnings
            .iter()
            .any(|warning| warning.message.contains("network_is_expensive")));

        let v4 = load_fixture("unsupported-v4.srs");
        assert!(v4
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "kept.example")));
        assert!(!v4
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "dropped.example")));
        assert!(v4
            .warnings
            .iter()
            .any(|warning| warning.message.contains("network_interface_address")));
        assert!(v4
            .warnings
            .iter()
            .any(|warning| warning.message.contains("default_interface_address")));

        let v5 = load_fixture("unsupported-v5.srs");
        assert_eq!(v5.version, 5);
        assert!(matches_domain(&v5.rules[0], "still.example"));
        assert!(v5.warnings[0].message.contains("package_name_regex"));

        let inverted = load_fixture("invert-v2.srs");
        assert!(inverted.rules.is_empty());
        assert!(inverted.warnings[0].message.contains("inverted"));

        let process = load_fixture("process-v2.srs");
        assert!(matches_domain(&process.rules[0], "keep.example"));
        assert!(!process
            .rules
            .iter()
            .any(|rule| matches_domain(rule, "drop.example")));
        assert!(process.warnings[0].message.contains("process_name"));
    }
}
