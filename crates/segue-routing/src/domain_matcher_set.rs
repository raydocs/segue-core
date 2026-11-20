use std::borrow::Cow;
use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickKind, StartKind};
use regex::{Regex, RegexSet};
use thiserror::Error;

use crate::{DomainMatcher, DomainNameMode};

/// Small routing rules are more common than geosite-sized matcher sets. A
/// linear scan avoids a hash lookup (and an ASCII-case normalization pass) for
/// each rule while the indexed representation still handles large sets.
const LINEAR_MATCHER_LIMIT: usize = 8;

/// Query-ready set of `full:`, `domain:`, `keyword:` and `regexp:` matchers
/// belonging to one rule.
///
/// Names are matched per label and ASCII case-insensitively: `domain:a.test`
/// matches `a.test` and `b.a.test` but not `ba.test`. Trailing dots are kept
/// as-is on both sides, so DNS callers normalize names before matching.
///
/// The compiled state is immutable and shared behind an `Arc`, so cloning a
/// set only bumps a reference count instead of copying its hash tables,
/// automaton and regexes.
#[derive(Clone, Default)]
pub struct DomainMatcherSet {
    inner: Option<Arc<DomainMatcherSetInner>>,
    matcher_count: usize,
}

enum CompiledRegexes {
    Empty,
    Single(Regex),
    Set(RegexSet),
    Fallback(Vec<Regex>),
}

impl CompiledRegexes {
    fn from_regexes(mut regexes: Vec<Regex>) -> Self {
        match regexes.len() {
            0 => Self::Empty,
            1 => Self::Single(regexes.pop().expect("single regex")),
            _ => match RegexSet::new(regexes.iter().map(Regex::as_str)) {
                Ok(set) => Self::Set(set),
                Err(_) => Self::Fallback(regexes),
            },
        }
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty)
    }

    fn len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Single(_) => 1,
            Self::Set(set) => set.len(),
            Self::Fallback(list) => list.len(),
        }
    }

    fn pattern_bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Single(regex) => regex.as_str().len(),
            Self::Set(set) => set.patterns().iter().map(String::len).sum(),
            Self::Fallback(list) => list.iter().map(|regex| regex.as_str().len()).sum(),
        }
    }

    fn is_match(&self, domain: &str) -> bool {
        match self {
            Self::Empty => false,
            Self::Single(regex) => regex.is_match(domain),
            Self::Set(set) => set.is_match(domain),
            Self::Fallback(list) => list.iter().any(|regex| regex.is_match(domain)),
        }
    }

    fn patterns_eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) => true,
            (Self::Single(a), Self::Single(b)) => a.as_str() == b.as_str(),
            (Self::Set(a), Self::Set(b)) => a.patterns() == b.patterns(),
            (Self::Fallback(a), Self::Fallback(b)) => {
                a.iter().map(Regex::as_str).eq(b.iter().map(Regex::as_str))
            }
            (a, b) if a.len() == b.len() => a.pattern_strs().eq(b.pattern_strs()),
            _ => false,
        }
    }

    fn pattern_strs(&self) -> Box<dyn Iterator<Item = &str> + '_> {
        match self {
            Self::Empty => Box::new(std::iter::empty()),
            Self::Single(regex) => Box::new(std::iter::once(regex.as_str())),
            Self::Set(set) => Box::new(set.patterns().iter().map(String::as_str)),
            Self::Fallback(list) => Box::new(list.iter().map(Regex::as_str)),
        }
    }
}

struct DomainMatcherSetInner {
    linear: Option<Box<[DomainMatcher]>>,
    full: HashSet<Box<str>>,
    suffix: HashSet<Box<str>>,
    subdomain: HashSet<Box<str>>,
    keyword_count: usize,
    keyword_pattern_bytes: usize,
    keyword_digest: u64,
    keyword_automaton: Option<AhoCorasick>,
    regex: CompiledRegexes,
}

impl DomainMatcherSet {
    pub fn builder() -> DomainMatcherSetBuilder {
        DomainMatcherSetBuilder::default()
    }

    /// Compiles `matchers` in one pass; `mode` picks the `full:`/`domain:`
    /// pattern normalization.
    pub fn compile(
        matchers: &[DomainMatcher],
        mode: DomainNameMode,
    ) -> Result<Self, DomainMatcherSetError> {
        let mut builder = Self::builder();
        for matcher in matchers {
            builder.insert(matcher, mode);
        }
        builder.build()
    }

    pub fn is_empty(&self) -> bool {
        self.matcher_count == 0
    }

    /// Returns the number of source matchers inserted, duplicates included.
    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    /// Returns the retained pattern payload in bytes, excluding hash-table,
    /// automaton and regex-engine overhead.
    pub fn pattern_bytes(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.pattern_bytes())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let Some(inner) = &self.inner else {
            return false;
        };
        if let Some(matchers) = &inner.linear {
            return matchers.iter().any(|matcher| matcher.matches(domain));
        }
        let domain = lowercase_ascii(domain);
        inner.full.contains(domain.as_ref())
            || inner.matches_suffix(&domain)
            || inner.matches_subdomain(&domain)
            || inner.matches_keyword(&domain)
            || inner.matches_regex(&domain)
    }
}

impl DomainMatcherSetInner {
    fn pattern_bytes(&self) -> usize {
        if let Some(matchers) = &self.linear {
            return matchers.iter().map(matcher_pattern_bytes).sum();
        }
        self.full.iter().map(|name| name.len()).sum::<usize>()
            + self.suffix.iter().map(|name| name.len()).sum::<usize>()
            + self.subdomain.iter().map(|name| name.len()).sum::<usize>()
            + self.keyword_pattern_bytes
            + self.regex.pattern_bytes()
    }

    fn matches_suffix(&self, domain: &str) -> bool {
        !self.suffix.is_empty()
            && (self.suffix.contains(domain)
                || domain
                    .rmatch_indices('.')
                    .any(|(index, _)| self.suffix.contains(&domain[index + 1..])))
    }

    fn matches_subdomain(&self, domain: &str) -> bool {
        !self.subdomain.is_empty()
            && domain
                .rmatch_indices('.')
                .any(|(index, _)| index > 0 && self.subdomain.contains(&domain[index + 1..]))
    }

    fn matches_keyword(&self, domain: &str) -> bool {
        self.keyword_automaton
            .as_ref()
            .is_some_and(|automaton| automaton.is_match(domain))
    }

    fn matches_regex(&self, domain: &str) -> bool {
        self.regex.is_match(domain)
    }

    fn matcher_kind_count(&self, select: fn(&DomainMatcher) -> bool) -> usize {
        self.linear.as_deref().map_or(0, |matchers| {
            matchers.iter().filter(|matcher| select(matcher)).count()
        })
    }
}

impl fmt::Debug for DomainMatcherSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let counts = |select: fn(&DomainMatcherSetInner) -> usize| {
            self.inner.as_ref().map_or(0, |inner| select(inner))
        };
        f.debug_struct("DomainMatcherSet")
            .field(
                "full",
                &counts(|inner| {
                    inner.full.len()
                        + inner
                            .matcher_kind_count(|matcher| matches!(matcher, DomainMatcher::Full(_)))
                }),
            )
            .field(
                "suffix",
                &counts(|inner| {
                    inner.suffix.len()
                        + inner.matcher_kind_count(|matcher| {
                            matches!(matcher, DomainMatcher::Suffix(_))
                        })
                }),
            )
            .field(
                "subdomain",
                &counts(|inner| {
                    inner.subdomain.len()
                        + inner.matcher_kind_count(|matcher| {
                            matches!(matcher, DomainMatcher::Subdomain(_))
                        })
                }),
            )
            .field(
                "keyword",
                &counts(|inner| {
                    inner.keyword_count
                        + inner.matcher_kind_count(|matcher| {
                            matches!(matcher, DomainMatcher::Keyword(_))
                        })
                }),
            )
            .field(
                "regex",
                &counts(|inner| {
                    inner.regex.len()
                        + inner.matcher_kind_count(|matcher| {
                            matches!(matcher, DomainMatcher::Regex(_))
                        })
                }),
            )
            .field("matcher_count", &self.matcher_count)
            .finish()
    }
}

impl PartialEq for DomainMatcherSet {
    fn eq(&self, other: &Self) -> bool {
        self.matcher_count == other.matcher_count
            && match (&self.inner, &other.inner) {
                (None, None) => true,
                (Some(a), Some(b)) => {
                    a.linear == b.linear
                        && a.full == b.full
                        && a.suffix == b.suffix
                        && a.subdomain == b.subdomain
                        && a.keyword_count == b.keyword_count
                        && a.keyword_pattern_bytes == b.keyword_pattern_bytes
                        && a.keyword_digest == b.keyword_digest
                        && a.regex.patterns_eq(&b.regex)
                }
                (Some(_), None) | (None, Some(_)) => false,
            }
    }
}

impl Eq for DomainMatcherSet {}

#[derive(Debug, Error)]
pub enum DomainMatcherSetError {
    #[error("keyword matchers exceed the automaton limits: {0}")]
    Keyword(#[from] aho_corasick::BuildError),
}

#[derive(Debug, Default)]
pub struct DomainMatcherSetBuilder {
    linear: Vec<DomainMatcher>,
    indexed: bool,
    full: HashSet<Box<str>>,
    suffix: HashSet<Box<str>>,
    subdomain: HashSet<Box<str>>,
    keywords: Vec<Box<str>>,
    regex: Vec<Regex>,
    matcher_count: usize,
}

impl DomainMatcherSetBuilder {
    /// Adds one matcher; the already compiled regex of a `regexp:` matcher is
    /// shared, not recompiled.
    pub fn insert(&mut self, matcher: &DomainMatcher, mode: DomainNameMode) {
        if !self.indexed {
            if self.matcher_count < LINEAR_MATCHER_LIMIT {
                let normalized = normalize_linear_matcher(matcher, mode);
                if !self.linear.contains(&normalized) {
                    self.linear.push(normalized);
                }
                self.matcher_count += 1;
                return;
            }
            self.indexed = true;
            for existing in std::mem::take(&mut self.linear) {
                self.insert_normalized(existing);
            }
        }
        self.insert_raw(matcher, mode);
        self.matcher_count += 1;
    }

    fn insert_raw(&mut self, matcher: &DomainMatcher, mode: DomainNameMode) {
        match matcher {
            DomainMatcher::Keyword(keyword) => self.keywords.push(lowercase_boxed(keyword)),
            DomainMatcher::Full(domain) => {
                self.full.insert(lowercase_boxed(mode.pattern(domain)));
            }
            DomainMatcher::Suffix(suffix) => {
                self.suffix.insert(lowercase_boxed(mode.pattern(suffix)));
            }
            DomainMatcher::Subdomain(suffix) => {
                self.subdomain.insert(lowercase_boxed(mode.pattern(suffix)));
            }
            DomainMatcher::Regex(matcher) => self.regex.push(matcher.regex().clone()),
        }
    }

    fn insert_normalized(&mut self, matcher: DomainMatcher) {
        match matcher {
            DomainMatcher::Keyword(keyword) => self.keywords.push(keyword.into_boxed_str()),
            DomainMatcher::Full(domain) => {
                self.full.insert(domain.into_boxed_str());
            }
            DomainMatcher::Suffix(suffix) => {
                self.suffix.insert(suffix.into_boxed_str());
            }
            DomainMatcher::Subdomain(suffix) => {
                self.subdomain.insert(suffix.into_boxed_str());
            }
            DomainMatcher::Regex(matcher) => self.regex.push(matcher.regex().clone()),
        }
    }

    pub fn matcher_count(&self) -> usize {
        self.matcher_count
    }

    pub fn build(self) -> Result<DomainMatcherSet, DomainMatcherSetError> {
        if self.matcher_count == 0 {
            return Ok(DomainMatcherSet::default());
        }
        let matcher_count = self.matcher_count;
        let inner = if !self.indexed {
            DomainMatcherSetInner {
                linear: Some(self.linear.into_boxed_slice()),
                full: HashSet::new(),
                suffix: HashSet::new(),
                subdomain: HashSet::new(),
                keyword_count: 0,
                keyword_pattern_bytes: 0,
                keyword_digest: 0,
                keyword_automaton: None,
                regex: CompiledRegexes::Empty,
            }
        } else {
            let keyword_count = self.keywords.len();
            let keyword_pattern_bytes = self.keywords.iter().map(|keyword| keyword.len()).sum();
            let keyword_digest = digest_keywords(&self.keywords);
            let keyword_automaton = if self.keywords.is_empty() {
                None
            } else {
                Some(
                    AhoCorasick::builder()
                        .kind(Some(AhoCorasickKind::ContiguousNFA))
                        .start_kind(StartKind::Unanchored)
                        .build(self.keywords.iter().map(|keyword| keyword.as_bytes()))?,
                )
            };
            DomainMatcherSetInner {
                linear: None,
                full: self.full,
                suffix: self.suffix,
                subdomain: self.subdomain,
                keyword_count,
                keyword_pattern_bytes,
                keyword_digest,
                keyword_automaton,
                regex: CompiledRegexes::from_regexes(self.regex),
            }
        };
        Ok(DomainMatcherSet {
            inner: Some(Arc::new(inner)),
            matcher_count,
        })
    }
}

fn digest_keywords(keywords: &[Box<str>]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for keyword in keywords {
        for byte in (keyword.len() as u64).to_le_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        for &byte in keyword.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
    }
    hash
}

fn lowercase_boxed(value: &str) -> Box<str> {
    value.to_ascii_lowercase().into_boxed_str()
}

fn normalize_linear_matcher(matcher: &DomainMatcher, mode: DomainNameMode) -> DomainMatcher {
    match matcher {
        DomainMatcher::Keyword(keyword) => DomainMatcher::Keyword(keyword.to_ascii_lowercase()),
        DomainMatcher::Full(domain) => {
            DomainMatcher::Full(mode.pattern(domain).to_ascii_lowercase())
        }
        DomainMatcher::Suffix(suffix) => {
            DomainMatcher::Suffix(mode.pattern(suffix).to_ascii_lowercase())
        }
        DomainMatcher::Subdomain(suffix) => {
            DomainMatcher::Subdomain(mode.pattern(suffix).to_ascii_lowercase())
        }
        DomainMatcher::Regex(matcher) => DomainMatcher::Regex(matcher.clone()),
    }
}

fn matcher_pattern_bytes(matcher: &DomainMatcher) -> usize {
    match matcher {
        DomainMatcher::Keyword(pattern)
        | DomainMatcher::Full(pattern)
        | DomainMatcher::Suffix(pattern)
        | DomainMatcher::Subdomain(pattern) => pattern.len(),
        DomainMatcher::Regex(matcher) => matcher.pattern().len(),
    }
}

fn lowercase_ascii(value: &str) -> Cow<'_, str> {
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(value.to_ascii_lowercase())
    } else {
        Cow::Borrowed(value)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::RegexMatcher;

    fn matchers(
        full: &[&str],
        suffix: &[&str],
        keyword: &[&str],
        regex: &[&str],
    ) -> Vec<DomainMatcher> {
        full.iter()
            .map(|name| DomainMatcher::Full((*name).to_owned()))
            .chain(
                suffix
                    .iter()
                    .map(|name| DomainMatcher::Suffix((*name).to_owned())),
            )
            .chain(
                keyword
                    .iter()
                    .map(|name| DomainMatcher::Keyword((*name).to_owned())),
            )
            .chain(
                regex
                    .iter()
                    .map(|pattern| DomainMatcher::Regex(RegexMatcher::new(*pattern).unwrap())),
            )
            .collect()
    }

    fn compile(
        full: &[&str],
        suffix: &[&str],
        keyword: &[&str],
        regex: &[&str],
    ) -> DomainMatcherSet {
        DomainMatcherSet::compile(
            &matchers(full, suffix, keyword, regex),
            DomainNameMode::Routing,
        )
        .unwrap()
    }

    fn table_bytes(set: &HashSet<Box<str>>) -> usize {
        let buckets = if set.capacity() == 0 {
            0
        } else {
            (set.capacity() * 8).div_ceil(7).next_power_of_two()
        };
        buckets * (size_of::<Box<str>>() + 1)
    }

    fn heap_bytes(set: &HashSet<Box<str>>) -> usize {
        set.iter().map(|name| name.len()).sum()
    }

    #[test]
    fn clone_shares_compiled_state() {
        let set = compile(&["a.test"], &[], &[], &[]);
        let cloned = set.clone();
        assert!(Arc::ptr_eq(
            set.inner.as_ref().unwrap(),
            cloned.inner.as_ref().unwrap()
        ));
        assert_eq!(cloned, set);
        assert!(cloned.matches("a.test"));
    }

    #[test]
    fn small_sets_use_the_linear_fast_path_without_retaining_indexes() {
        let set = compile(&["a.test", "b.test"], &["suffix.test"], &["kw"], &["^rx$"]);
        let inner = set.inner.as_deref().unwrap();

        assert_eq!(inner.linear.as_deref().unwrap().len(), 5);
        assert!(inner.full.is_empty());
        assert!(inner.suffix.is_empty());
        assert!(inner.subdomain.is_empty());
        assert_eq!(inner.keyword_count, 0);
        assert!(inner.keyword_automaton.is_none());
        assert!(inner.regex.is_empty());
        assert!(set.matches("B.TEST"));
        assert!(set.matches("deep.SUFFIX.test"));
        assert!(set.matches("prefix-KW-suffix"));
        assert!(set.matches("RX"));
    }

    #[test]
    fn sets_above_the_linear_limit_use_the_compiled_indexes() {
        let full = (0..=LINEAR_MATCHER_LIMIT)
            .map(|index| format!("host-{index}.test"))
            .collect::<Vec<_>>();
        let matchers = full
            .iter()
            .map(|name| DomainMatcher::Full(name.clone()))
            .collect::<Vec<_>>();
        let set = DomainMatcherSet::compile(&matchers, DomainNameMode::Routing).unwrap();
        let inner = set.inner.as_deref().unwrap();

        assert!(inner.linear.is_none());
        assert_eq!(inner.full.len(), LINEAR_MATCHER_LIMIT + 1);
        assert!(set.matches("HOST-8.TEST"));
        assert!(!set.matches("missing.test"));
    }

    #[test]
    fn empty_set_matches_nothing_and_reports_zero_sizes() {
        let empty = DomainMatcherSet::default();
        assert!(empty.is_empty());
        assert_eq!(empty.matcher_count(), 0);
        assert_eq!(empty.pattern_bytes(), 0);
        assert!(!empty.matches(""));
        assert!(!empty.matches("example.com"));
        assert_eq!(DomainMatcherSet::builder().build().unwrap(), empty);
        assert_eq!(
            format!("{empty:?}"),
            "DomainMatcherSet { full: 0, suffix: 0, subdomain: 0, keyword: 0, regex: 0, matcher_count: 0 }"
        );
    }

    #[test]
    fn full_names_match_exactly_and_case_insensitively() {
        let set = compile(&["Example.COM", "exact.test."], &[], &[], &[]);
        assert_eq!(set.matcher_count(), 2);
        assert!(set.matches("example.com"));
        assert!(set.matches("EXAMPLE.com"));
        assert!(!set.matches("www.example.com"));
        assert!(!set.matches("example.com."));
        assert!(set.matches("exact.test."));
        assert!(!set.matches("exact.test"));
        assert!(!set.matches("notexample.com"));
    }

    #[test]
    fn suffixes_match_on_label_boundaries_only() {
        let set = compile(&[], &["Example.com", "corp", ".lead.test", ""], &[], &[]);
        assert!(set.matches("example.com"));
        assert!(set.matches("a.b.EXAMPLE.com"));
        assert!(!set.matches("notexample.com"));
        assert!(!set.matches("example.com.evil"));
        assert!(set.matches("corp"));
        assert!(set.matches("intranet.corp"));
        assert!(!set.matches("corp.example"));
        assert!(set.matches(".lead.test"));
        assert!(set.matches("x..lead.test"));
        assert!(!set.matches("www.lead.test"));
        assert!(set.matches(""));
        assert!(set.matches("trailing.dot."));
        assert!(!set.matches("nodot"));
    }

    #[test]
    fn full_and_suffix_rules_for_the_same_name_are_kept_apart() {
        let set = compile(&["shared.test"], &["shared.test"], &[], &[]);
        assert_eq!(set.matcher_count(), 2);
        assert!(set.matches("shared.test"));
        assert!(set.matches("deep.shared.test"));

        let full_only = compile(&["only.test"], &[], &[], &[]);
        assert!(!full_only.matches("deep.only.test"));

        let duplicated = compile(&["dup.test", "DUP.test"], &[], &[], &[]);
        assert_eq!(duplicated.matcher_count(), 2);
        assert_eq!(duplicated.pattern_bytes(), "dup.test".len());
    }

    #[test]
    fn keywords_match_anywhere_case_insensitively_including_empty() {
        let set = compile(&[], &[], &["Ample", "zz"], &[]);
        assert!(set.matches("EXAMPLE.com"));
        assert!(set.matches("sample"));
        assert!(set.matches("buzz.test"));
        assert!(!set.matches("other.test"));
        assert!(!set.matches(""));

        let empty_keyword = compile(&[], &[], &[""], &[]);
        assert!(empty_keyword.matches(""));
        assert!(empty_keyword.matches("anything"));
    }

    #[test]
    fn regexes_match_the_lowercased_name() {
        let set = compile(
            &[],
            &[],
            &[],
            &[r"^[^.]*local[^.]*$", r"^api\.[a-z]+\.test$"],
        );
        assert!(set.matches("MyLocalHost"));
        assert!(!set.matches("local.host"));
        assert!(set.matches("API.svc.test"));
        assert!(!set.matches("api.svc.test."));
    }

    #[test]
    fn dns_mode_trims_trailing_dots_from_full_and_suffix_patterns() {
        let matchers = matchers(&["dotted.test."], &["trailing.example."], &[], &[]);
        let routing = DomainMatcherSet::compile(&matchers, DomainNameMode::Routing).unwrap();
        let dns = DomainMatcherSet::compile(&matchers, DomainNameMode::Dns).unwrap();

        assert!(routing.matches("dotted.test."));
        assert!(!routing.matches("dotted.test"));
        assert!(routing.matches("a.trailing.example."));
        assert!(!routing.matches("a.trailing.example"));

        assert!(dns.matches("dotted.test"));
        assert!(!dns.matches("dotted.test."));
        assert!(dns.matches("a.trailing.example"));
        assert!(!dns.matches("a.trailing.example."));
        assert_eq!(dns.matcher_count(), 2);
    }

    #[test]
    fn regex_matchers_share_the_prevalidated_regex() {
        let matcher = RegexMatcher::new(r"^cdn[0-9]+\.example$").unwrap();
        let mut builder = DomainMatcherSet::builder();
        builder.insert(
            &DomainMatcher::Regex(matcher.clone()),
            DomainNameMode::Routing,
        );
        let set = builder.build().unwrap();
        assert_eq!(set.matcher_count(), 1);
        assert_eq!(set.pattern_bytes(), matcher.pattern().len());
        assert!(set.matches("CDN7.example"));
        assert!(!set.matches("cdn.example"));
    }

    #[test]
    fn equality_debug_and_pattern_bytes_cover_all_kinds() {
        let left = compile(&["a.test"], &["b.test"], &["kw"], &["^c$"]);
        let right = compile(&["A.TEST"], &["B.test"], &["KW"], &["^c$"]);
        assert_eq!(left, right);
        assert_ne!(left, compile(&["a.test"], &["b.test"], &["kw"], &["^d$"]));
        assert_ne!(left, compile(&["a.test"], &["b.test"], &[], &["^c$"]));
        assert_ne!(
            left,
            compile(&["a.test", "a.test"], &["b.test"], &["kw"], &["^c$"])
        );
        assert_eq!(left.pattern_bytes(), 6 + 6 + 2 + 3);
        assert_eq!(
            format!("{left:?}"),
            "DomainMatcherSet { full: 1, suffix: 1, subdomain: 0, keyword: 1, regex: 1, matcher_count: 4 }"
        );
        let cloned = left.clone();
        assert!(cloned.matches("x.b.test") && cloned.matches("c") && cloned.matches("akwz"));
    }

    #[test]
    fn geosite_sized_mix_stays_within_the_memory_budget() {
        let mut builder = DomainMatcherSet::builder();
        for index in 0..100_000 {
            builder.insert(
                &DomainMatcher::Suffix(format!("site-{index}.geosite-suffix.example")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..20_000 {
            builder.insert(
                &DomainMatcher::Full(format!("host-{index}.geosite-full.example")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..2_000 {
            builder.insert(
                &DomainMatcher::Keyword(format!("keyword-{index:04}")),
                DomainNameMode::Routing,
            );
        }
        for index in 0..200 {
            builder.insert(
                &DomainMatcher::Regex(
                    RegexMatcher::new(format!(r"^ad[0-9]*-{index}\.[a-z]+\.example$")).unwrap(),
                ),
                DomainNameMode::Routing,
            );
        }
        let set = builder.build().unwrap();
        assert_eq!(set.matcher_count(), 122_200);
        let inner = set.inner.as_deref().unwrap();

        let name_table_bytes = table_bytes(&inner.full) + table_bytes(&inner.suffix);
        let name_heap_bytes = heap_bytes(&inner.full) + heap_bytes(&inner.suffix);
        let automaton_bytes = inner
            .keyword_automaton
            .as_ref()
            .map_or(0, AhoCorasick::memory_usage);
        let regex_pattern_bytes = inner.regex.pattern_bytes();
        eprintln!(
            "names: tables {name_table_bytes} B + heap {name_heap_bytes} B; keywords: automaton {automaton_bytes} B; regex patterns {regex_pattern_bytes} B"
        );

        let flat_vec_name_bytes = 120_000 * 32 + name_heap_bytes;
        assert!(name_table_bytes + name_heap_bytes <= flat_vec_name_bytes);
        assert!(automaton_bytes <= 1024 * 1024);

        assert!(set.matches("www.site-77777.geosite-suffix.example"));
        assert!(set.matches("host-19999.geosite-full.example"));
        assert!(!set.matches("www.host-19999.geosite-full.example"));
        assert!(set.matches("cdn.keyword-1999.test"));
        assert!(set.matches("ad42-199.tracker.example"));
        assert!(!set.matches("clean.example"));
    }

    #[test]
    fn subdomains_match_strictly_below_and_above_linear_limit() {
        let small = DomainMatcherSet::compile(
            &[DomainMatcher::Subdomain("Example.COM".to_owned())],
            DomainNameMode::Routing,
        )
        .unwrap();
        assert!(!small.matches("example.com"));
        assert!(!small.matches(".example.com"));
        assert!(small.matches("sub.example.com"));
        assert!(small.matches("a.b.EXAMPLE.com"));

        let mut builder = DomainMatcherSet::builder();
        for index in 0..=LINEAR_MATCHER_LIMIT {
            builder.insert(
                &DomainMatcher::Subdomain(format!("sub-{index}.example")),
                DomainNameMode::Routing,
            );
        }
        let large = builder.build().unwrap();
        assert!(large.inner.as_deref().unwrap().linear.is_none());
        assert!(!large.matches("sub-0.example"));
        assert!(!large.matches(".sub-0.example"));
        assert!(large.matches("edge.SUB-0.example"));
        assert!(large.matches("deep.edge.sub-8.example"));
    }
}
