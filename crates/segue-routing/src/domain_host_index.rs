use std::collections::HashMap;
use std::net::IpAddr;

use crate::DomainMatcher;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsHostTarget {
    Ip(IpAddr),
    Ips(Vec<IpAddr>),
    Domain(String),
    /// Xray-core's `"#N"` value: answer the name with DNS RCODE `N` (0..=15)
    /// and no records. `#0` is an empty NOERROR answer.
    Rcode(u8),
}

/// `dns.hosts`-style index from domain matchers to one target each.
///
/// `full:` names live in a hash map keyed by the DNS-normalized name
/// (ASCII-lowercased, trailing dots trimmed) and win over every other matcher;
/// the first `full:` inserted for a name is kept. Non-degenerate `Suffix` and
/// `Subdomain` matchers are indexed by label boundary with monotonic insertion
/// order so O(labels) probes preserve exact insertion-order precedence beside
/// `Keyword` / `Regex` entries in `others`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainHostIndex<T> {
    full: HashMap<Box<str>, T>,
    suffix: HashMap<Box<str>, (usize, T)>,
    subdomain: HashMap<Box<str>, (usize, T)>,
    others: Vec<(usize, DomainMatcher, T)>,
    next_order: usize,
}

impl<T> Default for DomainHostIndex<T> {
    fn default() -> Self {
        Self {
            full: HashMap::new(),
            suffix: HashMap::new(),
            subdomain: HashMap::new(),
            others: Vec::new(),
            next_order: 0,
        }
    }
}

impl<T> DomainHostIndex<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, matcher: DomainMatcher, target: T) {
        match matcher {
            DomainMatcher::Full(name) => {
                self.full
                    .entry(normalize_dns_pattern(name).into_boxed_str())
                    .or_insert(target);
            }
            DomainMatcher::Suffix(suffix) => {
                let order = self.take_order();
                let normalized = normalize_dns_pattern(suffix);
                if normalized.is_empty() || normalized.starts_with('.') {
                    self.others
                        .push((order, DomainMatcher::Suffix(normalized), target));
                } else {
                    self.suffix
                        .entry(normalized.into_boxed_str())
                        .or_insert((order, target));
                }
            }
            DomainMatcher::Subdomain(suffix) => {
                let order = self.take_order();
                let normalized = normalize_dns_pattern(suffix);
                if normalized.is_empty() || normalized.starts_with('.') {
                    self.others
                        .push((order, DomainMatcher::Subdomain(normalized), target));
                } else {
                    self.subdomain
                        .entry(normalized.into_boxed_str())
                        .or_insert((order, target));
                }
            }
            matcher @ (DomainMatcher::Keyword(_) | DomainMatcher::Regex(_)) => {
                let order = self.take_order();
                self.others.push((order, matcher, target));
            }
        }
    }

    fn take_order(&mut self) -> usize {
        let order = self.next_order;
        self.next_order += 1;
        order
    }

    pub fn lookup(&self, normalized_domain: &str) -> Option<&T> {
        if let Some(target) = self.full.get(normalized_domain) {
            return Some(target);
        }
        let mut best: Option<(usize, &T)> = None;
        if !self.suffix.is_empty() {
            if let Some((order, target)) = self.suffix.get(normalized_domain) {
                best = Some((*order, target));
            }
        }
        if !self.suffix.is_empty() || !self.subdomain.is_empty() {
            for (dot_idx, _) in normalized_domain.match_indices('.') {
                let tail = &normalized_domain[dot_idx + 1..];
                if let Some((order, target)) = self.suffix.get(tail) {
                    if best.is_none_or(|(best_order, _)| *order < best_order) {
                        best = Some((*order, target));
                    }
                }
                if dot_idx > 0 {
                    if let Some((order, target)) = self.subdomain.get(tail) {
                        if best.is_none_or(|(best_order, _)| *order < best_order) {
                            best = Some((*order, target));
                        }
                    }
                }
            }
        }
        for (order, matcher, target) in &self.others {
            if best.is_some_and(|(best_order, _)| *order >= best_order) {
                break;
            }
            if matcher.matches(normalized_domain) {
                best = Some((*order, target));
                break;
            }
        }
        best.map(|(_, target)| target)
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.suffix.len() + self.subdomain.len() + self.others.len()
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && self.suffix.is_empty()
            && self.subdomain.is_empty()
            && self.others.is_empty()
    }
}

impl<T> Extend<(DomainMatcher, T)> for DomainHostIndex<T> {
    fn extend<I: IntoIterator<Item = (DomainMatcher, T)>>(&mut self, entries: I) {
        let entries = entries.into_iter();
        self.full.reserve(entries.size_hint().0);
        for (matcher, target) in entries {
            self.insert(matcher, target);
        }
    }
}

impl<T> FromIterator<(DomainMatcher, T)> for DomainHostIndex<T> {
    fn from_iter<I: IntoIterator<Item = (DomainMatcher, T)>>(entries: I) -> Self {
        let mut index = Self::new();
        index.extend(entries);
        index
    }
}

fn normalize_dns_pattern(mut pattern: String) -> String {
    let trimmed = pattern.trim_end_matches('.').len();
    pattern.truncate(trimmed);
    pattern.make_ascii_lowercase();
    pattern
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;
    use crate::RegexMatcher;

    fn full(name: &str) -> DomainMatcher {
        DomainMatcher::Full(name.to_owned())
    }

    fn suffix(name: &str) -> DomainMatcher {
        DomainMatcher::Suffix(name.to_owned())
    }

    fn keyword(name: &str) -> DomainMatcher {
        DomainMatcher::Keyword(name.to_owned())
    }

    fn regex(pattern: &str) -> DomainMatcher {
        DomainMatcher::Regex(RegexMatcher::new(pattern).unwrap())
    }

    #[test]
    fn empty_index_matches_nothing() {
        let index = DomainHostIndex::<u8>::new();
        assert!(index.is_empty());
        assert_eq!(index.len(), 0);
        assert_eq!(index.lookup(""), None);
        assert_eq!(index.lookup("example.com"), None);
        assert_eq!(index, DomainHostIndex::default());
    }

    #[test]
    fn exact_names_win_over_earlier_broader_matchers() {
        let index: DomainHostIndex<u8> = [
            (keyword("example"), 1),
            (suffix("proxy.example"), 2),
            (full("PROXY.EXAMPLE."), 3),
            (regex(r"^www\."), 4),
        ]
        .into_iter()
        .collect();
        assert_eq!(index.len(), 4);
        assert_eq!(index.lookup("proxy.example"), Some(&3));
        assert_eq!(index.lookup("www.proxy.example"), Some(&1));
        assert_eq!(index.lookup("www.other.test"), Some(&4));
        assert_eq!(index.lookup("other.test"), None);
        assert_eq!(index.lookup("proxy.example."), Some(&1));
    }

    #[test]
    fn first_exact_entry_for_a_name_is_kept() {
        let mut index = DomainHostIndex::new();
        index.insert(full("Dup.Test"), "first");
        index.insert(full("dup.test."), "second");
        index.insert(full("dup.test"), "third");
        assert_eq!(index.len(), 1);
        assert_eq!(index.lookup("dup.test"), Some(&"first"));
    }

    #[test]
    fn other_matchers_keep_insertion_order() {
        let index: DomainHostIndex<&str> = [
            (suffix("Corp.Example."), "suffix"),
            (keyword("corp"), "keyword"),
        ]
        .into_iter()
        .collect();
        assert_eq!(index.lookup("intranet.corp.example"), Some(&"suffix"));
        assert_eq!(index.lookup("corp.example"), Some(&"suffix"));
        assert_eq!(index.lookup("corp.other"), Some(&"keyword"));
        assert_eq!(index.lookup("notcorp.example"), Some(&"keyword"));
        assert_eq!(index.lookup("unrelated.test"), None);
    }

    #[test]
    fn full_host_entries_stay_within_the_per_entry_budget() {
        const HOSTS: usize = 50_000;
        const MAX_HEAP_BYTES_PER_ENTRY: usize = 96;

        assert!(size_of::<(DomainMatcher, u64)>() <= 48);
        assert!(size_of::<(Box<str>, u64)>() <= 24);

        let mut index = DomainHostIndex::new();
        for index_value in 0..HOSTS {
            index.insert(
                full(&format!("host-{index_value}.hosts-probe.invalid")),
                index_value as u64,
            );
        }
        assert_eq!(index.len(), HOSTS);
        assert!(index.others.is_empty());

        let name_bytes = index.full.keys().map(|name| name.len()).sum::<usize>();
        let buckets = (index.full.capacity() * 8).div_ceil(7).next_power_of_two();
        let table_bytes = buckets * (size_of::<(Box<str>, u64)>() + 1);
        let heap_bytes = name_bytes + table_bytes;
        eprintln!(
            "hosts index: table {table_bytes} B + names {name_bytes} B = {} B/entry",
            heap_bytes / HOSTS
        );
        assert!(heap_bytes <= HOSTS * MAX_HEAP_BYTES_PER_ENTRY);
        assert_eq!(
            index.lookup("host-49999.hosts-probe.invalid"),
            Some(&49_999)
        );
        assert_eq!(index.lookup("miss-49999.hosts-probe.invalid"), None);
    }

    #[test]
    fn suffix_and_subdomain_index_preserves_insertion_order_beside_others() {
        let mut index = DomainHostIndex::new();
        index.insert(suffix("Late.Example."), "suffix-first");
        index.insert(keyword("early"), "keyword-second");
        index.insert(
            DomainMatcher::Subdomain("sub.example".to_owned()),
            "subdomain-third",
        );
        index.insert(suffix("sub.example"), "suffix-fourth");
        assert!(index.others.len() == 1);

        // `suffix("late.example")` beats `keyword("early")` because suffix was inserted first.
        assert_eq!(index.lookup("early.late.example"), Some(&"suffix-first"));
        // `keyword("early")` beats `subdomain("sub.example")` because keyword came second.
        assert_eq!(index.lookup("early.sub.example"), Some(&"keyword-second"));
        // `subdomain("sub.example")` matches strict subdomain before `suffix("sub.example")`.
        assert_eq!(index.lookup("api.sub.example"), Some(&"subdomain-third"));
        // Apex `sub.example` skips `subdomain("sub.example")` and hits `suffix("sub.example")`.
        assert_eq!(index.lookup("sub.example"), Some(&"suffix-fourth"));
        // Trailing-dot query still respects exact matcher semantics.
        assert_eq!(index.lookup("sub.example."), None);
    }
}
