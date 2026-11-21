//! Bounded in-memory DNS cache with stale-while-revalidate (SWR),
//! singleflight deduplication, and RFC 8305 address-family interleaving.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use crate::dial::Resolver;
use crate::metrics::Metrics;
use crate::Clock;

/// Interleave IPv6 and IPv4 addresses (RFC 8305 §4 style) while preserving
/// `addrs[0]`'s address family first, deduplicating addresses, and keeping
/// intra-family order intact.
pub fn interleave_addrs(addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    if addrs.is_empty() {
        return addrs;
    }
    let first_v6 = addrs[0].is_ipv6();
    let mut primary = VecDeque::new();
    let mut secondary = VecDeque::new();
    let mut seen = Vec::with_capacity(addrs.len());
    for ip in addrs {
        if seen.contains(&ip) {
            continue;
        }
        seen.push(ip);
        if ip.is_ipv6() == first_v6 {
            primary.push_back(ip);
        } else {
            secondary.push_back(ip);
        }
    }
    let mut out = Vec::with_capacity(seen.len());
    while !primary.is_empty() || !secondary.is_empty() {
        if let Some(ip) = primary.pop_front() {
            out.push(ip);
        }
        if let Some(ip) = secondary.pop_front() {
            out.push(ip);
        }
    }
    out
}

/// Configuration for [`DnsCache`] / [`cached_resolver`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DnsCacheConfig {
    /// Freshness window (`0` disables caching).
    pub ttl: Duration,
    /// Grace window after `ttl` during which stale entries are served while
    /// one background refresh updates the cache.
    pub stale_ttl: Duration,
    /// Maximum cached domain names before evicting expired / least-recently-used.
    pub max_entries: usize,
    /// Hard timeout applied to singleflight / background refreshes.
    pub refresh_timeout: Duration,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            ttl: Duration::from_secs(30),
            stale_ttl: Duration::from_secs(60),
            max_entries: 4096,
            refresh_timeout: Duration::from_secs(5),
        }
    }
}

#[derive(Clone)]
struct Entry {
    ips: Vec<IpAddr>,
    fetched_at: u64,
    last_used: u64,
}

type InFlightRx = watch::Receiver<Option<Result<Vec<IpAddr>, String>>>;
type InFlightTx = watch::Sender<Option<Result<Vec<IpAddr>, String>>>;

#[derive(Default)]
struct CacheState {
    entries: HashMap<String, Entry>,
    in_flight: HashMap<String, InFlightRx>,
    lru_seq: u64,
}

impl CacheState {
    fn next_seq(&mut self) -> u64 {
        self.lru_seq = self.lru_seq.wrapping_add(1);
        self.lru_seq
    }

    fn insert(
        &mut self,
        host: String,
        ips: Vec<IpAddr>,
        fetched_at: u64,
        stale_limit_secs: u64,
        cap: usize,
    ) {
        if cap == 0 {
            return;
        }
        let seq = self.next_seq();
        if !self.entries.contains_key(&host) && self.entries.len() >= cap {
            self.entries
                .retain(|_, e| fetched_at.saturating_sub(e.fetched_at) < stale_limit_secs);
            while self.entries.len() >= cap {
                let oldest = self
                    .entries
                    .iter()
                    .min_by_key(|(_, e)| e.last_used)
                    .map(|(k, _)| k.clone());
                match oldest {
                    Some(k) => {
                        self.entries.remove(&k);
                    }
                    None => break,
                }
            }
        }
        self.entries.insert(
            host,
            Entry {
                ips,
                fetched_at,
                last_used: seq,
            },
        );
    }
}

struct InFlightGuard {
    state: Arc<Mutex<CacheState>>,
    host: Option<String>,
    tx: Option<InFlightTx>,
}

impl InFlightGuard {
    fn disarm(&mut self) {
        self.host = None;
    }

    fn complete(mut self, res: Result<Vec<IpAddr>, String>) {
        self.disarm();
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(res));
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        if let Some(host) = self.host.take() {
            self.state.lock().unwrap().in_flight.remove(&host);
        }
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Some(Err("dns resolution aborted".into())));
        }
    }
}

/// Bounded TTL + SWR + singleflight DNS cache wrapping an upstream [`Resolver`].
pub struct DnsCache {
    inner: Resolver,
    clock: Clock,
    cfg: DnsCacheConfig,
    metrics: Option<Arc<Metrics>>,
    state: Arc<Mutex<CacheState>>,
}

impl DnsCache {
    pub fn new(
        inner: Resolver,
        clock: Clock,
        cfg: DnsCacheConfig,
        metrics: Option<Arc<Metrics>>,
    ) -> Self {
        Self {
            inner,
            clock,
            cfg,
            metrics,
            state: Arc::new(Mutex::new(CacheState::default())),
        }
    }

    fn ttl_secs(&self) -> u64 {
        if self.cfg.ttl.is_zero() {
            0
        } else {
            self.cfg.ttl.as_secs().max(1)
        }
    }

    fn stale_limit_secs(&self) -> u64 {
        let ttl = self.ttl_secs();
        if ttl == 0 {
            return 0;
        }
        let swr = if self.cfg.stale_ttl.is_zero() {
            0
        } else {
            self.cfg.stale_ttl.as_secs().max(1)
        };
        ttl.saturating_add(swr)
    }

    fn spawn_lookup(&self, host: String, tx: InFlightTx, stale_limit_secs: u64) {
        let inner = self.inner.clone();
        let clock = self.clock.clone();
        let state = self.state.clone();
        let timeout = self.cfg.refresh_timeout;
        let max_entries = self.cfg.max_entries;
        tokio::spawn(async move {
            let mut guard = InFlightGuard {
                state: state.clone(),
                host: Some(host.clone()),
                tx: Some(tx),
            };
            let lookup = tokio::time::timeout(timeout, (inner)(host.clone())).await;
            let result = match lookup {
                Ok(Ok(ips)) if !ips.is_empty() => {
                    let ordered = interleave_addrs(ips);
                    let now = (clock)();
                    {
                        let mut st = state.lock().unwrap();
                        st.in_flight.remove(&host);
                        guard.disarm();
                        st.insert(host, ordered.clone(), now, stale_limit_secs, max_entries);
                    }
                    Ok(ordered)
                }
                Ok(Ok(_)) => {
                    {
                        let mut st = state.lock().unwrap();
                        st.in_flight.remove(&host);
                        guard.disarm();
                    }
                    Err("dns returned no addresses".into())
                }
                Ok(Err(e)) => {
                    {
                        let mut st = state.lock().unwrap();
                        st.in_flight.remove(&host);
                        guard.disarm();
                    }
                    Err(e.to_string())
                }
                Err(_) => {
                    {
                        let mut st = state.lock().unwrap();
                        st.in_flight.remove(&host);
                        guard.disarm();
                    }
                    Err("dns lookup timed out".into())
                }
            };
            guard.complete(result);
        });
    }

    pub async fn resolve(&self, host: String) -> io::Result<Vec<IpAddr>> {
        let ttl_secs = self.ttl_secs();
        if ttl_secs == 0 || self.cfg.max_entries == 0 {
            let ips = (self.inner)(host).await?;
            return Ok(interleave_addrs(ips));
        }
        let stale_limit_secs = self.stale_limit_secs();
        let now = (self.clock)();

        let (mut rx, spawn_tx) = {
            let mut st = self.state.lock().unwrap();
            let seq = st.next_seq();
            if let Some(entry) = st.entries.get_mut(&host) {
                let age = now.saturating_sub(entry.fetched_at);
                if age < ttl_secs {
                    entry.last_used = seq;
                    let ips = entry.ips.clone();
                    if let Some(m) = &self.metrics {
                        Metrics::inc(&m.dns_cache_hits);
                    }
                    return Ok(ips);
                }
                if age < stale_limit_secs {
                    entry.last_used = seq;
                    let ips = entry.ips.clone();
                    if let Some(m) = &self.metrics {
                        Metrics::inc(&m.dns_cache_stale_hits);
                    }
                    let stale_spawn = if !st.in_flight.contains_key(&host) {
                        let (tx, rx) = watch::channel(None);
                        st.in_flight.insert(host.clone(), rx);
                        Some((host, tx))
                    } else {
                        None
                    };
                    drop(st);
                    if let Some((h, tx)) = stale_spawn {
                        self.spawn_lookup(h, tx, stale_limit_secs);
                    }
                    return Ok(ips);
                }
            }
            if let Some(m) = &self.metrics {
                Metrics::inc(&m.dns_cache_misses);
            }
            if let Some(rx) = st.in_flight.get(&host) {
                (rx.clone(), None)
            } else {
                let (tx, rx) = watch::channel(None);
                st.in_flight.insert(host.clone(), rx.clone());
                (rx, Some(tx))
            }
        };

        if let Some(tx) = spawn_tx {
            self.spawn_lookup(host, tx, stale_limit_secs);
        }

        loop {
            if let Some(res) = rx.borrow_and_update().as_ref() {
                return res.clone().map_err(io::Error::other);
            }
            if rx.changed().await.is_err() {
                return Err(io::Error::other("dns resolution canceled"));
            }
        }
    }
}

/// Wrap `inner` in a bounded [`DnsCache`] and expose it as a [`Resolver`].
pub fn cached_resolver(
    inner: Resolver,
    clock: Clock,
    cfg: DnsCacheConfig,
    metrics: Option<Arc<Metrics>>,
) -> Resolver {
    let cache = Arc::new(DnsCache::new(inner, clock, cfg, metrics));
    Arc::new(move |host: String| {
        let cache = cache.clone();
        Box::pin(async move { cache.resolve(host).await })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use tokio::sync::Notify;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn interleave_addrs_alternates_families_preserving_first_and_dedup() {
        let a = vec![
            ip("2001:db8::1"),
            ip("2001:db8::2"),
            ip("2001:db8::1"),
            ip("1.1.1.1"),
            ip("1.0.0.1"),
        ];
        assert_eq!(
            interleave_addrs(a),
            vec![
                ip("2001:db8::1"),
                ip("1.1.1.1"),
                ip("2001:db8::2"),
                ip("1.0.0.1"),
            ]
        );
        let b = vec![ip("8.8.8.8"), ip("8.8.4.4"), ip("2001:4860::8888")];
        assert_eq!(
            interleave_addrs(b),
            vec![ip("8.8.8.8"), ip("2001:4860::8888"), ip("8.8.4.4")]
        );
    }

    #[tokio::test]
    async fn cache_fresh_hit_skips_resolver() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(1000));
        let metrics = Arc::new(Metrics::default());
        let inner: Resolver = {
            let calls = calls.clone();
            Arc::new(move |_h| {
                calls.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok(vec![ip("93.184.216.34"), ip("2606:2800:220:1::1")]) })
            })
        };
        let clock: Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let res = cached_resolver(
            inner,
            clock,
            DnsCacheConfig::default(),
            Some(metrics.clone()),
        );

        let first = res("example.com".into()).await.unwrap();
        assert_eq!(first, vec![ip("93.184.216.34"), ip("2606:2800:220:1::1")]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.dns_cache_misses.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.dns_cache_hits.load(Ordering::Relaxed), 0);

        now.store(1010, Ordering::SeqCst);
        let second = res("example.com".into()).await.unwrap();
        assert_eq!(second, first);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(metrics.dns_cache_hits.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cache_singleflight_deduplicates_concurrent_misses() {
        let calls = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let inner: Resolver = {
            let calls = calls.clone();
            let entered = entered.clone();
            let release = release.clone();
            Arc::new(move |_h| {
                let calls = calls.clone();
                let entered = entered.clone();
                let release = release.clone();
                Box::pin(async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    entered.notify_one();
                    release.notified().await;
                    Ok(vec![ip("1.1.1.1")])
                })
            })
        };
        let clock: Clock = Arc::new(|| 500);
        let res = cached_resolver(inner, clock, DnsCacheConfig::default(), None);

        let r1 = tokio::spawn({
            let res = res.clone();
            async move { res("cf.test".into()).await.unwrap() }
        });
        entered.notified().await;
        let r2 = tokio::spawn({
            let res = res.clone();
            async move { res("cf.test".into()).await.unwrap() }
        });
        let r3 = tokio::spawn({
            let res = res.clone();
            async move { res("cf.test".into()).await.unwrap() }
        });
        tokio::task::yield_now().await;
        release.notify_waiters();

        assert_eq!(r1.await.unwrap(), vec![ip("1.1.1.1")]);
        assert_eq!(r2.await.unwrap(), vec![ip("1.1.1.1")]);
        assert_eq!(r3.await.unwrap(), vec![ip("1.1.1.1")]);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_stale_while_revalidate_returns_immediately_and_refreshes_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(100));
        let metrics = Arc::new(Metrics::default());
        let refreshed = Arc::new(Notify::new());
        let inner: Resolver = {
            let calls = calls.clone();
            let refreshed = refreshed.clone();
            Arc::new(move |_h| {
                let calls = calls.clone();
                let refreshed = refreshed.clone();
                Box::pin(async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    if n == 0 {
                        Ok(vec![ip("1.1.1.1")])
                    } else {
                        refreshed.notify_one();
                        Ok(vec![ip("8.8.8.8")])
                    }
                })
            })
        };
        let clock: Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let cfg = DnsCacheConfig {
            ttl: Duration::from_secs(10),
            stale_ttl: Duration::from_secs(20),
            max_entries: 64,
            refresh_timeout: Duration::from_secs(2),
        };
        let res = cached_resolver(inner, clock, cfg, Some(metrics.clone()));

        assert_eq!(res("swr.test".into()).await.unwrap(), vec![ip("1.1.1.1")]);
        now.store(115, Ordering::SeqCst);
        let (a, b) = tokio::join!(res("swr.test".into()), res("swr.test".into()));
        assert_eq!(a.unwrap(), vec![ip("1.1.1.1")]);
        assert_eq!(b.unwrap(), vec![ip("1.1.1.1")]);
        refreshed.notified().await;
        // Let spawned refresh task store the new entry.
        for _ in 0..20 {
            tokio::task::yield_now().await;
            if res("swr.test".into()).await.unwrap() == vec![ip("8.8.8.8")] {
                break;
            }
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(res("swr.test".into()).await.unwrap(), vec![ip("8.8.8.8")]);
        assert!(metrics.dns_cache_stale_hits.load(Ordering::Relaxed) >= 1);
    }

    #[tokio::test]
    async fn cache_does_not_cache_errors_or_empty_and_evicts_at_cap() {
        let calls = Arc::new(AtomicUsize::new(0));
        let now = Arc::new(AtomicU64::new(200));
        let inner: Resolver = {
            let calls = calls.clone();
            Arc::new(move |h| {
                let calls = calls.clone();
                Box::pin(async move {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    match h.as_str() {
                        "err.test" => {
                            if n == 0 {
                                Err(io::Error::other("transient"))
                            } else {
                                Ok(vec![ip("9.9.9.9")])
                            }
                        }
                        "empty.test" => Ok(Vec::new()),
                        "a.test" => Ok(vec![ip("1.1.1.1")]),
                        "b.test" => Ok(vec![ip("1.0.0.1")]),
                        _ => Ok(vec![ip("8.8.8.8")]),
                    }
                })
            })
        };
        let clock: Clock = {
            let now = now.clone();
            Arc::new(move || now.load(Ordering::SeqCst))
        };
        let cfg = DnsCacheConfig {
            ttl: Duration::from_secs(30),
            stale_ttl: Duration::from_secs(30),
            max_entries: 2,
            refresh_timeout: Duration::from_secs(2),
        };
        let res = cached_resolver(inner, clock, cfg, None);

        assert!(res("err.test".into()).await.is_err());
        assert_eq!(res("err.test".into()).await.unwrap(), vec![ip("9.9.9.9")]);
        assert!(res("empty.test".into()).await.is_err());
        let before = calls.load(Ordering::SeqCst);
        assert!(res("empty.test".into()).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), before + 1);

        // Cache now holds err.test (lru 1); insert a.test (lru 2), touch err.test (lru 3),
        // then insert b.test (cap=2) -> evicts a.test, keeping err.test & b.test.
        assert_eq!(res("a.test".into()).await.unwrap(), vec![ip("1.1.1.1")]);
        assert_eq!(res("err.test".into()).await.unwrap(), vec![ip("9.9.9.9")]);
        let before_evict = calls.load(Ordering::SeqCst);
        assert_eq!(res("b.test".into()).await.unwrap(), vec![ip("1.0.0.1")]);
        assert_eq!(res("err.test".into()).await.unwrap(), vec![ip("9.9.9.9")]);
        assert_eq!(calls.load(Ordering::SeqCst), before_evict + 1);
        assert_eq!(res("a.test".into()).await.unwrap(), vec![ip("1.1.1.1")]);
        assert_eq!(calls.load(Ordering::SeqCst), before_evict + 2);
    }
}
