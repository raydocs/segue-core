//! Race a second carrier dial when the first is slow.
//!
//! A lost SYN costs macOS about a second before it retransmits, and a lost
//! TLS flight about three round trips. Nothing the kernel can set on the
//! socket fixes that without root, so a dial that is still running after a
//! short delay starts one more dial to the same exit. The first success
//! carries the session. At most two dials are in flight. The caller's
//! carrier timeout bounds the whole race, not each attempt.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

/// RFC 8305's default connection-attempt delay, used when the exit has no
/// smoothed RTT yet.
const DEFAULT_DELAY: Duration = Duration::from_millis(250);
/// RFC 8305: not below 100 ms.
const MIN_DELAY: Duration = Duration::from_millis(100);
/// RFC 8305: not above 2 s.
const MAX_DELAY: Duration = Duration::from_secs(2);

/// A dial that is still running after the other one won. Dropping it
/// cancels that dial.
pub(crate) type Attempt<T, E> = Pin<Box<dyn Future<Output = Result<T, E>> + Send>>;

/// The first successful dial, or the first error if both failed.
pub(crate) struct RaceOutcome<T, E> {
    /// `Ok` is the first success. `Err` is the earlier failure, and only
    /// when both attempts failed.
    pub value: Result<T, E>,
    /// `1` or `2` when [`Self::value`] is `Ok`. `0` when both failed.
    pub attempt: u8,
    /// A second dial was started.
    pub second_started: bool,
    /// The other attempt, if it was started and has not finished. The
    /// caller decides whether to drop it or park the stream.
    pub loser: Option<Attempt<T, E>>,
}

/// How long to wait for the first dial before starting the second.
///
/// `1.5 × srtt` when the exit's smoothed RTT is known (Chromium's QUIC/TCP
/// race), otherwise 250 ms. Clamped to 100 ms..=2 s.
pub(crate) fn race_delay(srtt: Option<Duration>) -> Duration {
    let raw = match srtt {
        Some(srtt) => srtt.saturating_mul(3) / 2,
        None => DEFAULT_DELAY,
    };
    raw.clamp(MIN_DELAY, MAX_DELAY)
}

fn boxed<Fut, T, E>(fut: Fut) -> Attempt<T, E>
where
    Fut: Future<Output = Result<T, E>> + Send + 'static,
{
    Box::pin(fut)
}

fn won<T, E>(
    value: T,
    attempt: u8,
    second_started: bool,
    loser: Option<Attempt<T, E>>,
) -> RaceOutcome<T, E> {
    RaceOutcome {
        value: Ok(value),
        attempt,
        second_started,
        loser,
    }
}

fn lost<T, E>(error: E, second_started: bool) -> RaceOutcome<T, E> {
    RaceOutcome {
        value: Err(error),
        attempt: 0,
        second_started,
        loser: None,
    }
}

/// Start `dial` once. If it has not finished after `delay`, start it again.
/// Never more than two attempts. The first `Ok` wins; if the first attempt
/// fails before `delay`, the second starts at once. The error is the one
/// that happened first, and only when both failed.
pub(crate) async fn race<F, Fut, T, E>(dial: F, delay: Duration) -> RaceOutcome<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>> + Send + 'static,
{
    let mut first = boxed(dial());
    let early_error = tokio::select! {
        biased;
        res = &mut first => match res {
            Ok(value) => return won(value, 1, false, None),
            Err(error) => Some(error),
        },
        _ = tokio::time::sleep(delay) => None,
    };

    // Attempt 1 failed before the delay: do not wait it out.
    if let Some(error) = early_error {
        return match dial().await {
            Ok(value) => won(value, 2, true, None),
            Err(_) => lost(error, true),
        };
    }

    let mut second = boxed(dial());
    tokio::select! {
        biased;
        res = &mut first => match res {
            Ok(value) => won(value, 1, true, Some(second)),
            Err(error) => match second.await {
                Ok(value) => won(value, 2, true, None),
                Err(_) => lost(error, true),
            },
        },
        res = &mut second => match res {
            Ok(value) => won(value, 2, true, Some(first)),
            Err(error) => match first.await {
                Ok(value) => won(value, 1, true, None),
                // `error` is attempt 2's, and it finished while attempt 1
                // was still running, so it is the earlier failure.
                Err(_) => lost(error, true),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn race_delay_clamps() {
        assert_eq!(race_delay(None), Duration::from_millis(250));
        assert_eq!(
            race_delay(Some(Duration::from_millis(20))),
            Duration::from_millis(100)
        );
        assert_eq!(
            race_delay(Some(Duration::from_millis(172))),
            Duration::from_millis(258)
        );
        assert_eq!(
            race_delay(Some(Duration::from_secs(5))),
            Duration::from_secs(2)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn fast_first_attempt_dials_once() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let start = tokio::time::Instant::now();
        let outcome = race(
            move || {
                calls2.fetch_add(1, Ordering::SeqCst);
                async { Ok::<u8, &str>(1) }
            },
            Duration::from_millis(250),
        )
        .await;
        assert_eq!(outcome.value, Ok(1));
        assert_eq!(outcome.attempt, 1);
        assert!(!outcome.second_started);
        assert!(outcome.loser.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn slow_first_attempt_loses_to_a_fast_second() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let start = tokio::time::Instant::now();
        let outcome = race(
            move || {
                let n = calls2.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        Ok::<u8, &str>(1)
                    } else {
                        tokio::time::sleep(Duration::from_millis(40)).await;
                        Ok(2)
                    }
                }
            },
            Duration::from_millis(250),
        )
        .await;
        assert_eq!(outcome.value, Ok(2));
        assert_eq!(outcome.attempt, 2);
        assert!(outcome.second_started);
        assert!(outcome.loser.is_some());
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // delay + attempt 2's own time, and not the slow first dial.
        assert_eq!(start.elapsed(), Duration::from_millis(290));
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test(start_paused = true)]
    async fn early_failure_starts_the_second_attempt_immediately() {
        let starts = Arc::new(Mutex::new(Vec::new()));
        let starts2 = Arc::clone(&starts);
        let start = tokio::time::Instant::now();
        let outcome = race(
            move || {
                starts2.lock().unwrap().push(start.elapsed());
                let n = starts2.lock().unwrap().len();
                async move {
                    if n == 1 {
                        Err("down")
                    } else {
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        Ok(2)
                    }
                }
            },
            Duration::from_millis(250),
        )
        .await;
        assert_eq!(outcome.value, Ok(2));
        assert_eq!(outcome.attempt, 2);
        assert!(outcome.second_started);
        assert!(outcome.loser.is_none());
        let starts = starts.lock().unwrap();
        assert_eq!(starts.as_slice(), &[Duration::ZERO, Duration::ZERO]);
        assert_eq!(start.elapsed(), Duration::from_millis(30));
    }

    #[tokio::test(start_paused = true)]
    async fn both_attempts_failing_returns_the_first_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let outcome = race(
            move || {
                let n = calls2.fetch_add(1, Ordering::SeqCst);
                async move { Err::<u8, _>(if n == 0 { "first" } else { "second" }) }
            },
            Duration::from_millis(250),
        )
        .await;
        assert_eq!(outcome.value, Err("first"));
        assert_eq!(outcome.attempt, 0);
        assert!(outcome.second_started);
        assert!(outcome.loser.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // Attempt 2 fails while attempt 1 is still running: its error is
        // the earlier one, even though attempt 1 fails afterwards.
        let later = Arc::new(AtomicUsize::new(0));
        let later2 = Arc::clone(&later);
        let start = tokio::time::Instant::now();
        let outcome = race(
            move || {
                let n = later2.fetch_add(1, Ordering::SeqCst);
                async move {
                    if n == 0 {
                        tokio::time::sleep(Duration::from_millis(400)).await;
                        Err::<u8, _>("late")
                    } else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        Err("early")
                    }
                }
            },
            Duration::from_millis(200),
        )
        .await;
        assert_eq!(outcome.value, Err("early"));
        assert!(outcome.loser.is_none());
        assert_eq!(start.elapsed(), Duration::from_millis(400));
        assert_eq!(later.load(Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn earlier_finisher_wins_when_both_are_slow() {
        async fn race_pair(first_ms: u64, second_ms: u64) -> RaceOutcome<u8, &'static str> {
            let calls = Arc::new(AtomicUsize::new(0));
            race(
                move || {
                    let n = calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let wait = if n == 0 { first_ms } else { second_ms };
                        tokio::time::sleep(Duration::from_millis(wait)).await;
                        Ok(if n == 0 { 1 } else { 2 })
                    }
                },
                Duration::from_millis(200),
            )
            .await
        }

        let start = tokio::time::Instant::now();
        let outcome = race_pair(500, 80).await;
        assert_eq!(outcome.value, Ok(2));
        assert_eq!(outcome.attempt, 2);
        assert!(outcome.loser.is_some());
        assert_eq!(start.elapsed(), Duration::from_millis(280));

        let start = tokio::time::Instant::now();
        let outcome = race_pair(250, 500).await;
        assert_eq!(outcome.value, Ok(1));
        assert_eq!(outcome.attempt, 1);
        assert!(outcome.second_started);
        assert!(outcome.loser.is_some());
        assert_eq!(start.elapsed(), Duration::from_millis(250));
    }

    #[tokio::test(start_paused = true)]
    async fn never_more_than_two_dials() {
        let calls = Arc::new(AtomicUsize::new(0));
        let calls2 = Arc::clone(&calls);
        let outcome = race(
            move || {
                calls2.fetch_add(1, Ordering::SeqCst);
                async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    Ok::<u8, &str>(1)
                }
            },
            Duration::from_millis(100),
        )
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        // Both dials take 5 s from when they start, so the one that started
        // first finishes first. Dropping the loser must not dial again.
        assert_eq!(outcome.attempt, 1);
        assert!(outcome.loser.is_some());
        drop(outcome);
        tokio::time::advance(Duration::from_secs(30)).await;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }
}
