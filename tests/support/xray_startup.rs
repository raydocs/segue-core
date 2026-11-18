//! Starting a reference process — Xray-core, or a Go stand-in that binds a
//! port of its own — on a port the harness picked by binding `127.0.0.1:0`
//! and dropping the listener. Another test's socket can take that port
//! before the reference binds it, and the reference then exits at once with
//! `listen tcp 127.0.0.1:PORT: bind: address already in use` (or the same
//! for `listen udp`). Every such start is attempted again on fresh ports;
//! any other early exit still fails at once with the reference's output.
//!
//! Each suite includes its own copy of this file through `#[path]`, so not
//! every item is used in every test binary.
#![allow(dead_code)]

use std::process::Child;
use std::time::Duration;

/// Whether the reference's output shows another socket holding one of its
/// ports: TCP's `listen tcp 127.0.0.1:1234: bind: address already in use`,
/// and UDP's `listen udp ...` alike.
pub fn port_taken(output: &str) -> bool {
    output.contains("bind: address already in use")
}

/// Runs `$attempt` up to five times and takes the first start it returns.
/// `$attempt` is one whole start — picking fresh ports, rendering the config
/// for them, spawning the reference and waiting for it — and yields `None`
/// only when the reference exited because another socket held its port,
/// which [`wait_ready`] reports and any other exit must not.
///
/// A macro, not a function: `$attempt` is re-expanded on every attempt, so
/// it can borrow the caller's paths and config-rendering closure, which a
/// `FnMut() -> impl Future` parameter cannot hand back. The attempt count is
/// written here alone, so every suite shares one policy.
macro_rules! start_on_fresh_ports {
    ($what:expr, $attempt:expr) => {{
        // A start that keeps losing its port for five attempts in a row is
        // failing for some other reason the output is not saying.
        const ATTEMPTS: usize = 5;
        let what = $what;
        let mut number = 1;
        loop {
            if let Some(reference) = ($attempt).await {
                break reference;
            }
            assert!(
                number < ATTEMPTS,
                "{what} lost its port {ATTEMPTS} times in a row"
            );
            eprintln!(
                "{what} lost its port on attempt {number} of {ATTEMPTS}; starting it again on a fresh one"
            );
            number += 1;
        }
    }};
}

/// Waits until `ready` holds for the reference's output, which `logs`
/// renders. Returns `false` when the reference exited because another socket
/// took its port — the caller then starts it again through
/// [`start_on_fresh_ports`] — and panics with the output on any other exit,
/// or when `deadline` passes.
pub async fn wait_ready(
    child: &mut Child,
    logs: impl Fn() -> String,
    ready: impl Fn(&str) -> bool,
    what: &str,
    deadline: Duration,
) -> bool {
    let deadline = tokio::time::Instant::now() + deadline;
    loop {
        let output = logs();
        if child.try_wait().expect("check the reference").is_some() {
            assert!(
                port_taken(&output),
                "{what} exited before it was ready:\n{output}"
            );
            return false;
        }
        if ready(&output) {
            return true;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "{what} was not ready in time:\n{output}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
