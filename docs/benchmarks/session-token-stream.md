# Session token-stream baseline

Stage 0 measurement for later carrier work (racing, warm carriers, redundancy,
coalescing). Nothing in the product changes. The harness is a loopback
`cargo test` binary (debug, not `--release`).

```text
app TCP ──SOCKS── kernel session ──impair (tcp-loss emulate)── relay ── origin
```

The origin, after one request line, writes one 30-byte event every 20 ms for
`SEGUE_TOKEN_SECONDS` (default 30). Each event carries its index and the
origin's send time. The carrier is plain TCP, the same shape as
`roaming_e2e`. The impair relay sits on that carrier with `--tcp-loss emulate`.

## What is measured

**Token stream**, per profile and seed:

- time to first token, from the start of the SOCKS handshake
- token delay = arrival − origin send time (p50, p99, p99.9, max)
- token inter-arrival (p50, p99, p99.9)
- stalls: inter-arrival gaps `> 300 ms` and `> 1 s` (a gap over 1 s is in both)
- bytes the impair relay wrote in each direction, and app payload
  (the 12-byte request plus `N × 30` event bytes)

**New flows**: 20 sequential connections, one `PING` and an 8-byte response.
TTFB is from the start of the SOCKS handshake until that response. This is
the baseline for racing and warm carriers.

Percentile index is `ceil(p × n) − 1` on the sorted sample. With 20 new
flows, p99 is the worst sample, so that column matches max.

There is no carrier re-attach column. `SessionHealth` is not observable
from the test without changing the kernel.

Profiles: `clean`, `rtt170`, `cn163-offpeak`, `cn163-peak`. Seeds: 1, 2, 3.
The same seed makes the same loss decisions. The millisecond columns are
wall-clock on this machine, so they move a little between runs; the loss
sequence does not.

## TCP loss model

Emulation never drops a TCP byte. Each read chunk, capped at 1400 B, is one
segment. A lost segment is delivered after a recovery delay and everything
behind it waits, then flushes in order. `rtt` is twice the profile's one-way
delay. Three or more later segments inside one `rtt` is a fast retransmit
(`rtt`); otherwise a tail-loss probe (`2 × rtt`). A lost retransmission adds
`max(200 ms, 3 × rtt)`, doubling per further loss, each step capped at 8 s.
The first segment in each direction stands for the SYN flight: 1 s, then
another 1 s. This is a model of TCP recovery, not TCP, and a Linux `tc netem`
job will calibrate it later. Constants live in `crates/segue-bench/src/impair.rs`.
The mode is off unless the relay is asked (`--tcp-loss emulate`).

## How to run

```sh
export CARGO_HOME=/Volumes/dev/ci/cargo RUSTUP_HOME=/Volumes/dev/ci/rustup \
  CARGO_TARGET_DIR=/Volumes/dev/ci/bee-target.noindex PATH=/Volumes/dev/ci/cargo/bin:$PATH
SEGUE_TOKEN_SECONDS=10 bash scripts/bench/session-redundancy.sh
```

Set `SEGUE_BENCH_OUT` to also write the same numbers as JSON. The test is
`#[ignore]`d; the script passes `--ignored`. Loopback only, port 0.

The test checks, rather than leaving it to the eye: on `clean`, no stall over
300 ms and token-delay p99 under 20 ms; on `rtt170`, token-delay p50 within
85 ± 15 ms; on `cn163-peak`, at least one stall over 300 ms.

## Baseline

`SEGUE_TOKEN_SECONDS=10` (500 events), seeds 1–3, debug test binary,
2026-11-18. Both tables are what that run printed.

### Token stream

| profile | seed | ttft_ms | delay_p50_ms | delay_p99_ms | delay_p99.9_ms | delay_max_ms | ia_p50_ms | ia_p99_ms | ia_p99.9_ms | stalls_300 | stalls_1s | up_bytes | down_bytes | payload_bytes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| clean | 1 | 3.656 | 0.154 | 0.614 | 0.735 | 0.735 | 20.124 | 22.365 | 22.715 | 0 | 0 | 3818 | 17596 | 15012 |
| clean | 2 | 2.437 | 0.224 | 0.567 | 0.706 | 0.706 | 20.123 | 22.409 | 22.542 | 0 | 0 | 3808 | 17585 | 15012 |
| clean | 3 | 1.201 | 0.123 | 0.539 | 0.743 | 0.743 | 20.12 | 22.258 | 22.631 | 0 | 0 | 3846 | 17596 | 15012 |
| rtt170 | 1 | 355.745 | 87.396 | 90.386 | 90.788 | 90.788 | 20.144 | 24.583 | 25.813 | 0 | 0 | 3644 | 17588 | 15012 |
| rtt170 | 2 | 353.397 | 87.4 | 90.633 | 93.409 | 93.409 | 20.04 | 26.122 | 27.209 | 0 | 0 | 3526 | 17588 | 15012 |
| rtt170 | 3 | 346.428 | 87.357 | 90.605 | 91.223 | 91.223 | 20.143 | 25.15 | 26.096 | 0 | 0 | 3589 | 17588 | 15012 |
| cn163-offpeak | 1 | 359.669 | 88.863 | 152.381 | 176.44 | 176.44 | 20.199 | 42.209 | 106.227 | 0 | 0 | 3203 | 17588 | 15012 |
| cn163-offpeak | 2 | 348.119 | 1596.409 | 3414.331 | 3443.172 | 3443.172 | 0.003 | 29.927 | 3376.175 | 3 | 3 | 2446 | 16300 | 15012 |
| cn163-offpeak | 3 | 344.431 | 88.626 | 94.151 | 104.825 | 104.825 | 20.274 | 33.082 | 36.491 | 0 | 0 | 3617 | 17588 | 15012 |
| cn163-peak | 1 | 361.701 | 1180.997 | 4489.029 | 4588.494 | 4588.494 | 0.003 | 625.975 | 3387.972 | 7 | 3 | 1979 | 16793 | 15012 |
| cn163-peak | 2 | 347.176 | 1602.49 | 3418.737 | 3452.847 | 3452.847 | 0.001 | 30.379 | 3384.892 | 3 | 3 | 2455 | 16720 | 15012 |
| cn163-peak | 3 | 349.238 | 319.39 | 1681.608 | 1722.714 | 1722.714 | 0.004 | 32.414 | 1656.377 | 4 | 4 | 2501 | 16945 | 15012 |

On `rtt170` (no loss, 85 ms one way) token-delay p50 is about 87 ms and
inter-arrival stays near the 20 ms send spacing. On `cn163-peak` a lost
segment head-of-line blocks the events behind it, so p50 delay leaves the
one-way band and the stall columns are non-zero. `cn163-offpeak` seed 2 is
the same shape; seeds 1 and 3 barely leave the one-way delay. That spread is
the seeded burst model, not a failed run.

### New flows

| profile | seed | ttfb_p50_ms | ttfb_p99_ms | ttfb_max_ms |
|---|---:|---:|---:|---:|
| clean | 1 | 0.832 | 1.354 | 1.354 |
| clean | 2 | 0.862 | 1.534 | 1.534 |
| clean | 3 | 1.507 | 4.075 | 4.075 |
| rtt170 | 1 | 354.061 | 361.248 | 361.248 |
| rtt170 | 2 | 350.888 | 352.983 | 352.983 |
| rtt170 | 3 | 350.225 | 353.517 | 353.517 |
| cn163-offpeak | 1 | 359.415 | 364.439 | 364.439 |
| cn163-offpeak | 2 | 349.483 | 352.695 | 352.695 |
| cn163-offpeak | 3 | 350.019 | 356.144 | 356.144 |
| cn163-peak | 1 | 363.669 | 366.329 | 366.329 |
| cn163-peak | 2 | 350.119 | 353.22 | 353.22 |
| cn163-peak | 3 | 348.957 | 359.809 | 359.809 |

A new flow on `rtt170` is about two round trips (SOCKS is local; the session
open crosses the impaired carrier). These three lossy seeds did not lose the
handshake flight, so their TTFB stays next to `rtt170`.
