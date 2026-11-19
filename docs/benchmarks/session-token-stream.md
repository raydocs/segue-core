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

## Standby carrier

`SEGUE_STANDBY=0|1` (default 1, the product default) is the `standby` column.
The harness route is overseas, so an AI standby is not dialled in either mode.
The impairment is TCP loss recovery on one carrier, not a carrier being
replaced, which is the only stall a standby can skip. There is no
`SEGUE_SCENARIO=convo` in this script.

`SEGUE_TOKEN_SECONDS=10`, same seeds, debug test binary, 2026-11-18.

### Token stream, standby off

| standby | profile | seed | ttft_ms | delay_p50_ms | delay_p99_ms | delay_p99.9_ms | delay_max_ms | ia_p50_ms | ia_p99_ms | ia_p99.9_ms | stalls_300 | stalls_1s | up_bytes | down_bytes | payload_bytes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 0 | clean | 1 | 3.069 | 0.199 | 0.627 | 0.657 | 0.657 | 20.199 | 22.175 | 22.578 | 0 | 0 | 3765 | 17596 | 15012 |
| 0 | clean | 2 | 2.786 | 0.416 | 0.71 | 0.79 | 0.79 | 20.139 | 21.931 | 22.132 | 0 | 0 | 3639 | 17596 | 15012 |
| 0 | clean | 3 | 2.251 | 0.369 | 0.844 | 1.484 | 1.484 | 20.092 | 22.324 | 22.631 | 0 | 0 | 3621 | 17585 | 15012 |
| 0 | rtt170 | 1 | 355.887 | 87.576 | 90.457 | 90.881 | 90.881 | 20.085 | 25.307 | 26.158 | 0 | 0 | 3518 | 17588 | 15012 |
| 0 | rtt170 | 2 | 355.279 | 87.533 | 90.707 | 95.078 | 95.078 | 20.122 | 26.468 | 29.101 | 0 | 0 | 3553 | 17588 | 15012 |
| 0 | rtt170 | 3 | 355.13 | 87.619 | 90.837 | 91.087 | 91.087 | 20.072 | 24.788 | 26.69 | 0 | 0 | 3625 | 17588 | 15012 |
| 0 | cn163-offpeak | 1 | 361.219 | 88.95 | 155.636 | 175.395 | 175.395 | 19.985 | 40.671 | 105.772 | 0 | 0 | 3203 | 17588 | 15012 |
| 0 | cn163-offpeak | 2 | 354.741 | 1614.179 | 3414.544 | 3443.933 | 3443.933 | 0.003 | 29.057 | 3373.996 | 3 | 3 | 2428 | 16400 | 15012 |
| 0 | cn163-offpeak | 3 | 344.246 | 88.812 | 95.045 | 105.047 | 105.047 | 20.137 | 32.625 | 36.538 | 0 | 0 | 3581 | 17588 | 15012 |
| 0 | cn163-peak | 1 | 360.137 | 1183.958 | 4495.183 | 4595.418 | 4595.418 | 0.003 | 627.602 | 3393.185 | 7 | 3 | 1988 | 16793 | 15012 |
| 0 | cn163-peak | 2 | 345.263 | 1616.414 | 3410.847 | 3441.22 | 3441.22 | 0.002 | 30.628 | 3374.008 | 3 | 3 | 2438 | 16540 | 15012 |
| 0 | cn163-peak | 3 | 348.192 | 244.686 | 1681.143 | 1723.198 | 1723.198 | 0.006 | 31.596 | 1652.182 | 4 | 4 | 2573 | 16980 | 15012 |

### Token stream, standby on

| standby | profile | seed | ttft_ms | delay_p50_ms | delay_p99_ms | delay_p99.9_ms | delay_max_ms | ia_p50_ms | ia_p99_ms | ia_p99.9_ms | stalls_300 | stalls_1s | up_bytes | down_bytes | payload_bytes |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | clean | 1 | 2.881 | 0.394 | 0.698 | 1.266 | 1.266 | 20.101 | 22.457 | 22.689 | 0 | 0 | 3656 | 17596 | 15012 |
| 1 | clean | 2 | 2.136 | 0.412 | 0.916 | 4.641 | 4.641 | 20.141 | 22.626 | 25.516 | 0 | 0 | 3639 | 17596 | 15012 |
| 1 | clean | 3 | 1.688 | 0.296 | 0.721 | 1.577 | 1.577 | 20.089 | 22.389 | 31.138 | 0 | 0 | 3675 | 17585 | 15012 |
| 1 | rtt170 | 1 | 357.463 | 87.411 | 90.439 | 91.042 | 91.042 | 20.147 | 25.357 | 26.482 | 0 | 0 | 3598 | 17588 | 15012 |
| 1 | rtt170 | 2 | 353.132 | 87.523 | 90.555 | 91.04 | 91.04 | 20.12 | 25.353 | 26.143 | 0 | 0 | 3571 | 17588 | 15012 |
| 1 | rtt170 | 3 | 352.418 | 87.269 | 90.43 | 90.846 | 90.846 | 20.049 | 25.832 | 26.867 | 0 | 0 | 3590 | 17588 | 15012 |
| 1 | cn163-offpeak | 1 | 361.924 | 88.706 | 154.518 | 175.88 | 175.88 | 20.123 | 40.948 | 108.991 | 0 | 0 | 3203 | 17588 | 15012 |
| 1 | cn163-offpeak | 2 | 351.484 | 1601.171 | 3413.294 | 3439.147 | 3439.147 | 0.003 | 29.799 | 3372.659 | 3 | 3 | 2455 | 16440 | 15012 |
| 1 | cn163-offpeak | 3 | 348.216 | 88.694 | 95.284 | 104.851 | 104.851 | 20.255 | 30.834 | 37.705 | 0 | 0 | 3662 | 17588 | 15012 |
| 1 | cn163-peak | 1 | 363.319 | 1181.433 | 4490.247 | 4590.651 | 4590.651 | 0.003 | 626.449 | 3388.69 | 7 | 3 | 1997 | 16793 | 15012 |
| 1 | cn163-peak | 2 | 347.937 | 1610.587 | 3413.569 | 3451.751 | 3451.751 | 0.002 | 30.397 | 3384.597 | 3 | 3 | 2446 | 16085 | 15012 |
| 1 | cn163-peak | 3 | 350.505 | 244.983 | 1681.174 | 1722.548 | 1722.548 | 0.001 | 31.259 | 1654.019 | 4 | 3 | 2717 | 16975 | 15012 |

### New flows, standby off

| standby | profile | seed | ttfb_p50_ms | ttfb_p99_ms | ttfb_max_ms |
|---:|---|---:|---:|---:|---:|
| 0 | clean | 1 | 1.181 | 1.697 | 1.697 |
| 0 | clean | 2 | 1.873 | 3.225 | 3.225 |
| 0 | clean | 3 | 1.318 | 1.724 | 1.724 |
| 0 | rtt170 | 1 | 354.316 | 357.706 | 357.706 |
| 0 | rtt170 | 2 | 353.343 | 356.577 | 356.577 |
| 0 | rtt170 | 3 | 350.254 | 357.554 | 357.554 |
| 0 | cn163-offpeak | 1 | 360.033 | 364.912 | 364.912 |
| 0 | cn163-offpeak | 2 | 347.339 | 352.891 | 352.891 |
| 0 | cn163-offpeak | 3 | 348.739 | 352.61 | 352.61 |
| 0 | cn163-peak | 1 | 360.3 | 366.414 | 366.414 |
| 0 | cn163-peak | 2 | 350.216 | 358.843 | 358.843 |
| 0 | cn163-peak | 3 | 347.467 | 352.141 | 352.141 |

### New flows, standby on

| standby | profile | seed | ttfb_p50_ms | ttfb_p99_ms | ttfb_max_ms |
|---:|---|---:|---:|---:|---:|
| 1 | clean | 1 | 1.936 | 6.5 | 6.5 |
| 1 | clean | 2 | 1.443 | 1.802 | 1.802 |
| 1 | clean | 3 | 1.876 | 5.194 | 5.194 |
| 1 | rtt170 | 1 | 356.43 | 359.202 | 359.202 |
| 1 | rtt170 | 2 | 351.695 | 354.224 | 354.224 |
| 1 | rtt170 | 3 | 352.239 | 355.619 | 355.619 |
| 1 | cn163-offpeak | 1 | 362.746 | 367.584 | 367.584 |
| 1 | cn163-offpeak | 2 | 349.403 | 357.691 | 357.691 |
| 1 | cn163-offpeak | 3 | 350.303 | 353.367 | 353.367 |
| 1 | cn163-peak | 1 | 360.462 | 367.216 | 367.216 |
| 1 | cn163-peak | 2 | 350.643 | 353.006 | 353.006 |
| 1 | cn163-peak | 3 | 350.104 | 357.408 | 357.408 |

No token-stall row improved. Head-of-line stalls on `cn163-offpeak` seed 2 and
`cn163-peak` (the multi-second delay and the stall counts) are the same shape
in both modes. `rtt170` delay p50 stays about 87 ms. The clean-path p99.9 on
seed 2 (0.79 ms to 4.6 ms) and two clean new-flow p99 samples (about 2 ms to
5–6 ms) moved, and `cn163-peak` seed 3 lost one `stalls_1s` count (4 to 3).
Those are single-run noise on a path that never dials the spare, not a
standby effect. Nothing got worse in a way this harness can attribute to the
switch.
