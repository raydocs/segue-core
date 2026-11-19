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
`SEGUE_EXIT_CLASS=ai|overseas` (default `ai`) is the `class` column. The
tables in this section were recorded before that switch, on an overseas
route, so an AI standby was not dialled in either mode. The impairment is
TCP loss recovery on one carrier, not a carrier being replaced, which is
the only stall a standby can skip. The conversation scenario is below.

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

## Conversation

One app TCP connection, kept open the way an HTTP/2 connection would be.
Each turn the app writes `turn <upload> <silence_ms> <tokens>` and that many
body bytes. The origin checksums the body (FNV-1a 64), waits `silence_ms`
sending nothing, then writes `tokens` events of 30 bytes every 20 ms. Event 0
carries the checksum in bytes 16..24. The next turn is the next request on
the same connection.

Default, and the tables below: 3 turns, upload 1 MiB, silence 5 s, 500 tokens.
`SEGUE_CONVO_TURNS`, `SEGUE_CONVO_UPLOAD`, `SEGUE_CONVO_SILENCE_MS` and
`SEGUE_CONVO_TOKENS` override that. The long run is 4 MiB / 45 s / 3000.

Profiles `rtt170`, `cn163-offpeak`, `cn163-peak`, `--tcp-loss emulate`, seeds
1–3. On `rtt170` only, one extra fault during turn 2: blackout 2 s over the
upload, blackout 8 s over the token stream, blackout 40 s over the token
stream, reset during the upload, reset during the token stream, silent drop
during the silence. A blackout holds bytes and then forwards them. A reset
closes connections that already exist. A silent drop stops forwarding on
those connections and does not close them. A connection accepted afterwards
still works.

`survived` means every turn finished on that same app socket, the origin's
checksum matched the bytes the app sent, and every token index arrived once,
in order. `upload_ms` is from the request send to the origin having the whole
body. `ttft_after_silence_ms` is the first token's arrival minus (that instant
plus the planned silence). Stalls are token inter-arrival gaps, not the
silence. A gap over 1 s is also a gap over 300 ms; a gap over 20 s is in all
three stall columns. `session_carriers` counts engine dials whose first byte
was not `CTRL_HELLO`. `control_streams` counts the dial whose first byte was
`CTRL_HELLO` (the relay control stream, not a session move). `engine_dials`
also counts a raced dial that was dropped before it wrote. Relay byte totals
include session framing and that control stream, so the ratio against
`payload_up` / `payload_down` is replay only when it is far above 1.

The test asserts only `rtt170` with no fault: survived, one session carrier,
one control stream, no stall over 300 ms. Every other row is reported,
including runs that die.

```sh
SEGUE_SCENARIO=convo bash scripts/bench/session-redundancy.sh
```

`SEGUE_SCENARIO=both` (the script default) runs the token stream and then
this. Debug test binary, loopback, 2026-11-18.

### Runs

| profile | seed | fault | survived | end_turn | end_phase | app_saw | engine_dials | control_streams | session_carriers | impair_accepts | up_bytes | down_bytes | payload_up | payload_down |
|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| rtt170 | 1 | none | yes | - | - |  | 2 | 1 | 1 | 2 | 3159114 | 55218 | 3145794 | 45000 |
| rtt170 | 2 | none | yes | - | - |  | 2 | 1 | 1 | 2 | 3158934 | 55240 | 3145794 | 45000 |
| rtt170 | 3 | none | yes | - | - |  | 2 | 1 | 1 | 2 | 3159019 | 55328 | 3145794 | 45000 |
| cn163-offpeak | 1 | none | yes | - | - |  | 12 | 1 | 11 | 12 | 3438473 | 56100 | 3145794 | 45000 |
| cn163-offpeak | 2 | none | yes | - | - |  | 20 | 1 | 19 | 20 | 3552805 | 51862 | 3145794 | 45000 |
| cn163-offpeak | 3 | none | yes | - | - |  | 12 | 1 | 11 | 12 | 3507236 | 56350 | 3145794 | 45000 |
| cn163-peak | 1 | none | yes | - | - |  | 28 | 1 | 27 | 28 | 3926011 | 58650 | 3145794 | 45000 |
| cn163-peak | 2 | none | yes | - | - |  | 20 | 1 | 19 | 20 | 3425945 | 52465 | 3145794 | 45000 |
| cn163-peak | 3 | none | yes | - | - |  | 63 | 1 | 62 | 63 | 4878062 | 63968 | 3145794 | 45000 |
| rtt170 | 1 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 3 | 3266174 | 55342 | 3145794 | 45000 |
| rtt170 | 2 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 3 | 3265929 | 55329 | 3145794 | 45000 |
| rtt170 | 3 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 3 | 3238621 | 55263 | 3145794 | 45000 |
| rtt170 | 1 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 3 | 3156647 | 56328 | 3145794 | 45000 |
| rtt170 | 2 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 3 | 3156573 | 53614 | 3145794 | 45000 |
| rtt170 | 3 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 3 | 3156585 | 53992 | 3145794 | 45000 |
| rtt170 | 1 | blackout-tokens-40s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 12 | 2102511 | 18259 | 3145794 | 45000 |
| rtt170 | 2 | blackout-tokens-40s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 12 | 2102368 | 18193 | 3145794 | 45000 |
| rtt170 | 3 | blackout-tokens-40s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 12 | 2102396 | 18237 | 3145794 | 45000 |
| rtt170 | 1 | reset-upload | yes | - | - |  | 4 | 2 | 2 | 4 | 3159672 | 55228 | 3145794 | 45000 |
| rtt170 | 2 | reset-upload | yes | - | - |  | 4 | 2 | 2 | 4 | 3159606 | 55305 | 3145794 | 45000 |
| rtt170 | 3 | reset-upload | yes | - | - |  | 4 | 2 | 2 | 4 | 3159482 | 55426 | 3145794 | 45000 |
| rtt170 | 1 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 4 | 3159761 | 55255 | 3145794 | 45000 |
| rtt170 | 2 | reset-tokens | yes | - | - |  | 5 | 2 | 2 | 5 | 3159473 | 55167 | 3145794 | 45000 |
| rtt170 | 3 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 4 | 3159718 | 55200 | 3145794 | 45000 |
| rtt170 | 1 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 5 | 3160116 | 55251 | 3145794 | 45000 |
| rtt170 | 2 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 5 | 3160083 | 55244 | 3145794 | 45000 |
| rtt170 | 3 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 5 | 3159899 | 55262 | 3145794 | 45000 |

On `rtt170` with no fault the conversation survives on one session carrier and one control stream. Relay bytes sit just above the payload (framing and the control stream, not a replay). The lossy profiles also survive, but they move. `cn163-peak` seed 3 dialled 62 session carriers and the relay wrote about 1.55× the upload (`4878062 / 3145794`).

The only runs that did not survive are the 40 s token blackout, all three seeds. Turn 2 dies during the token stream. The app socket sees `reset: Connection reset by peer (os error 54)`. The session dialled 9 carriers (the one that was live, then eight more) and 3 control streams before that reset. Turns 2 and 3 are absent below because the connection was already gone.

A 2 s upload blackout survives and costs one extra carrier; that turn's upload is about 2.6 s. An 8 s token blackout survives with one extra carrier and one stall of about 8 s. A reset, of the upload or of the token stream, survives: the control stream is dialled again (2 control streams) and the session moves once. `reset-tokens` seed 2 is the only one of those with a stall over 300 ms (379 ms). A silent drop during the silence also survives, with a third session carrier and a gap of about 180 ms on that turn, under 300 ms on all three seeds.

### Turns

| profile | seed | fault | turn | upload_ms | ttft_after_silence_ms | delay_p50_ms | delay_p99_ms | delay_max_ms | stalls_300 | stalls_1s | stalls_20s | longest_gap_ms |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rtt170 | 1 | none | 1 | 1933.865 | 89.668 | 86.923 | 90.079 | 90.491 | 0 | 0 | 0 | 26.151 |
| rtt170 | 1 | none | 2 | 474.733 | 88.812 | 86.842 | 90.424 | 90.938 | 0 | 0 | 0 | 26.299 |
| rtt170 | 1 | none | 3 | 266.301 | 92.519 | 87.051 | 90.402 | 90.758 | 0 | 0 | 0 | 26.88 |
| rtt170 | 2 | none | 1 | 1938.125 | 90.461 | 87.501 | 90.708 | 101.434 | 0 | 0 | 0 | 36.23 |
| rtt170 | 2 | none | 2 | 481.391 | 90.691 | 87.377 | 90.599 | 97.049 | 0 | 0 | 0 | 28.572 |
| rtt170 | 2 | none | 3 | 297.573 | 89.717 | 87.36 | 90.338 | 93.643 | 0 | 0 | 0 | 26.515 |
| rtt170 | 3 | none | 1 | 1958.121 | 89.483 | 87.521 | 90.646 | 91.662 | 0 | 0 | 0 | 27.281 |
| rtt170 | 3 | none | 2 | 504.752 | 89.375 | 87.47 | 90.748 | 93.361 | 0 | 0 | 0 | 27.598 |
| rtt170 | 3 | none | 3 | 476.703 | 90.854 | 86.955 | 90.149 | 90.518 | 0 | 0 | 0 | 26.637 |
| cn163-offpeak | 1 | none | 1 | 6235.597 | 94.458 | 88.688 | 175.431 | 262.109 | 0 | 0 | 0 | 189.527 |
| cn163-offpeak | 1 | none | 2 | 6458.753 | 96.441 | 89.029 | 175.012 | 271.385 | 0 | 0 | 0 | 201.058 |
| cn163-offpeak | 1 | none | 3 | 6632.899 | 92.881 | 88.981 | 154.441 | 175.393 | 0 | 0 | 0 | 103.863 |
| cn163-offpeak | 2 | none | 1 | 6618.807 | 92.048 | 1689.965 | 3411.514 | 3442.529 | 3 | 3 | 0 | 3376.117 |
| cn163-offpeak | 2 | none | 2 | 5829.498 | 90.142 | 1698.226 | 3410.284 | 3438.953 | 3 | 3 | 0 | 3372.361 |
| cn163-offpeak | 2 | none | 3 | 5864.574 | 92.39 | 1672.606 | 3409.912 | 3433.452 | 3 | 3 | 0 | 3367.011 |
| cn163-offpeak | 3 | none | 1 | 6386.811 | 88.724 | 88.864 | 94.781 | 104.332 | 0 | 0 | 0 | 36.737 |
| cn163-offpeak | 3 | none | 2 | 7100.335 | 93.287 | 88.696 | 94.258 | 104.48 | 0 | 0 | 0 | 37.736 |
| cn163-offpeak | 3 | none | 3 | 5595.631 | 90.858 | 88.725 | 95.071 | 103.682 | 0 | 0 | 0 | 36.392 |
| cn163-peak | 1 | none | 1 | 16227.682 | 96.619 | 385.01 | 1682.359 | 1722.912 | 8 | 2 | 0 | 1272.628 |
| cn163-peak | 1 | none | 2 | 17003.396 | 94.18 | 471.553 | 1700.948 | 1722.243 | 10 | 3 | 0 | 1270.718 |
| cn163-peak | 1 | none | 3 | 17335.233 | 96.886 | 471.413 | 1774.132 | 1875.753 | 9 | 2 | 0 | 1272.031 |
| cn163-peak | 2 | none | 1 | 7232.221 | 93.052 | 1740.57 | 3409.445 | 3440.112 | 3 | 3 | 0 | 3373.108 |
| cn163-peak | 2 | none | 2 | 6207.665 | 88.797 | 1694.157 | 3409.374 | 3433.907 | 3 | 3 | 0 | 3368.536 |
| cn163-peak | 2 | none | 3 | 6304.506 | 89.834 | 1689.11 | 3411.046 | 3448.879 | 3 | 3 | 0 | 3383.454 |
| cn163-peak | 3 | none | 1 | 28930.598 | 93.605 | 94.405 | 1681.876 | 1721.581 | 4 | 3 | 0 | 1654.741 |
| cn163-peak | 3 | none | 2 | 29881.521 | 94.737 | 103.283 | 1681.369 | 1721.859 | 4 | 3 | 0 | 1655.262 |
| cn163-peak | 3 | none | 3 | 28637.276 | 87.732 | 91.925 | 1621.242 | 1720.967 | 3 | 3 | 0 | 1650.592 |
| rtt170 | 1 | blackout-upload-2s | 1 | 1938.612 | 90.809 | 87.115 | 90.363 | 91.08 | 0 | 0 | 0 | 25.858 |
| rtt170 | 1 | blackout-upload-2s | 2 | 2728.058 | 93.373 | 86.992 | 90.311 | 90.958 | 0 | 0 | 0 | 26.57 |
| rtt170 | 1 | blackout-upload-2s | 3 | 274.951 | 92.816 | 87.092 | 90.18 | 90.988 | 0 | 0 | 0 | 26.592 |
| rtt170 | 2 | blackout-upload-2s | 1 | 1916.986 | 88.215 | 87.036 | 90.34 | 92.309 | 0 | 0 | 0 | 26.472 |
| rtt170 | 2 | blackout-upload-2s | 2 | 2563.702 | 92.01 | 86.928 | 90.132 | 90.833 | 0 | 0 | 0 | 27.723 |
| rtt170 | 2 | blackout-upload-2s | 3 | 468.962 | 90.086 | 86.831 | 90.228 | 90.576 | 0 | 0 | 0 | 26.192 |
| rtt170 | 3 | blackout-upload-2s | 1 | 1910.607 | 88.653 | 87.12 | 90.231 | 90.627 | 0 | 0 | 0 | 27.395 |
| rtt170 | 3 | blackout-upload-2s | 2 | 2560.237 | 94.249 | 87.028 | 90.524 | 90.663 | 0 | 0 | 0 | 27.174 |
| rtt170 | 3 | blackout-upload-2s | 3 | 477.251 | 90.235 | 87.026 | 90.19 | 90.419 | 0 | 0 | 0 | 26.922 |
| rtt170 | 1 | blackout-tokens-8s | 1 | 1954.256 | 93.481 | 86.945 | 90.403 | 91.059 | 0 | 0 | 0 | 25.577 |
| rtt170 | 1 | blackout-tokens-8s | 2 | 471.788 | 90.101 | 3245.817 | 7968.386 | 8070.15 | 1 | 1 | 0 | 8002.387 |
| rtt170 | 1 | blackout-tokens-8s | 3 | 271.983 | 93.907 | 87.121 | 90.133 | 90.842 | 0 | 0 | 0 | 27.25 |
| rtt170 | 2 | blackout-tokens-8s | 1 | 1931.961 | 88.848 | 87.361 | 93.392 | 98.394 | 0 | 0 | 0 | 28.916 |
| rtt170 | 2 | blackout-tokens-8s | 2 | 502.223 | 90.565 | 3245.356 | 7968.412 | 8067.564 | 1 | 1 | 0 | 8002.58 |
| rtt170 | 2 | blackout-tokens-8s | 3 | 273.214 | 92.798 | 87.57 | 90.437 | 90.933 | 0 | 0 | 0 | 26.531 |
| rtt170 | 3 | blackout-tokens-8s | 1 | 1969.45 | 91.962 | 87.431 | 90.614 | 91.157 | 0 | 0 | 0 | 25.872 |
| rtt170 | 3 | blackout-tokens-8s | 2 | 502.405 | 89.88 | 3249.706 | 7966.977 | 8068.83 | 1 | 1 | 0 | 8003.355 |
| rtt170 | 3 | blackout-tokens-8s | 3 | 472.2 | 89.361 | 87.48 | 90.669 | 91.002 | 0 | 0 | 0 | 26.994 |
| rtt170 | 1 | blackout-tokens-40s | 1 | 1933.867 | 89.029 | 87.323 | 90.54 | 91.024 | 0 | 0 | 0 | 28.155 |
| rtt170 | 2 | blackout-tokens-40s | 1 | 1960.299 | 90.244 | 87.388 | 90.528 | 90.922 | 0 | 0 | 0 | 27.097 |
| rtt170 | 3 | blackout-tokens-40s | 1 | 1948.892 | 88.893 | 87.117 | 90.406 | 90.982 | 0 | 0 | 0 | 26.852 |
| rtt170 | 1 | reset-upload | 1 | 1981.503 | 91.582 | 87.462 | 90.294 | 91.065 | 0 | 0 | 0 | 25.904 |
| rtt170 | 1 | reset-upload | 2 | 825.68 | 92.493 | 87.389 | 90.362 | 90.826 | 0 | 0 | 0 | 26.127 |
| rtt170 | 1 | reset-upload | 3 | 299.304 | 93.692 | 87.545 | 90.591 | 95.297 | 0 | 0 | 0 | 27.045 |
| rtt170 | 2 | reset-upload | 1 | 1972.465 | 92.444 | 86.744 | 89.952 | 90.564 | 0 | 0 | 0 | 27.907 |
| rtt170 | 2 | reset-upload | 2 | 819.192 | 92.2 | 87.216 | 90.447 | 102.065 | 0 | 0 | 0 | 28.599 |
| rtt170 | 2 | reset-upload | 3 | 466.46 | 92.513 | 87.077 | 90.345 | 90.864 | 0 | 0 | 0 | 25.585 |
| rtt170 | 3 | reset-upload | 1 | 1942.148 | 90.307 | 87.268 | 90.601 | 91.079 | 0 | 0 | 0 | 26.443 |
| rtt170 | 3 | reset-upload | 2 | 854.8 | 89.509 | 87.637 | 90.859 | 91.273 | 0 | 0 | 0 | 27.938 |
| rtt170 | 3 | reset-upload | 3 | 492.609 | 89.442 | 87.438 | 90.529 | 90.916 | 0 | 0 | 0 | 26.205 |
| rtt170 | 1 | reset-tokens | 1 | 1907.215 | 90.893 | 87.673 | 90.996 | 92.86 | 0 | 0 | 0 | 32.603 |
| rtt170 | 1 | reset-tokens | 2 | 501.759 | 88.221 | 87.549 | 140.698 | 241.987 | 0 | 0 | 0 | 176.275 |
| rtt170 | 1 | reset-tokens | 3 | 269.19 | 91.499 | 87.468 | 90.617 | 91.741 | 0 | 0 | 0 | 27.904 |
| rtt170 | 2 | reset-tokens | 1 | 1972.789 | 90.009 | 87.432 | 90.407 | 90.949 | 0 | 0 | 0 | 26.325 |
| rtt170 | 2 | reset-tokens | 2 | 475.426 | 95.116 | 87.573 | 350.352 | 448.876 | 1 | 0 | 0 | 379.399 |
| rtt170 | 2 | reset-tokens | 3 | 300.625 | 89.251 | 87.486 | 90.781 | 91.198 | 0 | 0 | 0 | 27.753 |
| rtt170 | 3 | reset-tokens | 1 | 1966.166 | 93.012 | 87.381 | 90.527 | 90.796 | 0 | 0 | 0 | 26.682 |
| rtt170 | 3 | reset-tokens | 2 | 493.573 | 91.976 | 87.351 | 144.593 | 246.575 | 0 | 0 | 0 | 178.038 |
| rtt170 | 3 | reset-tokens | 3 | 303.986 | 95.036 | 87.08 | 90.392 | 90.758 | 0 | 0 | 0 | 27.108 |
| rtt170 | 1 | silent-silence | 1 | 1948.407 | 90.299 | 86.662 | 90.187 | 95.985 | 0 | 0 | 0 | 25.814 |
| rtt170 | 1 | silent-silence | 2 | 470.49 | 92.684 | 87.071 | 160.827 | 261.993 | 0 | 0 | 0 | 195.043 |
| rtt170 | 1 | silent-silence | 3 | 277.579 | 90.937 | 87.192 | 90.264 | 90.919 | 0 | 0 | 0 | 26.213 |
| rtt170 | 2 | silent-silence | 1 | 1918.505 | 88.224 | 86.961 | 90.207 | 90.605 | 0 | 0 | 0 | 26.71 |
| rtt170 | 2 | silent-silence | 2 | 467.537 | 92.44 | 86.919 | 149.001 | 249.034 | 0 | 0 | 0 | 181.703 |
| rtt170 | 2 | silent-silence | 3 | 276.11 | 91.279 | 86.716 | 90.191 | 90.528 | 0 | 0 | 0 | 26.827 |
| rtt170 | 3 | silent-silence | 1 | 1936.38 | 85.697 | 87.328 | 90.414 | 91.115 | 0 | 0 | 0 | 26.321 |
| rtt170 | 3 | silent-silence | 2 | 478.67 | 89.407 | 87.512 | 147.467 | 248.028 | 0 | 0 | 0 | 178.486 |
| rtt170 | 3 | silent-silence | 3 | 293.398 | 91.971 | 87.62 | 90.808 | 91.115 | 0 | 0 | 0 | 26.79 |

On `rtt170` with no fault, token-delay p50 stays near the 85 ms one-way delay and no inter-arrival gap exceeds 300 ms. The first 1 MiB upload takes about 1.9 s; the second and third take about 0.3–0.5 s. On `cn163-peak` the same upload takes 7–30 s and the token stream stalls for 1–2 s, the same head-of-line shape as the token-stream table above. `cn163-offpeak` seed 2 is that shape too; seeds 1 and 3 keep token-delay p50 on the one-way delay while the upload still takes about 6 s.

## Stream survival: before and after

Same conversation (3 turns, 1 MiB, 5 s silence, 500 tokens, seeds 1–3, every profile and fault, plus a 120 s token blackout). Debug test binary, loopback, 2026-11-18. `standby` is the switch; an overseas route never dials one, so its standby counters stay 0 even when the switch is on. Turn rows for `rtt170` with no fault are below each runs table. The other turn rows match the shape in the conversation section above, except where a row says it died.

### Overseas (before: no standby, 30 s give-up)

`SEGUE_EXIT_CLASS=overseas`. The switch was left at the product default (`SEGUE_STANDBY=1`); nothing was dialled.

| class | standby | profile | seed | fault | survived | end_turn | end_phase | app_saw | engine_dials | control_streams | session_carriers | standby_dials | standby_bound | promotions | swaps | impair_accepts | up_bytes | down_bytes | payload_up | payload_down |
|---|---:|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| overseas | 1 | rtt170 | 1 | none | yes | - | - |  | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 3159196 | 55207 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | none | yes | - | - |  | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 3159029 | 55218 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | none | yes | - | - |  | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 3159044 | 55218 | 3145794 | 45000 |
| overseas | 1 | cn163-offpeak | 1 | none | yes | - | - |  | 12 | 1 | 11 | 0 | 0 | 0 | 0 | 12 | 3396077 | 56063 | 3145794 | 45000 |
| overseas | 1 | cn163-offpeak | 2 | none | yes | - | - |  | 20 | 1 | 19 | 0 | 0 | 0 | 0 | 20 | 3435701 | 52747 | 3145794 | 45000 |
| overseas | 1 | cn163-offpeak | 3 | none | yes | - | - |  | 13 | 1 | 12 | 0 | 0 | 0 | 0 | 13 | 3534376 | 56494 | 3145794 | 45000 |
| overseas | 1 | cn163-peak | 1 | none | yes | - | - |  | 28 | 1 | 27 | 0 | 0 | 0 | 0 | 28 | 4200384 | 57883 | 3145794 | 45000 |
| overseas | 1 | cn163-peak | 2 | none | yes | - | - |  | 20 | 1 | 19 | 0 | 0 | 0 | 0 | 20 | 3549373 | 53274 | 3145794 | 45000 |
| overseas | 1 | cn163-peak | 3 | none | yes | - | - |  | 64 | 1 | 63 | 0 | 0 | 0 | 0 | 64 | 5061147 | 62587 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3304216 | 55345 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3310640 | 55351 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3380286 | 55373 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3156774 | 55823 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3156623 | 61206 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3156718 | 56374 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | blackout-tokens-40s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 0 | 0 | 0 | 0 | 12 | 2102435 | 18270 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | blackout-tokens-40s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 0 | 0 | 0 | 0 | 12 | 2102381 | 18226 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | blackout-tokens-40s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 0 | 0 | 0 | 0 | 12 | 2102396 | 18226 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | blackout-tokens-120s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 0 | 0 | 0 | 0 | 12 | 2102487 | 18204 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | blackout-tokens-120s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 0 | 0 | 0 | 0 | 12 | 2102429 | 18193 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | blackout-tokens-120s | no | 2 | tokens | reset: Connection reset by peer (os error 54) | 12 | 3 | 9 | 0 | 0 | 0 | 0 | 12 | 2102440 | 18281 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | reset-upload | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3159706 | 55371 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | reset-upload | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159305 | 55338 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | reset-upload | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159430 | 55316 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159756 | 55255 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159667 | 55321 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159814 | 55283 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 1 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3160118 | 55255 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 2 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3159990 | 55218 | 3145794 | 45000 |
| overseas | 1 | rtt170 | 3 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3160071 | 55211 | 3145794 | 45000 |

`rtt170` with no fault: one session carrier, one control stream, token-delay p50 about 87 ms, no stall over 300 ms (longest gap about 28 ms). The 40 s and 120 s token blackouts both die on turn 2 with `reset: Connection reset by peer (os error 54)`, 9 session carriers and 3 control streams. `cn163-peak` seed 3 dialled 63 session carriers and the relay wrote about 1.61× the upload (`5061147 / 3145794`).

| class | standby | profile | seed | fault | turn | upload_ms | ttft_after_silence_ms | delay_p50_ms | delay_p99_ms | delay_max_ms | stalls_300 | stalls_1s | stalls_20s | longest_gap_ms |
|---|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| overseas | 1 | rtt170 | 1 | none | 1 | 1938.856 | 93.145 | 87.28 | 90.351 | 90.632 | 0 | 0 | 0 | 26.662 |
| overseas | 1 | rtt170 | 1 | none | 2 | 477.441 | 91.211 | 87.521 | 90.347 | 91.312 | 0 | 0 | 0 | 27.207 |
| overseas | 1 | rtt170 | 1 | none | 3 | 275.106 | 93.186 | 87.485 | 90.614 | 90.965 | 0 | 0 | 0 | 26.715 |
| overseas | 1 | rtt170 | 2 | none | 1 | 1980.764 | 90.91 | 87.351 | 90.345 | 90.558 | 0 | 0 | 0 | 26.423 |
| overseas | 1 | rtt170 | 2 | none | 2 | 482.27 | 90.434 | 87.329 | 90.552 | 91.123 | 0 | 0 | 0 | 27.294 |
| overseas | 1 | rtt170 | 2 | none | 3 | 483.66 | 93.413 | 87.386 | 90.494 | 90.792 | 0 | 0 | 0 | 26.469 |
| overseas | 1 | rtt170 | 3 | none | 1 | 1922.885 | 87.828 | 87.293 | 90.416 | 90.894 | 0 | 0 | 0 | 27.764 |
| overseas | 1 | rtt170 | 3 | none | 2 | 474.702 | 92.485 | 87.495 | 90.421 | 90.673 | 0 | 0 | 0 | 26.178 |
| overseas | 1 | rtt170 | 3 | none | 3 | 273.458 | 90.165 | 87.409 | 90.321 | 90.493 | 0 | 0 | 0 | 26.522 |

### AI, standby off (patience only)

`SEGUE_EXIT_CLASS=ai SEGUE_STANDBY=0`. The session may stay detached for 150 s. No spare is dialled.

| class | standby | profile | seed | fault | survived | end_turn | end_phase | app_saw | engine_dials | control_streams | session_carriers | standby_dials | standby_bound | promotions | swaps | impair_accepts | up_bytes | down_bytes | payload_up | payload_down |
|---|---:|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ai | 0 | rtt170 | 1 | none | yes | - | - |  | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 3159162 | 55284 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | none | yes | - | - |  | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 3159093 | 55196 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | none | yes | - | - |  | 2 | 1 | 1 | 0 | 0 | 0 | 0 | 2 | 3159190 | 55196 | 3145794 | 45000 |
| ai | 0 | cn163-offpeak | 1 | none | yes | - | - |  | 12 | 1 | 11 | 0 | 0 | 0 | 0 | 12 | 3464942 | 56027 | 3145794 | 45000 |
| ai | 0 | cn163-offpeak | 2 | none | yes | - | - |  | 20 | 1 | 19 | 0 | 0 | 0 | 0 | 20 | 3430735 | 52780 | 3145794 | 45000 |
| ai | 0 | cn163-offpeak | 3 | none | yes | - | - |  | 13 | 1 | 12 | 0 | 0 | 0 | 0 | 13 | 3633586 | 56516 | 3145794 | 45000 |
| ai | 0 | cn163-peak | 1 | none | yes | - | - |  | 28 | 1 | 27 | 0 | 0 | 0 | 0 | 28 | 3960877 | 58486 | 3145794 | 45000 |
| ai | 0 | cn163-peak | 2 | none | yes | - | - |  | 20 | 1 | 19 | 0 | 0 | 0 | 0 | 20 | 3449933 | 53041 | 3145794 | 45000 |
| ai | 0 | cn163-peak | 3 | none | yes | - | - |  | 64 | 1 | 63 | 0 | 0 | 0 | 0 | 64 | 4873938 | 61566 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3308231 | 55241 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3323947 | 55373 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | blackout-upload-2s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3376507 | 55296 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3156745 | 54314 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3156622 | 55000 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 0 | 0 | 0 | 0 | 3 | 3156699 | 56237 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | blackout-tokens-40s | yes | - | - |  | 15 | 4 | 11 | 0 | 0 | 0 | 0 | 15 | 3157195 | 68810 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | blackout-tokens-40s | yes | - | - |  | 15 | 4 | 11 | 0 | 0 | 0 | 0 | 15 | 3157143 | 52218 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | blackout-tokens-40s | yes | - | - |  | 15 | 4 | 11 | 0 | 0 | 0 | 0 | 15 | 3157172 | 52049 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | blackout-tokens-120s | yes | - | - |  | 42 | 11 | 31 | 0 | 0 | 0 | 0 | 42 | 3157106 | 51899 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | blackout-tokens-120s | yes | - | - |  | 42 | 11 | 31 | 0 | 0 | 0 | 0 | 42 | 3156971 | 51943 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | blackout-tokens-120s | yes | - | - |  | 42 | 11 | 31 | 0 | 0 | 0 | 0 | 42 | 3157091 | 81875 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | reset-upload | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3159844 | 55360 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | reset-upload | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3159621 | 55349 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | reset-upload | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159363 | 55294 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159684 | 55337 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | reset-tokens | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3159989 | 55188 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | reset-tokens | yes | - | - |  | 4 | 2 | 2 | 0 | 0 | 0 | 0 | 4 | 3159642 | 55216 | 3145794 | 45000 |
| ai | 0 | rtt170 | 1 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3160073 | 55288 | 3145794 | 45000 |
| ai | 0 | rtt170 | 2 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3160056 | 55222 | 3145794 | 45000 |
| ai | 0 | rtt170 | 3 | silent-silence | yes | - | - |  | 5 | 2 | 3 | 0 | 0 | 0 | 0 | 5 | 3159918 | 55262 | 3145794 | 45000 |

The 40 s and 120 s token blackouts survive on the same app connection. They do it by redialling: 11 session carriers for 40 s, 31 for 120 s. Lossy profiles dial about as many session carriers as the overseas run (`cn163-peak` seed 3 is 63 again). `rtt170` with no fault is one session carrier, no stall over 300 ms.

| class | standby | profile | seed | fault | turn | upload_ms | ttft_after_silence_ms | delay_p50_ms | delay_p99_ms | delay_max_ms | stalls_300 | stalls_1s | stalls_20s | longest_gap_ms |
|---|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ai | 0 | rtt170 | 1 | none | 1 | 1939.748 | 92.883 | 87.554 | 90.454 | 92.211 | 0 | 0 | 0 | 29.319 |
| ai | 0 | rtt170 | 1 | none | 2 | 475.661 | 93.776 | 87.534 | 90.495 | 91.035 | 0 | 0 | 0 | 26.884 |
| ai | 0 | rtt170 | 1 | none | 3 | 286.813 | 90.919 | 87.29 | 90.569 | 91.111 | 0 | 0 | 0 | 27.413 |
| ai | 0 | rtt170 | 2 | none | 1 | 1949.921 | 89.787 | 87.483 | 90.536 | 91.033 | 0 | 0 | 0 | 26.845 |
| ai | 0 | rtt170 | 2 | none | 2 | 479.183 | 92.915 | 87.52 | 90.552 | 91.025 | 0 | 0 | 0 | 26.304 |
| ai | 0 | rtt170 | 2 | none | 3 | 270.312 | 89.896 | 87.421 | 90.457 | 90.984 | 0 | 0 | 0 | 27.605 |
| ai | 0 | rtt170 | 3 | none | 1 | 1945.087 | 91.711 | 87.469 | 90.298 | 90.605 | 0 | 0 | 0 | 26.733 |
| ai | 0 | rtt170 | 3 | none | 2 | 502.709 | 89.786 | 87.545 | 90.47 | 91.427 | 0 | 0 | 0 | 28.326 |
| ai | 0 | rtt170 | 3 | none | 3 | 272.47 | 93.607 | 87.49 | 90.615 | 99.58 | 0 | 0 | 0 | 30.209 |

### AI, standby on

`SEGUE_EXIT_CLASS=ai SEGUE_STANDBY=1`. In this run `standby_bound` counts a demoted carrier again, once per swap (`standby_bound − swaps` is the fresh `REDUNDANT_OK` count; it matches `standby_dials` on every lossy row except `cn163-peak` seed 3, where one dial had not bound). That double count is fixed after this run.

| class | standby | profile | seed | fault | survived | end_turn | end_phase | app_saw | engine_dials | control_streams | session_carriers | standby_dials | standby_bound | promotions | swaps | impair_accepts | up_bytes | down_bytes | payload_up | payload_down |
|---|---:|---|---:|---|---|---:|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ai | 1 | rtt170 | 1 | none | yes | - | - |  | 3 | 1 | 2 | 1 | 1 | 0 | 0 | 3 | 3159282 | 55979 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | none | yes | - | - |  | 3 | 1 | 2 | 1 | 1 | 0 | 0 | 3 | 3159211 | 56080 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | none | yes | - | - |  | 3 | 1 | 2 | 1 | 1 | 0 | 0 | 3 | 3159113 | 55803 | 3145794 | 45000 |
| ai | 1 | cn163-offpeak | 1 | none | yes | - | - |  | 12 | 1 | 11 | 3 | 8 | 5 | 5 | 12 | 3388308 | 66095 | 3145794 | 45000 |
| ai | 1 | cn163-offpeak | 2 | none | yes | - | - |  | 15 | 1 | 14 | 7 | 16 | 9 | 9 | 15 | 3510429 | 70290 | 3145794 | 45000 |
| ai | 1 | cn163-offpeak | 3 | none | yes | - | - |  | 7 | 1 | 6 | 2 | 9 | 7 | 7 | 7 | 4135953 | 58571 | 3145794 | 45000 |
| ai | 1 | cn163-peak | 1 | none | yes | - | - |  | 28 | 1 | 27 | 4 | 12 | 8 | 8 | 28 | 3881747 | 58401 | 3145794 | 45000 |
| ai | 1 | cn163-peak | 2 | none | yes | - | - |  | 18 | 1 | 17 | 4 | 13 | 9 | 9 | 18 | 3431380 | 59933 | 3145794 | 45000 |
| ai | 1 | cn163-peak | 3 | none | yes | - | - |  | 64 | 1 | 63 | 6 | 11 | 6 | 6 | 64 | 4753324 | 68153 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | blackout-upload-2s | yes | - | - |  | 5 | 1 | 4 | 2 | 3 | 1 | 1 | 5 | 3474744 | 56140 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | blackout-upload-2s | yes | - | - |  | 5 | 1 | 4 | 2 | 3 | 1 | 1 | 5 | 3712649 | 56129 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | blackout-upload-2s | yes | - | - |  | 5 | 1 | 4 | 2 | 3 | 1 | 1 | 5 | 3606047 | 55929 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 1 | 2 | 1 | 1 | 3 | 3156335 | 59830 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 1 | 2 | 1 | 1 | 3 | 3156409 | 59747 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | blackout-tokens-8s | yes | - | - |  | 3 | 1 | 2 | 1 | 2 | 1 | 1 | 3 | 3156241 | 59668 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | blackout-tokens-40s | yes | - | - |  | 17 | 4 | 13 | 2 | 2 | 0 | 0 | 17 | 3157036 | 57815 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | blackout-tokens-40s | yes | - | - |  | 17 | 4 | 13 | 2 | 2 | 0 | 0 | 17 | 3157295 | 57914 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | blackout-tokens-40s | yes | - | - |  | 17 | 4 | 13 | 2 | 2 | 0 | 0 | 17 | 3157170 | 57493 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | blackout-tokens-120s | yes | - | - |  | 44 | 11 | 33 | 2 | 2 | 0 | 0 | 44 | 3157140 | 52608 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | blackout-tokens-120s | yes | - | - |  | 44 | 11 | 33 | 2 | 2 | 0 | 0 | 44 | 3157107 | 52776 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | blackout-tokens-120s | yes | - | - |  | 44 | 11 | 33 | 2 | 2 | 0 | 0 | 44 | 3157235 | 67527 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | reset-upload | yes | - | - |  | 6 | 2 | 4 | 2 | 2 | 0 | 0 | 6 | 3159422 | 56215 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | reset-upload | yes | - | - |  | 6 | 2 | 4 | 2 | 2 | 0 | 0 | 6 | 3159511 | 55905 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | reset-upload | yes | - | - |  | 7 | 2 | 5 | 2 | 2 | 0 | 0 | 7 | 3159820 | 56017 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | reset-tokens | yes | - | - |  | 7 | 2 | 4 | 2 | 2 | 0 | 0 | 7 | 3159740 | 56093 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | reset-tokens | yes | - | - |  | 6 | 2 | 4 | 2 | 2 | 1 | 0 | 6 | 3159726 | 55961 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | reset-tokens | yes | - | - |  | 6 | 2 | 4 | 2 | 2 | 0 | 0 | 6 | 3159799 | 56236 | 3145794 | 45000 |
| ai | 1 | rtt170 | 1 | silent-silence | yes | - | - |  | 8 | 2 | 6 | 3 | 4 | 1 | 1 | 8 | 3160293 | 55971 | 3145794 | 45000 |
| ai | 1 | rtt170 | 2 | silent-silence | yes | - | - |  | 8 | 2 | 6 | 3 | 4 | 1 | 1 | 8 | 3160151 | 56067 | 3145794 | 45000 |
| ai | 1 | rtt170 | 3 | silent-silence | yes | - | - |  | 8 | 2 | 6 | 3 | 4 | 1 | 1 | 8 | 3159983 | 56286 | 3145794 | 45000 |

`rtt170` with no fault: 1 session carrier + 1 standby, one control stream, no stall over 300 ms (longest gap about 27 ms). The 40 s and 120 s token blackouts survive on the same app connection. The spare does not: a blackout holds every connection that already exists, promotions stay 0, and the session redials through the outage the same way patience-only does (13 and 33 session carriers, against 11 and 31). Lossy profiles do not dial far fewer carriers. `cn163-peak` seed 3 is still 63 session carriers (6 of them standby dials) and the relay wrote 4753324 bytes against 5061147 overseas. `cn163-offpeak` seed 3 dropped from 12 carriers to 6 and wrote more (`4135953` against `3534376`): a swap at `t_stall` replays uplink that TCP recovery was about to deliver, and the spare shares the impaired relay, so the next stall usually re-attaches instead of swapping again.

| class | standby | profile | seed | fault | turn | upload_ms | ttft_after_silence_ms | delay_p50_ms | delay_p99_ms | delay_max_ms | stalls_300 | stalls_1s | stalls_20s | longest_gap_ms |
|---|---:|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ai | 1 | rtt170 | 1 | none | 1 | 1915.662 | 88.896 | 87.375 | 90.406 | 90.856 | 0 | 0 | 0 | 26.435 |
| ai | 1 | rtt170 | 1 | none | 2 | 470.546 | 92.944 | 87.533 | 90.27 | 90.979 | 0 | 0 | 0 | 25.656 |
| ai | 1 | rtt170 | 1 | none | 3 | 287.675 | 92.69 | 87.377 | 90.613 | 91.007 | 0 | 0 | 0 | 27.254 |
| ai | 1 | rtt170 | 2 | none | 1 | 2156.825 | 93.449 | 87.571 | 90.468 | 90.648 | 0 | 0 | 0 | 26.587 |
| ai | 1 | rtt170 | 2 | none | 2 | 495.351 | 93.287 | 87.32 | 90.42 | 90.805 | 0 | 0 | 0 | 25.447 |
| ai | 1 | rtt170 | 2 | none | 3 | 272.758 | 89.52 | 87.491 | 90.526 | 90.719 | 0 | 0 | 0 | 26.544 |
| ai | 1 | rtt170 | 3 | none | 1 | 1930.088 | 88.474 | 87.295 | 90.629 | 91.02 | 0 | 0 | 0 | 26.492 |
| ai | 1 | rtt170 | 3 | none | 2 | 470.283 | 94.568 | 87.508 | 90.457 | 90.751 | 0 | 0 | 0 | 26.569 |
| ai | 1 | rtt170 | 3 | none | 3 | 270.749 | 92.462 | 87.437 | 90.468 | 90.979 | 0 | 0 | 0 | 26.506 |

### What the three runs say

| | 40 s blackout | 120 s blackout | rtt170 none | cn163-peak seed 3 carriers | cn163-peak seed 3 up |
|---|---|---|---|---:|---:|
| overseas | dies, reset, 9 carriers | dies, reset, 9 carriers | 1 carrier, no stall > 300 ms | 63 | 5061147 |
| ai, standby off | survives, 11 carriers | survives, 31 carriers | 1 carrier, no stall > 300 ms | 63 | 4873938 |
| ai, standby on | survives, 13 carriers | survives, 33 carriers | 1 carrier + 1 standby, no stall > 300 ms | 63 | 4753324 |

Patience is what keeps the app connection through a 40 s or 120 s token blackout. The standby does not, on this harness: the impair sits on every carrier, so a spare cannot skip a blackout, and on a lossy profile it swaps a handful of times and then the session re-attaches as before.

## Move reasons

`SEGUE_CONVO_FAULTS=none SEGUE_SCENARIO=convo SEGUE_EXIT_CLASS=ai SEGUE_STANDBY=1`, same 3×1 MiB / 5 s / 500 conversation. No behaviour change yet: the client still gives a carrier up at `t_stall` (1 s) with or without a spare. `stall` is the client's own timer, `relay_stall` is a `STALL` hint (the relay's `t_live`), `resumes` is a RESUME onto a new carrier, `replay_bytes` is uplink sent again after a promotion or a RESUME, `recover_max_ms` is the longest wait from that loss until the next byte of progress. `hold`, `closed`, `io`, `reject` and `attach` were 0 on every row and are omitted.

### Before

| profile | seed | carriers | standby_dials | promotions | stall | relay_stall | resumes | replay_bytes | recover_max_ms | up_bytes | up/payload |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rtt170 | 1 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3159177 | 1.00 |
| rtt170 | 2 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3159178 | 1.00 |
| rtt170 | 3 | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3158986 | 1.00 |
| cn163-offpeak | 1 | 11 | 3 | 5 | 9 | 3 | 7 | 1822852 | 1598 | 3495323 | 1.11 |
| cn163-offpeak | 2 | 16 | 3 | 5 | 12 | 5 | 12 | 2141802 | 1565 | 3346096 | 1.06 |
| cn163-offpeak | 3 | 6 | 1 | 6 | 10 | 0 | 4 | 3358968 | 1589 | 4143161 | 1.32 |
| cn163-peak | 1 | 27 | 4 | 8 | 27 | 3 | 22 | 3166208 | 1592 | 4050142 | 1.29 |
| cn163-peak | 2 | 16 | 3 | 5 | 12 | 5 | 12 | 1499166 | 1382 | 3453382 | 1.10 |
| cn163-peak | 3 | 63 | 6 | 6 | 57 | 5 | 56 | 2408562 | 1565 | 4379437 | 1.39 |

Payload up is 3145794. Every row survived. `rtt170` does not move.

On both `cn163-offpeak` and `cn163-peak` the client's `t_stall` is the move. A relay `STALL` is a few of them (0–5 against 9–57). The 2 s transport hold, a close, a write or decode error, `REJECT` and `t_attach` did not fire. Recovery tops out around 1.6 s, which is the 1 s timer plus a dial. Offpeak seed 1 has no token gap over 300 ms while `stall` is 9 and the three uploads take 7.6 s, 7.7 s and 4.9 s, so those moves are in the upload. Peak, and offpeak seed 2, also have multi-second token gaps, so the same timer fires while tokens are in flight. A RESUME then drops the spare; most moves have no spare bound (`resumes` is almost `stall + relay_stall − promotions`).

### After

Same command, after the solo rule: an AI session with no spare bound waits `t_stall_solo` (5 s); a bound spare still swaps at 1 s; a spare dropped by the RESUME is redialled at once. The transport hold is unchanged.

| profile | seed | survived | carriers | standby_dials | promotions | stall | relay_stall | resumes | replay_bytes | recover_max_ms | up_bytes | up/payload |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rtt170 | 1 | yes | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3159004 | 1.00 |
| rtt170 | 2 | yes | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3159033 | 1.00 |
| rtt170 | 3 | yes | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3159065 | 1.00 |
| cn163-offpeak | 1 | yes | 12 | 6 | 10 | 13 | 2 | 5 | 2978420 | 1598 | 3593199 | 1.14 |
| cn163-offpeak | 2 | yes | 13 | 8 | 11 | 14 | 1 | 4 | 2928868 | 1574 | 3327047 | 1.06 |
| cn163-offpeak | 3 | yes | 4 | 2 | 8 | 9 | 0 | 1 | 2965032 | 1566 | 4401088 | 1.40 |
| cn163-peak | 1 | no (turn 3 tokens, timeout) | 26 | 13 | 25 | 35 | 2 | 12 | 3239097 | 1597 | 3867219 | 1.23 |
| cn163-peak | 2 | yes | 13 | 8 | 11 | 14 | 1 | 4 | 2154496 | 1574 | 3466649 | 1.10 |
| cn163-peak | 3 | no (turn 2 tokens, timeout) | 39 | 20 | 38 | 55 | 1 | 18 | 2609379 | 1563 | 2928481 | 0.93 |

Targets were `cn163-offpeak` ≤ 4 carriers and `cn163-peak` ≤ 8 on every seed, upload on the wire ≤ 1.15× payload, and every row surviving. None of those hold, except offpeak seed 3's carrier count and three rows' byte ratio. `rtt170` is unchanged.

The 5 s wait rarely applies. Redialling the spare at once keeps one bound, so the next silence swaps at 1 s (`stall` is still almost every move; `promotions` equals `swaps`). On this impair the spare is the same lossy path, the demoted carrier stays quiet, and the following stall RESUMEs. That is what still moves the carrier. Two peak rows that survived before now time out in the token phase. `relay_stall` is 0–2. `hold`, `closed`, `io`, `reject` and `attach` are still 0.

### Blackouts

`SEGUE_CONVO_FAULTS=blackout` on the same build. Every `rtt170` blackout row survived. Carrier counts match the previous standby-on run: upload 2 s is 4 session carriers, tokens 8 s is 2, tokens 40 s is 13, tokens 120 s is 33. The moves during the long holds are `t_attach` (the RESUME is not answered while the impair holds the carrier), not `t_stall`. Token `delay_max` on the blackout turn is the hold plus under a second (8.07 s, 40.7–40.8 s, 120.7–120.8 s). That is inside `t_stall_solo` of the previous recovery. The 2 s upload's second turn takes 3.0–3.5 s.

### After t_stall_ai

Same no-fault command, after two changes. An AI session waits `t_stall_ai` (5 s) before unacked silence or a `STALL` hint gives the carrier up, whether or not a spare is bound. The relay waits `t_live_ai` (5 s) for that session. A `STALL` that arrives after a promotion is remembered and acted on once the new carrier is quiet, including a download with nothing unacked: the previous build dropped that hint, the relay went DETACHED, and the token stream stayed open until the harness timed out. The client announces `t_stall_ms` 5000. The relay's keepalive stays 500 ms, because it is half the shorter of the relay's own `t_stall` (1 s) and that announcement.

| profile | seed | survived | carriers | standby_dials | promotions | stall | relay_stall | resumes | replay_bytes | recover_max_ms | up_bytes | up/payload |
|---|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| rtt170 | 1 | yes | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3158962 | 1.00 |
| rtt170 | 2 | yes | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3158971 | 1.00 |
| rtt170 | 3 | yes | 2 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3159060 | 1.00 |
| cn163-offpeak | 1 | yes | 7 | 3 | 9 | 8 | 4 | 3 | 1920318 | 5595 | 4040402 | 1.28 |
| cn163-offpeak | 2 | yes | 13 | 7 | 14 | 13 | 3 | 5 | 3370024 | 9683 | 3507598 | 1.12 |
| cn163-offpeak | 3 | yes | 2 | 1 | 6 | 5 | 1 | 0 | 1318954 | 4712 | 4333341 | 1.38 |
| cn163-peak | 1 | yes | 18 | 9 | 31 | 33 | 6 | 8 | 3387140 | 17183 | 4548337 | 1.45 |
| cn163-peak | 2 | yes | 11 | 5 | 16 | 13 | 5 | 5 | 3018394 | 9852 | 4949436 | 1.57 |
| cn163-peak | 3 | yes | 10 | 5 | 15 | 13 | 5 | 4 | 1839104 | 13437 | 4057977 | 1.29 |

Every row survived, including the two peak rows that timed out in the token phase before. `hold`, `io`, `reject` and `attach` are 0. `closed` is 0 except offpeak seed 2 (3), peak seed 2 (3) and peak seed 3 (1). `rtt170` does not move.

Targets were still `cn163-offpeak` ≤ 4 carriers and `cn163-peak` ≤ 8 on every seed, and upload ≤ 1.15× payload. Offpeak seed 3 is the only carrier-count hit (2). Offpeak seed 2 is the only cn163 byte-ratio hit (1.12). The other cn163 rows are 7–18 carriers and 1.28–1.57×. Waiting 5 s cut the peak rows that used to die (26 and 39 carriers, timeout) to 18, 11 and 10, and they finish. It did not get them under the target. `recover_max_ms` is now the 5 s wait plus the dial, up to 17 s on peak seed 1, not the old 1.6 s.

### Blackouts after t_stall_ai

`SEGUE_CONVO_FAULTS=blackout` on this build. Every row survived, including every `rtt170` blackout. Upload 2 s is 2 session carriers. Tokens 8 s is 2–3, tokens 40 s is 13, tokens 120 s is 33. The moves during the 40 s and 120 s holds are `t_attach` (9–29) and the RESUME that follows (10–30), not `t_stall`. Token `delay_max` on the blackout turn is the hold plus under a second: 8.07 s, 40.8–40.9 s, 120.8–121.0 s. An 8 s blackout does not stall the stream more than 6 s after the path returns. The 2 s upload's second turn takes 2.4 s.
