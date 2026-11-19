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
