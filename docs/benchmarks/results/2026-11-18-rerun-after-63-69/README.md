# Rerun after #63 and #69: Segue vs sing-box 1.15.0-alpha.13 vs mihomo, 2026-11-18

Same machine, same commands, same sing-box / mihomo / Xray-core fixture
binaries (SHA-256 below) as the [2026-11-17 comparison]
(../2026-11-17-singbox-1.15a13-mihomo/README.md), rerun on current main
after two performance PRs landed:

- **#63** — a VLESS request is no longer held 500 ms when the client sends
  nothing (first-payload hold; on a server-first download nothing ever
  arrives).
- **#69** — Vision switches to a direct copy across split TLS application
  records instead of padding (Xray-core #7164).

Only `segue` and `segue-bench` were rebuilt, from this worktree at
`38c54f1a` (= main, clean). Five runs per series, machine otherwise idle.
The engine label `xray-rust` is the release `segue` binary.

**Read the day-to-day caveat first.** The unchanged Go engines got
50–75 % faster between the two afternoons on the throughput and duration
columns (sing-box gRPC median 3634 → 6212 Mbps, mihomo 5277 → 9307), so
those columns moved mostly with machine state, not with our code. The
numbers that are about code, with within-day controls, are the
time-to-first-byte rows: segue's ~520 ms hold vanished while mihomo's own
~215 ms hold (same binary both days) stayed exactly where it was.

## Machine

| | |
| --- | --- |
| Model | Mac mini (Mac18,5) — same machine as 2026-11-17 |
| Chip | Apple M6 (12 cores: 2 Super, 4 Performance, 6 Efficiency) |
| RAM | 16 GB |
| OS | macOS 27.0.1 (build 26A434) |
| Rust | 1.96.0, `cargo build --release -j 4` |
| Run window | 2026-11-18 14:23:30–14:25:31 UTC; nothing else ran on the machine |

## Revisions and binaries

| piece | revision | binary SHA-256 |
| --- | --- | --- |
| segue / harness tree | `38c54f1a40d4b74f943f0b9883fae2b910220bbf` (clean at every run) | `segue` `f98d18ff11897829544ac6d22130816afe2ff171c083f2c981404679eb8c7db2` |
| segue-bench (release) | same tree, `harness_profile=release` | `cecbe973816ff92cf94acb933e2e9bc14281e1133494922031401d7230a32cfb` |
| sing-box | tag `v1.15.0-alpha.13`, `824dbcfb4dd0a95921840b1737b950cde590241e` | `a74f2b05b4b98ea19b643b372768ffb4d24ac32df75f3fe143356966ffeadd31` — unchanged since 2026-11-17 |
| mihomo | Alpha `3c0d10a503f7b2fde3fe167d4d91dd05725d5268` | `0f77725a275861ad1d83ee4d6613ead9f4df6adc623d7a68d593ec09fea51367` — unchanged since 2026-11-17 |
| Xray-core fixture (server only) | v26.11.9 `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` | `73cc95e649b75ae9953a0d147db8ad73543f663c72bf0852d617df71dc8f9237` — unchanged since 2026-11-17 |

The segue tree moved from `26a668b1` (2026-11-17) to `38c54f1a`: #62–#65
and #71 are docs and tests, #66–#68 and #70 are session/kernel/test fixes
off this path; the performance-relevant changes are #63 and #69.

## Commands

The 2026-11-17 command block was rerun verbatim (same `B=(...)` argument
vector, `--runs 5`, per-series `--out-dir` under
`/Volumes/dev/ci/tmp/bench-2026-11-18/`); see the
[2026-11-17 README]
(../2026-11-17-singbox-1.15a13-mihomo/README.md#commands) for the exact
lines. One workload was added — a server-first 1 GiB download over direct
freedom (no proxy protocol), one connection, 256 × 4 MiB, per engine:

```sh
"$H" run --engine xray-rust "${B[@]}" --workload tcp-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
"$H" run --engine sing-box  "${B[@]}" --workload tcp-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
"$H" run --engine mihomo    "${B[@]}" --workload tcp-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
```

The sing-box REALITY series is still a one-iteration smoke (`--runs 1
--iterations 1`); it failed the same way as on 2026-11-17.

## Time to first byte

TTFB is not a harness column; it is `duration_ms − transfer_duration_ms`
per run (everything before the first validated payload byte: SOCKS
connect, tunnel handshake, and any first-request hold), then
min/p50/p95 of the five runs, computed offline from each `result.json`.
With five samples p95 is the worst run (nearest-rank, the harness's own
percentile).

VLESS paths (from the bulk series below):

| engine | gRPC TTFB ms min/p50/p95 | REALITY TTFB ms min/p50/p95 |
| --- | --- | --- |
| segue | 10 / **10** / 20 | 59 / **71** / 77 |
| sing-box (lite) | 9 / **9** / 22 | no completed run |
| mihomo | 213 / **213** / 217 | 210 / **217** / 220 |

Added `tcp-bulk-throughput` workload (direct freedom, no proxy protocol):

| engine | TTFB ms min/p50/p95 |
| --- | --- |
| segue | 8 / **9** / 12 |
| sing-box | 8 / **9** / 15 |
| mihomo | 8 / **9** / 10 |

mihomo's ~215 ms on the VLESS rows is its own first-payload wait (it held
~225 ms on 2026-11-17 with the same binary); on the direct path everyone
is ~9 ms. Segue matches sing-box on every path now.

## Segue before (2026-11-17) and after (2026-11-18)

Median of five runs, from the 2026-11-17 README and this run. The
"control" column is the median move of the two unchanged Go engines on
the same metric, i.e. the day-to-day machine drift.

| segue metric | 2026-11-17 | 2026-11-18 | control drift |
| --- | --- | --- | --- |
| gRPC Mbps | 12879 | **26110** | sing-box 3634 → 6212, mihomo 5277 → 9307 |
| gRPC duration ms | 1187 | **339** | 2389 → 1395, 1853 → 1137 |
| gRPC transfer ms | 667 | **329** | 2364 → 1383, 1628 → 923 |
| gRPC TTFB ms p50 | 520 | **10** | sing-box 17 → 9, mihomo 225 → 213 |
| gRPC CPU ms/GiB | 940 | **540** | 3040 → 2440, 2110 → 1630 |
| REALITY Mbps | 9090 | **21692** | mihomo 10605 → 18085 |
| REALITY duration ms | 1635 | **466** | mihomo 1036 → 689 |
| REALITY transfer ms | 945 | **396** | mihomo 810 → 475 |
| REALITY TTFB ms p50 | 690 | **71** | mihomo 228 → 217 |
| REALITY CPU ms/GiB | 920 | **470** | mihomo 840 → 540 |
| TCP8 echo Mbps | 3667 | **7490** | 3616 → 5243, 3340 → 5350 |
| TCP8 echo p50 µs | 119 | **63** | 125 → 95, 127 → 93 |
| TCP8 CPU ms/GiB | 2622 | **1475** | 4588 → 4260, 4424 → 4260 |

What is safely attributable to the code, not the day:

- **The 500 ms hold is gone (#63).** gRPC TTFB p50 520 → 10 ms and
  REALITY TTFB p50 690 → 71 ms, while mihomo's own hold (same binary,
  same machine, same fixture) moved 225 → 213 and 228 → 217 ms. A
  constant that only one engine carried disappeared; the others kept
  theirs. `docs/CHANGELOG`'s 513 ms → 10 ms claim (measured on 3 release
  runs inside #63) reproduces on this 3-engine harness.
- **The REALITY band tightened (#69 and #63 together).** The five runs
  spanned 4679–11393 Mbps on 2026-11-17 (one 3040 ms run); they span
  21583–21802 Mbps today, the tightest series on this page.

What is not: every throughput, duration and CPU column improved for the
unchanged Go engines too, by roughly +50–75 %. Segue's raw gains in those
columns (about +100 %) exceed the drift but not by enough that five runs
two days apart can separate code from machine. The 2026-11-17 afternoon
shared the machine with other work; this window did not. Quote the TTFB
rows as the #63/#69 evidence, and the throughput tables as same-day,
same-state comparisons between engines.

## VLESS + gRPC, 1 connection, 256 × 4 MiB

Same shape as 2026-11-17: server-first download through h2c gRPC to the
Xray-core fixture. `throughput_mbps` is decimal megabits, received bytes
only; `duration_ms` includes time before the first validated byte; TTFB
is defined above.

| engine | Mbps min/median/p95 | duration ms | transfer ms | TTFB p50 | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- | --- |
| segue (`xray-rust`) | 23599 / **26110** / 26513 | 334 / **339** / 384 | 324 / **329** / 364 | **10 ms** | **13.9 MiB** (14256 KiB) | 520 / **540** / 570 |
| sing-box (lite) | 6029 / **6212** / 6280 | 1377 / **1395** / 1434 | 1368 / **1383** / 1425 | **9 ms** | **49.2 MiB** (50368 KiB) | 2390 / **2440** / 2480 |
| mihomo | 9168 / **9307** / 9399 | 1127 / **1137** / 1150 | 914 / **923** / 937 | **213 ms** | **47.8 MiB** (48896 KiB) | 1610 / **1630** / 1670 |

No per-chunk latency on this workload. Each run received exactly
1,073,741,824 bytes and sent 0. Segue's duration and transfer windows are
now the same event (339 vs 329 ms); on 2026-11-17 the run was 1187 ms
around a 667 ms transfer, the gap being the hold.

## TCP8 (`tcp-freedom`, 8 connections)

Direct outbound echo, 8 SOCKS connections × 1000 × 4096 bytes both ways.
Rate includes the round trip; CPU ms/GiB is extrapolated from ~62.5 MiB
and is noisier than the 1 GiB rows. The whole run is ~70 ms at a 100 ms
RSS sample.

| engine | echo Mbps | p50 µs | p99 µs | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- |
| segue | 6722 / **7490** / 7490 | 62 / **63** / 64 | 119 / **122** / 122 | **6.2 MiB** (6352 KiB) | **1475** |
| sing-box | 4900 / **5243** / 5519 | 90 / **95** / 99 | 156 / **160** / 248 | **38.8 MiB** (39776 KiB) | **4260** |
| mihomo | 4724 / **5350** / 5462 | 92 / **93** / 105 | 149 / **160** / 189 | **31.0 MiB** (31712 KiB) | **4260** |

p99 is still not a stable tail: sing-box's five-run p99 band is
156–248 µs. The medians separate cleanly (segue 63, sing-box 95, mihomo
93).

## VLESS + REALITY + Vision, 1 connection, 256 × 4 MiB

Same 1 GiB download through REALITY (`www.google.com` cover,
fingerprint `chrome`, `xtls-rprx-vision`) to the same fixture. The
fixture spends ~8 s learning the cover before each run, outside
`duration_ms`; it is not sampled and shares the CPU.

| engine | Mbps min/median/p95 | duration ms | transfer ms | TTFB p50 | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- | --- |
| segue | 21583 / **21692** / 21802 | 455 / **466** / 474 | 394 / **396** / 398 | **71 ms** | **9.8 MiB** (9984 KiB) | 460 / **470** / 490 |
| mihomo | 15967 / **18085** / 19747 | 655 / **689** / 748 | 435 / **475** / 538 | **217 ms** | **32.8 MiB** (33584 KiB) | 530 / **540** / 650 |
| sing-box | no completed run | | | | | |

sing-box 1.15.0-alpha.13 still fails against this server exactly as on
2026-11-17: it deletes the `X25519MLKEM768` key share
(`common/tls/reality_client.go`), the client logs
`reality verification failed`, and the SOCKS CONNECT fails. The
one-iteration smoke reproduced it; no five-run series. Stderr:

`/Volumes/dev/ci/tmp/bench-2026-11-18/reality-smoke-singbox/1795011923034/sing-box/reality-vision-bulk-throughput/stderr.log`

## Added workload: `tcp-bulk-throughput`, 1 connection, 256 × 4 MiB

New in this rerun. A local source server writes the whole 1 GiB
immediately on connect (server-first); the client reads through SOCKS →
engine → direct freedom outbound. No proxy protocol, so this isolates
the SOCKS + dial path — the workload the TTFB section quantifies.

| engine | Mbps min/median/p95 | duration ms | transfer ms | TTFB p50 | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- | --- |
| segue | 85049 / **86768** / 88557 | 106 / **109** / 110 | 97 / **99** / 101 | **9 ms** | **6.2 MiB** (6384 KiB) | **130** |
| sing-box | 97613 / **98735** / 99883 | 95 / **96** / 101 | 86 / **87** / 88 | **9 ms** | **33.4 MiB** (34208 KiB) | **110** |
| mihomo | 53025 / **61357** / 62246 | 146 / **150** / 171 | 138 / **140** / 162 | **9 ms** | **28.7 MiB** (29344 KiB) | **190** |

~85–99 Gbps is loopback memory-copy territory; read this table for TTFB,
RSS and CPU, not as a WAN rate. mihomo's throughput sits below the other
two on the direct path while its VLESS TTFB (213 ms above) shows where
its own hold lives.

## Harness output

Raw run directories stayed outside the repo; per-run `result.json` files
sit next to each `summary.json`. Series logs are the matching `*.log`
files in `/Volumes/dev/ci/tmp/bench-2026-11-18/`.

| series | summary.json |
| --- | --- |
| gRPC segue | `/Volumes/dev/ci/tmp/bench-2026-11-18/grpc-segue/1795011810861/xray-rust/grpc-bulk-throughput/summary.json` |
| gRPC sing-box | `/Volumes/dev/ci/tmp/bench-2026-11-18/grpc-singbox/1795011813772/sing-box/grpc-bulk-throughput/summary.json` |
| gRPC mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-18/grpc-mihomo/1795011821766/mihomo/grpc-bulk-throughput/summary.json` |
| TCP8 segue | `/Volumes/dev/ci/tmp/bench-2026-11-18/tcp8-segue/1795011828332/xray-rust/tcp-freedom/summary.json` |
| TCP8 sing-box | `/Volumes/dev/ci/tmp/bench-2026-11-18/tcp8-singbox/1795011829337/sing-box/tcp-freedom/summary.json` |
| TCP8 mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-18/tcp8-mihomo/1795011830460/mihomo/tcp-freedom/summary.json` |
| REALITY segue | `/Volumes/dev/ci/tmp/bench-2026-11-18/reality-segue/1795011831487/xray-rust/reality-vision-bulk-throughput/summary.json` |
| REALITY mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-18/reality-mihomo/1795011874684/mihomo/reality-vision-bulk-throughput/summary.json` |
| TTFB (tcp-bulk) segue | `/Volumes/dev/ci/tmp/bench-2026-11-18/ttfb-segue/1795011919213/xray-rust/tcp-bulk-throughput/summary.json` |
| TTFB (tcp-bulk) sing-box | `/Volumes/dev/ci/tmp/bench-2026-11-18/ttfb-singbox/1795011920408/sing-box/tcp-bulk-throughput/summary.json` |
| TTFB (tcp-bulk) mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-18/ttfb-mihomo/1795011921755/mihomo/tcp-bulk-throughput/summary.json` |

## What this does and does not show

It shows a synthetic loopback SOCKS path on one Mac mini: the harness
opens SOCKS to the client, the client dials an Xray-core fixture on the
same machine (or a local echo / local bulk source), and the harness
checks the bytes. RSS and CPU are the client process only, sampled every
100 ms. TTFB is derived (`duration − transfer`), not a sampled timer.

It does not show TUN, a phone, a WAN, loss, or energy. The fixture
shares the CPU, so a bulk rate is lower than a dedicated server would
be. sing-box gRPC is the lite stack this harness has always built, not
grpc-go. TCP8 and the added tcp-bulk workload are direct, not VLESS.
mihomo's mixed port and `find-process-mode: off` are the harness config,
not a stock client profile. Five runs on an idle desktop still leave a
noisy TCP8 tail; and, the bigger caveat on this page, the two afternoons
are not the same machine state — the unchanged Go engines moved 50–75 %
between them, so only the TTFB rows (where mihomo's own hold is the
control) should be read as before/after evidence for #63 and #69.
