# Segue vs sing-box 1.15.0-alpha.13 vs mihomo Alpha, 2026-11-17

Local loopback SOCKS comparison on this Mac mini. Five runs each. Figures
are harness medians (`min/median/p95` of the five runs). The engine label
`xray-rust` is the release `segue` binary.

This is not the published M3 Pro anchor in `docs/benchmarks.md` (Apple M3
Pro, 18 GB, macOS 26.5.2). Different machine, different revisions. Do not
read the rows as an update of that table.

## Machine

| | |
| --- | --- |
| Model | Mac mini (Mac18,5) |
| Chip | Apple M6 (12 cores: 2 Super, 4 Performance, 6 Efficiency) |
| RAM | 16 GB |
| OS | macOS 27.0.1 (build 26A434) |
| Rust | 1.96.0, `cargo build --release -j 4` |
| Go | 1.27.4 darwin/arm64, `GOTOOLCHAIN=local`, `GOMAXPROCS=4` |

## Revisions and binaries

| piece | revision | binary SHA-256 |
| --- | --- | --- |
| segue / harness tree | `26a668b1b9e2a2b06bbd060abcff43899cd69614` (clean at every run) | `segue` `6f485c7f54c0edb4ebe276c33161d405d18143a0bb5a16c7594d3232668187cf` |
| segue-bench (release) | same tree, `harness_profile=release` | `f69b6df291cff5d9cc2646080f54efe4cafc9d00f0c04ac89124fce2e111dc85` |
| sing-box | tag `v1.15.0-alpha.13`, `824dbcfb4dd0a95921840b1737b950cde590241e` (clean) | `a74f2b05b4b98ea19b643b372768ffb4d24ac32df75f3fe143356966ffeadd31` |
| mihomo | Alpha `3c0d10a503f7b2fde3fe167d4d91dd05725d5268` (clean; `vcs.modified=false`). `mihomo -v` prints `Mihomo Meta 1.10.0` | `0f77725a275861ad1d83ee4d6613ead9f4df6adc623d7a68d593ec09fea51367` |
| Xray-core fixture (server only) | v26.11.9 `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` | `73cc95e649b75ae9953a0d147db8ad73543f663c72bf0852d617df71dc8f9237` |

`sing-box version` prints `version unknown` because the release `-X` version
ldflags were not passed. The same line prints revision `824dbcf` and the
tags below. Build info records `CGO_ENABLED=1` for both sing-box and mihomo.

## Commands

Environment for the Go builds:

```sh
export PATH=/Volumes/dev/ci/go-sdk-1.27.4/go/bin:$PATH
export GOPATH=/Volumes/dev/ci/go GOCACHE=/Volumes/dev/ci/go-cache
export GOTOOLCHAIN=local GOMAXPROCS=4
```

sing-box, worktree of the fetched tag, harness tag set (no `with_grpc`, so
the gRPC leg is `v2raygrpclite`). Go 1.27 rejects the `badlinkname` reference
to `net/http/internal/http2.disableExtendedConnectProtocol` unless the linker
check is disabled; `-ldflags=-checklinkname=0` is that flag and nothing else:

```sh
git -C /Volumes/dev/ref/sing-box fetch --depth 50 origin tag v1.15.0-alpha.13
git -C /Volumes/dev/ref/sing-box worktree add --detach \
  /Volumes/dev/ci/tmp/sing-box-1.15a13 v1.15.0-alpha.13
cd /Volumes/dev/ci/tmp/sing-box-1.15a13
go build -tags 'with_gvisor,with_utls,badlinkname,tfogo_checklinkname0' \
  -ldflags='-checklinkname=0' -trimpath \
  -o /Volumes/dev/ci/tmp/bin/sing-box ./cmd/sing-box
```

mihomo, from `/Volumes/dev/ref/mihomo` at `3c0d10a` (no module download of a
newer Go; `go 1.20` in `go.mod` builds with 1.27.4):

```sh
cd /Volumes/dev/ref/mihomo
go build -trimpath -o /Volumes/dev/ci/tmp/bin/mihomo .
```

Xray-core fixture, `CGO_ENABLED=0`, matching the harness oracle build:

```sh
cd /Volumes/dev/ci/xray/Xray-core
CGO_ENABLED=0 go build -o /Volumes/dev/ci/tmp/bin/xray ./main
```

Harness and client, from this worktree:

```sh
export CARGO_HOME=/Volumes/dev/ci/cargo RUSTUP_HOME=/Volumes/dev/ci/rustup \
  CARGO_TARGET_DIR=/Volumes/dev/ci/bee-target.noindex PATH=/Volumes/dev/ci/cargo/bin:$PATH
cargo +1.96.0 build -j 4 --release -p segue-cli --bin segue -p segue-bench --bin segue-bench
```

Every series is `segue-bench run` with `--no-auto-build`, `--runs 5`,
`--sample-interval-ms 100` (the default), and the binaries above. Bulk
workloads add `--run-timeout-ms 180000`. TCP8 uses `--run-timeout-ms 120000`.
The canonical argument vector is `provenance.invocation_args` in each
`summary.json`.

```sh
H=/Volumes/dev/ci/bee-target.noindex/release/segue-bench
B=(--no-auto-build
   --xray-rust-bin /Volumes/dev/ci/bee-target.noindex/release/segue
   --xray-core-bin /Volumes/dev/ci/tmp/bin/xray
   --xray-core-dir /Volumes/dev/ci/xray/Xray-core
   --sing-box-bin /Volumes/dev/ci/tmp/bin/sing-box
   --sing-box-dir /Volumes/dev/ci/tmp/sing-box-1.15a13
   --mihomo-bin /Volumes/dev/ci/tmp/bin/mihomo
   --runs 5)
# VLESS + gRPC, one connection, 256 x 4 MiB download (1 GiB)
"$H" run --engine xray-rust "${B[@]}" --workload grpc-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
"$H" run --engine sing-box  "${B[@]}" --workload grpc-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
"$H" run --engine mihomo    "${B[@]}" --workload grpc-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
# TCP8: tcp-freedom, 8 connections, 1000 echoes of 4096 bytes, direct outbound
"$H" run --engine xray-rust "${B[@]}" --workload tcp-freedom \
  --connections 8 --iterations 1000 --payload-size 4096 --run-timeout-ms 120000
"$H" run --engine sing-box  "${B[@]}" --workload tcp-freedom \
  --connections 8 --iterations 1000 --payload-size 4096 --run-timeout-ms 120000
"$H" run --engine mihomo    "${B[@]}" --workload tcp-freedom \
  --connections 8 --iterations 1000 --payload-size 4096 --run-timeout-ms 120000
# VLESS + REALITY + xtls-rprx-vision, same 1 GiB download. sing-box omitted; see below.
"$H" run --engine xray-rust "${B[@]}" --workload reality-vision-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
"$H" run --engine mihomo    "${B[@]}" --workload reality-vision-bulk-throughput \
  --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 180000
```

There is no harness workload named `tcp8`. The 8-connection case is
`tcp-freedom`, the same shape as the 8-connection command in
`docs/benchmarks.md`. Mihomo is `--engine mihomo`: a mixed-port SOCKS inbound
and the same direct, VLESS gRPC (`security: none`, service name `bench`), or
VLESS REALITY outbound. `find-process-mode` is `off`. REALITY sets
`support-x25519mlkem768: true` because the v26.11.9 server requires that key
share.

## VLESS + gRPC, 1 connection, 256 × 4 MiB

Server-first download through h2c gRPC to the Xray-core fixture. Throughput
is the harness transfer window (`throughput_mbps`: decimal megabits, received
bytes only). `duration_ms` includes time before the first validated byte.
Peak RSS is `peak_rss_kib / 1024`. CPU is `cpu_millis_per_gib`.

| engine | Mbps min/median/p95 | duration ms | transfer ms | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- |
| segue (`xray-rust`) | 11735 / **12879** / 13401 | 1161 / **1187** / 1254 | 641 / **667** / 732 | **12.5 MiB** (12816 KiB) | 920 / **940** / 950 |
| sing-box (lite) | 3424 / **3634** / 3670 | 2358 / **2389** / 2540 | 2341 / **2364** / 2509 | **49.2 MiB** (50384 KiB) | 2980 / **3040** / 3320 |
| mihomo | 5080 / **5277** / 5766 | 1716 / **1853** / 1912 | 1490 / **1628** / 1691 | **48.5 MiB** (49680 KiB) | 1920 / **2110** / 2230 |

No per-chunk latency on this workload. Each run received exactly
1,073,741,824 bytes and sent 0.

Segue's median transfer window is 667 ms and the run is 1187 ms. The gap is
the VLESS first-payload hold (about 500 ms) on a server-first download, not
gRPC setup. sing-box reaches the first byte in about 25 ms; mihomo in about
225 ms. Quote both columns.

## TCP8 (`tcp-freedom`, 8 connections)

Direct outbound, not a proxy protocol. Eight SOCKS connections each echo
1000 × 4096 bytes (32,768,000 bytes each way). The rate includes the echo
round trip; it is not comparable to the bulk table. CPU ms/GiB is
extrapolated from that ~62.5 MiB, so it is noisier than the 1 GiB rows.
The whole run is about 145 ms at a 100 ms RSS sample, so the RSS peak is
one or two samples.

Latency is microseconds. The cell is the median across the five runs of that
run's own percentile, with the five-run min/p95 of the same percentile.

| engine | echo Mbps | p50 µs | p99 µs | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- |
| segue | 3616 / **3667** / 4065 | 108 / **119** / 121 | 261 / **322** / 395 | **6.25 MiB** (6400 KiB) | **2622** |
| sing-box | 3277 / **3616** / 3772 | 116 / **125** / 127 | 286 / **291** / 465 | **39.1 MiB** (40064 KiB) | **4588** |
| mihomo | 2689 / **3340** / 3884 | 113 / **127** / 137 | 284 / **414** / 678 | **30.9 MiB** (31600 KiB) | **4424** |

p99 moves hundreds of microseconds between runs. The median is not a stable
tail.

## VLESS + REALITY + Vision, 1 connection, 256 × 4 MiB

Same download size as the gRPC table, through REALITY (`www.google.com`
cover, fingerprint `chrome`, `xtls-rprx-vision`) to the same Xray-core
fixture. The fixture spends about 8 s learning the cover origin before each
run; that wait is outside `duration_ms`. The fixture process is not sampled
and shares the CPU.

| engine | Mbps min/median/p95 | duration ms | transfer ms | peak RSS | CPU ms/GiB |
| --- | --- | --- | --- | --- | --- |
| segue | 4679 / **9090** / 11393 | 1483 / **1635** / 3040 | 754 / **945** / 1836 | **9.7 MiB** (9904 KiB) | 780 / **920** / 1040 |
| mihomo | 9674 / **10605** / 13195 | 889 / **1036** / 1116 | 651 / **810** / 888 | **32.8 MiB** (33600 KiB) | 730 / **840** / 910 |
| sing-box | no completed run | | | | |

Segue's slow run was 4679 Mbps and 3040 ms; the other four were
8902–11393 Mbps. mihomo's five runs stayed between 9674 and 13195. One
slow run moves the median. These are five-run medians, not a tight band.

sing-box 1.15.0-alpha.13 still deletes the `X25519MLKEM768` key share in
`common/tls/reality_client.go`. Against this server the client logs
`reality verification failed` and the SOCKS CONNECT fails. A one-iteration
smoke was enough; there is no five-run series. Stderr:

`/Volumes/dev/ci/tmp/bench-2026-11-17/reality-smoke-singbox-cgo/1794975378914/sing-box/reality-vision-bulk-throughput/stderr.log`

## Harness output

Raw run directories stayed outside the repo. Each `summary.json` is the
five-run aggregate; per-run `result.json` files sit next to it.

| series | summary.json |
| --- | --- |
| gRPC segue | `/Volumes/dev/ci/tmp/bench-2026-11-17/grpc-segue/1794974817126/xray-rust/grpc-bulk-throughput/summary.json` |
| gRPC sing-box | `/Volumes/dev/ci/tmp/bench-2026-11-17/grpc-singbox-cgo/1794975304764/sing-box/grpc-bulk-throughput/summary.json` |
| gRPC mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-17/grpc-mihomo-cgo/1794975318471/mihomo/grpc-bulk-throughput/summary.json` |
| TCP8 segue | `/Volumes/dev/ci/tmp/bench-2026-11-17/tcp8-segue/1794974848488/xray-rust/tcp-freedom/summary.json` |
| TCP8 sing-box | `/Volumes/dev/ci/tmp/bench-2026-11-17/tcp8-singbox-cgo/1794975328934/sing-box/tcp-freedom/summary.json` |
| TCP8 mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-17/tcp8-mihomo-cgo/1794975330910/mihomo/tcp-freedom/summary.json` |
| REALITY segue | `/Volumes/dev/ci/tmp/bench-2026-11-17/reality-segue/1794974966587/xray-rust/reality-vision-bulk-throughput/summary.json` |
| REALITY mihomo | `/Volumes/dev/ci/tmp/bench-2026-11-17/reality-mihomo-cgo/1794975332561/mihomo/reality-vision-bulk-throughput/summary.json` |

Stdout logs for those series are the matching `*.log` files in
`/Volumes/dev/ci/tmp/bench-2026-11-17/`.

## What this does and does not show

It shows a synthetic loopback SOCKS path on one Mac mini: the harness opens
SOCKS to the client, the client dials an Xray-core fixture on the same
machine (or a local echo, for TCP8), and the harness checks the bytes. RSS
and CPU are the client process only, sampled every 100 ms.

It does not show TUN, a phone, a WAN, loss, or energy. The fixture shares
the CPU, so a bulk rate is lower than a dedicated server would be. sing-box
gRPC is the lite stack this harness has always built, not grpc-go. TCP8 is
a direct echo, not VLESS. mihomo's mixed port and `find-process-mode: off`
are the harness config, not a stock client profile. Five runs on an idle
desktop still leave a wide REALITY band and a noisy TCP8 tail; the medians
are the summary, not a claim that the next run will match them.
