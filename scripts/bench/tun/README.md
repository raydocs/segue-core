# TUN benchmark on a throwaway macOS VM

Loopback SOCKS numbers do not measure the path AI apps use. This script
runs that path on one machine: the engine owns the default route, the
workload dials the documentation address `198.51.100.20:5001`, and an
Xray-core v26.11.9 fixture redirects the flow to a sink on
`127.0.0.1:5001`. The engine dials the fixture on loopback, which is not
captured by the TUN. dummynet shapes only that carrier port.

It changes routes and PF. Run it only on a throwaway volume (an Amp Mac
Satellite: root, SIP off). `--dry-run` prints every command and does not
run them. A real run refuses unless all three are true:

- `SEGUE_VM_BENCH=throwaway`
- `sysctl kern.hv_vmm_present` is `1`
- the process is root

The script never reboots and never calls `shutdown`. Cleanup is
unconditional: engines get `SIGTERM` (then `SIGKILL`), utun routes that
were not present before the engine started are deleted, the bench pipe
is deleted, and both anchors are flushed. Copy the block between
`BEGIN-TUN-BENCH` and `END-TUN-BENCH` out before the Satellite is
destroyed. That block is the JSON result and the Markdown table.

## What it measures

One engine at a time. Protocols are VLESS+REALITY+Vision and VLESS+gRPC
(h2c, service name `bench`, no `flow`), the same UUID and REALITY keys
as `crates/segue-bench`. Engines:

| id | process |
| --- | --- |
| `segue-kernel` | `segue-kernel run`, inline rule for `198.51.100.20/32`, `tun.ipv6` false |
| `sing-box` | tun inbound `auto_route`, loopback excluded, vless outbound |
| `mihomo-system` | `tun.enable`, `stack: system` |
| `mihomo-mixed` | `tun.enable`, `stack: mixed` |

Workloads, all to `198.51.100.20:5001`: 1 GiB one stream, 1 GiB across 8
streams, 200 one-byte echoes (p50/p99), and 20 fresh-connection
time-to-first-byte samples. RSS and CPU come from `ps -o rss= -o time=`
every 100 ms, the same fields segue-bench samples. Mbps is
`ceil(bytes * 8 / (duration_ms * 1000))`.

Pins, the same commits as
`docs/benchmarks/results/2026-11-18-rerun-after-63-69`:

| piece | revision |
| --- | --- |
| Xray-core | `v26.11.9` `676eaf66f8f05d4d558ee7a74b4736623d3feeb9` |
| sing-box | `v1.15.0-alpha.13` `824dbcfb4dd0a95921840b1737b950cde590241e` |
| mihomo | `3c0d10a503f7b2fde3fe167d4d91dd05725d5268` |

sing-box is built with
`-tags with_gvisor,with_utls,badlinkname,tfogo_checklinkname0` and
`-ldflags=-checklinkname=0`, as on 2026-11-17. mihomo is built with
`-tags with_gvisor` so `stack: mixed` links. The SOCKS binary was not;
do not compare RSS against that binary.

Two deliberate differences from the SOCKS fixture: REALITY's fallback
`dest` is the local sink, not `www.google.com:443`, and the freedom
outbound sets `"redirect": "127.0.0.1:5001"`.

## Link model

`dnctl` pipe 7, classified by PF `dummynet out quick on lo0` for the
carrier port in both directions (`no state`, which pfctl requires).
Each direction is delayed once, so RTT is twice `delay`. `plr` is the
per-direction loss.

| id | delay | plr | bw | transfer |
| --- | --- | --- | --- | --- |
| `clean` | none | | | 1 GiB |
| `rtt50` | 25 ms | 0 | 200 Mbit/s | 1 GiB |
| `rtt50-loss1` | 25 ms | 0.01 | 200 Mbit/s | 8 MiB |
| `rtt150-loss3` | 75 ms | 0.03 | 80 Mbit/s | 8 MiB |

This macOS rejects a pipe queue of 1 MiB or more (`dnctl -n` reports
`queue size must be < 1MB`; a slot queue cannot exceed 100). A delay
pipe with the default 50-slot queue drops bursts on lo0, whose packets
are up to 16 KiB, so a "no loss" row would be loss. `bw` is set so the
bandwidth-delay product fits in `queue 900Kbytes` even if `delay` is
rounded up to the next 10 ms tick (25 becomes 30, 75 becomes 80). The
configured `delay` is what the script asks for; the tick is the kernel's.
Loss rows are 8 MiB because a 3% loss at 150 ms cannot finish 1 GiB
inside a Satellite lifetime (`MSS / (RTT * sqrt(p))`). Pass
`--lossy-bytes 1073741824` to force 1 GiB. It will time out.

If the loaded ruleset has `dummynet-anchor "com.apple/*"`, rules go in
`com.apple/segue.tunbench` and `/etc/pf.conf` is not reloaded. Otherwise
the script comments out `set skip on lo0`, appends anchor
`segue.tunbench`, and reloads a copy. `pfctl -f` flushes anchors the
system inserted at runtime. That is acceptable only because the volume
is discarded.

## Amp prompt

Paste this into an Amp thread that is a new Mac Satellite (6 CPU, 14 GB,
root, SIP off). Do not point it at any machine you keep.

```text
You are on a throwaway macOS Satellite (root, SIP off). Do not reboot it.
Do not run this on any other machine: it installs a utun default route
and PF dummynet rules, and a real run refuses unless the host is a VM.

The Satellite needs git, python3, Go 1.27 or newer, and Rust 1.96 (or
whatever `cargo` on PATH can build this workspace with) before the
benchmark starts. Outbound network is required for the clones and the
builds. After the first engine takes the default route, do not expect
general internet to work. The machine should otherwise be idle.

Clone https://github.com/raydocs/segue-core.git, check out the branch
that contains scripts/bench/tun-bench-macos.sh, then as root:

export SEGUE_VM_BENCH=throwaway
bash scripts/bench/tun-bench-macos.sh --work-dir /var/tmp/segue-tun-bench

When it finishes, copy the entire region from the line BEGIN-TUN-BENCH
through END-TUN-BENCH out of the log. That region is the only result
that survives: the Satellite is destroyed afterwards. Do not reboot.
A first run is about 1–2 hours after the builds; the 150 ms + 3% cells
are the slow part. If you only want the command plan, add --dry-run
(still with SEGUE_VM_BENCH=throwaway). A real run on a machine that is
not a VM exits 2.
```

A dry plan, safe on a machine that is not a VM:

```bash
SEGUE_VM_BENCH=throwaway bash scripts/bench/tun-bench-macos.sh --dry-run
```

Checkouts already at the pinned commits are reused
(`/Volumes/dev/ci/xray/Xray-core`, `/Volumes/dev/ci/tmp/sing-box-1.15a13`,
`/Volumes/dev/ref/mihomo`, or `--xray-src` / `--sing-box-src` /
`--mihomo-src`). Otherwise the script clones into the work dir.

## Tests

```bash
python3 -m unittest discover -s scripts/bench/tun -p 'test_*.py'
bash -n scripts/bench/tun-bench-macos.sh
```
