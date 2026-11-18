**Performance**

- The 3-engine loopback benchmark (segue vs sing-box 1.15.0-alpha.13 vs
  mihomo, same binaries as the 2026-11-17 run) was rerun on main after the
  VLESS first-request fix and the Vision direct copy: VLESS+gRPC
  time-to-first-byte fell from a ~520 ms median hold to 10 ms (mihomo's own
  ~215 ms hold, same binary, is the control), REALITY+Vision TTFB from
  ~690 ms to 71 ms and its five-run band tightened to 21583–21802 Mbps.
  Throughput tables moved 50–75 % for the unchanged Go engines too, so the
  pages mark TTFB, not raw Mbps, as the before/after evidence; see the
  [2026-11-18 rerun report](docs/benchmarks/results/2026-11-18-rerun-after-63-69/README.md).
