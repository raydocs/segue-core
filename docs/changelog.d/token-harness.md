**Testing**

- `segue-bench impair --tcp-loss emulate` models TCP loss as recovery delay
  (fast retransmit, tail-loss probe, RTO, and a 1 s SYN flight) instead of
  dropping bytes. Off by default; the previous TCP path is unchanged. It is a
  model of TCP recovery, not TCP.
- Ignored loopback benchmark `redundancy_e2e`
  (`scripts/bench/session-redundancy.sh`) measures token delay, inter-arrival,
  stalls and new-flow TTFB through the session stack on `clean`, `rtt170`,
  `cn163-offpeak` and `cn163-peak`. Baseline:
  `docs/benchmarks/session-token-stream.md`.
