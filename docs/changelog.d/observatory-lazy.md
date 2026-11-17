- On mobile, mobile-plus and low-memory profiles the observatory no longer
  probes from the moment the core starts. Probing begins on the first
  connection through a `leastPing` or `leastLoad` balancer and pauses after
  30 minutes without one — sing-box urltest's `idle_timeout` — then resumes
  on the next such connection. Delays already measured stay in place across
  the pause. Desktop and throughput profiles keep the previous eager
  schedule, and `TunRuntimeOptions::eager_observatory` forces that schedule
  on every profile. `observatory_idle_timeout` overrides the 30 minutes.
  Xray's observatory JSON fields are unchanged.
- `leastPing` keeps its current outbound until another healthy one is faster
  by more than `pingTolerance` (default 50 ms, sing-box urltest `tolerance`).
  With no incumbent it still picks the lowest delay, tie-broken by tag order.
  `leastLoad`'s Xray `tolerance`, `expected` and `baselines` are unchanged;
  the same `pingTolerance` applies only when that ranking selects a single
  outbound, so a top-N spread does not stick to one member.
