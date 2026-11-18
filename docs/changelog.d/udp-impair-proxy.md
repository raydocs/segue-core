**Testing**

- New `segue-bench impair` userspace link-impairment relay (UDP and TCP, no
  root): fixed delay, jitter, uniform loss, Gilbert-Elliott burst loss,
  bandwidth cap and reordering, all seeded and reproducible. Named profiles
  `clean`, `rtt170`, `rtt170-loss2`, `cn163-peak` (172 ms RTT, ~3-packet
  bursts, 8 % loss) and `cn163-offpeak` (2 %) reproduce the measured
  China Telecom 163 path locally, so WAN-like tests no longer need `tc netem`.
