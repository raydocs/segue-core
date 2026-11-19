**Testing**

- `segue-bench dgramsim`: seeded model of a 60 s token stream (30–60 B every
  20 ms, 85 ms one-way) comparing impair's TCP recovery with datagram last-N,
  K-flow duplication and 40 ms coalescing, under Bernoulli 7.5% and a
  Gilbert-Elliott fit of the measured short bursts. Design note:
  `docs/design/session-datagram-redundancy.md`.
