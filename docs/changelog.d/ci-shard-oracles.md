- CI's `go-oracles` gate is four parallel shards (`go-oracles-protocols`,
  `go-oracles-carriers`, `go-oracles-wireguard`, `go-oracles-tunnels`) plus
  the same `go-oracles` job, which now fails unless every shard succeeded.
  On the 2026-11-16 main run (43811109067) the single job took 31.9 minutes;
  the slowest shard is about ten minutes of those steps. Every oracle command
  is unchanged and still runs once. Checkout, the root-disk target, Go 1.27.4,
  Rust 1.96.0 and pinned Xray-core are shared through
  `.github/actions/go-oracle-setup`. Each shard reports its own disk use,
  because the runners no longer share one build directory. Stable tag pushes
  still skip the gate.
