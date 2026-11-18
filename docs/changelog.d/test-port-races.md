**Tests and CI**

- The HTTP runtime chaining tests no longer pick the stand-in SOCKS upstream's
  port by binding a listener and dropping it before the core binds the same
  port; that window let a parallel test's socket take the port and fail
  `core.start()` with `AddrInUse` (PR #70, rust-test-engine). The upstream now
  runs as its own core whose inbound binds port 0, and the chained profile
  reads the real port back through `core.inbound_addr`, the same pattern the
  reference-process suites already follow with `start_on_fresh_ports!`.
