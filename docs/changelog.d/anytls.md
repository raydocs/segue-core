- **AnyTLS outbound.** A new `anytls` outbound protocol, client only, over the
  existing TLS/REALITY carrier. It speaks the `sing-anytls` wire format: the
  SHA-256 password hello, the 7-byte command frames, the reference padding
  scheme (including server-sent scheme updates), and UDP over sing's
  UDP-over-TCP framing. TCP flows multiplex over a bounded session pool with
  `idle_session_check_interval`, `idle_session_timeout` and `min_idle_session`,
  named as sing-box and mihomo name them. Xray-core has no AnyTLS, so the
  config shape is Segue's own; see `docs/design/anytls-outbound.md`.
