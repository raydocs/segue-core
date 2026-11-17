- Add client-only ShadowTLS v3 raw-TCP stream security, including uTLS-shaped
  authenticated ClientHello session IDs, the genuine TLS relay handshake,
  chained-HMAC application framing, fixed reference vectors and a real-local-TLS
  loopback test. References: SagerNet/sing-shadowtls `v3_client.go`,
  `v3_conn.go`, `v3_server.go`, and mihomo `transport/shadowtls` (local
  reference checkouts, 2026-11-17).
