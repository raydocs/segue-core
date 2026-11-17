- Every uTLS fingerprint now advertises its profile's whole cipher suite
  list, in uTLS's order with GREASE at its index, instead of only the suites
  rustls implements: `chrome` sends 15 suites, `firefox` 17, `safari` 20 and
  `ios` 26. BoringSSL padding is no longer grown to make up the missing
  bytes, so padded hellos match uTLS's own byte for byte and carry the
  JA3/JA4 a real browser does. The CBC and RSA key exchange suites among them
  are advertised only; a server that selects one fails the handshake with
  `SelectedUnofferedCipherSuite`. Upstream 405b8695.
- The vendored rustls (shaped-rustls, 0.23.40) carries the rustls
  0.23.45/0.23.46 security fixes: strict brotli certificate decompression,
  which refuses brotli's large-window extension and trailing input
  (RUSTSEC-2026-0348); the key exchange hint is saved only after the server
  is authenticated (0349); a TLS 1.3 handshake message may not share a record
  with a key-changing message (0285); and `Debug` no longer prints TLS
  session secrets (0346). No ClientHello byte changes. Upstream d38badbe.
- `scripts/check-vendored-advisories.sh` audits the upstream release behind
  every vendored crate, and any git dependency, against RustSec, since
  `cargo audit` matches advisories only for registry packages. The
  supply-chain CI job runs it after `cargo audit`. Upstream ace50c52.
