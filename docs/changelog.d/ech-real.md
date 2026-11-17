- **Real ECH on the TLS outbound path**, as Xray-core v26.11.9 reads it
  (`infra/conf/transport_security.go:317`, `transport/internet/tls/ech.go`).
  `tlsSettings.echConfigList` now takes a standard padded base64
  ECHConfigList and switches the handshake to rustls' ECH mode
  (`vendor/shaped-rustls` `ClientConfigBuilder::with_ech`,
  `rustls/src/client/ech.rs:38-107`), so the inner SNI travels encrypted and
  only the config's public name is visible. The config is built for TLS 1.3
  alone, on aws-lc-rs' HPKE suites, and the ECHConfigList joins the TLS config
  cache key. `echConfigList` is part of the generated
  `docs/config-contract.json`.
- `tlsSettings.echForceQuery` is rejected: Xray-core removed it with its other
  deprecated TLS fields (upstream commit `55956f8d`, "Deprecated TLS fields
  were removed").
- Real ECH is refused at config time with a shaping `fingerprint` (the uTLS
  parrot hello carries only GREASE ECH) and on QUIC carriers, which never place
  rustls' ECH extension; the transport builders refuse both again. The GREASE
  ECH path, REALITY and uTLS-shaped hellos are unchanged.
- The DNS resolver forms of `echConfigList` (`udp://`, `https://`,
  `name+scheme://`) are refused with a clear config error and a TODO: the
  bundled DNS client cannot query HTTPS (type 65) resource records, so the ECH
  config cannot be fetched at dial time yet.
- No loopback ECH handshake test: the vendored shaped-rustls has client-side
  ECH only (no `EncryptedClientHelloKeys` on `ServerConfig`), so the tests
  cover the parsed config, the ECH-enabled `ClientConfig`, the outer hello's
  ECH extension and public-name SNI, the cache key, and every rejection.
