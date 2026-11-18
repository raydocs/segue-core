**Hysteria2**

- Audited the Hysteria2 client's congestion control against Xray-core
  v26.11.9 and sing-box 1.15.0-alpha.13: the auth request's `Hysteria-CC-RX`
  and the Brutal/BBR selection already match Xray exactly. The auth request
  is now built by a named `auth_request` helper with a unit test pinning its
  headers. See `docs/notes/hy2-congestion.md`.
