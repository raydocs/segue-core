- Test harness: every suite that starts Xray-core (or a Go stand-in binding a
  port) on a port it picked by binding `127.0.0.1:0` and releasing it now
  retries the start on a fresh port when the child exits with
  `bind: address already in use` — TCP or UDP — up to five times, re-rendering
  the config for each attempt. Any other early exit still fails at once with
  the full output. This closes the race that failed `go-oracles`'
  `proxy_carriers::http_carrier_every_transport_and_security_tcp`:
  `listen tcp 127.0.0.1:33617: bind: address already in use`. The shared
  helper generalizes upstream's `f33a50b0` (ported as `b68f0254`, which covered
  the mux/Shadowsocks/Trojan/VMess reference alone) to
  `tests/support/xray_startup.rs`, used by the local Xray interop suite (main
  server/client, MASQUE, reverse portal, direct UDP masks, XDRIVE), the SOCKS
  and HTTP runtimes, live REALITY, and the MASQUE TUN runtime. Upstream commits
  `f33a50b0`, `b68f0254`.
