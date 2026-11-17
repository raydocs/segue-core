- iOS and macOS: the packet tunnel provider cancels the tunnel with
  `XrayPacketTunnelProviderError.tunFileDescriptorStopped` when the core's read
  or write loop gives up on the borrowed utun descriptor, instead of the
  system going on showing a connected VPN that moves no packets. A start that
  arrives while an earlier DNS bootstrap lookup still holds the bootstrap
  worker now runs as soon as that lookup returns, within its own deadline,
  instead of waiting the deadline out and failing with `dnsBootstrapTimedOut`.
  (upstream `00cfb9b6`)
- Android: `startXrayTunnel()` while a session is stopping (after
  `stopXrayTunnel()` or a packet-pump or descriptor failure) is queued and runs
  once the stop finishes, rather than being dropped without a callback; a
  later call replaces it and the replaced one reports
  `onXrayTunnelStartCancelled`. `stopXrayTunnel()` waits for an
  `onXrayTunnelStarted` already in flight, and no `onXrayTunnelStarted` comes
  after it returns. (upstream `c9fe6baa`)
- Android and Apple: profiles whose VLESS outbound is in the simplified form
  start again; the DNS bootstrap reads the address and port from it as from the
  `vnext` form. (upstream `8fa287b9`)
- CLI: `segue run` stops gracefully on SIGTERM as on SIGINT, so `systemctl
  stop`, `docker stop` and launchd let the core shut down and tell a QUIC
  carrier's server the flow ended. (upstream `c1a69b7b`)
- Interop tests: the shared protocol-reference harness starts the reference
  again on a fresh port when another test's socket took the one it picked, and
  retries a same-port restart for about two seconds; mKCP's header-custom
  prefix answers with a random token rather than the client's, so a stream's
  crossing datagrams no longer drop nearly every reply. The xdns carrier case
  and the WireGuard timed-lifecycle cases allow more room on a slow runner.
  (upstream `f33a50b0`, `1efb1e47`, `3b257e07`; fixture option
  `--vless-encryption` from `e1e1c5a3`)
