- Apple: the reference client has an opt-in kill switch, off by default.
  `includeAllNetworks` and `excludeLocalNetworks` (default true) travel in the
  provider configuration and start options with the other tunnel settings.
  While the setting is off, the saved `NETunnelProviderProtocol` does not have
  `includeAllNetworks`, `excludeLocalNetworks`, `excludeAPNs`,
  `excludeCellularServices` or `enforceRoutes` assigned. While it is on, the
  client sets those flags on the protocol it saves: all networks into the
  tunnel, LAN excluded unless the second option is turned off, APNs and
  cellular services excluded on iOS 16.4+ and macOS 13.3+, and `enforceRoutes`
  on iOS and macOS. tvOS cannot apply the flags. This is not a lockdown across
  quit or reboot.
- Android: `XrayVpnService.onRevoke()` stops the core with the same
  `stopXrayTunnel()` path an explicit stop uses, then reports `"revoked"`
  through `onXrayTunnelStopped` and `XrayVpnRuntimeSnapshot.stopReason`.
  The snapshot also exposes `isAlwaysOn` and `isLockdownEnabled` on API 29+,
  and null on older releases. The library does not install its own firewall;
  always-on and lockdown remain the system VPN toggles.
