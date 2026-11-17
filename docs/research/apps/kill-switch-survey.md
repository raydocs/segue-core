# Kill switch: how serious VPN apps build it, and where Segue stands

Engineering study, 2026-11-17. Scope: the kill-switch / leak-protection design of
Mullvad, Proton VPN, the official WireGuard apps and IVPN, per operating system,
compared against Segue's own prior product (Tono) and against
`crates/segue-kernel/src/killswitch.rs` in this repository.

Everything about the other apps below was read from the clones in the table, not
from memory. Citations are `path:line` relative to the clone named in the same
sentence or table row; where a paragraph cites several files from one clone, the
clone is named once and the paths are relative to it. Anything I could not confirm
in code is marked **unverified**.

## Sources

| Clone | Revision | Date | Notes |
| --- | --- | --- | --- |
| `/Volumes/dev/ref/apps/mullvadvpn-app` | `7e0e4413ce79491fb6aa619b7d9e503552f0bc20` | 2026-11-17 | Rust `talpid-core` + `talpid-winfw`; Electron, Android, iOS in-tree. |
| `/Volumes/dev/ref/apps/proton-android` | `deb11fef4092a1ecfcf51a7d40bdece9eb4c3e5e` | 2026-10-22 | Current Android app. |
| `/Volumes/dev/ref/apps/proton-ios-mac-app` | `d851e0fd1bad01a103d65bf816f2acc99115ff35` | 2026-10-21 | Current iOS+macOS app (Swift). |
| `/Volumes/dev/ref/apps/proton-win-app` | `52b9967ae9b196117adce7a52774dc148672b72c` | 2026-11-13 | Windows app + callout driver. |
| `/Volumes/dev/ref/apps/proton-python-proton-vpn-killswitch-network-manager` | `e19a187e7f86d1d4f4edb022958ade131c5e251c` | 2024-09-26 | Linux NM kill switch (deprecated upstream). |
| `/Volumes/dev/ref/apps/proton-python-proton-vpn-killswitch-network-manager-wireguard` | `2b421f04843f419e1c7537d217dfa4882b0ff913` | 2024-09-26 | Same, WireGuard variant. |
| `/Volumes/dev/ref/apps/proton-ios` | `61d44b353075135c40ae43befdba8a29ec68fb3d` | 2021-08-03 | **Stale** (2021); used only for history. |
| `/Volumes/dev/ref/apps/proton-mac-app` | `0285a2a500adeed21629f43131724021c69ec6fd` | 2021-08-03 | **Stale** (2021, v1.9.3); pf-era. |
| `/Volumes/dev/ref/apps/wireguard-windows` | `6ece77bc487c8aa697e3c092197621c4f3e5ccb8` | 2026-09-22 | Shallow (30 commits). |
| `/Volumes/dev/ref/apps/wireguard-apple` | `2fec12a6e1f6e3460b6ee483aa00ad29cddadab1` | 2023-02-15 | Shallow; archived-era snapshot. |
| `/Volumes/dev/ref/apps/desktop-app` | `98b99f55614cd184f3e0a20e517235c2d03ed6bd` | 2026-11-16 | IVPN desktop (Go daemon, shell-script firewalls). |
| `/Volumes/dev/ref/apps/tono` | `006984ae211056ea2f921c93d0b6e74f6c7f3a5e` | 2026-11-09 | Private: macOS helper (Swift), Windows service (Rust). |

Clone depth is 30, so commit hashes are cited only in this table; in-tree history
older than the boundary is not searchable and is not claimed.

---

## 1. Mechanism per OS

### Summary table

| | macOS | Windows | Linux | iOS | Android |
| --- | --- | --- | --- | --- | --- |
| **Mullvad** | pf anchor `mullvad` | WFP: baseline + DNS + persistent sublayers | nftables `mullvad` (inet) | `NETunnelProviderProtocol.includeAllNetworks` (opt-in) + error-state tunnel | none of its own; `VpnService` routes + OS always-on/lockdown |
| **Proton** | `NE includeAllNetworks` + `NEFilterPacketProvider` (Advanced) | WFP + callout driver | NM dummy connection (deprecated plugins) | `includeAllNetworks` + zero-peer tunnel (Advanced) | OS always-on + lockdown only |
| **WireGuard** | none | WFP, dynamic session, opt-in | n/a in these repos | none | n/a |
| **IVPN** | pf anchor `ivpn_firewall` (shell script) | WFP provider `IVPN Kill Switch` | iptables/ip6tables chains `IVPN-*` | n/a in these repos | n/a in these repos |
| **Tono** | pf anchor `tono.killswitch` (Swift helper) | WFP single provider/sublayer `tono-kill-switch` | n/a | not in this clone | not in this clone |
| **Segue today** | *none* | *none* | *none* | NE full-tunnel routes + DNS anchor, **no IAC/enforceRoutes** | full-tunnel routes + DNS anchor, **no always-on awareness** |

### macOS

**Mullvad** — pf, anchored. Anchor name `"mullvad"`
(`talpid-core/src/firewall/macos.rs:24`). `apply_policy` = enable pf → add anchor
(Scrub/Filter/Nat) → `set_rules` in one transaction → flush PF states
(`talpid-core/src/firewall/macos.rs:79-95`; anchor kinds `:974-984`). The ruleset
ends in a `Drop::Return` outbound rule followed by an unconditional quick `Drop`
(`:234-245`) — fail-closed tail. A scrub rule makes pf filter reassembled packets
only (`:264-271`). PF keeps approved connection states forever, so the app kills
states on every transition except loopback, mDNS, LAN and the relay/tunnel
endpoints (`:97-213`). The 14.6 ≤ macOS < 15.1 workaround installs a NAT anchor and
`route-to` rules to force Apple services that bind sockets to the physical
interface back into the tunnel (`:26-45`, `:273-356`, `:445-459`).

**Proton** — two layers. The shared NE path sets
`protocolConfiguration.includeAllNetworks`
(`proton-ios-mac-app`, `libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/WireguardConfigurator.swift:94-98`).
For *Advanced* mode macOS adds a content-filter system extension,
`ProTUNPacketFilterProvider: NEFilterPacketProvider`
(`libraries/Core/NEProviders/Sources/ProTUNExtension/PacketFilter/ProTUNPacketFilterProvider.swift:25-47`),
installed with `filterPackets = true` and `grade = .firewall`
(`libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/PacketFilterConfigurator.swift:41-65`).
The packet filter starts from `.failClosed`
(`libraries/Core/NEProviders/Sources/ProTUNExtension/PacketFilter/PacketFilterCoordinator.swift:29-31`,
`.../PacketFilterPolicy.swift:49-50`). There is **no** pfctl and no privileged
helper on modern Proton macOS (grep for `pfctl`/`SMJobBless`/`AuthorizationRef`
returns nothing). The 2021 app was the opposite: a SMJobBless'd helper running
`pfctl -Fa -f ... -e` against the **main** ruleset, no anchor
(`proton-mac-app`, `ProtonVPN/FirewallManager.swift:435-477`,
`ProtonVPNNetworkHelper/CommandLineToolRunner.swift:150-153`).

**WireGuard** — nothing. `wireguard-apple` has no kill switch of any kind:
`generateNetworkSettings` emits only *included* routes and never excluded ones
(`Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift:77-128`), and the
provider only starts and stops the adapter
(`Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift:16-90`).

**IVPN** — pf anchor `ivpn_firewall` with sub-anchors and tables, driven by a shell
script the Go daemon invokes
(`desktop-app/daemon/References/macOS/etc/firewall.sh:22-27`, `:58-69`). Tail is
`block return out quick all` then `block drop quick all` (`:153-154`). pf is
enabled with a token stored in `State:/Network/IVPN/PacketFilter` so it can be
released with `pfctl -X` (`:157-165`).

### Windows

**Mullvad** — WFP in `talpid-winfw`. Fixed-GUID sublayers: `SUBLAYER_BASELINE`
(weight `u16::MAX`), `SUBLAYER_DNS` (weight −1), and `SUBLAYER_PERSISTENT`
(`talpid-winfw/src/guids.rs:20-21,71`; `talpid-winfw/src/objects.rs:30-55`;
`talpid-winfw/src/persistent.rs:52-60`). Block-all filters sit at the base weight;
every permit is a higher-weight filter (`talpid-winfw/src/rules.rs:179-214`,
permits at `:219,258,339,440,508,553,583,613,654,758,974`). On daemon exit while
blocked, ephemeral objects are replaced *in one transaction* with persistent,
boot-time block-alls (`talpid-winfw/src/persistent.rs:37-92`; four GUIDs at
`talpid-winfw/src/guids.rs:83-98`). Whether that persistence is kept is decided by
lockdown mode (`CleanupPolicy` at `talpid-winfw/src/lib.rs:240-250`, selected in
`talpid-core/src/firewall/windows/mod.rs:284-306`; `LockdownMode::should_persist`
at `talpid-core/src/firewall/mod.rs:293-301`).

**Proton** — WFP plus a callout driver (`ProtonVPN.CalloutDriver`) for DNS; blocks
on `AppAuthConnectV4/V6` with `SoftBlock`
(`proton-win-app`, `src/ProtonVPN.Service/Firewall/Firewall.cs:100-115`, `:674-717`).
Advanced mode writes into a **permanent** WFP session/sublayer
(`src/ProtonVPN.Service/Firewall/IpFilter.cs:30-36`, `:81-85`) so filters exist
before the service runs; the service sweeps leftover permanent filters on start and
rebuilds process permits (`src/ProtonVPN.Service/Firewall/Firewall.cs:79-98`,
`:308-314`).

**WireGuard** — WFP, dynamic session (`cFWPM_SESSION_FLAG_DYNAMIC`,
`tunnel/firewall/blocker.go:26-46`), provider/sublayer/filter GUIDs generated fresh
per enable (`tunnel/firewall/blocker.go:48-58`), sublayer weight `^uint16(0)` = max
(`:87-96`). Base is `blockAll` at weight 0 on all four ALE auth layers
(`:164`; `tunnel/firewall/rules.go:889-974`); permits: WireGuard service by
AppId+user (weight 15, `tunnel/firewall/rules.go:127-176`), DNS-restrict (14),
loopback (13), tunnel interface by LUID (12), DHCPv4/v6 and NDP (12)
(`tunnel/firewall/blocker.go:112-167`). Enabled only when the config is exactly one
peer with a `/0` AllowedIP and Table ≠ off (`tunnel/addressconfig.go:165-176`).
**Not persistent** — nothing survives reboot or crash; the session is dynamic and
no `FWPM_FILTER_FLAG_PERSISTENT` is used (constants defined but unused at
`tunnel/firewall/types_windows.go:184,368`).

**IVPN** — WFP provider/sublayer GUIDs fixed
(`desktop-app/daemon/service/firewall/firewall_windows.go:38-44`), weight `0xFFF0`
(`:298`), filter weights blockAll=2 … allowDNS=10
(`desktop-app/daemon/service/firewall/winlib/filter_cteation_helpers.go:34-47`). In
persistent mode it adds a **boot-time** block-all filter in addition to a
persistent one (`desktop-app/daemon/service/firewall/firewall_windows.go:326-337`,
`:394-405`).

### Linux

**Mullvad** — nftables, one table `mullvad` in family `inet`
(`talpid-core/src/firewall/linux.rs:63,146`), chains `input`/`output`/`forward`
(policy Drop), `prerouting`, `mangle` (route, mangle priority), `nat`
(`:64-69`, `:285-317`). Daemon-only traffic is matched by `meta skuid == 0`
(`:786-810`); split tunneling matches cgroupv2 or `net_cls` (`:354-382`). Boot
blocking is a separate oneshot unit ordered `Before=network-pre.target
mullvad-daemon.service` (`dist-assets/linux/mullvad-early-boot-blocking.service:10-17`),
which applies `FirewallPolicy::Blocked{allowed_endpoint:None}`
(`mullvad-daemon/src/early_boot_firewall.rs:16-30`).

**Proton** — no iptables/nftables at all. A *dummy NetworkManager connection* with a
low route metric captures traffic; a second IPv6 dummy (`ipv6leakintrf0`) handles
IPv6 leaks
(`proton-python-proton-vpn-killswitch-network-manager`,
`proton/vpn/killswitch/backend/linux/networkmanager/killswitch_connection_handler.py:110-200`).
"Permanent" means `save_to_disk=True` so NM recreates the connections at boot
(`:137`). Both plugins are deprecated upstream (`README.md:2`) in favour of
`python-proton-network-manager`.

**IVPN** — iptables/ip6tables, chains `IVPN-IN/OUT/FORWARD` and friends, terminal
`-j DROP` (`desktop-app/daemon/References/Linux/etc/firewall.sh:37-64`, `:258-260`).
No rule persistence; instead an in-process 60 s watchdog re-applies rules if a
distro boot wipes them
(`desktop-app/daemon/service/firewall/firewall_linux.go:96-139`). Note `:214-217`:
LAN allow is IPv4-only with an explicit TODO.

### iOS

**Mullvad** — `NETunnelProviderProtocol.includeAllNetworks` and
`excludeLocalNetworks` are set from settings
(`ios/MullvadVPN/TunnelManager/TunnelConfiguration.swift:21-26`), default **off**
(`ios/MullvadSettings/IncludeAllNetworksSettings.swift:47-52`), labelled "Force all
apps"
(`ios/MullvadVPN/Coordinators/Settings/IncludeAllNetworks/IncludeAllNetworksSettingsViewModel.swift:31`).
`enforceRoutes` is **not used anywhere** in the clone. Its always-on rule is an
unconditional `NEOnDemandRuleConnect` (`ios/MullvadVPN/TunnelManager/TunnelConfiguration.swift:28-33`).
Blocking states are implemented by installing an error-state tunnel config (empty
addresses/AllowedIPs, peer `127.0.0.1:9090`, DNS `127.0.0.1`)
(`ios/PacketTunnelCore/Actor/PacketTunnelActor+ErrorState.swift:118-143`), and a
failure to do so only logs "Traffic blocking may not be active" (`:135-141`).

**Proton** — same NE flag, plus an *Advanced* mode that (A) clears Apple's default
exclusions (`excludeCellularServices`, `excludeAPNs`, `excludeDeviceCommunication`)
(`proton-ios-mac-app`, `libraries/Shared/Connection/Sources/ConnectionShared/ProviderConfiguration+KillSwitch.swift:28-38`)
and (B) keeps a **zero-peer** tunnel running while "disconnected" so
`includeAllNetworks` keeps dropping everything
(`libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/WireguardConfigurator.swift:105-141`,
`:297`). The zero-peer cold-start config explicitly sets `isOnDemandEnabled = false`
(`:307`), so after a reboot nothing re-arms the blackhole until the app runs —
despite the UI string promising "across reboots"
(`libraries/Foundations/Strings/Sources/Strings/Strings.swift:758`).

**WireGuard** — none, as above.

### Android

**Mullvad** — no firewall of its own (`talpid-core/src/firewall/android.rs:1-27` is a
stub). It relies on `VpnService` routes `0/0`+`::/0` and, in blocking states,
installs a blocking tun config (`talpid-tunnel/src/tun_provider/mod.rs:114-157`);
`setBlocking(false)` is used, not lockdown (`android/.../TalpidVpnService.kt:116`).
Always-on and "Block connections without VPN" are Android system settings it only
explains (`android/lib/ui/resource/src/main/res/values/strings.xml:62-72`).

**Proton** — same model, even more explicit: it *reads* `service.isAlwaysOn` and
`service.isLockdownEnabled` and stores them for telemetry/UI
(`proton-android/app/src/main/java/com/protonvpn/android/vpn/wireguard/WireguardBackend.kt:158-170`),
and its "kill switch" screen is instructions to enable both system toggles
(`app/src/main/res/values/strings.xml:217-227`). Split-tunnel apps and LAN are not
reachable under lockdown, and the UI warns exactly that (`:228-230`).

---

## 2. Allowed exceptions

Paths in this table are relative to the clone named in the row.

| | loopback | DHCP | NDP/DHCPv6 | DNS | tunnel endpoint | LAN | captive portal |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Mullvad mac | `talpid-core/src/firewall/macos.rs:702-710` | 68→255.255.255.255:67 `:790-844` | RS/RA/NS/NA subset `:846-911` | all :53 dropped, then per-server tunnel/non-tunnel allows `:634-651` | relay IP+proto, root only `:594-610` | only with `allow_lan` `:712-739` | no dedicated rule (unverified) |
| Mullvad win | permit weight class 7 `talpid-winfw/src/rules.rs:219` | `:258` | `:339` | DNS sublayer, separate `DnsPermit*` `:818-972` | `PermitEndpoint`, DNS sublayer if port 53 `talpid-winfw/src/lib.rs:190-202` | `:508,553` | none |
| Mullvad linux | `talpid-core/src/firewall/linux.rs:497-509` | `:510-552` | `:553-620` | reject then per-server allows `:871-886` | fwmark path `:740-784` | by design not in table | none |
| Proton mac | always `libraries/Core/NEProviders/Sources/ProTUNExtension/PacketFilter/PacketFilterCoordinator.swift:99-101` | in: any, out: local net `.../PacketFilterPolicy.swift:107-110` | hop-limit 255, local scope `.../PacketFilterPolicy.swift:111-115` | `matchDomains = [""]` `libraries/Core/NEProviders/Sources/ProTUNExtension/Settings.swift:35-36` | excluded routes + allow `.../PacketFilterPolicy.swift:129-140` | `excludeLocalNetworks` `libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/WireguardConfigurator.swift:95` | **none found** (grep `captive` = 0) |
| Proton win | `src/ProtonVPN.Service/Firewall/Firewall.cs:698-717` | `:498-528` | `:793-820` | NRPT or DNS callout `:385-420` | tunnel iface permit `:530-566` | only if LAN option `:778-820` | none |
| Proton linux (NM) | not explicit (guess: kernel routes) | **no permit** (guess, not in code) | separate IPv6 dummy | dummy DNS `0.0.0.0`/`::1` `proton/vpn/killswitch/backend/linux/networkmanager/killswitch_connection_handler.py:72-90` | all routes except server `:72-90` | none | none |
| WireGuard win | `permitLoopback` `tunnel/firewall/rules.go:261-280` | 68→67 broadcast `:359-397` | `permitNdp` `:586+` | all :53 denied, then configured servers `:977-1177` | tunnel service by AppId+user `:127-176` | **none** — LAN effectively blocked under `/0` `docs/netquirk.md:11-19` | none |
| IVPN mac | `daemon/References/macOS/etc/firewall.sh:137` | `:146-147` | DHCPv6 via inet6 rules | only configured servers `:336-363` | VPN iface + server IP `:214-215` | exception tables `:141-144` | none |
| IVPN win | `127.0.0.1/8`, `::1` `daemon/service/firewall/firewall_windows.go:408,340-350` | local port 68 `:433` | v6 link-local `:359-378` | port 53 blocked then allowed `:353,414-430` | dynamic permit on connect `:561-599` | opt-in ranges `:476-493` | none |
| IVPN linux | `daemon/References/Linux/etc/firewall.sh:212-213,293-294` | 67/68 `:297-298` | FE80::/10, FD00::/8 `:216-221` | configured servers `:653-675` | VPN interface `:487-499` | IP v4 only (TODO `daemon/service/firewall/firewall_linux.go:214-217`) | none |
| Tono mac | `tooling/scripts/core-helper/KillSwitchPF.swift:291` render | 67/68 | NDP rules inside `renderRules` | LAN 53/853 drop `:182-212` | relay permits by uid `:502-507` | `tono-lan` set excl. 53/853 | none (`docs/decisions/045-2026-10-02-macos-lan-discovery-pf.md`) |
| Tono win | intent floor `apps/windows/service/src/core/wfp_model.rs:280-300` | floor | floor | not permitted in WFP; DNS redirected to the TUN `apps/windows/service/src/core/dns/mod.rs:4-18` | weight-8 permit bound to pid+generation `wfp_model.rs:808`, `windows_kill_switch/state.rs:199-219` | LAN/discovery excl. 53/853 `wfp_model.rs:699-786` | RDP exception waits for proof `windows_kill_switch/state.rs:257-266` |

Two observations that hold across the board:

- **DNS is treated as a first-class leak channel, separately from "all traffic".**
  Every desktop implementation blocks port 53 *before* it allows LAN or the tunnel,
  then re-permits only named resolvers (Mullvad
  `talpid-core/src/firewall/macos.rs:377-379`, IVPN
  `daemon/References/macOS/etc/firewall.sh:336-363`, Tono
  `tooling/scripts/core-helper/KillSwitchPF.swift:193-212`). Mobile uses
  `matchDomains = [""]` or a TUN DNS anchor instead.
- **No product implements captive-portal detection in the firewall.** Search for
  `captive` in Proton macOS/Windows returns nothing; Mullvad's docs never mention
  it. Either the OS handles it or the user is simply blocked (unverified which).

---

## 3. States and what is blocked

| App | State model | Blocked in connecting | Blocked in connected | Blocked in reconnecting | Blocked in error | Blocked on user disconnect |
| --- | --- | --- | --- | --- | --- | --- |
| Mullvad | `Connecting`/`Connected`/`Disconnecting`/`Blocked` (`talpid-core/src/firewall/mod.rs:84-137`); desktop has **no** separate reconnecting state — a reconnect re-enters Connecting (`talpid-core/src/tunnel_state_machine/connected_state.rs:446`) | yes, except endpoints/LAN/DHCP | only non-tunnel | yes (Connecting) | yes (`talpid-core/src/tunnel_state_machine/error_state.rs:75-97` → `Blocked`) | only with Lockdown (`talpid-core/src/tunnel_state_machine/disconnected_state.rs:73-112`); otherwise rules removed |
| Proton mac/win | Connecting/Connected/Reconnecting/Disconnecting/Error; iOS keeps a `.reconnecting` state (`proton-ios-mac-app`, `ios/PacketTunnelCore/Actor/State.swift:29-34`) | yes (includeAllNetworks already in config) | no | yes | Advanced: fail-closed; Standard: NE | Advanced keeps blocking; Standard clears (`libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/WireguardConfigurator.swift:280-293`) |
| WireGuard win | firewall on from service start to service stop (`tunnel/service.go:190`) | yes | only non-tunnel | yes (same session) | crash = fail-open (dynamic WFP) | service stop removes filters (`tunnel/interfacewatcher.go:189`) |
| IVPN | state enum `CONNECTED/…/EXITING` (`daemon/vpn/types.go:66-78`), firewall enabled *before* connecting (`daemon/service/service_connect.go:948-958`) | yes | only non-tunnel | stays enabled (`daemon/service/service_connect.go:553`) | stays armed until explicit disconnect | released on disconnect unless persistent (`daemon/service/service_connect.go:649-657`; persistent cannot be disabled `daemon/service/service.go:826-828`) |
| Tono | Windows `Bootstrap`/`Locked`/`Blocked` (`apps/windows/service/src/core/structure.rs:592-600`); macOS standard vs strict | yes (floor) | only tunnel + DIRECT | yes | non-strict fails open after 3 watchdog ticks (`windows_kill_switch/policy.rs:40-56`); strict never | standard releases; strict ("permanent") does not (`apps/windows/service/src/core/macos_kill_switch.rs:614`) |
| Segue (`killswitch.rs`) | `Connecting/Connected/Reconnecting/Error/Disconnected` (`crates/segue-kernel/src/killswitch.rs:15-26`) | Proxy→`Refuse` (Strict) or `Wait` (Wait) | Proxied → `Proxy` | same as connecting | `Refuse` | `Release` |

Mullvad's own documentation draws the distinction most clearly, and it is worth
copying the vocabulary: *the kill switch is not a setting* — the connecting,
disconnecting and error states enforce it; the **Lockdown** setting only decides
whether the *disconnected* state blocks too (`docs/security.md:253-280`).

Segue's `Refuse`/`Wait` split is close to Mullvad's connecting policy for the AI
class and to Tono's AI hold, but Segue has one extra posture no surveyed app has:
`Verdict::Wait` — hold the flow, decide again when the posture changes
(`crates/segue-kernel/src/killswitch.rs:45-47`). None of the four apps do per-flow
waiting; they block or admit per packet rule.

---

## 4. Leak protection beyond "block everything"

- **DNS.** Desktop apps block :53 and re-permit named resolvers only (citations in
  §2). Tono additionally rewrites every network service's DNS to `127.0.0.1` after
  snapshotting the originals, and restores the snapshot on release
  (`tooling/scripts/core-helper/ProtectedDNSManager.swift:147-245`, `:277-352`).
  Segue's kernel answers DNS itself and refuses everything when no policy bundle is
  valid (`crates/segue-kernel/src/dns.rs:14-16`,
  `crates/segue-kernel/src/policy.rs:113-125`).
- **IPv6.** Mullvad and IVPN permit NDP/DHCPv6 explicitly rather than disabling
  IPv6; Proton macOS captures the default IPv6 route into the tunnel even with no
  IPv6 support "so it doesn't leak"
  (`proton-ios-mac-app`, `libraries/Core/NEProviders/Sources/ProTUNExtension/Settings.swift:48-53`).
  Proton Linux uses a separate IPv6 dummy interface
  (`proton/vpn/killswitch/backend/linux/networkmanager/killswitch_connection_handler.py:170-200`).
  Segue's Apple shell already routes both families into the tunnel with a comment
  saying why
  (`platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift:2401-2428`).
- **WebRTC/local.** No surveyed app does anything WebRTC-specific (grep across all
  clones). This is a browser-level problem, not a VPN one — but see Tono §8 for the
  LAN-discovery exception that made Tono's ruleset much larger.
- **Split tunnel.** Mullvad Windows enforces it with a kernel driver, not WFP
  (`talpid-core/src/split_tunnel/windows/service.rs:16-18`); Proton's Linux dummy
  connection has a "routed" mode that excludes the server IP from `0/0`
  (`proton/vpn/killswitch/backend/linux/networkmanager/killswitch_connection_handler.py:72-90`);
  WireGuard's kill-switch heuristic *disables itself* for multi-peer or non-`/0`
  configs (`tunnel/addressconfig.go:165-176`) — the honest choice, since a split
  route cannot be blocked without also blocking itself.

---

## 5. Boot-time blocking, crash behaviour, and fail-open vs fail-closed

This is where the products differ most, and where the honest answers are ugly.

| App | Before the daemon starts | Daemon crash | Reboot with rules installed |
| --- | --- | --- | --- |
| Mullvad win | persistent+**boottime** block-alls written on exit (`talpid-winfw/src/persistent.rs:37-92`) | rules live in BFE, survive process death | survive if lockdown persisted them |
| Mullvad mac | **nothing** — launchd cannot order before other services; documented leak window (`docs/known-issues.md:45-70`) | pf rules are kernel-resident and stay | pf rules do **not** survive reboot (`docs/known-issues.md:45-70`) |
| Mullvad linux | dedicated `mullvad-early-boot-blocking.service` before `network-pre.target` | nft rules stay; systemd restarts daemon in 1 s (`dist-assets/linux/mullvad-daemon.service:5-21`) | re-applied by the early unit |
| Proton win | permanent WFP session/sublayer (`src/ProtonVPN.Service/Firewall/IpFilter.cs:30-36`, `:81-85`) | Advanced: kernel filters persist; **Standard: fail-open** (`src/ProtonVPN.Service/Firewall/Firewall.cs:79-98`) | Advanced survives; leftover filters swept on start |
| Proton mac | none; NE on-demand only | Advanced: packet filter fail-closed + zero-peer retry loop (3×3 s, `libraries/Shared/Connection/Sources/Connection/ConnectionFeature.swift:312-341`) | Advanced zero-peer start sets `isOnDemandEnabled = false` (`libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/WireguardConfigurator.swift:307`) — **does not re-arm at boot until the app runs** |
| WireGuard win | none (dynamic session) | **fail-open** — filters vanish with the handle | none |
| IVPN win | boottime filter when persistent (`daemon/service/firewall/firewall_windows.go:330-337`) | fail-closed; WFP session opened non-dynamic (`daemon/service/firewall/winlib/manager.go:96`) | persists |
| IVPN mac | none (anchor loaded by daemon at start) | pf stays enabled via `pfctl -E` token | not persistent |
| IVPN linux | none; 60 s watchdog re-applies (`daemon/service/firewall/firewall_linux.go:120-139`) | rules stay | relies on service start |
| Tono mac | **deliberately none** — `/etc/pf.conf` declares the anchor only, no `load anchor from`, so Safe Mode does not load it (`tooling/scripts/core-helper/KillSwitchPF.swift:711-730`; `docs/decisions/034-2026-09-30-pf-conf-does-not-load-rules-at-boot.md`, `035-2026-09-30-boot-does-not-rearm-kill-switch.md`) | helper idle loop releases after ~30 s if the core is down (`tooling/scripts/core-helper/KillSwitchManager.swift:215,267`); hung helper = no release (`docs/findings.d/MAC-HELPER-HANG-WATCHDOG.md:3`) | **does not re-arm** (`docs/decisions/035-2026-09-30-boot-does-not-rearm-kill-switch.md:4`) |
| Tono win | persistent intent floor installed before legacy sweep, avoiding a zero-filter window (`windows_kill_switch/startup.rs:351-359`); restored `Locked` downgraded to `Blocked` (`:360-460`) | non-strict releases after 3 ticks; strict reinstalls (`windows_kill_switch/policy.rs:14-56`) | persistent floor survives |
| Segue | n/a — no OS firewall code in this repo | n/a | n/a |

The consensus is: **fail-closed while running, explicitly fail-open across boot on
macOS, and persistent-only if the user opted in.** Nobody claims to block before
launchd on macOS, because they can't, and Mullvad says so publicly
(`docs/known-issues.md:45-70`). Tono's ADR 035 makes the same call for a different
reason: without a user-visible strict mode, a leftover block would be an
unrequested lockdown (`docs/decisions/035-2026-09-30-boot-does-not-rearm-kill-switch.md:4`).

---

## 6. UI: how the products explain it

- Mullvad: a dedicated "Kill switch" page that says it *cannot be disabled*, plus a
  separate Lockdown setting described as "block the internet if you click Disconnect
  or Quit"
  (`desktop/packages/mullvad-vpn/src/renderer/components/views/kill-switch/KillSwitchView.tsx:17-65`,
  `desktop/packages/mullvad-vpn/src/renderer/features/tunnel/components/lockdown-mode-setting/LockdownModeSetting.tsx:32`).
  Status label "BLOCKED CONNECTION"/"FAILED TO SECURE CONNECTION"
  (`desktop/packages/mullvad-vpn/src/renderer/components/views/main/components/connection-panel/components/connection-status/ConnectionStatus.tsx:53-56`).
  The changelog entry about it: "Update the Lockdown mode and Kill switch settings to
  better explain their purpose and where they intersect" (`CHANGELOG.md:50-51`) — a
  product admission that users confuse the two.
- Proton: Off / Standard / Advanced, with copy that distinguishes "disconnect you
  when the tunnel drops" from "block all internet when not connected"
  (`proton-ios-mac-app`, `libraries/Foundations/Strings/Sources/Strings/Strings.swift:820-832`)
  and an explicit warning "Internet stays blocked across reboots and intentional
  disconnects until you turn it off" (`:758`) — which the code contradicts for the
  reboot case (see §5).
- WireGuard Windows: one checkbox, "Block untunneled traffic (kill-switch)", with a
  tooltip that spells out the exact heuristic (`ui/editdialog.go:132-133`). It is
  UI-only: it rewrites `0.0.0.0/0` into `/1`+`/1` so the service's `/0` heuristic
  does not fire (`ui/editdialog.go:184-281`).
- IVPN: "On-demand" vs "Always-on firewall", with the always-on copy explaining it
  starts at boot and stays active with the client closed
  (`desktop-app/ui/src/components/settings/settings-firewall.vue:35-40`).
- Android (both Mullvad and Proton): the "kill switch" screen is step-by-step
  instructions to enable the two system toggles
  (`proton-android/app/src/main/res/values/strings.xml:217-227`;
  `mullvadvpn-app android/lib/ui/resource/src/main/res/values/strings.xml:62-72`),
  with a warning that lockdown also blocks split apps and LAN.
- Tono: `Leak protection: Bootstrap/Locked/Blocked`, `Protected, not connected`,
  `Kill Switch is blocking direct Internet from an earlier session`
  (`apps/windows/app/src/locales/en/tono.json:375-380`, `:346`, `:371-372`;
  `apps/macos/Tono/Localizable.xcstrings:3505,3535`).

---

## 7. Known bugs and CVEs (what the clones actually contain)

No CVE identifiers exist in the WireGuard or IVPN trees; both maintainers document
issues instead of CVEs. What is there:

| Item | Where |
| --- | --- |
| CVE-2025-46351: macOS uninstall left a launch daemon → local privilege escalation (fixed) | `CHANGELOG.md:606-609` (mullvadvpn-app) |
| CVE-2019-14899: tunnel IPv6 address detectable on LAN; ARP/tunnel-IP hardening | `CHANGELOG.md:1971-1975` (mullvadvpn-app); `talpid-core/src/firewall/linux.rs:180-197,937-945` |
| TunnelVision (CVE-2024-3661) / TunnelCrack LocalNet (CVE-2023-36672, -35838): iOS leaks to a local attacker's network unless `includeAllNetworks` is on; Mullvad cannot enable it by default because of iOS update bugs | `mullvadvpn-app docs/known-issues.md:73-102` |
| macOS boot leak window (launchd cannot order Mullvad before other services); disclosed in the 2022 audit | `mullvadvpn-app docs/known-issues.md:45-70` |
| Android leaks during tunnel reconfiguration, including with "Block connections without VPN" on (OS bugs, no known mitigation) | `mullvadvpn-app docs/known-issues.md:105-176` |
| Android LAN broadcast/multicast bypasses the VPN | `mullvadvpn-app docs/known-issues.md:135+` |
| PF approved states outlive rule removal → must flush states on every transition (fixed) | `CHANGELOG.md:913` (mullvadvpn-app); `talpid-core/src/firewall/macos.rs:97-213` |
| macOS 14.6–15.1 Apple services bind to the physical interface and bypass the tunnel (NAT workaround) | `mullvadvpn-app talpid-core/src/firewall/macos.rs:26-45` |
| Windows permanent filters left over after downgrading from Advanced are wiped by `DestroyAllFilters()` | `proton-win-app src/ProtonVPN.Service/Firewall/Firewall.cs:186-196` |
| Linux Ubuntu 24.04 + `ipv6.disabled=1`: the NM kill-switch backend does not work, logged only | `proton-python-proton-vpn-killswitch-network-manager proton/vpn/killswitch/backend/linux/networkmanager/nmkillswitch.py:105-127`, `.../util.py:28-41` |
| IVPN: 3.15.13 "Firewall: fixed transaction abort and filter ordering"; 3.15.0 "Hardened firewall rules to prevent DNS leaks"; 3.11.14 "Firewall occasionally OFF after autoconnect"; 3.10.14 "boot-time firewall rules"; 3.9.0 "DNS leak via link-local IPv6"; 3.7.0 "Vulnerability fixes" | `desktop-app/CHANGELOG.md:61,132,414,519,720,804` |
| WireGuard Windows: Hyper-V permit disabled ("if somebody complains, try enabling it"); NDP validation looser than the commented spec | `wireguard-windows tunnel/firewall/blocker.go:156-162`, `tunnel/firewall/rules.go:587-593` |
| WireGuard UI kept a stale kill-switch checkbox state when `Table = off` was added | commit `30027bd` in the clone's history ("ui: update the blocking state when Table is off") |

The pattern in every changelog is the same three failure classes: **rule-ordering
mistakes** (DNS blocked after LAN was allowed, or vice versa), **stale state**
(PF states, leftover persistent filters), and **boot/reboot gaps**. None of the
four apps solved boot blocking on macOS, and the only ones that solved it on
Windows did so with permanent WFP filters.

---

## 8. Tono

Tono is the closest thing to a design document for what Segue's shell should look
like, and it is the only surveyed product that separates **intent** (persisted),
**state** (live), and **rules** (rendered) into distinct modules.

- **Windows WFP.** One provider and one sublayer (`tono-kill-switch`, weight 1000),
  all rules weighted inside it: hard permit 8, infra 7, core-LAN block 6, LAN permit
  4, block-all 1 (`apps/windows/service/src/core/wfp_model.rs:47-66`). The *intent
  floor* — loopback, DHCPv4/v6, NDP — is persistent, over persistent block-alls on
  all four ALE layers (`wfp_model.rs:280-300`); session rules are never persistent
  (`wfp_model.rs:1056-1060`). The tunnel permit is bound to the core's
  `(pid, generation)` and retracted on replacement or LUID reuse
  (`windows_kill_switch/state.rs:199-219`) — a defence nobody else in this survey
  has.
- **macOS PF.** Anchor `tono.killswitch`; `/etc/pf.conf` gets the anchor
  *declaration only*, never `load anchor from`, so Safe Mode does not arm the block
  (`tooling/scripts/core-helper/KillSwitchPF.swift:19`, `:711-730`). Rules end in
  `block drop out quick all`; LAN discovery is narrowed to IGMP, `224.0.0.0/24`,
  limited broadcast and SSDP `239.255.255.250:1900`, with DNS on those ranges
  dropped (`docs/decisions/045-2026-10-02-macos-lan-discovery-pf.md`).
- **Routing coupling.** Tono's three-tier router (`three-tier`/`ai-home`/`stable`)
  determines what the firewall may permit; DIRECT tuples and root-only 80/443
  permits are rendered *only while `Locked` with a live tunnel*
  (`apps/windows/service/src/core/wfp_model.rs:20-25`, `:935-1030`). This is the
  opposite of Segue's kernel, where the rule table exists but the *shell* has no OS
  firewall to render it into.
- **Fail-open by default, fail-closed on request.** Crash/hang/unreadable state
  releases; non-strict unhealthy waits 3 ticks then releases; strict reinstalls
  forever (`windows_kill_switch/policy.rs:14-56`, `windows_kill_switch/watchdog.rs:221-260`).
  After release it tries a narrow AI-only hold first
  (`windows_kill_switch/disarm.rs:123-128`,
  `docs/decisions/031-2026-09-30-fail-open-keeps-ai-block.md`) — the same "AI
  traffic must not leak to the real address" idea as Segue's `Protection::Strict`.
- **DNS.** macOS rewrites every service to `127.0.0.1:53` after snapshotting,
  restores the snapshot on release
  (`tooling/scripts/core-helper/ProtectedDNSManager.swift:147-245`, `:277-352`);
  Windows writes an NRPT catch-all to the TUN-side `198.18.0.2`, empties the IPv6
  static list, and pins DoH off (`apps/windows/service/src/core/dns/mod.rs:1-64`).
- **Documented gaps.** No user-facing macOS strict switch; boot does not re-arm
  (`docs/decisions/035-2026-09-30-boot-does-not-rearm-kill-switch.md`); a "short gap
  after boot" before `/etc/pf.conf` is migrated
  (`docs/decisions/034-2026-09-30-pf-conf-does-not-load-rules-at-boot.md:5`); DNS is
  not held at `127.0.0.1` when the core is dead because PF is not confirmed live
  (`docs/decisions/035-2026-09-30-boot-does-not-rearm-kill-switch.md:4`); a hung helper is unrecoverable
  (`docs/findings.d/MAC-HELPER-HANG-WATCHDOG.md:3`); corrupt WFP releases after ~3 s
  unless strict (`docs/decisions/027-2026-09-30-windows-corrupt-wfp-releases.md:3-5`);
  AI traffic can still reach the real address in the fail-open window
  (`docs/decisions/030-2026-09-30-exhausted-recovery-fails-open.md`, `031-2026-09-30-fail-open-keeps-ai-block.md`,
  `036-2026-09-30-crash-hang-releases-then-ai-layer.md`); the macOS control-plane
  permit is a **UID**, not an app boundary
  (`tooling/scripts/core-helper/KillSwitchPF.swift:520-540`,
  `docs/decisions/086-2026-10-10-h1f5-control-window.md:4`).

Lessons worth taking: the persistent floor + non-persistent session split, the
pid/generation tunnel permit, the "declaration only" pf.conf hook, and the explicit
ADR that says *why* boot does not re-arm.

---

## 9. Segue as it stands

`crates/segue-kernel/src/killswitch.rs` is a **pure state machine**: five postures
(`crates/segue-kernel/src/killswitch.rs:15-26`), six events, and a
`verdict(action, protection)` that is structural — no posture maps a proxied action
to `Direct` (`:109-134`). `hold_tunnel()` is true in every posture except
`Disconnected` (`:89-91`), which is what makes "only an explicit user disconnect
releases" testable (`:198-210`). The posture is driven from carrier outcomes in
`crates/segue-kernel/src/session/mod.rs` (`:584`, `:677`, `:816`, `:882-890`) and
projected to the UI as `connected`/`reconnecting`/`disconnected`
(`crates/segue-kernel/src/control.rs:73-83`).

That is a good core, and it is **ahead of the surveyed products in one respect**:
the `Strict` (AI) vs `Wait` (overseas) split, and `Verdict::Wait`, let a flow be
held across a reconnect instead of refused outright — no surveyed app does this
per-flow; they block at the packet rule layer.

The gaps are all on the shell side:

1. **`KillSwitch::verdict` has no callers.** Repo-wide grep: only the module and its
   own tests. `crates/segue-kernel/src/tun.rs` has its *own* `Verdict` enum
   (`:384`) and its own `policy()` (`:2431-2470`); nothing consults posture. The doc
   comment at `crates/segue-kernel/src/killswitch.rs:6` says "the shell that owns the
   tunnel interface reads `KillSwitch::hold_tunnel`" — that is a planned contract,
   not a fact.
2. **`Protection` has no producer.** `Protection::Strict`/`Wait` are chosen only in
   tests; the kernel's AI refusal is a hand-rolled check in the dialer
   (`crates/segue-kernel/src/session/mod.rs:672-682`, `exit_class == EXIT_AI && down`),
   not a call to `verdict`. The two can drift.
3. **`Verdict::Wait` has no implementation.** The "caller refuses when its own wait
   deadline passes" (`crates/segue-kernel/src/killswitch.rs:46`) does not exist
   anywhere: `crates/segue-kernel/src/tun.rs` maps `TcpRoute::Refuse` straight to a
   RST (`:2441`) and has no hold-then-decide path.
4. **No OS-level block outside the TUN.** Nothing in `crates/` or `platform/` touches
   pf, WFP, nftables, iptables, or launchd (grep: only
   `scripts/check-tproxy-linux.sh`, a CI test). So while Segue's process is running,
   unproxied traffic is protected only because the TUN holds the default route; when
   the app is not running, or between app start and tunnel establishment, **nothing
   is blocked**. Every one of the four products has at least a documented answer
   here, and Mullvad/IVPN/Tono have persistent rules on Windows and Linux.
5. **`includeAllNetworks` / `enforceRoutes` / Android always-on are absent.** Apple:
   the shell sets `includedRoutes = [default()]`, `excludedRoutes` for bootstrap
   endpoints, `matchDomains = [""]`, and does not touch `includeAllNetworks`
   (`platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift:2386-2436`);
   grep for `includeAllNetworks|enforceRoutes|excludeLocalNetworks` = 0 hits.
   On-demand is only *mirrored and restored*
   (`platform/apple/Sources/XrayAppleClient/XrayClientTunnelController.swift:195-217`),
   never enabled. Android: full routes + DNS anchor
   (`platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayVpnService.kt:973-980`,
   `:769`) and `protect(fd)` for outbound sockets
   (`platform/android/xraymobile/src/main/java/org/xrayrust/mobile/XrayCore.kt:1301`),
   but the service does not read `isAlwaysOn`/`isLockdownEnabled` and never sees
   `onRevoke` (only the test `devicehost` service overrides it,
   `platform/android/devicehost/src/main/java/org/xrayrust/devicehost/DeviceGateVpnService.kt:70-74`).
6. **Fail-closed policy exists but is only enforced in the kernel prototype.**
   `Policy::fail_closed()` refuses every flow including fake-IP
   (`crates/segue-kernel/src/policy.rs:111-125`,
   `crates/segue-kernel/src/tun.rs:2042-2072`), and the FFI plan puts the kill switch
   on the ABI (`docs/design/ffi-kernel-embedding.md:173`, `:209-229`, `:391`), but
   `crates/segue-ffi` has no kernel mode at all (`crates/segue-ffi/src` has only
   `lib.rs`, `profile_import.rs`, `tun_admission.rs`) and the capability bits stop at
   `1 << 30` (`crates/segue-ffi/include/segue_ffi.h:250`). So the kill switch does
   not ship to either mobile app today.
7. **Reserved destinations are refused but private/LAN traffic is not released.**
   `reserved_dst` refuses RFC1918, loopback, link-local, CGNAT and ULA inside the TUN
   (`crates/segue-kernel/src/tun.rs:531-570`). That is stricter than every surveyed
   app, which all permit LAN (Mullvad `talpid-core/src/firewall/macos.rs:712-739`,
   Proton `excludeLocalNetworks`, IVPN exception tables). It also means a LAN device
   is unreachable while Segue holds the tunnel, with no setting to change that.

---

## 10. What Segue should copy / avoid

Ranked, most valuable first.

### Copy

1. **Wire `verdict` into the data path and delete the duplicate decision.** Two
   independent AI-refusal implementations (`crates/segue-kernel/src/killswitch.rs:126-132`
   and `crates/segue-kernel/src/session/mod.rs:672-682`) is the exact failure mode
   Mullvad's and IVPN's changelogs are full of ("filter ordering", "transaction
   abort"). Make `TunKernel`/SOCKS ask `KillSwitch::verdict` and derive `Protection`
   from `exit_class`, so posture is the single source. Add the FFI test the design
   doc already asks for (`docs/design/ffi-kernel-embedding.md:555-560`).
2. **Tono's persistent floor / non-persistent session split, on Windows and Linux
   first.** Persistent block-alls + loopback/DHCP/NDP permits that exist before the
   service starts (`apps/windows/service/src/core/wfp_model.rs:280-300`,
   `talpid-winfw/src/persistent.rs:37-92`,
   `dist-assets/linux/mullvad-early-boot-blocking.service:10-17`), with everything
   else rendered only while a tunnel is live and bound to `(pid, generation)`
   (`windows_kill_switch/state.rs:199-219`). This is the only way to close gap 4, and
   it is a shell feature that does not change the kernel contract.
3. **Adopt Mullvad's vocabulary: "kill switch is not a setting; Lockdown is."**
   Segue's `Disconnected` ≈ Mullvad's disconnected-with-lockdown-off; `hold_tunnel`
   is the always-on part. Exposing `killswitch::Posture` to the UI already does most
   of this (`crates/segue-kernel/src/control.rs:73-83`); name the two things
   separately in the copy so the `Release` verdict is not mistaken for a failure.
4. **Turn on `includeAllNetworks` (and, where it exists, `enforceRoutes`) on iOS, and
   read Android's `isAlwaysOn`/`isLockdownEnabled`.** This is the cheapest real gain:
   Segue's Apple shell already builds a full tunnel and a DNS anchor; IAC adds the
   OS-level drop during connecting/error, which iOS currently does not get. Guard it
   behind a setting and copy Proton's `excludeAPNs`/`excludeCellularServices`
   handling from
   `libraries/Shared/Connection/Sources/ConnectionShared/ProviderConfiguration+KillSwitch.swift:28-38`,
   because IAC breaks notifications otherwise. On Android, implement `onRevoke` and
   surface lockdown state — Proton's
   `app/src/main/java/com/protonvpn/android/vpn/wireguard/WireguardBackend.kt:158-170`
   is nine lines.
5. **A tiny, testable rule-ordering invariant.** Mullvad, IVPN and Tono all encode
   "DNS drop before LAN allow before tunnel allow". Segue should have one function
   that renders (or checks) firewall rules in a fixed order with a unit test, so the
   shell cannot reorder them. Tono's `renderRules` and `wfp_model.rs` are the models.
6. **Persist and explain intent across restarts.** Tono's ADR 035 is the right
   precedent: if Segue has no user-facing strict mode, a leftover block after a crash
   is an unrequested lockdown. Decide this explicitly, in an ADR, before adding
   persistent rules.

### Avoid

1. **Do not copy WireGuard's `/0` heuristic.** `tunnel/addressconfig.go:165-176`
   silently disables the kill switch for multi-peer or split configs, and the UI
   compensates by rewriting `/0` into `/1`s (`ui/editdialog.go:184-281`). Segue's
   policy bundles are explicit about routes; a config-derived heuristic would be a
   silent fail-open.
2. **Do not copy Proton's "blocks across reboots" claim while the code sets
   `isOnDemandEnabled = false`** (`libraries/Foundations/Strings/Sources/Strings/Strings.swift:758`
   vs `libraries/Shared/Connection/Sources/ExtensionManager/Dependencies/WireguardConfigurator.swift:307`).
   If the boot behaviour is a gap, say so — Mullvad publishes its macOS boot leak
   (`docs/known-issues.md:45-70`) and that is the trust-preserving move.
3. **Do not build a UID-scoped control-plane permit.** Tono's own
   `docs/decisions/086-2026-10-10-h1f5-control-window.md:4` says the uid is not an app
   boundary (`tooling/scripts/core-helper/KillSwitchPF.swift:520-540`). Segue's AI
   strictness makes the same class of traffic security-relevant.
4. **Do not depend on PF state surviving rule edits.** Mullvad flushes states on
   every transition for a reason (`talpid-core/src/firewall/macos.rs:97-213`); a
   macOS shell that swaps rules without flushing leaves previously-approved
   connections running.
5. **Do not add a broad LAN exception by default.** All four apps permit LAN and all
   four then have to document LAN-related leaks (IVPN
   `daemon/service/firewall/firewall_linux.go:214-217`, Mullvad `CHANGELOG.md:97`,
   Tono `docs/decisions/045-2026-10-02-macos-lan-discovery-pf.md`). Segue's current
   `reserved_dst` refusal (`crates/segue-kernel/src/tun.rs:531-570`) is stricter; if a
   LAN setting is added, make it explicit and render it from the same ordered rule
   function.
