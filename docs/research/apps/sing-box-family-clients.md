# sing-box-family and multi-core client apps: how they embed a core

Engineering study, 2026-11-17. Scope: how seven client apps embed and drive a proxy core,
what their iOS NetworkExtension / Android VpnService / desktop-service structure looks like,
and what Segue Core should take from each. Every claim cites a file path in the read-only clone
it came from; the clone revision is given per app. Anything I inferred rather than read is
marked **GUESS**.

Sources (shallow clones, read-only, under `/Volumes/dev/ref/apps/`):

| Clone | Revision | Notes |
| --- | --- | --- |
| `sing-box-for-apple` | `768b3de2baf2` (v1.15.0-alpha.13) | Swift; SFI/SFM/SFT/SFM.System + extensions. |
| `sing-box-for-android` | `07376b138862` (v1.15.0-alpha.13) | Kotlin/Compose; `libs/libbox.aar`. |
| `hiddify-app` | `14f9eef699da` (5.9.8) | Flutter; iOS NE + Android VpnService + desktop. |
| `hiddify-core` | `a16860489374` | Go; gomobile AAR/xcframework + gRPC server + CLI. |
| `karing` | `178d4a0cb9b2` | Flutter; **materially incomplete clone** (see §Karing). |
| `NekoBoxForAndroid` | `5768494d8ae3` | Kotlin; `libcore` gomobile bind from a sing-box fork. |
| `v2rayN` | `f57b1bf47961` | .NET/Avalonia; cores as child processes, no VPN extension. |

Segue paths are relative to this repository at the start of this branch (`59d39b3a`).

---

## 1. Summary table

| | Core embedded as | iOS app↔extension | Android service | Desktop | Import formats | Update channel |
| --- | --- | --- | --- | --- | --- | --- |
| **sing-box-for-apple** | `Libbox.xcframework` (gomobile), linked in Xcode | `startVPNTunnel(options:)` carries `configContent`; `sendProviderMessage` for reload; `LibboxCommandServer` gRPC/loopback for status | — | macOS System Extension + root LaunchDaemon helper (`HelperService/`), or in-app extension | Full sing-box JSON only; `sing-box://import-remote-profile`, file/QR | GitHub `sing-box` releases, `.pkg`; stable/beta |
| **sing-box-for-android** | `libs/libbox.aar` | — | `VPNService` (tun) or `ProxyService` (no tun), chosen by `Libbox.hasTunInbound`; `CommandServer` for status | — | Full sing-box JSON; `decodeProfileContent` (old `.bpf`), QR/deep link | GitHub `sing-box` releases, F-Droid |
| **hiddify-app** | `hiddify-core` (own Go fork of sing-box) gomobile AAR/xcframework; app talks **gRPC** to it | Extension runs only the core's gRPC server; the **app** starts the core over gRPC; system-started tunnel starts it itself | `VPNService`/`ProxyService`; core in the same process; gRPC on 127.0.0.1 | `hiddify-core` dylib/FFI + elevated `admin_bgservice` (port 18020) | Shares (base64), clash, sing-box JSON; `profile-*` headers | GitHub releases API, self-install per `InstallKind`; Store |
| **Karing** | Forked sing-box `Libbox.xcframework` + `:libbox` AAR via a private `vpn_service` Flutter plugin | Opaque `LibVpnCore` framework (source gitignored); app-group **JSON files**, no provider messages seen | Service is inside the missing plugin; Dart only edits package lists | Separate privileged service exe (Linux `sudo`, Windows admin) | clash, sing-box, v2ray, ss, wireguard files; many schemes | Own `autoupdate.json` feed, beta/stable, self-update |
| **NekoBox** | `libcore.aar`, gomobile bind of `MatsuriDayo/sing-box` fork | — | `VpnService` (tun) / `ProxyService`; AIDL binder, `DefaultNetworkListener` actor | — | `sn://` universal links, clash YAML, base64 URI lists, per-protocol beans | GitHub releases **check only** (opens browser) |
| **v2rayN** | Child process per core (`xray`, `sing-box`, `mihomo`, …) | — | — | Windows/macOS/Linux; TUN via core's own tun inbound, needs admin/sudo; system proxy via registry/WinINet | base64 list, plain URIs, SIP008, WireGuard `.conf`, clash YAML, sing-box/Xray JSON | GitHub releases, external `AmazTool` replacer (no signature check) |

---

## 2. sing-box-for-apple (SFI/SFM)

### Core embedding

`Libbox.xcframework` is an Xcode framework reference (`sing-box.xcodeproj/project.pbxproj:555`,
linked at `:904`). There is no build script in the repo that produces it — it ships with the
release. Everything goes through the gomobile API (`LibboxSetup`, `LibboxNewCommandServer`,
`LibboxTunOptionsProtocol`, …).

### Extension structure

`Extension/PacketTunnelProvider.swift` is four lines (`class PacketTunnelProvider: ExtensionProvider {}`).
All behaviour is in `Library/Network/ExtensionProvider.swift` (`NEPacketTunnelProvider`
subclass, `:12`):

- `startTunnel(options:)` (`:133`) resolves the start options from the caller **or** a persisted
  snapshot file, `start_options.plist` (`:73`, `:89`, `Library/Network/ExtensionStartOptions.swift:4`).
  The snapshot is why a system-initiated start (on-demand) works with no app running.
- Setup is `LibboxSetupOptions` + `LibboxSetup` (`:177`–`:209`), then a `LibboxCommandServer`
  (`:217`). `startOrReloadService(configContent, …)` actually starts the proxy (`:269`–`:281`).
- `handleAppMessage` decodes start options, persists and reloads (`:352`–`:360`). So the app→extension
  control channel is: **config = `startVPNTunnel` options**, **reload = provider message + disk
  snapshot**, **status/logs/connections = command server**.
- `sleep()` calls `commandServer.pause()`, `wake()` calls `wake()` (`:364`, `:370`).

### TUN and NetworkExtension settings

`Library/Network/ExtensionPlatformInterface.swift:28`–`:222`:

- Builds `NEPacketTunnelNetworkSettings` from the core's tun options: MTU, DNS (with
  `matchDomains = [""]` when there is no default route so the DNS applies globally, `:163`–`:169`),
  v4/v6 addresses, included/excluded routes.
- `autoRouteUseSubRangesByDefault` splits the default route into 8 *sub-ranges* instead of
  `0.0.0.0/0` (`:77`–`:88`, `:132`–`:141`) — a well-known workaround so iOS treats the tunnel routes
  as "specific" rather than "default".
- `excludeDefaultRoute` appends `0.0.0.0/31` / `::/127` excludes (`:95`–`:100`, `:150`–`:156`);
  `excludeAPNsRoute` appends `17.0.0.0/8` and the proxy bypass `push.apple.com` (`:102`–`:107`,
  `:186`–`:192`).
- `includeAllNetworks` is reported to the core from the start-option override
  (`:409`–`:414`), and the real NE protocol flags are set app-side in
  `Library/Network/ExtensionProfile.swift:152`–`:166`: `includeAllNetworks`, `excludeLocalNetworks`,
  `enforceRoutes`, `excludeAPNs`, `excludeCellularServices`, `excludeDeviceCommunication`.
  Defaults differ per platform: `excludeLocalNetworks` is **true on iOS, false on macOS**
  (`Library/Database/SharedPreferences.swift:26`–`:36`), `excludeAPNs` true, `enforceRoutes` false.
- The TUN fd comes from KVC on the packet flow
  (`packetFlow.value(forKeyPath: "socket.fileDescriptor")`, `:211`), falling back to
  `LibboxGetTunnelFileDescriptor()` (`:216`).
- `clearDNSCache()` re-applies network settings with a nil settings round-trip (`:417`–`:436`).

### Memory under the extension limit

- The OOM killer is **always on for iOS/macOS app-extension builds** and configurable on macOS:
  `options.oomKillerEnabled = true` on `#else` (non-macOS) at `ExtensionProvider.swift:204`, and on
  macOS it is a user preference with a memory limit in MB (`:199`–`:202`; defaults
  `oom_killer_enabled=false`, `oom_memory_limit_mb=50`, `oom_killer_kill_connections=false` at
  `SharedPreferences.swift:60`–`:62`; UI `ApplicationLibrary/Views/Tools/OOMReportListView.swift:63`–`:77`).
- OOM and crash evidence is first-class: `LibboxPromoteOOMDraft()` is called after setup (`:213`)
  and again by the app after a disconnect (`ExtensionProfile.swift:79`–`:95`), and reports are
  surfaced by `OOMReportManager` (`Library/Shared/OOMReportManager.swift:30`) with per-report
  artifacts (config, Go log, profile).
- `HangWatchdog` samples the main thread and dumps goroutines (`Library/Shared/HangWatchdog.swift:15`
  onward); `NativeCrashReporter` is installed for both the extension and the root helper.

### On-demand and "always on"

- `makeDefaultOnDemandRules()` = one `NEOnDemandRuleConnect` with `probeURL http://captive.apple.com`
  (`ExtensionProfile.swift:120`–`:125`).
- "Always On" is just on-demand with the default rules; the model has three modes
  (`ApplicationLibrary/Views/Setting/OnDemandRulesView.swift:5`–`:8`): off, on-demand with custom
  rules, always-on. `start()` sets `isOnDemandEnabled = alwaysOn || onDemandEnabled`
  (`ExtensionProfile.swift:193`) — note `stop()` clears it and records `wasOnDemandEnabled`
  (`:292`–`:300`) so a user stop is not immediately undone by the system.
- Custom rules cover action, interface type, SSID, DNS search-domain/server match, probe URL and
  nested `NEEvaluateConnectionRule` (`Library/Network/OnDemandRule.swift:1`–`:236`).

### Other notable pieces

- Two macOS variants in one codebase: a regular app extension and a **System Extension** with a
  root LaunchDaemon helper (`SystemExtension/main.swift`, `HelperService/main.swift`); the app
  installs it via `OSSystemExtensionRequest` (`Library/Network/SystemExtension.swift:12`). The mach
  service name is version-suffixed on purpose, because launchd keeps the old version's endpoint
  (`Library/Shared/AppConfiguration.swift:39`–`:42`).
- Remote control of another device's SFM via `RemoteServer` + `LibboxNewRemoteCommandClient`
  (`Library/Network/ExtensionEnvironments.swift:329`–`:364`).
- Import is sing-box JSON only; the QR/deep link is `sing-box://import-remote-profile` parsed by
  `LibboxParseRemoteProfileImportLink` (`SFI/MainView.swift:558`–`:563`). Remote profiles are
  plain URLs with optional auto-update (`Library/Database/Profile+Update.swift:7`–`:29`).

---

## 3. sing-box-for-android (SFA)

### Core embedding and process model

`libs/libbox.aar` (`app/build.gradle.kts:187`–`:190`; a `libbox-legacy` variant for the
`otherLegacy` flavour). Everything runs in the app's own process inside a foreground service;
status flows over `LibboxCommandClient` (`app/src/main/java/io/nekohasekai/sfa/utils/CommandClient.kt:22`,
`:136` with a 1 s status interval).

Two service classes, chosen at start: `VPNService` when the selected config has a tun inbound,
`ProxyService` (plain foreground service, no tun) otherwise —
`Settings.kt:138`–`:165`, `Libbox.hasTunInbound(content)` at `:164`. Both delegate to
`BoxService` (`BoxService.kt:51`).

`BoxService.onStartCommand` (`:356`) is `START_NOT_STICKY`; it starts the `CommandServer`
(`:114`) and then `startOrReloadService(content, OverrideOptions)` with the auto-redirect flag and
the per-app include/exclude lists (`:152`–`:168`). A persisted `Settings.startedByUser` plus a
`BootReceiver` restart the service after boot (`bg/BootReceiver.kt:16`–`:33`), and crash-report
state can suppress that restart (`:25`–`:29`).

### VpnService

`app/src/main/java/io/nekohasekai/sfa/bg/VPNService.kt:58`–`:186`:

- `Builder().setSession("sing-box").setMtu(options.mtu)`; `setMetered(false)` on Q+ (`:60`–`:68`).
- `allowBypass()` only if the user enabled "Allow Apps to Bypass VPN" (`:70`, settings
  `database/Settings.kt:100`, UI `compose/screen/settings/ServiceSettingsScreen.kt:274`). There is
  **no** `setBlocking`/kill switch: SFA does not implement "block connections without VPN" itself —
  that is the system always-on setting, and SFA's manifest does not advertise
  `SUPPORTS_ALWAYS_ON` (verified absent in `app/src/main/AndroidManifest.xml`).
- Routes: on Tiramisu+ the core's exact prefixes plus `excludeRoute(...)` for the core's excludes
  (`:94`–`:121`); below that the older `inet4RouteRange` (`:123`–`:138`).
- Per-app: `addAllowedApplication` / `addDisallowedApplication` from the core's options
  (`:140`–`:163`); the lists themselves are assembled app-side in `BoxService` from preferences,
  always adding the app's own package for the include case (`BoxService.kt:154`–`:166`).
- System HTTP proxy via `setHttpProxy(ProxyInfo.buildDirectProxy(...))` on Q+ (`:167`–`:178`).
- The fd is `builder.establish()`, stored on the service (`:184`–`:186`).

### Network changes and idle

- `DefaultNetworkListener.kt:192`–`:230`: an actor over `ConnectivityManager` callbacks; on API 31+
  `registerBestMatchingNetworkCallback`, 28–30 `requestNetwork`, 26–27
  `registerDefaultNetworkCallback` (the comment at `:183` explains why the VPN interface would
  otherwise be reported as the default network). `DefaultNetworkMonitor.kt:14`/`:26` start/stop it.
- Doze: `ACTION_DEVICE_IDLE_MODE_CHANGED` → `commandServer.pause()/wake()` through a channel
  (`BoxService.kt:84`–`:92`, `:279`–`:284`).

### Import and update

- Import accepts a file (JSON config imported directly, or the older `Libbox.decodeProfileContent`
  `.bpf`), a QR code, `sing-box://import-remote-profile`, and URLs
  (`compose/screen/configuration/ProfileImportHandler.kt:44`–`:120`).
- Update: GitHub `SagerNet/sing-box` releases, stable=`/latest`, beta=`?per_page=3`
  (`app/src/github/.../GitHubUpdateChecker.kt:17`, `:32`–`:33`), or F-Droid
  (`update/FDroidUpdateChecker.kt:22`).

---

## 4. Hiddify (app + core)

This is the most architecturally different of the group: the core is a **separate Go project**
(`hiddify/hiddify-core`, a fork of sing-box, `go.mod:32` `github.com/sagernet/sing-box v1.13.0`)
exposing both gomobile bindings and **its own gRPC service**.

### Core embedding

- Android: `gomobile bind -androidapi=21 -javapkg=com.hiddify.core -libname=hiddify-core` over
  `.../experimental/libbox ./platform/mobile` (`hiddify-core/Makefile:123`).
- iOS/macOS/tvOS: `gomobile bind -target ios,iossimulator,tvos,tvossimulator,macos -libname=hiddify-core`
  (`Makefile:126`); a separate `HiddifyTunnelCore` for the macOS tunnel (`:285`).
- Desktop: `-buildmode=c-shared` dylib/so/dll (`Makefile:272`–`:277`), loaded with `dart:ffi`
  (`hiddify-app/lib/hiddifycore/core_interface/core_interface_desktop.dart:3`, `:30`–`:60`).
- `platform/mobile/mobile.go:27`–`:70`: `Setup` stores device memory, calls `hcore.Setup` with a
  listen address and a mode; `Start`, `Stop`, `Close(mode)`, `Pause`, `Wake` are thin wrappers.
  `SetCoreStoppedListener` (`:68`) forwards a **core-stopped** callback to the platform.

### The app talks gRPC to its own core

- Ports: foreground 17078, background 17079 (`core_interface_mobile.dart:32`–`:33`); macOS 17080;
  desktop 17078. Two modes: `2` = gRPC background **with mTLS**, `4` = background insecure
  (`ios/.../ExtensionProvider.swift:79`, `android/.../BoxService.kt:209`–`:210`).
- mTLS identity is a client cert file in the shared base folder (`grpc/client.crt`), not a secret
  passed over the channel: `core_interface_mobile.dart:59`–`:70`, and the extension switches mode on
  the file's presence (`ios/.../ExtensionProvider.swift:69`–`:79`).
- Because the UI can be gone, the core has an explicit **self-stop notification** path:
  `v2/hcore/core_stopped.go:14`–`:31` (`SetCoreStoppedHandler`, called on its own goroutine), and
  both platforms tear the tunnel/service down when it fires
  (`android/.../BoxService.kt:316`–`:330`, `ios/.../ExtensionProvider.swift:179`–`:189`).

### iOS extension

`ios/HiddifyPacketTunnel/SingBox/ExtensionProvider.swift`:

- On `startTunnel`, it **does not start the core**. It creates directories, runs `MobileSetup` with
  the gRPC listen address, installs the stopped-listener and sets `LibboxSetMemoryLimit(true)`
  (`:72`–`:92`). The app then calls `MobileStart` over gRPC.
- If the system started it (`options == nil`, i.e. always-on or the Settings switch), it calls
  `MobileStart("", "")` itself, which makes the core replay the last start request it persisted
  (`:94`–`:102`). That is the same "persisted last request" idea as sing-box-for-apple's
  `start_options.plist`, but persisted **inside the core**.
- `stopService` closes both modes and clears the listener (`:141`–`:147`); `reloadService` only
  toggles `reasserting` because the app does the restart over gRPC (`:149`–`:155`).
- `sleep()` deliberately does nothing — the comment says pausing broke reconnects after wake (`:169`).
- `openTun` is a near copy of sing-box-for-apple's, including the sub-range routes and
  `socket.fileDescriptor` KVC (`ExtensionPlatformInterface.swift:24`–`:236`), and `includeAllNetworks`
  from override preferences (`:405`–`:412`).

### iOS app side

`ios/Runner/VPN/VPNManager.swift`: `NETunnelProviderManager` loaded once (`:96`–`:110`); always-on is
`NEOnDemandRuleConnect` with the captive-portal probe (`:135`–`:155`); it refuses to enable on-demand
while disconnected so the system does not connect on its own (`:147`–`:153`); `disconnect` clears
on-demand first, then `stopVPNTunnel` (`:252`–`:262`). Traffic stats still use
`sendProviderMessage("stats")` (`:205`–`:228`), answered by `PacketTunnelProvider.swift:36`–`:37`.

### Android service

- Manifest declares `SUPPORTS_ALWAYS_ON=true` for the VPN service
  (`android/app/src/main/AndroidManifest.xml:148`–`:150`).
- Always-on is detected by the intent action being `VpnService.SERVICE_INTERFACE`
  (`bg/VPNService.kt:35`–`:41`); the service is told whether to start the core by
  `EXTRA_START_CORE`, defaulting to true when absent (`BoxService.kt:114`–`:123`, `:396`).
- `openTun` retries `prepare()` for up to 1 s (`VPNService.kt:91`–`:101`) — a real-world fix for a
  revoke race — and otherwise mirrors sing-box-for-android.
- Per-app proxy is applied in the service from preferences, and the app always excludes itself in
  exclude mode (`VPNService.kt:182`–`:207`).
- Teardown is one path: `teardown()` closes TUN, clears the listener, closes every gRPC mode it may
  have started, then stops the network monitor (`BoxService.kt:354`–`:380`). The comment at `:369`–`:372`
  records a bug worth copying the fix of: closing only the insecure mode left 17079 listening.
- Memory: `DeviceMemory` gives the core a quarter of total RAM (not the Java heap class) and marks
  low-memory devices under 2.5 GiB (`utils/DeviceMemory.kt:18`–`:47`). The core then calls
  `libbox.SetMemoryLimit` on non-iOS (`hiddify-core/v2/hcore/start.go:274`) and is always on for iOS.

### Desktop

`core_interface_desktop_tun.dart:25`–`:56`: Windows/Linux run the full core in an elevated
`admin_bgservice` on port 18020 (`hiddify-core/v2/hcore/admin_bgservice.go:21`), decided by
`NeedAdminBgService` (`:31`); Linux elevates via pkexec, else sudo with an askpass dialog or in a
terminal (`admin_bgservice_elevate_linux.go:39`–`:77`). Flutter itself never elevates.

### Import and update

- Link schemes: `hiddify, v2ray, v2rayn, v2rayng, clash, clashmeta, sing-box`
  (`lib/utils/link_parsers.dart:17`–`:45`).
- Subscription handling is header-driven (`lib/features/profile/data/profile_parser.dart:68`–`:79`):
  `profile-title`, `content-disposition`, `subscription-userinfo`, `profile-update-interval`,
  `support-url`, `profile-web-page-url`, plus vendor extensions. Base64 payloads are decoded with a
  safe decode (`:351`).
- Update: GitHub releases API (`lib/core/model/constants.dart:9`), installed according to how the
  app was installed — APK, setup exe, deb, AppImage (`lib/features/app_update/model/install_kind.dart:8`–`:56`).

---

## 5. Karing

**Caveat: the clone is incomplete.** The gomobile glue is gitignored: `bind/apple/` (`.gitignore:60`),
`android` core module `bind/android/core` (`.gitignore:61`), and the `vpn_service` Flutter plugin is
a `path: ../vpn-service/` override outside the repo (`pubspec.yaml:177`). Claims about the service
and the Apple wrapper are therefore mostly **GUESS** from call sites.

Readable facts:

- iOS/macOS/tvOS link `Libbox.xcframework` from `../bind/apple/` (forked sing-box;
  `ios/Runner.xcodeproj/project.pbxproj:133`), pinned core version `1.14.0`
  (`lib/app/modules/setting_manager.dart:1663`, also used as the advertised UA `:1686`).
- The tunnel is `class PacketTunnelProvider: ExtensionProvider {}` in its own `LibVpnCore`
  framework (`ios/karingService/PacketTunnelProvider.swift:1`–`:3`).
- App↔extension transport: app-group files (`service.json`, `service_core.json`, `settings.json`,
  `service_core.log` under `group.com.nebula.karing`'s Caches) plus a tvOS HTTP server on port 4040
  (`tvos/Runner/DashboardView.swift:36`–`:45`, `:248`–`:281`); no `sendProviderMessage` or gRPC call
  appears anywhere in the clone (**GUESS**: control travels through the `vpn_service` plugin).
- Schemes imported: `clash://install-config`, `sing-box://import-remote-profile`,
  `karing://install-config|connect|disconnect|reconnect` (`lib/screens/scheme_handler.dart:20`–`:30`).
- Android has a `:libbox` Gradle module (`android/settings.gradle.kts:27`) and a Dart plugin
  `vpn_service` (`pubspec.yaml:131`).
- macOS ships both an app extension and a system extension; the app entitlement declares
  `packet-tunnel-provider-systemextension` + `com.apple.developer.system-extension.install`
  (`macos/Runner/Runner.entitlements`).
- All the same NE knobs are exposed in a TUN sheet — `includeAllNetworks`, `excludeLocalNetworks`,
  `excludeCellularServices`, `excludeAPNs`, `excludeDeviceCommunication`, `enforceRoutes`
  (`lib/screens/group_helper.dart:532`–`:605`), persisted in `SettingConfigItemTUN`
  (`setting_manager.dart:527`–`:533`). Where they are applied to `NETunnelProviderProtocol` is not
  in the clone (**GUESS**: in `LibVpnCore`).
- Per-app proxy on Android is only a package-list screen in Dart (`lib/screens/perapp_android_screen.dart:22`);
  the `Builder` calls are in the plugin (**GUESS**).
- Onboarding is a real wizard: agreement → language → region → diversion preset → novice screen
  (`lib/screens/home_screen.dart:392`, `:433`–`:575`, `NoviceScreen` at `:546`–`:548`), then it
  opens "add profile" and, on desktop, a tutorial webview (`:560`–`:575`).
- Update: own feed `https://dot.karing.app/autoupdate.json` (`lib/app/modules/remote_config.dart:83`),
  channels stable/beta, self-installs apk/exe/pkg/deb with the user's sudo password where needed.
- No kill switch, no `NetworkCallback`/`NWPathMonitor` subscription in the readable code — network
  changes are left to the core (**GUESS** that the plugin handles them).

Karing's distinctive choice versus sing-box-for-apple: it hides the whole extension layer in a
shared framework used by iOS/macOS/tvOS, and drives it from the UI through its own plugin and
app-group JSON files rather than a command server.

---

## 6. NekoBox for Android

- Core: own Go module `libcore/` bound with `gomobile-matsuri bind` into `app/libs/libcore.aar`
  (`libcore/build.sh:17`–`:23`), built against a local sing-box fork
  (`libcore/go.mod:13`, `replace github.com/sagernet/sing-box => ../../sing-box` at `:87`).
- Config is generated in Kotlin from per-protocol "beans" into a sing-box JSON
  (`fmt/ConfigBuilder.kt:62`–`:63`, DNS at `:136`–`:177`, `:633`), so imports never have to be
  sing-box JSON.
- Two services over one `BaseService` state machine (`bg/BaseService.kt:29`): `VpnService`
  (`bg/VpnService.kt:21`) and `ProxyService` (`bg/ProxyService.kt:9`); the same
  `START_NOT_STICKY` start/stop/state-broadcast logic is shared (`BaseService.kt:312`–`:402`).
- VpnService (`VpnService.kt:89`–`:209`): fixed private VLAN addresses (`:26`–`:30`) rather than
  core-provided ones, `bypassLan` adds the private routes (`:108`–`:122`), per-app include/exclude
  with a `needBypassRootUid` special case for fake-TCP hysteria (`:138`–`:189`), optional
  `setHttpProxy` to its own mixed port (`:191`–`:193`), and `setUnderlyingNetworks` so the VPN never
  becomes its own upstream (`:202`–`:210`).
- Network changes: `DefaultNetworkListener` (same actor pattern as sing-box,
  `utils/DefaultNetworkListener.kt:20`), consumed in `preInit` where an interface-name change
  triggers `Libcore.resetAllConnections(true)` if enabled (`BaseService.kt:275`–`:292`,
  `DataStore.kt:92`). No blocking/kill switch: `onRevoke` just stops (`VpnService.kt:211`).
  `allowBypass`/`setBlocking` are absent. `SUPPORTS_ALWAYS_ON` is absent from the manifest, and
  "persist across reboot" is a `BootReceiver` that is disabled by default
  (`AndroidManifest.xml:330`–`:331`, `BootReceiver.kt:30`–`:40`).
- Imports: `sn://` universal (zlib+base64 Kryo) for single nodes and whole groups
  (`fmt/UniversalFmt.kt:7`–`:37`); clash YAML, base64 URI lists and plain lists in
  `group/RawUpdater.kt:230`, `:698`–`:706`; per-protocol parsers under `fmt/`.
- Update: GitHub release **check only** — it compares the release name and opens the browser
  (`ui/AboutFragment.kt:214`–`:247`).

---

## 7. v2rayN

- Not an embedded core at all: a manager that generates config and **launches each core as a child
  process**. Core table with exes, argument templates and download URLs per OS/arch:
  `ServiceLib/Manager/CoreInfoManager.cs:97`–`:292` (Xray `run -c {0}`, sing-box `run -c {0}
  --disable-color`, mihomo `-f {0}`). Supported cores: `ServiceLib/Enums/ECoreType.cs:3`–`:21`.
- Launch: `CoreManager.cs:360`–`:386` (`ProcessService` with `UseShellExecute=false`, stdout/stderr
  redirected into the log), Windows child processes joined to a Job object so the core dies with the
  GUI (`:391`–`:402`). Linux/macOS TUN needs root: a generated `run_as_sudo.sh` piped into
  `sudo -S` (`Manager/CoreAdminManager.cs:32`–`:70`).
- Control plane is HTTP, not gRPC: Xray `metrics.listen` scraped at `/debug/vars`, sing-box and
  mihomo via a Clash-compatible `external_controller` (`Singbox/SingboxStatisticService.cs:10`,
  `Manager/ClashApiManager.cs:11`). Ports are derived by offset from the SOCKS port
  (`AppManager.cs` — `socks + 4/+5`, and +1 for state when TUN is on).
- Desktop TUN uses the core's own tun inbound with `auto_route`/`strict_route`/`stack`
  (`Singbox/SingboxInboundService.cs:54`–`:85`); the system proxy is registry + WinINet on Windows
  (`Handler/SysProxy/ProxySettingWindows.cs:8`–`:25`) and shell scripts on Linux/macOS.
- Subscriptions: base64 list, plain URIs, SIP008, WireGuard `.conf`, clash YAML, sing-box/Xray JSON
  (`Handler/SubscriptionHandler.cs:247`, `Handler/Data/ConfigDbHandler.cs` import chain). Per-sub
  `User-Agent` defaulting to `v2rayN/<version>`, arbitrary headers, optional external converter
  (`&target=`) and extra sub URLs (`SubscriptionHandler.cs:137`–`:235`).
- Kill-switch analogue is TUN "strict route" plus a WFP block-leak rule, and a legacy "pre-SOCKS"
  sing-box side-core so the core's own traffic bypasses the TUN
  (`V2ray/V2rayInboundService.cs:93`, `Services/CoreConfig/Singbox/SingboxInboundService.cs`).
- Self-update replaces the running exe through a helper (`v2rayN/AmazTool/UpgradeApp.cs:9`); **no
  signature or checksum verification** in the updater.
- No onboarding wizard; first run just writes default config and shows "check server settings" when
  there is no node.

---

## 8. Cross-cutting observations

| Theme | What the group converges on | Outlier |
| --- | --- | --- |
| TUN fd | iOS: KVC `socket.fileDescriptor` (all sing-box-derived apps); Android: `Builder.establish()` | v2rayN: the core makes its own tun |
| Config handoff | Either bundled in start options with a **persisted snapshot** (SFI, Hiddify core) or read from a path in a shared folder (SFA, Karing, NekoBox) | Hiddify moves the *control* to gRPC |
| Status/UI data | Command-server (sing-box `LibboxCommandClient`), Clash API (v2rayN), or gRPC (Hiddify) | Karing: files |
| Default-route shape | Default route, with 8-sub-range split as an option (SFI, Hiddify) | NekoBox: fixed `/30` + private routes |
| Memory | iOS: always-on OOM killer; Android: voluntary device-RAM-derived limit | v2rayN: none (desktop) |
| Kill switch | None of the mobile apps implement one; they rely on OS always-on + `allowBypass`/`enforceRoutes` | v2rayN: TUN strict-route + WFP |
| Network change | An explicit `ConnectivityManager` callback actor (SFA, NekoBox, Hiddify) / `NWPathMonitor` (SFI) feeding the core | Karing: delegated to core |

---

## What Segue should copy / avoid

Ranked by value to Segue as it stands today (one Rust core over a C ABI, `xray_core_set_tun_fd`,
platform packages in `platform/apple` and `platform/android`).

1. **Already covered — the persisted start request on iOS; keep it that way.** sing-box-for-apple
   writes `start_options.plist` and falls back to it when `startTunnel` is entered with no options
   (`Library/Network/ExtensionProvider.swift:73`–`:110`); Hiddify keeps the last start request
   **inside the core** so the extension can start it alone
   (`ios/.../ExtensionProvider.swift:94`–`:102`). Segue already has the equivalent: the provider
   resolves the config reference from the start options **or** `providerConfiguration`
   (`platform/apple/Sources/XrayAppleTunnel/XrayPacketTunnelProvider.swift:1364`), with the config
   itself in a shared keychain group (`platform/apple/HostApp/PacketTunnel.entitlements:5`–`:8`).
   The one thing Segue lacks is Hiddify's *core-side* replay of the last request, which matters only
   if Segue ever moves config out of the keychain; no action needed today.
2. **Partly covered — widen the "engine is dead" latch from the TUN loops to the whole engine.**
   Hiddify added `SetCoreStoppedHandler` because, with the app closed, the tunnel stayed up with
   nothing behind it (`hiddify-core/v2/hcore/core_stopped.go:14`–`:31`,
   `ios/.../ExtensionProvider.swift:179`–`:189`, `android/.../BoxService.kt:316`–`:330`). Segue
   already does this for the TUN data path — Apple cancels the tunnel when the packet pump fails or
   the utun loop stops (`XrayPacketTunnelProvider.swift:3047`, `:3062`), Android polls the loop-exit
   counters (`XrayTunFdLoopWatch.kt:12`–`:32`, wired at `XrayVpnService.kt:818`). What is missing is
   the same signal for a core that stops **itself** (config reload failure, fatal error) rather than
   losing its fd: the FFI has `xray_core_start`/`xray_core_stop` (`segue_ffi.h:331`–`:332`) but no
   engine-death callback. Adding one is small and closes the Hiddify bug class for Segue too.
3. **Copy — the 8-sub-range default route option and the APNs exclusion.** Both sing-box apps use
   `1.0.0.0/8 … 128.0.0.0/1` instead of `0.0.0.0/0` (`ExtensionPlatformInterface.swift:77`–`:88`)
   plus `excludeAPNsRoute` → `17.0.0.0/8` and a `push.apple.com` proxy bypass (`:102`–`:107`,
   `:186`–`:192`).
   Segue currently hard-codes `includedRoutes = [NEIPv4Route.default()]`
   (`platform/apple/.../XrayPacketTunnelProvider.swift:2390`), so this is an easy, well-understood
   win for captive-portal and push reliability.
4. **Copy — `excludeLocalNetworks` defaults per platform and the full NE flag set.** SFI sets
   includeAllNetworks / excludeLocalNetworks / enforceRoutes / excludeAPNs / excludeCellularServices /
   excludeDeviceCommunication from user prefs (`ExtensionProfile.swift:152`–`:166`), defaults
   `excludeLocalNetworks=true` on iOS and false on macOS (`SharedPreferences.swift:26`–`:36`), and
   reports the effective values to the core for its own decisions
   (`ExtensionProvider.swift:44`–`:68`, `ExtensionPlatformInterface.swift:409`). Segue sets none of
   these (`grep` over `platform/apple` finds no `includeAllNetworks`), so `includeAllNetworks` users
   get a tunnel that silently differs from every other client.
5. **Copy — Android per-app include/exclude with exact-prefix routes.** SFA assembles the lists
   app-side, always adding its own package in include mode (`BoxService.kt:154`–`:166`), uses
   `excludeRoute` on Tiramisu+ (`VPNService.kt:94`–`:121`), and NekoBox applies
   `setUnderlyingNetworks` so the tunnel is never its own upstream (`VpnService.kt:202`–`:210`).
   Segue's `XrayVpnService.buildTunnel` (`XrayVpnService.kt:969`) only adds `0.0.0.0/0`/`::/0`
   (`:973`–`:974`) and `addDisallowedApplication(packageName)` (`:980`): no per-app support at all,
   the single biggest feature gap in Segue's Android package. (Segue's underlying-network story is
   fine — it has `networkChangeRebindEnabled`/`selectUnderlyingNetwork` hooks with a documented
   default, `:601`–`:622`.)
6. **Copy — an explicit always-on story per platform, and a user stop that is not undone.** Hiddify
   advertises `SUPPORTS_ALWAYS_ON` and distinguishes the system's start intent from the app's
   (`android/app/src/main/AndroidManifest.xml:148`–`:150`, `BoxService.kt:114`–`:123`, `:396`);
   on iOS it refuses to enable on-demand while disconnected so the VPN does not start behind the
   user's back (`VPNManager.swift:147`–`:153`). SFI's `wasOnDemandEnabled` marker
   (`ExtensionProfile.swift:283`–`:300`) solves the same iOS problem. Segue has no
   `SUPPORTS_ALWAYS_ON` and only *restores* on-demand state (`XrayClientTunnelController.swift:195`–`:216`),
   i.e. it preserves what exists but gives the user no policy.
7. **Copy — device-memory-derived limit rather than a fixed OOM number, and make iOS enforcement
   unconditional.** Hiddify takes `totalMem / 4` and marks low-RAM devices, explicitly rejecting
   `memoryClass` because the core is native (`utils/DeviceMemory.kt:18`–`:47`); SFI simply forces the
   killer on for iOS, whatever the user's setting (`ExtensionProvider.swift:204`). Segue measures
   resident memory in the Apple provider (`XrayPacketTunnelProvider.swift:563`–`:615`) but has no
   budget knob in the FFI (`grep` for `memory_limit` over `crates/segue-ffi/include/segue_ffi.h` is
   empty), so the Android side in particular has nothing to hold the core to.
8. **Copy — subscription header handling (`profile-title`, `subscription-userinfo`,
   `profile-update-interval`).** Hiddify treats these as the subscription contract
   (`lib/features/profile/data/profile_parser.dart:68`–`:79`), and v2rayN adds per-sub User-Agent,
   extra headers and an optional converter (`SubscriptionHandler.cs:137`–`:235`). Segue's importers
   are protocol-link based (`crates/segue-*` import docs); if subscriptions land, copy the header
   list, not a bespoke format.
9. **Copy, carefully — the network-monitor actor.** SFA's and NekoBox's
   `ConnectivityManager` actor with `registerBestMatchingNetworkCallback` → `requestNetwork` →
   `registerDefaultNetworkCallback` fallback (`bg/DefaultNetworkListener.kt:192`–`:230`) exists because
   the naive callback returns the VPN interface as the default network. Segue already has
   `XrayNetworkChangeCoordinator.kt`; the lesson to confirm is that Segue asks for the *underlying*
   network, not the default, and sets it as the tun's underlying network.
10. **Avoid — the hidden-core split (Karing).** Karing's useful platform logic lives in gitignored
    `bind/apple` and an out-of-tree Flutter plugin (`.gitignore:60`–`:61`, `pubspec.yaml:177`), so
    nothing about its extension can be reviewed or ported. Segue keeps its providers in-tree
    (`platform/apple/Sources/XrayAppleTunnel`, `platform/android/xraymobile`); keep it that way.
11. **Avoid — the process-per-core desktop model (v2rayN).** It works on a desktop with a Job object
    and a sudo script, but it has no in-process control plane, needs an external helper to
    self-update, and does no signature check on updates (`v2rayN/AmazTool/UpgradeApp.cs`, no checksum in
    `Services/UpdateService.cs`). If Segue ships a desktop service, prefer the in-process core plus
    an elevated service (Hiddify's `admin_bgservice`, `admin_bgservice.go:21`) or a system extension
    (SFI `SystemExtension/`).
12. **Avoid — a second gRPC hop between app and core on mobile.** Hiddify's gRPC design buys a clean
    UI/core split and survives the app being killed, but it costs a whole lifecycle layer
    (modes 2/4, mTLS cert files, `MobileStart("")` replay, "close the mode you started" bug at
    `BoxService.kt:369`). Segue's C ABI with direct calls plus one status/event channel
    is simpler; take the *stopped-callback* lesson (item 2), not the transport.

Risks and gaps in this study: the Karing clone lacks the files that would answer most questions
about it; the SFI `Libbox` binary is vendored, so the core-side behaviour (OOM killer semantics,
`startOrReloadService`) could not be read; and none of these apps were built or run, so all
"behaviour" above is from source, not observation.
