# Segue macOS app

Status: design, 2026-11-17. First platform to ship. The product is the owner's.
The core scenario is Claude Code, Codex, ChatGPT and Claude desktop on a Mac
on a censored network. The headline is the AI lock: AI traffic leaves only
through the connected IDC exit, and other traffic keeps working. This is not
a block-everything kill switch (`docs/design/ai-lock.md`).

Tono is the same owner's product. Its macOS helper, PF rules, DNS restore,
release daemon and update transaction are copied, not rewritten. Paths below
are from the read-only clone `/Volumes/dev/ref/apps/tono` at `006984ae`, unless
they start with `crates/`, `platform/` or `docs/` (this repo). Other apps are
the clones named in `docs/research/apps/kill-switch-survey.md`.

The beta is a notarized Developer ID app the owner can hand out. It is not an
App Store app, and it does not wait on the mobile FFI kernel mode
(`docs/design/ffi-kernel-embedding.md` stages 2–7) or on a control plane.

## What is copied

| | |
| --- | --- |
| **Lift, rename only** | `tooling/scripts/core-helper/` PF hook and label rules (`KillSwitchPF.swift` `hookedMainConfiguration`, per-rule `label`), DNS snapshot/restore (`ProtectedDNSManager.swift`), peer check (`tooling/scripts/helper-shared/PeerAuthorization.swift`), socket server and session generation (`SocketServer.swift`), power gate (`HelperPower.swift`), release daemon (`ReleaseWorker.swift`), protocol-version build gate (`apps/macos/Tono/Core/HelperProtocolVersion.swift` plus `tooling/scripts/build-core-helper.sh`), install script shape (`HelperManager.swift` `installScript` / `osascript`). The pure XCTest files that pin those contracts. |
| **Lift, then change behaviour** | `CoreManager.swift` (exec `segue-kernel`, not sing-box). `KillSwitchPF.renderRules` (today ends in `block drop out quick all`; the steady state becomes the AI-scoped renderer already in `renderAIHomeRules`). `SelectiveFailOpen.swift` (suffix list, sinkhole target; drop the hard-coded Anthropic prefixes). `KillSwitchManager` startup (decision 035 does not re-arm; Segue re-arms the narrow layer only). |
| **New** | utun + route install inside `segue-kernel run` (the binary today is SOCKS + DNS only, `crates/segue-kernel/src/main.rs:78-163`). A helper DNS listener that answers armed AI names with empty NOERROR. One menu-bar window. A diagnostics zip. |
| **Not in the beta** | sing-box, mihomo, tailscale (`apps/macos/Tono/Resources/`). Sea-scene views. Account, catalog, Cloudflare worker client. Sparkle (already not on Tono's active path). The native update transaction (stage 6, after someone is using the beta). Per-app filters. `SMAppService.daemon` as the installer. |

`docs/research/apps/tono-and-segue-app-suite.md` §5 said not to copy Tono's
code. That was a licence guess. The owner has since said Tono is theirs and
to reuse it. This document follows that.

## 1. Tunnel host

Three ways to hold a packet path on macOS:

| | System Extension `NEPacketTunnelProvider` (Developer ID) | App Store app extension | Root helper + utun (Tono) |
| --- | --- | --- | --- |
| Who ships it | Proton Mac: `NEProvider.startSystemExtensionMode()` in `proton-ios-mac-app` `apps/macos/ProTUN-Extension-Desktop/main.swift:40`. sing-box standalone: `Variant.useSystemExtension = true` in `sing-box-for-apple/SFM.System/StandaloneApplicationDelegate.swift:9`, provider in `SystemExtension/PacketTunnelProvider.swift`. | WireGuard: `PacketTunnelProvider: NEPacketTunnelProvider` in `wireguard-apple/Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift:8`, no kill switch. sing-box also builds this shape (`Extension/PacketTunnelProvider.swift`). | Mullvad desktop: LaunchDaemon `net.mullvad.daemon` (`mullvadvpn-app/dist-assets/uninstall_macos.sh:32`), userspace tun via `gotatun::open_tun` (`talpid-wireguard/src/lib.rs:482`, `talpid-wireguard/src/gotatun/mod.rs:265`), pf anchor `"mullvad"` (`talpid-core/src/firewall/macos.rs:24`). Tono: LaunchDaemon, sing-box opens the tun, helper owns PF. |
| AI lock while our process is dead | Extension death removes the tunnel routes. `includeAllNetworks` then blocks **everything** (Proton sets it from `WireguardConfigurator.swift:94-98` in that clone). A split route for AI prefixes just disappears, and AI goes direct. Proton's extra layer is `NEFilterPacketProvider`, and it drops packets that are not for the tunnel (`ProTUNPacketFilterProvider.swift:25-27`) — again everything, not AI only. | Same route behaviour, and a sandboxed appex cannot install PF or a LaunchDaemon. No way to leave an AI-only hold behind. | utun and its routes die with the process, so ordinary traffic falls back to the physical network. PF rules and `/etc/resolver` files are kernel state and survive the process. That is the only one of the three that can drop AI and pass everything else while Segue is dead. |
| App quit | NE stops unless on-demand reconnects it. Proton's always-on zero-peer tunnel does **not** re-arm at boot (`WireguardConfigurator.swift:307` sets `isOnDemandEnabled = false`; see `docs/research/apps/kill-switch-survey.md` §5). | Same. | Helper is `KeepAlive` + `RunAtLoad` (`apps/macos/Tono/Resources/tono-core-helper.plist:16-19`). Quit stops the kernel and keeps the narrow hold (Tono decision `docs/decisions/073-2026-10-07-normal-quit-retains-ai-floor.md`). |
| Crash | System extension is restarted by sysextd only if the OS still wants the tunnel. There is no separate AI hold. | Same, plus jetsam. The ~50 MB cap is documented for the iOS tunnel (`tono` `apps/ios/PacketTunnel/PacketTunnelProvider.swift:204-205`). Neither Proton's nor sing-box's macOS provider sets a budget; a root process has no NE cap. | launchd restarts the helper. PF and resolver files stay. Tono's idle loop releases a **full** block after ~30 s (`KillSwitchManager.swift` as cited in `docs/research/apps/kill-switch-survey.md` §5); Segue must not release the narrow layer on that timer. |
| Reboot | No macOS product in the survey blocks before launchd. Mullvad documents the window (`mullvadvpn-app/docs/known-issues.md:45-70`). | Same. | Helper starts at load. Tono **refuses** to re-arm a full block (`docs/decisions/035-2026-09-30-boot-does-not-rearm-kill-switch.md`) because a leftover block is an unrequested lockdown. A narrow AI layer is safe to re-arm from persisted intent. See §2. |
| Sleep / network change | NE gets `NWPath` updates inside the provider. | Same. | Lift `HelperPower.swift`. The utun's routes vanish if the interface does; the AI layer does not. On wake the helper reads the kernel control API and reconnects, and does not clear intent. |
| Update | Replacing a system extension needs another user approval and drops the tunnel for the swap. | App Store delivers it; still drops the tunnel. | Tono's root transaction replaces app, helper and core while a private executor keeps the obligation (`apps/macos/NATIVE_UPDATE_V1.md`). Not in the first beta (§4). |
| Install | System Settings approval, Developer ID, notarization. Not accepted by the Mac App Store. sing-box's standalone build **also** registers a root helper (`HelperServiceManager.swift:10-22`, `SMAppService.daemon`) for neighbour-table / NAT work, not for the tunnel. | App Store, or Developer ID with a one-time VPN approval. Least friction. Cannot do the lock. | One administrator password via `osascript` (`HelperManager.swift:300-310`), then Login Items "Allow in the Background" (`SMAppService.statusForLegacyPlist`, `HelperManager.swift:725-728`). Same friction Tono and Mullvad already ship. |
| Entitlements | Network Extension system-extension entitlement, `packet-tunnel-provider`. Filter needs a second extension (Proton's packet filter). | App-extension Network Extension entitlement. Sandbox. | No Network Extension entitlement. Hardened runtime, no `com.apple.security.get-task-allow` (the peer requirement rejects it: `PeerAuthorization.swift:30-47`). Developer ID + notarization. |
| Memory | No 50 MB jetsam in these macOS providers. The process is still a NE the OS can kill, and sing-box keeps an OOM reporter (`Library/Shared/OOMReportManager.swift`). | The iOS cap is real; macOS appex limits are tighter than a normal process and are not something to bet the kernel on. | Ordinary root process. `segue-kernel`'s budget (`docs/design/ffi-kernel-embedding.md` §5.2, ~17 MiB before TLS) is irrelevant as a cap. |

**Use the root helper and a utun.** The lock has to keep working when the GUI,
the kernel, or both are dead, and it must not take the rest of the Mac
offline. NE can do "block everything" or "block nothing" at that moment. It
cannot do "block AI, pass the rest" without a second privileged mechanism,
which is the helper again. Proton and sing-box are the wrong shape for this
product: they are full-tunnel VPNs. Mullvad's desktop and Tono are the right
shape, and Tono's code is already the AI-scoped one (`renderAIHomeRules`,
`SelectiveFailOpen`).

The kernel is not linked into the helper. `CoreManager` execs `segue-kernel`,
the way it execs sing-box today. FFI `proprietary-kernel` stays the mobile
plan.

While the tunnel is healthy the kernel takes the **default route** (exit
address excluded, so the carrier does not loop). That is what makes DNS,
SNI and the QUIC drop in `docs/design/ai-lock.md` apply to apps that ignore
the system proxy. "Other traffic keeps working" is the dead-tunnel case: the
utun closes, its routes go with it, and only the AI layer remains. A
split-tunnel default would let hard-coded DoH and QUIC-to-a-real-IP bypass
the kernel the whole time the user is connected.

## 2. AI lock outside the process

Two different layers, both owned by the helper, neither of them
`block drop all`:

1. **PF anchor `segue.ailock`.** `/etc/pf.conf` gets the anchor declaration
   only, never `load anchor "…" from`, for the same reason as Tono: Apple's
   `pfctl` loads that file at boot, including Safe Mode, and this daemon does
   not run there (`KillSwitchPF.swift:709-726`,
   `docs/decisions/034-2026-09-30-pf-conf-does-not-load-rules-at-boot.md`).
   While intent is armed the helper loads the child in one `pfctl -f`
   transaction (`kernelMainConfiguration` in the same file). Rules, in order:
   pass on `lo0`, pass on the current utun if one exists, then
   `block drop out quick` to each AI CIDR, with its own `label` so pfctl
   cannot collapse rules (`HelperProtocolVersion.swift:52-63` is the bug that
   taught that). No `user` match: the kernel reaches the IDC exit by IP, never
   by dialling an AI address (`renderAIHomeRules`, `KillSwitchPF.swift:625-649`).
   The CIDR list is the kernel's list: built-in `crates/segue-kernel/data/ai-lock.txt`
   plus the signed bundle's `ai_cidrs`. The built-in file ships **no** CIDRs
   on purpose (CDN ranges are shared; OpenAI's published ranges are egress,
   not destinations). Until a bundle adds a prefix, this anchor blocks
   nothing and the DNS guard is the whole OS lock. Do not copy Tono's
   hard-coded `160.79.104.0/23` (`SelectiveFailOpen.swift:14-15`, decision
   `docs/decisions/036-2026-09-30-crash-hang-releases-then-ai-layer.md`). The
   kernel authors rejected inventing it (`ai-lock.txt` TODO: `api.anthropic.com`
   is behind a CDN). A bundle may add a prefix later; the renderer must not
   grow a second list.

2. **DNS guard.** Not a machine-wide resolver at `127.0.0.1`. Tono points
   every service there only while the core is alive, and refuses to leave it
   there when the core is dead (`ProtectedDNSManager.swift:1-13`, decision
   035): a dead listener is a dead network. Segue does the same split.
   - Tunnel up: lift the snapshot/restore. System DNS points at the kernel's
     DNS listen address. The kernel returns a fake IPv4 for AI names and an
     empty NOERROR for AAAA (`docs/design/ai-lock.md`).
   - Tunnel down, intent still armed: restore the snapshot **first**, then
     write `/etc/resolver/<suffix>` for each armed suffix, `nameserver`
     `127.0.0.1` port owned by the **helper**. The helper answers those
     queries with empty NOERROR for A and AAAA and does not recurse. Other
     names never see this listener. Suffixes are the built-in list in
     `ai-lock.txt` (anthropic.com, claude.ai, claude.com, openai.com,
     chatgpt.com, oaistatic.com, oaiusercontent.com) plus bundle `ai_domains`.
     Not Tono's longer `SelectiveFailOpen.suffixes` (that file adds x.ai,
     grok, perplexity, Aliyun). Those are a product choice; the kernel list
     is the one the lock already promises.
   - Helper dead too: launchd `KeepAlive` restarts it. For the gap, the
     `/etc/resolver` files still point at a closed port, so those names fail
     instead of leaking. Everything else uses the restored resolver.

Tono's sinkhole is `192.0.2.1` with no process (`SelectiveFailOpen.swift:16-18`),
which fails slowly (timeout) and is not empty NOERROR. A helper listener
fails fast and matches the kernel. The files stay, so the hold does not
depend on the listener being up.

**Arm.** The app sends arm over the socket. The helper persists intent, then
installs the anchor and the resolver files, then starts `segue-kernel`. A
lost arm reply keeps the intent (Tono: `KillSwitchService.arm`'s failure
path; `docs/research/apps/tono-and-segue-app-suite.md` §6 item 12). The
kernel being down is not a reason to clear intent.

**Disarm.** Only an explicit user action: Disconnect, or Restore network.
The helper clears intent, deletes `/etc/resolver` files, restores DNS, then
flushes the anchor. A lost disarm reply is not a release; the app shows the
helper's read-back. Restore network is the release daemon (§3), so a stuck
helper cannot trap the user. Order is Tono's: DNS restored and read back
before the firewall opens (`docs/research/apps/kill-switch-survey.md` §8).

**Reboot.** `ai-lock.md` says do not re-arm a leftover block across reboot
unless the user asked. Persisted intent **is** the user asking, and the
thing re-armed is not a block-all. Helper start, if intent is armed: install
the resolver files and the CIDR anchor, do not start the tunnel until the
user's session is up and the app (or a helper reconnect) asks. If intent is
clear, install nothing, even if rule files are lying around. Safe Mode does
not run the daemon and does not load the anchor
(decision 034). `/etc/resolver` files **do** survive Safe Mode — Tono's
research in `docs/selective-fail-open.md` — so Restore network and the
release daemon must delete them, and the uninstall path must too.

**States.** Rows are the OS, not the kernel. The kernel matrix is
`docs/design/ai-lock.md` and applies only while `segue-kernel` is running
and the flow is inside the utun. "AI name" means a name on the armed suffix
list, asked of the system resolver. "AI CIDR" means a prefix on the armed
list (empty today).

| | AI name | AI CIDR | AI literal IP, not in a CIDR; QUIC to it; hard-coded DoH | Other traffic |
| --- | --- | --- | --- | --- |
| Intent clear (user off, after Restore) | normal | normal | normal | normal |
| Armed, tunnel not up (quit, crash, boot, reconnect not finished, sleep before the utun returns) | empty NOERROR from the helper, or a timeout if the helper is also down | PF drop, if any CIDR is armed | **not held.** This is the leak. | direct, works |
| Connecting | helper still answers empty until the kernel DNS is the system resolver, then fake-IP | PF drop except on the utun | enters the utun only after the default route is installed; until then, not held | direct until the default route moves, then the kernel (`Wait` / direct per policy) |
| Connected | kernel fake-IP, IDC exit | through the utun, IDC exit, not a different egress group | inside the utun: QUIC refused, SNI sniffed (`docs/design/ai-lock.md`). DoH to 1.1.1.1 is encrypted; the follow-up is AI only if SNI or a CIDR matches | kernel policy, direct or overseas. Works |
| Reconnecting / Error, kernel still alive | kernel refuses AI (Strict) | PF still drops off-utun | kernel refuses; QUIC still dropped on the home route | kernel `Wait` then refuse; the utun still holds the default route so "works" means "held", not "direct" |
| Reconnecting / Error, kernel dead | same as armed, tunnel not up | same | not held | utun is gone, so direct |
| Update swap (stage 6) | AI layer stays | AI layer stays | not held | direct while the utun is down |
| Safe Mode | resolver files still redirect AI names | anchor not loaded, so not dropped | not held | works |

The awkward row is "kernel alive but reconnecting": ordinary traffic is
inside a tunnel that is not forwarding, so it stalls until the kernel gives
up and exits. That matches the kernel (`Protection::Wait`, then refuse) and
is acceptable only because the helper's watchdog must **exit the kernel**
on a deadline and fall through to "kernel dead", where ordinary traffic is
direct and AI stays locked. Tono's non-strict watchdog releases everything
(`docs/decisions/036`); Segue's watchdog releases the utun only. The deadline
should be the kernel's own `WAIT_DEADLINE`, not a second policy.

**Limits, said in the product copy:**

- OpenAI, ChatGPT web and anything else on Cloudflare is not a CIDR we can
  block. Blocking `104.18.0.0/16` or AS13335 also blocks other people's
  sites. Tono rejected that (`docs/selective-fail-open.md`, decision 036).
  The name guard is the only hold, and it is bypassed by the next three.
- An app with a hard-coded DoH resolver never asks the system resolver.
  `/etc/resolver` does not see the question.
- A client that already has the address, or connects to a literal, skips
  DNS. With no CIDR, PF does not see an AI flow. ECH hides SNI even inside
  the tunnel; `ai-lock.md` refuses a hidden name to an IP outside `ai_ips`
  locally rather than sending it overseas. Outside the tunnel that refusal
  does not exist.
- QUIC to an IP we do not list is just UDP/443. PF will not drop all QUIC.
- Cached answers and live connections from before the layer was installed
  keep going until they expire. Installing the layer does not flush every
  state on the machine; it kills states to the CIDRs just armed (Tono's
  per-address kill, `HelperProtocolVersion.swift:29-33`), not `pfctl -F states`.
- PF does not match a code signature. A `user` clause is not an app
  boundary (`docs/decisions/086-2026-10-10-h1f5-control-window.md`, cited from
  `docs/research/apps/kill-switch-survey.md` §8).

**Per-app, not in v1.** Proton's packet filter does not know the source app;
the callback is interface, direction and bytes
(`ProTUNPacketFilterProvider.swift:32-38`). Proton's per-app feature is a
different extension and keys off `sourceAppIdentifier`
(`libraries/Core/PlutoniumExtension/.../NEAppProxyFlow+Helpers.swift:22`).
An `NEFilterDataProvider` audit-token match would lock `Claude.app` and let
`curl` and Claude Code's helper processes through, which is the opposite of
the guarantee. It is also a second system extension and a second approval,
and none of it exists in Tono. Destination, not application.

## 3. Processes

```
Segue.app          menu bar, the logged-in user, not sandboxed
    |  unix socket /var/run/segue/service.sock
    v
segue-core-helper  root LaunchDaemon, KeepAlive
    |  exec, supervises, restarts
    v
segue-kernel       root child; utun, default route, DNS, loopback control API
    ^
    |  /var/run/segue-release.sock   (only Restore network)
segue-release      second root LaunchDaemon, lifted from ReleaseWorker.swift
```

The app is not the protection authority. It can ask the helper to arm or
disarm. It cannot flush PF itself. Killing the app does not clear intent
(decision 073). Killing the kernel drops the utun and leaves the AI layer.

**App.** SwiftUI `MenuBarExtra`. New, small: status, connect, restore
network, "open the config folder", export diagnostics. Do not port
`apps/macos/Tono/Views/Sea*`. Status text comes from the helper's read-back,
not from a local "I called connect" flag (Tono's
`TunnelConfirmation` rule, `docs/research/apps/tono-and-segue-app-suite.md`
§6 item 4). Connected means the kernel's control snapshot says `connected`
**and** the helper sees the utun.

**Helper.** `SMAppService` is how the app *reads* Login Items state
(`statusForLegacyPlist`), not how it installs. sing-box installs with
`SMAppService.daemon(plistName:)` (`HelperServiceManager.swift:10-22`). That
API is the wrong port for this helper: Tono's installer copies a signed
binary to `/Library/PrivilegedHelperTools`, writes the allowed-uid file, and
checks the Developer ID requirement before the `osascript` prompt
(`HelperManager.swift:284-310`). `SMAppService.daemon` would throw that
away for a shorter install. Keep the script. Rename the label, the socket,
the plist and the requirement's bundle id.

**Kernel embedding.** Not the FFI. `segue-kernel run` must grow a tun mode:
open a utun, install the default route with the exit address on the physical
interface, run `TunStack` (already in `crates/segue-kernel/src/tun.rs`),
and publish the interface name on the control API the helper already has a
pattern for (`crates/segue-kernel/src/main.rs:98-108`). Direct and domestic
sockets bind the physical interface, which is what Tono's root core does
(`CoreManager.swift` `StrictRuntimeProof`, `bind_interface`). That sidesteps
FFI open question Q3 (the kernel's DNS sockets are unprotected raw sockets):
on a root utun process, binding the physical NIC is the protection. Do not
wait for `xray_kernel_load_config_json`.

**IPC.** Versioned JSON envelopes on the unix socket, one in-flight owner,
the contract version a single constant whose bump the build enforces
(`HelperProtocolVersion.swift:1-22`). Start at `1`. Do not carry Tono's
`4.52.70`. Peer check, unchanged in structure: `getpeereid` against the
allowed-uid file, then `LOCAL_PEERTOKEN`, then
`SecCodeCopyGuestWithAttributes` with `kSecGuestAttributeAudit`, requirement
`anchor apple generic and identifier "<bundle id>" and certificate
leaf[subject.OU] = "<team>" and entitlement["com.apple.security.get-task-allow"]
absent` (`PeerAuthorization.swift:46-79`). UID alone is not a boundary; the
comment in that file says why. Audit-token pid version is only unique within
a boot, so anything that grants a long-lived right also stores
`kern.bootsessionuuid` (`TonoAuthenticatedPeer.bootSession`). The kernel's
own control token stays in a root-only file. The app never sees it; the
helper does.

**State files.** Root-owned, mode `0700` directory, `0600` files, under
`/Library/Application Support/Segue/`. The user's config directory is the
only thing the app writes, and the helper accepts only that path
(`CoreManager.swift` `validateConfigDirectory`).

| File | Writer | Survives reboot | Cleared by Restore |
| --- | --- | --- | --- |
| `ai-lock.intent` | helper | yes; this is the re-arm bit | yes |
| `pf.segue.conf` and the anchor rules | helper | the file yes, the loaded anchor no (decision 034) | yes |
| `protected-dns.json` | helper | yes, until restore read-back | yes, after read-back |
| `/etc/resolver/<suffix>` | helper | yes, including Safe Mode | yes |
| `pf.reference` (the `pfctl -E` token) | helper | bound to the boot, as Tono's | yes |
| kernel fake-IP journal, control token | kernel, in the helper's runtime dir | journal yes, token no | token no; journal kept so addresses are not reused |
| user config + policy bundle | app | yes | no |

**Logs.** Helper log and kernel log under that directory. The kernel JSON
and tickets are never written (the FFI plan's rule,
`docs/design/ffi-kernel-embedding.md` §3.4; the kernel's `Debug` for tickets
already redacts). Export is a zip the user asks for: those two logs, the
intent bit, the helper status snapshot, passed through a redaction of home
paths and utun peer addresses. No upload in the beta. Tono's uploader talks
to the control plane (`DiagnosticsLogUploader.swift`); there is nothing to
send to.

## 4. Updater

**Not Sparkle, and not in the first beta.**

Sparkle remnants in Tono (`Tono/Info.plist`, `Package.resolved`,
`Resources/Sparkle-LICENSE.txt`) are not the installer.
`NATIVE_UPDATE_V1.md` replaced it because a user-level updater cannot
replace a root helper, cannot keep a protection obligation across the swap,
and cannot stop an old mapped binary from adopting the new one
(`UpdatePackage.sameCode`, dynamic `SecCodeCheckValidity`). Segue has the
same constraint the moment the helper exists.

The first beta is a notarized DMG the owner distributes by hand. The helper
install runs on first launch. Shipping the transaction before anyone has
the app is how Tono's release gates slipped
(`docs/research/apps/tono-and-segue-app-suite.md` §6 avoid item 11).

Stage 6 lifts `UpdateTransaction.swift`, `UpdateExecutor.swift`,
`UpdateStorage.swift` and the app side (`AppState+NativeUpdate.swift`,
`NativeUpdateDownload.swift`) once the helper's paths have stopped moving.
Same properties, still required then: a private copy of the old helper
performs the replace, consumption is a single durable grant,
`releaseSequence` only goes up, and a failed update keeps the AI layer
instead of clearing it. The release daemon stays out of that transaction so
Restore network still works mid-update (`ReleaseWorker.swift:1-16`).

## 5. Tests on the Mac mini

The runner is non-root, macOS 27, Xcode 27.2. It does not install a
LaunchDaemon, does not load a system extension, and does not call `pfctl`.
Rust tests stay on the existing Linux CI. The `apple:` job already runs on
this mini (`segue-macos` in `.github/workflows/ci.yml`, the XCFramework and
Swift package tests). App tests are another step on that job, not a new
runner. The job is not ephemeral and its work dir is on the external disk;
a test that touches `/etc`, `pfctl` or launchd does not belong there.

**On the mini, every PR:**

- `xcodebuild test` of the pure suites. These already exist on the Tono side
  and do not need root: PF render golden strings (the AI-scoped renderer,
  including "no `block drop all`" and "labels present"), the intent ×
  traffic-class table in §2 encoded as data, protocol-version gate (helper
  sources changed ⇒ version constant changed), peer-requirement string,
  disarm-vs-arm reply rules, diagnostics redaction, update-contract
  decisions with the launchd and pf effects injected (Tono's
  `NativeUpdate*Tests` and `UpdateContractV1Tests` are this shape).
- `bash -n` / a small shell test that the install script refuses a helper
  whose code requirement does not match, without running it as root
  (Tono's `HelperInstallScriptTests`).
- A fixture test that the suffix list the helper embeds equals
  `crates/segue-kernel/data/ai-lock.txt` plus an empty CIDR set. Drift fails
  the build. The kernel crate's posture tests stay where they are.

**Not on this runner.** A VM (Tart or UTM on the same mini, a different
user, admin) runs the privileged self-test the way Tono documents
`sudo … --update-self-test` (`NATIVE_UPDATE_V1.md` "Production-bound
verification"). Nightly, not per PR. It is allowed to touch PF, resolver
files and launchd because it is a throwaway volume.

That VM runs the AI-lock matrix against packet fixtures, not against live
vendor networks:

| Case | Pass |
| --- | --- |
| Armed, kernel not started | `dig` of an armed name is empty NOERROR; `dig example.com` is a real answer; TCP to a fixture CIDR is dropped; TCP to a non-AI address works |
| Connected | armed name resolves to a fake-IP; a connection's egress is the fixture exit; a non-AI connection is direct or overseas as the bundle says |
| Kill `segue-kernel` only | utun gone; non-AI still resolves and connects; armed name still empty; fixture CIDR still dropped |
| Kill the helper too | within the launchd restart, armed name fails (timeout or empty); non-AI works throughout |
| Reboot with intent armed | before the GUI opens, resolver files and the anchor are back; no `block drop all` |
| Reboot with intent clear | no resolver files, empty anchor |
| Restore network, helper paused in `sleep` | the release daemon clears files and the anchor |
| Hard-coded DoH and QUIC to an unlisted IP | **expected leak**, asserted so nobody "fixes" the test by claiming the lock |

Sleep, Safe Mode and a real notarized signature are manual on that VM, once,
before a beta is handed out. They are not CI.

## 6. Stages

Each stage is one PR-sized branch, testable on the mini without the later
ones. Sizes are one person, and they assume the copy in stage 0 is actually
a copy. They are estimates.

| | What | Done when | Size |
| --- | --- | --- | --- |
| 0 | Copy the helper, the release daemon, `HelperManager`, the peer check and the pure tests into `apps/macos` in this repo. Rename bundle id, labels, sockets, paths, anchor. Delete sing-box, mihomo, tailscale, sea views, account client. `CoreManager.start` refuses, so nothing opens a tun yet. | `xcodebuild test` green on the mini. A renamed helper binary exists. No user-facing app beyond a window that says the helper is not installed. | 3–5 days |
| 1 | `segue-kernel run` opens a utun, installs the default route, excludes the exit, binds direct dials to the physical NIC, reports the interface name on the control API. `CoreManager` execs it. No PF yet. | A dev Mac routes through the fixture exit while the process lives, and the route is gone when it dies. Unit test for route arguments; the utun itself is the VM. | 1–2 weeks |
| 2 | AI layer: intent file, `renderAIHomeRules`-shaped anchor, helper DNS listener, `/etc/resolver` files, snapshot/restore lifted from `ProtectedDNSManager`, quit keeps intent, Restore clears it, watchdog exits a stuck kernel instead of releasing the layer. Startup re-arms the narrow layer only. | §2 table encoded as tests is green. VM matrix rows "armed", "kill kernel", "restore" pass. | 1 week |
| 3 | Menu bar: connect, status from helper read-back, restore, config folder, diagnostics zip. Config is a kernel JSON and a signed bundle on disk. No accounts. | The owner can connect to an exit they already have, kill the app, and watch a non-AI site load while an armed name does not resolve. | 1 week |
| 4 | Developer ID, notarize, staple, DMG. Helper install prompt. This is the beta. | A machine that has never seen the app installs from the DMG, prompts once, and passes the stage-3 check. | 3–5 days |
| 5 | VM nightly: the rest of the matrix, including reboot and the release daemon against a paused helper. | Nightly is red on a real leak and green on the expected DoH/QUIC leak. | 3–5 days, overlaps 4 |
| 6 | Lift the native update transaction. Not before a beta is in someone's hands. | A signed update replaces app + helper + kernel, keeps the AI layer across the swap, and rolls back without clearing intent. | 2+ weeks |

Out of this list, on purpose: control-plane sign-in, per-app filter, system
extension, App Store, Sparkle, `SMAppService.daemon`, Windows, mobile FFI
kernel mode.

## 7. Open questions

Defaults are what the stages above assume. A different answer changes the
stage, not the recommendation in §1.

1. **Where does the app live?** Default: `apps/macos` in this repo until the
   beta is out. A `segue-apple` repo costs a second CI and an artifact hop
   the beta does not need.
2. **Re-arm across reboot?** Default: yes, the narrow layer only, from
   `ai-lock.intent`. Never a full block. This is the reading of
   `ai-lock.md` ("unless the user asked") that matches a persisted on-switch.
3. **Beta without accounts?** Default: yes. A kernel JSON and a signed
   policy bundle in the config folder. The control plane is not on the Mac
   critical path.
4. **Ship `160.79.104.0/23`?** Default: no, unless that prefix is in the
   signed bundle. The kernel list does not have it.
5. **Full tunnel while healthy?** Default: yes. Split-tunnel would make the
   in-kernel lock blind to DoH and to QUIC toward real IPs.
6. **Which Developer ID team and bundle id?** Default: bundle id
   `com.raydocs.segue`, and the same team Tono's requirement uses
   (`PeerAuthorization.swift:47`, OU `YY57758GS7`) if that cert is still
   the owner's. The requirement string is new either way; a Debug build
   with `get-task-allow` will be refused, as Tono's is.
7. **Installer API?** Default: Tono's `osascript` script, with
   `SMAppService.statusForLegacyPlist` only to explain "Allow in the
   Background". Not `SMAppService.daemon`.

## Appendix. `segue-kernel` exit codes

The helper treats these as the process contract (`crates/segue-kernel/src/process.rs`).
A clean shutdown (`SIGTERM`, `SIGINT`, or the listeners closing) flushes the
fake-IP journal and deletes the control token before the process ends. A tun
setup failure removes any route it already added.

| Code | When |
| --- | --- |
| 0 | Clean shutdown, or `--help` |
| 1 | A listener failed after the process was up |
| 2 | The arguments are not a known command |
| 3 | The kernel JSON, `--state-dir` or `--log` path was rejected |
| 4 | macOS utun, address, MTU or route install failed |
