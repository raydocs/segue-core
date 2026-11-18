# Generations of sing-box and mihomo: architecture history, goals, direction

Research note, 2026-11-17. Companion to `2026-11-sing-box-1.15-and-mihomo.md`
(which examined *technical* details of sing-box 1.15 alpha, sing-tun and mihomo
Alpha for adoption). This doc covers the *generational* history of both
projects — what each generation changed architecturally, what was deprecated
and why, what the work reveals about each project's goals, where they are
heading, and which structural debts Segue Core can exploit. No technical
protocol detail is repeated from the companion doc.

## Sources and citation keys

| Key | Source |
| --- | --- |
| `SB-CL:<line>` | `/Volumes/dev/ref/sing-box/docs/changelog.md` (testing branch, 2026-11-17) |
| `SB-DEP:<line>` | `/Volumes/dev/ref/sing-box/docs/deprecated.md` |
| `SB-MIG` | `/Volumes/dev/ref/sing-box/docs/migration.md` (1 479 lines) |
| `SB-SPONSORS:<line>` | `/Volumes/dev/ref/sing-box/docs/sponsors.md` |
| `tag (date)` | GitHub Releases API, `SagerNet/sing-box` and `MetaCubeX/mihomo` |
| `#PR` | GitHub pull request in the named repository |
| `MH <path>:<line>` | `/Volumes/dev/ref/mihomo` Alpha branch, commit `3c0d10a` (2026-11-15) |
| `SB <path>` | `/Volumes/dev/ref/sing-box` testing branch |

Release dates come from the GitHub Releases API (`repos/…/releases`), queried
2026-11-17. Repo metadata (creation date, default branch, license) from the
GitHub repos API.

---

## 1. sing-box: eight generations in four years

Repository created 2022-06-30; GPLv3 (`SB LICENSE`, "Copyright (C) 2022 by
nekohasekai"); first public beta `#### 1.0-beta1` / "Initial release"
(SB-CL:5427-5429). Repo description: "The universal proxy platform". Default
branch is now `testing`; releases ship in four tracks: stable, beta, testing,
oldstable (SB-CL:200, 605-610).

| Generation | Stable date | Architectural theme |
| --- | --- | --- |
| 1.0 | 2022 (beta) | Clean-slate "box of protocols": inbounds/outbounds, JSON config, TUN from day one |
| 1.2 – 1.4 | 2023-03 → 2023-08 | First-party GUI clients; VLESS/vision + reality + ShadowTLS v3; FakeIP + Clash API compat; TUIC, MPTCP |
| 1.5 – 1.7 | 2023-09 → 2023-11 | QUIC-era protocol race (Hysteria2, ECH, Brutal, HTTPUpgrade); first deprecation purge |
| **1.8** | 2024-01-06 | **Rule-set generation**: compiled binary rule-sets replace GeoIP/Geosite |
| 1.9 – 1.10 | 2024-05 → 2024-10 | DNS-leak precision (address filters, client-subnet) and Linux data-plane performance (`auto_redirect`) |
| **1.11 – 1.12** | 2025-01 → 2025-08 | **Rule actions + endpoints; DNS server rewrite**; massive Apple TUN perf jump |
| 1.13 | 2026-02-28 | uTLS demoted in favour of NaiveProxy; ICMP proxy; platform-native integrations; CCM/OCM services |
| **1.14** | 2026-08-31 | **Everything-platform**: OpenVPN/OpenConnect/Snell, L3 forwarding, namespaces, API service + Dashboard, Desktop client, App Store return |
| 1.15 | alphas 2026-09-04 → 10-24 | **In-house TCP/IP stack** (replaces gVisor/system in sing-tun), MASQUE, HTTP/2+3 proxy rewrite, Tailcat |

### 1.1 What each generation actually changed

- **1.0 (2022)** — no legacy: the config model (inbounds/outbounds/route/DNS as
  peers) is original, not a Clash port (SB-CL:5427-5435).
- **1.2.0 (2023-03-24)** — own iOS client (SFI); VLESS server + vision flow;
  reality TLS; ShadowTLS v3; NTP service; DHCP DNS; multiple-config loading
  (SB-CL:4920-4956).
- **1.3.0 (2023-06-27)** — FakeIP support; *Clash.Meta API compatibility* added
  to the Clash API to import that ecosystem's panels; h2mux multiplex;
  shadowsocks client reimplemented (SB-CL:4730-4766).
- **1.4.0 (2023-08-29)** — TUIC, MPTCP dialing (SB-CL:4586-4600).
- **1.5.0 (2023-09-29)** — Hysteria2 protocol support; ECH server + ECH on all
  QUIC outbounds; ACME DNS-01; `merge`/format tooling; deprecation list
  introduced (SB-CL:4394-4440).
- **1.6.0 (2023-10-31)** — *removal* release: ShadowsocksR and Proxy Protocol
  deleted; tvOS client; BBR rewrite (SB-CL:4213-4240, SB-DEP:188-200).
- **1.7.0 (2023-11-30)** — TCP Brutal CC for multiplex; HTTPUpgrade transport;
  multiplex config moved from outbound to inbound; Wi-Fi SSID rules
  (SB-CL:4053-4090).
- **1.8.0 (2024-01-06)** — *rule-set generation*: "independent collections of
  rules that can be compiled into binaries… load faster, use less memory, and
  update automatically", explicitly replacing GeoIP and Geosite, whose stated
  problems were "high memory usage and difficult management" and "lack of
  maintenance, inaccurate rules" (SB-CL:3769-3790, SB-DEP:160-187). Cache file
  moved out of the Clash API section (SB-CL:3766).
- **1.9.0 (2024-05-27)** — address-filter DNS rules to bypass Chinese sites via
  controlled DNS leaks; EDNS client-subnet; rejected-response caching;
  TunnelVision mitigation (SB-CL:3466-3527).
- **1.10.0 (2024-10-15)** — `auto_redirect`: TUN-adjacent kernel redirect for
  Linux routers so direct traffic keeps hardware offload; inline rule-sets
  become default; new sniffers; Clash API access control; rule-set memory
  optimization (SB-CL:3057-3140). Go floor → 1.20.
- **1.11.0 (2025-01-30)** — *rule actions*: legacy special outbounds
  (`block`/`dns`), inbound fields and DNS route options collapse into typed
  rule actions with *pre-match* ("Similar to Surge's pre-matching") so TUN can
  RST before connection; *endpoint* concept introduced with WireGuard;
  multi-network dialing (`network_strategy`) (SB-CL:2701-2780).
- **1.12.0 (2025-08-04)** — *DNS server rewrite*: typed DNS servers (`udp`,
  `tls`, `https`, `dhcp`, `tailscale`, …) replacing per-server legacy fields;
  `domain_resolver` replaces `outbound` DNS rules; Tailscale endpoint; AnyTLS;
  stdlib ECH; and a 3-40× TUN throughput jump on Apple platforms (tun_bench on
  M4: gVisor MTU 1500 upload 852M → 2.90G) (SB-CL:2165-2310). The same entry
  declares the App Store/Play Store apps "irrecoverable" pending a rewrite
  (SB-CL:2312-2315).
- **1.13.0 (2026-02-28)** — NaiveProxy outbound with the explicit uTLS
  demotion: "uTLS is not recommended for censorship circumvention due to
  fundamental architectural limitations; use NaiveProxy instead" (SB-CL:1744-1749);
  ICMP echo proxy; Chrome Root Store; kTLS; platform-native `local` DNS via
  systemd-resolved/getaddrinfo; *Claude Code and OpenAI Codex multiplexer
  services* (CCM/OCM) (SB-CL:1585-1740).
- **1.14.0 (2026-08-31)** — the breadth release (SB-CL:154-612): iOS/tvOS back
  on the App Store under a new account ("sing-box MT", SB-CL:158-167);
  OpenVPN client/server and OpenConnect endpoints; Snell implemented in Go
  despite being closed-source — "this is already impossible in 2026… we
  implemented it in Go instead of reinventing the wheel, with… performance at
  least on par with it" (SB-CL:250-255); L3 forwarding + `bridge` outbound
  (TCP/UDP/ICMP without L3→L4 translation); rootless Linux network namespaces;
  *sing-box API service* (gRPC) + web Dashboard + `sing-box api` CLI for remote
  control (SB-CL:289-305); USB/IP services; Hysteria Realm (NAT traversal
  rendezvous) + Hysteria2 Chrome-QUIC handshake parroting (SB-CL:168, 328-339);
  DNS response matching with `evaluate`/`race` (parallel response-dependent
  rules, SB-CL:345-372); mDNS + LAN neighbour (MAC/hostname) rules; TLS spoof
  (forged ClientHello to fool SNI filters); Windows Schannel and Apple
  Network.framework TLS/HTTP engines; JSON Schema; *sing-box for Desktop*
  (Windows/Linux GUI, SB-CL:197); four release tracks (SB-CL:200, 605-610); Go floor → 1.25
  (SB-CL:612).
- **1.15.0 alphas (2026-09-04 → 2026-10-24)** — sing-tun's *own TCP/IP stack*:
  "substantial improvements over all previous implementations in peak
  performance, energy efficiency, and memory usage"; the `stack` option
  (gVisor/system/mixed) is deprecated for removal in 1.17 (SB-CL:113-127,
  SB-DEP:7-15); MASQUE client/server (CONNECT-IP over HTTP/1.1-3);
  HTTP proxy rewritten with HTTP/2+3 and CONNECT-UDP (SB-CL:50-84); Tailcat
  (Tailscale's data plane without its control plane, SB-CL:88-103); full
  certificate pinning; fully functional Android `auto_redirect`; `on_demand`
  endpoints; cache-file write buffering.

### 1.2 Release mechanics

- Majors land every ~4-9 months; each major runs a months-long public
  pre-release (1.14: alpha.1 2026-03-07 → rc.5 2026-08-30; 1.15: 13 alphas in
  7 weeks) and the *previous* major keeps receiving patches (1.13.21,
  2026-08-30; 1.12.24). All dates from the releases API.
- The Go floor rises every single major, always "Due to maintenance
  difficulties": 1.10 → Go 1.20 (SB-CL:3111), 1.12 → 1.23 (SB-CL:2229), 1.13 →
  1.24 (SB-CL:1733), 1.14 → 1.25 (SB-CL:612).

## 2. mihomo: three names, one codebase, and a frozen stable line

| Generation | When | Architectural theme |
| --- | --- | --- |
| Clash (Dreamacro/clash) | 2016 → 2023-11 | Rule-based Go proxy; the config/API model mihomo still inherits. Repo deleted (GitHub API returns 404); last upstream commit appears in mihomo v1.17.0 notes ("fix: socks5 udp associate by @Dreamacro") |
| Clash.Meta | repo created 2021-05-20 (GitHub API; `MetaCubeX/Clash.Meta` now redirects to `MetaCubeX/mihomo`) | Protocol race on top of Clash: VMess/VLESS/SS, then Hysteria2, TUIC, SS2022; TUN inbound via sing-tun; MRS binary rule-sets (still hot: PRs #3423, #3433) |
| **mihomo** (rename) | v1.17.0, 2023-12-03 | Breaking rename: "Binary file name changes to `mihomo`, along with most of the const such as default config path" (release notes). GPL-3 (`MH LICENSE`) |
| v1.18 – v1.19 | 2024-01-02 → 2024-12-09 | Consolidation: GeoAutoUpdate, `include-all` groups, external API extensions (v1.18.0 notes); mieru protocol (v1.19.0 notes, #1702) |
| **v1.19.x frozen stable + rolling Alpha** | v1.19.1 (2024-12-31) → v1.19.34 (2026-11-11) | 34 patch releases, no v1.20 in ~2 years; all new work ships in the rolling `Prerelease-Alpha` release (created 2024-08-12, re-synced 2026-11-18), built from branch `Alpha` |

### 2.1 What the Alpha generation is adding (2026 commits, `MH` clone)

- **Own TCP/IP stack, `mips`** — a fourth TUN stack constant alongside
  gVisor/System/Mixed (`MH constant/tun.go:8-20`), backed by
  `metacubex/mipstack` (`MH go.mod:31`), and now the *default* TUN stack
  (`MH config/config.go:548`). Default tuning is explicitly memory-first:
  `ProcessorsPerChannel: 1, // For most users, memory usage is more important
  than peak performance` (`MH config/config.go:555`).
- **Protocol breadth**: ~30 outbound types including mesh overlays — tailscale,
  zerotier, easytier (embedded), wireguard, amneziawg — plus jls, restls,
  shadowquic, mieru, sudoku, trusttunnel, tlsmirror, masque, openvpn, gost
  relay (`MH adapter/outbound/` directory listing). Recent commits: Snell v6
  inbound+outbound (#3410, 2026-11-05) with optional userkey (#3460); sudoku
  "refactored and fixed issues… while also improving performance" (#3333,
  2026-10-21); ShadowTLS over X25519MLKEM768 (2026-11-14); SS multi-user
  listener (#3383, 2026-11-06).
- **Embedded mesh with memory care**: easytier-go bump "to keep guest memory
  off the Go heap" (#3454, 2026-11-11).
- **Forked dependency universe**: nearly every hot-path dependency is a
  `metacubex/*` fork (jls-quic-go, gvisor, sing-tun, tailscale, bart, bbolt…,
  `MH go.mod`), i.e. mihomo maintains its own copies of the SagerNet stack.

### 2.2 Where mihomo deliberately differs

- Compatibility-first: ShadowsocksR still shipped and still fixed (open PR
  #3445 "fix(ssr): handle partial frames"); `tls.custom-certifactes` kept as a
  deprecated *alias* (PR #3414); Go-1.20-built asset variants for old devices
  (v1.19.0 asset names `*-go120-*`, `*compatible*`); 50+ OS/arch asset
  combinations including linux mips/mips64le/loong64/riscv64/s390x, freebsd,
  windows arm.
- The Clash compatibility surface is the product: YAML config, RESTful API,
  external controllers/panels (metacubexd, `MH README.md`), providers and
  subscription parsing (subscription-userinfo fix #3455 in the Alpha notes).
- Governance by team: release notes credit many recurring contributors
  (Larvan2, wwqgtxx, xishang0128, H1JK, Skyxim, PuerNya, enfein, ForestL…) —
  contrast sing-box's single-maintainer model.

## 3. Deprecations: what each project admits failed

sing-box runs an explicit deprecation lifecycle — mark in N, remove in N+2
("Remove Deprecated Features by agreement", SB-CL:196) — and `deprecated.md`
(200 lines) plus a 1 479-line `migration.md` document the churn:

- **ShadowsocksR** (removed 1.6): "since the most commonly used proxy sales
  panel in the illegal industry stopped using this protocol, it does not make
  sense to continue to maintain it" (SB-DEP:188-193).
- **GeoIP/Geosite** (deprecated 1.8, removed 1.12): "high memory usage and
  difficult management"; "lack of maintenance, inaccurate rules"
  (SB-DEP:160-187).
- **Proxy Protocol** (removed 1.6): "added by Pull Request, has problems…
  meaningless for proxy purposes" (SB-DEP:195-200).
- **GSO in TUN** (1.11): "GSO has no advantages for transparent proxy
  scenarios" (SB-DEP:135-137).
- **uTLS for censorship resistance** (1.13 warning): "fundamental architectural
  limitations" (SB-CL:1744-1749) — the fingerprint-mimicry race conceded.
- **Everything queued for 1.16 removal** (8 items, SB-DEP:17-74): legacy DNS
  address filters → response matching; `independent_cache`; `store_rdrc`;
  inline ACME; `download_detour`; implicit HTTP client; legacy `strategy`;
  `rule_set_ip_cidr_accept_empty`. **Queued for 1.17**: the TUN `stack` option
  (SB-DEP:7-15). Each removal invalidates user configs — hence migration.md
  dwarfs most feature docs.

mihomo, by contrast, deprecates almost nothing: SSR survives (PR #3445),
legacy TLS field names survive as aliases (PR #3414), and the Clash-era config
schema is untouched. Its only real "deprecated" surface is the name itself —
the v1.17.0 rename was the one acknowledged break.

## 4. Goals as revealed by the work

| Dimension | sing-box | mihomo |
| --- | --- | --- |
| Mission | "The universal proxy platform" (repo description): one core, every protocol, every platform, own clients | Keep the Clash ecosystem alive and maximal: "Another Mihomo Kernel" (`MH README.md`) |
| Performance | Measured and published (tun_bench tables SB-CL:2286-2310); `auto_redirect` for router offload (SB-CL:3061); in-house TCP/IP stack for "peak performance, energy efficiency, and memory usage" (SB-CL:120) | Perf PR stream (GEOSITE matcher caching #3433, Windows process-table #3475, MRS decode allocations #3423); memory-first defaults (`MH config/config.go:555`) |
| Platforms | Own GUI clients for Apple/Android/Desktop (SB-CL:197, 587), 4 release tracks, JSON Schema, Schannel/Network.framework engines (SB-CL:547-553) | Headless kernel + third-party GUIs; enormous asset matrix incl. routers and Go-1.20 devices (v1.19.0 assets) |
| Anti-censorship race | Implement-or-die: Hysteria2, AnyTLS, Snell clean-room (SB-CL:250-255), Chrome QUIC parroting (SB-CL:168), TLS spoof (SB-CL:536-540), NaiveProxy > uTLS (SB-CL:1748), MASQUE (SB-CL:52) | Breadth: jls/restls/shadowquic/mieru/sudoku (entropy-shaped HTTP masking, `MH docs/config.yaml:1678-1695`)/Snell v6; PQC handshake (X25519MLKEM768) |
| Config model | Actively re-architected: rule-sets → rule actions → endpoints → typed DNS → response matching/race | Frozen by compatibility: Clash YAML + Clash API forever |
| Ecosystem | Own clients + Dashboard + gRPC API service with remote control (SB-CL:289-305) | metacubexd dashboard, CMFA Android client ("CMFA auto update-dependencies trigger", v1.17.0 notes), wiki.metacubex.one |
| License / money | GPLv3; GitHub Sponsors of the maintainer; Special Sponsor "Viral Tech, Inc. — Helping us re-list sing-box apps on the Apple Store" (SB-SPONSORS:12-16) | GPL-3; no funding docs found in repo |
| Governance | Single maintainer (nekohasekai), release-by-agreement removals (SB-CL:196) | Team of recurring committers, bot-generated release notes |
| Cadence | Majors every 4-9 months, months-long alphas, oldstable backports | Stable frozen ~2 years on v1.19.x; rolling Alpha synced continuously (2026-11-18) |

## 5. Where each is heading next

**sing-box 1.15 → 1.16** (evidence: 13 alphas through 2026-10-24, branches,
PRs):

- The in-house TCP/IP stack becomes the only TUN stack (1.17 removes the
  option, SB-DEP:7-15) — a bet that owning L3 beats gVisor and system stacks.
- HTTP as a first-class VPN substrate: MASQUE (CONNECT-IP) endpoints and the
  HTTP/2/3 + CONNECT-UDP proxy rewrite (SB-CL:50-84).
- Tailscale-adjacent mesh: Tailcat outbound/inbound + DERP client verification
  (SB-CL:88-103), after Tailscale endpoint, SSH server and Taildrop in 1.14
  (SB-CL:185, 558-567).
- Dormant-but-alive branches: `cloudflared` inbound (updated 2026-04-08), MITM
  (`dev-mitm`, 2025-02-04), Windows NDIS inbound (`dev-ndis`, 2025-01-03) —
  the MITM/NDIS threads show where product features may go.
- External PR queue is small and peripheral (Geph5 endpoint #4380,
  bandwidth-aware urltest #4398, ipset rules #4040): architecture stays
  maintainer-driven.

**mihomo Alpha** (evidence: Alpha branch log Oct-Nov 2026, open PRs):

- `mips` as default TUN stack plus easytier/zerotier/tailscale outbounds:
  mihomo is becoming a *mesh + proxy* hybrid kernel, with explicit heap-memory
  engineering (#3454).
- Protocol catch-up continues: Snell v6, sudoku polish (#3333), ShadowTLS PQC.
- Open PRs show quality-of-service work typical of a mature codebase: Mux.Cool
  client for vless/vmess (#3457), Tailscale exit-node readiness (#3467), UDP
  REJECT per-destination (#3418), a large perf/correctness sweep by one
  contributor (polaris-arch, #3421-#3437).
- No v1.20 signal exists anywhere in releases or PRs; the dual stable/Alpha
  model looks permanent.

## 6. Weak spots Segue Core can exploit (each with evidence)

1. **Config-model churn as a tax on users and GUI authors.** sing-box has
   broken configs in every recent major (8 removals pending in 1.16,
   SB-DEP:17-74; migration.md is 1 479 lines). A core with a stable, versioned
   config surface removes the #1 recurring sing-box complaint.
2. **Store and client lifecycle fragility.** sing-box's App Store/Play apps
   were declared "irrecoverable" (SB-CL:2312-2315) and returned only via a
   sponsor's developer account ("sing-box MT", SB-CL:158-167,
   SB-SPONSORS:16). An embeddable C-ABI core (Segue's model) lets app teams
   own their store identity and swap the engine without config breakage.
3. **Go runtime memory pressure on iOS-class budgets.** Both projects just
   built in-house TCP/IP stacks citing memory: sing-box's stack promises
   "substantial improvements… in memory usage" (SB-CL:120-122); mihomo made
   `mips` the default with "memory usage is more important than peak
   performance" (`MH config/config.go:548,555`) and works to move mesh guest
   memory off the Go heap (#3454). Neither escapes the GC itself — a
   Rust/no-GC core with bounded pools (Segue's design) is the structural
   answer, not another Go stack.
4. **Single-maintainer bus factor (sing-box).** One author signs the license
   (SB LICENSE), collects the sponsorship (SB-SPONSORS:9), and writes the
   multi-hundred-line release notes; the external PR queue (#4040-#4398) is
   mostly fixes. Continuity risk is real and observable.
5. **mihomo's frozen stable.** Two years of v1.19.x patches (v1.19.1 →
   v1.19.34) with every headline feature (Snell v6, mieru, `mips`, sudoku)
   locked in an unversioned rolling prerelease (created 2024-08-12). Anyone
   needing current protocols on mihomo must track nightly-grade builds — an
   opening for a core that ships both stability and current protocols.
6. **GPL-3 on both.** Code cannot be lifted into a permissive Rust core;
   ideas/protocols only, clean-room. That also means neither can absorb
   Segue's work back without relicensing friction — our differentiators stay
   ours.
7. **Protocol sprawl as maintenance debt.** mihomo carries ~30 outbounds
   including dead-weight (SSR still needs fixes, PR #3445; gost relay), and
   sing-box spends release capacity reimplementing closed protocols to stay in
   the race (Snell, SB-CL:250-255). A focused protocol set with interop tests
   (Segue's `scripts/check-*-interop.sh` pattern) ages better.
8. **Per-connection process lookup cost on Windows.** mihomo PR #3475 ("fetch
   the Windows connection table once per process lookup") confirms the
   GetExtendedTcpTable path is hot — matching the finding in our own design
   note `docs/design/…process-finding` (commit `1cc7a4fa`): a cheap, cached
   process finder is a differentiator neither rival has fully solved.
9. **Legacy API gravity (mihomo).** The Clash API and YAML schema are load-bearing for its whole GUI ecosystem (`MH README.md`; metacubexd), blocking the kind of model cleanup sing-box performs — mihomo can never deprecate its way to a better config model without abandoning its users.

## 7. Summary judgement

- sing-box evolves like a platform company product: repeated model rewrites
  (rule-sets → actions → endpoints → typed DNS → response matching), own
  clients on every OS, remote-control API, schema, four release tracks — at
  the cost of permanent config breakage and one human at the center.
- mihomo evolves like an ecosystem steward: it inherits the Clash contract,
  refuses to break it, and pours effort into protocol breadth, mesh overlays
  and memory tuning — but its stable line has been frozen for two years while
  the Alpha line carries the real product.
- Both independently concluded in 2026 that the Go/gVisor/system TUN stacks
  are the bottleneck and wrote their own TCP/IP stacks (SB-CL:120;
  `MH constant/tun.go:19`, `MH config/config.go:548`). Segue's bounded-pool
  Rust approach targets the same wall without the GC underneath — that is the
  opening.
