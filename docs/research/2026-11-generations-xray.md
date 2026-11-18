# Xray-core generational upgrades and goals (our protocol baseline)

Research note, 2026-11-17. Sources: GitHub release metadata and bodies for
XTLS/Xray-core (`gh release list/view`, tags v1.6.2 … v26.11.9), open PRs and
issues as of 2026-11-17/18, and the pinned upstream checkout
`/Volumes/dev/ci/xray/Xray-core` at `676eaf66` (= v26.11.9). Segue-side claims
were verified by grepping this repo's `crates/` and against
`docs/xray-core-v26.7.28-migration-audit.md`. Every claim cites a tag, PR
number, commit, or `file:line`.

## 1. Generations timeline

Xray-core's version scheme itself is a generation marker: classic `v1.x.y`
tags end at v1.8.24 (2024-08-30); the next tag is the date-based `v24.9.7`
(release body: SplitHTTP compatibility pinned to v1.8.24, **removal of the
QUIC and DomainSocket transports** and of ancient-config compat code, Go
1.23.1, binary 1 MB smaller). Since then releases are `vYY.M.D` pre-releases,
with an occasional "stable" promotion. Recent release bodies are often chained
pointers (`v26.7.28 → "See v26.9.9"`, `v26.9.30 → "See v26.10.21"`), i.e. one
accumulated notes page per wave, not per tag.

| # | Window | Tags | What landed | Why (arms race driver) |
|---|--------|------|-------------|------------------------|
| G1 | 2022-10 → 2023-03 | v1.6.2 → v1.8.0 | **XTLS Vision** (commit 5e695327, 2022-10-29, PR #1235); retirement of the classic XTLS modes ("Legends never die", 9e5bc07b, 2023-03-04, PR #1725); **REALITY** (commit 4d2e2b24, 2023-02-15, "THE NEXT FUTURE becomes THE REALITY NOW", first shipped in v1.8.0, 2023-03-09) | TLS-in-TLS fingerprinting of plain relays; active probing of fake SNI. Vision addresses the traffic shape; REALITY stops borrowing *forged* certificates and instead forwards the target site's real handshake |
| G2 | 2023 → 2024-06 | v1.8.x | REALITY hardening, e.g. crawler-mode crash fixes (v1.8.11, PRs #3288/#3279); Vision reader/writer refactor (v1.8.6) | Bugs under field probing; REALITY's "crawler" fallback serving real site content |
| G3 | 2024-06 → 2024-12 | v1.8.16 → v24.12.x | **SplitHTTP** transport (commit c10bd287, 2024-06-18, PR #3412, shipped v1.8.16); SplitHTTP Browser Dialer (c8f6ba9f, 2024-07-11, PR #3484); date-based versioning + removals (v24.9.7); **XHTTP**: real upload/download split (b30e05d1, 2024-10-31, PR #3955, shipped v24.10.31), `stream-one` mode (PR #4071, v24.11.30), packet-up refactor chasing stream-up (PR #4150, v24.12.18); removal of the bare HTTP transport (ae62a0fb, 2024-12-02) | CDNs that refuse WebSocket/gRPC; ALPN problems of WS; padding moved into the HTTP layer. XHTTP becomes the strategic transport ("XHTTP: Beyond REALITY", discussion #4113) |
| G4 | 2025 | v25.3.6 → v25.12.8 | XHTTP "Beyond REALITY" + MITM/domain-fronting notes (v25.3.6, discussion #4113); REALITY auto-**X25519MLKEM768** when the target supports it (v25.5.16); REALITY imitates the target's post-handshake records against the Aparecium detector (v25.6.8, issue #4778); **VLESS Encryption** — lightweight post-quantum ML-KEM-768 PFS 1-RTT / anti-replay 0-RTT AEAD (commit 7951a5c4, 2025-08-28, PR #5067); Vision `testpre`/`testseed` pre-connect (PR #5270, v25.12.8) | Traffic analysis that detects REALITY by missing `NewSessionTicket`s (Aparecium); harvest-now-decrypt-later → post-quantum; stated roadmap in v25.3.6: "next focus: Vision Seed & VLESS Encryption, Windows TUN & GUI client, ECH and REALITY post-quantum updates" |
| G5 | 2026-01 → 2026-11 | v26.1.23 → v26.11.9 | **TUN inbound** for Windows/Linux incl. Android (PRs #5464/#5509) and **Hysteria 2** outbound/transport (udphop) + Salamander udpmask (PR #5508, v26.1.23); **Finalmask**: XDNS relying on mKCP "like DNSTT" (c180c598, 2026-01-31, PR #5560), XICMP (PR #5633, v26.2.6), major expansion (PRs #5657/#5685/#5812/#5850, v26.3.27); VLESS **Reverse Proxy** (PR #5101, v25.9.11; real Source/Local transfer v25.10.15); **MASQUE** CONNECT-IP transport (7d3e44fe, 2026-09-24, PR #6807); **XDRIVE** universal remote-storage transport "ignoring IP whitelists", Google Drive backend (3461c511, 2026-09-19, PRs #5645/#6748); default uTLS fingerprint bumped to **Chrome 155+**, "untargeted by TSPU yet" (v26.11.9, issue #7259) | National-level DPI (TSPU in Russia is named explicitly in release notes); blocking of UDP/QUIC and of whole CDNs → disguise UDP over ICMP/DNS (finalmask), tunnel over cloud-storage APIs (XDRIVE); mobile clients want an in-process TUN |

Two 2026 releases were emergency security responses, not features:

- **v26.10.21** — eight Indian intermediate-CA private keys cracked because
  they were generated with weak randomness; the bundled RootCAs library
  dropped three roots and the release was rebuilt with Go 1.27.3 (two earlier
  tags, v26.10.10 and v26.10.17, were withdrawn).
- **v26.10.31** — a Linux kernel MPTCP listening-socket root hole plus Go
  1.24+ enabling MPTCP by default; MPTCP is now disabled by default (PR
  #7291). Release notes stress it affects Android clients' SOCKS/HTTP
  inbounds too.

## 2. What Xray deprecated and removed

"Non-removal" deprecations (printed by
`errors.PrintNonRemovalDeprecatedFeatureWarning`) are warnings only — the
feature keeps working, but upstream declares its successor:

| Deprecated | Successor | Cite (v26.11.9 checkout) |
|---|---|---|
| gRPC transport | "XHTTP stream-up H2" | `infra/conf/transport_internet.go:27` |
| WebSocket transport | "XHTTP H2 & H3" | `infra/conf/transport_internet.go:30` |
| HTTPUpgrade transport | "XHTTP H2 & H3" | `infra/conf/transport_internet.go:33` |
| VMess | VLESS Encryption | `infra/conf/vmess.go:65` |
| Trojan (no flow) | "VLESS with Flow & Seed" | `infra/conf/trojan.go:43` |
| Shadowsocks | VLESS Encryption | `infra/conf/shadowsocks.go:50` |
| `freedom.fragment` | `streamSettings.finalmask.tcp` | `infra/conf/freedom.go:97` |
| `freedom.noises` | `streamSettings.finalmask.udp` | `infra/conf/freedom.go:154` |
| `freedom.domainStrategy` | `sockopt.domainStrategy` (auto-migrated, removal planned) | `infra/conf/xray.go:422` |
| `allowInsecure` & friends | secure alternatives | commit 5836f36f "Config: Add Warning for deprecated features" |

Actually removed: QUIC and DomainSocket transports (v24.9.7 release body), the
bare HTTP/H2 transport (commit ae62a0fb, 2024-12-02), pre-v1.8 compat config
code (v24.9.7). Classic XTLS (non-Vision) modes were removed in the 2023
"Legends never die" cleanup (9e5bc07b, PR #1725).

Reading of the arc: every legacy transport (gRPC/WS/HTTPUpgrade/H2) is
funnelled into XHTTP; every legacy credential scheme (VMess/Trojan/SS) is
funnelled into VLESS with flow + VLESS Encryption; and per-outbound tricks
(fragment/noise) move into the stream layer as `finalmask`.

## 3. Goals and governance

- **Org**: "Project X" (github.com/XTLS) "originates from XTLS protocol",
  providing Xray-core and REALITY (README, first paragraph). License:
  Mozilla Public License 2.0 (README, "License").
- **People**: every release in the examined window was published by **RPRX**
  (release metadata, e.g. v1.8.0, v26.11.9); the release notes are first-person
  and single-voiced. v26.10.21's notes even mention that full notes for a
  half-year of updates are written in one go, and that "latest" was moved to a
  pre-release tag mid-cycle.
- **Funding**: sponsors (Remnawave, Happ, BlancVPN per README "Sponsors"),
  crypto donations and an NFT collection ("Announcement of NFTs by Project X",
  discussion #3633; README "Donation & NFTs" also links PR #5067 and
  discussion #4113 as canonical feature write-ups).
- **Documentation**: xtls.github.io; community support runs on Telegram
  channels (README "Telegram"). Sharing-link standard lives in discussion
  #716, updated per release (cited by v26.2.6 for `fm`/`pcs`/`vcn` params).
- **Cadence**: frequent dated pre-releases, occasional withdrawn tags, and
  "stable" promotions roughly monthly (see the release list, 2024-09 → now).
- **Direction statements**: the v25.3.6 roadmap quote in §1 G4; the v26.x
  line is execution of it plus the finalmask/XDRIVE platform bets.

## 4. Where it is heading (open PRs / issues, 2026-11-17)

- **XDRIVE hardening** dominates: S3 object deletion ordering (PR #7439),
  cancel pending storage ops on interrupt (#7421), ring-slot reuse before
  upload completes (#7415), WAL segment retry (#7410); issues on S3 412
  errors (#7428) and orphaned sessions after client disconnect (#7208).
- **Finalmask/XMC**: bound padding schedules + stop compressing frames (PR
  #7423); Yggdrasil (Minecraft) third-party login and texture verification as
  a feature request (#7394) with an implementation PR (#7416).
- **XHTTP/3**: drain connections filled by long-lived streams (#7440), close
  the UDP socket on failed QUIC dial (#7413), and an inbound default of 100
  QUIC streams that stalls packet-up uploads (issue #7397).
- **Post-quantum shaping**: pick the `random` uTLS fingerprint only from
  fingerprints that carry X25519MLKEM768 (PR #7432) — continuation of the G4
  post-quantum push.
- **Correctness backlog**: Vision panic/data-loss on oversized buffers
  (#7438), Vision never switching to direct copy on back-to-back records
  (issue #7164), `XtlsPadding` slice panic (issue #7369), concurrent REALITY
  dials sending only the first ClientHello segment (issue #7306), gRPC hunk
  reads larger than buf.Size (#7424), cached gRPC outbounds surviving
  `Instance.Close` (issue #7177).
- **VLESS multiplexing directly on transport** (PR #7364) — notable
  architecture change candidate for mux.cool.
- **TUN lifecycle**: end UDP flows when the inbound closes (#7350);
  `sockopt.interface` silently dialing unbound and looping back into the TUN
  (issue #7160); Linux `process` routing for IPv4-mapped sockets (#7414).

Take-aways for Segue: XDRIVE, finalmask/XMC and XHTTP/3 are the active
surfaces (expect continued wire churn); PQ-capable fingerprint selection is a
cheap, high-signal parity item; the #7160/#7306/#7164 bug classes are exactly
the ones our own TUN/REALITY paths can share.

## 5. Feature parity: Xray feature → Segue status

Grep-verified in this repo on 2026-11-17 (branch `bee/gen-xray`). "have" =
real implementation found; "partial" = config surface or a subset only;
"missing" = not found and not required by upstream's current surface.

| Xray feature | Introduced upstream | Segue status | Where / cite |
|---|---|---|---|
| VLESS + Vision flow | #1235, 5e695327 (2022) | have | `crates/segue-proxy/src/vless/{vision.rs,vision_stream.rs,wire.rs,udp.rs}` |
| VLESS Encryption (ML-KEM-768) | #5067, 7951a5c4 (2025-08) | have | `crates/segue-vless-encryption/src/{crypto,handshake,session,stream,padding}.rs` |
| REALITY | 4d2e2b24 (2023-02), v1.8.0 | have | `crates/segue-transport/src/reality.rs`, `reality_{connector,runtime,rustls}.rs`; ClientHello advertises the `[26,7,28]` marker (`docs/xray-core-v26.7.28-migration-audit.md:29`) |
| REALITY spider/crawler + post-handshake imitation | v1.8.11 crawler; v25.6.8 imitation | partial | `crates/segue-transport/src/reality_spider.rs` (crawler fallback); post-handshake `NewSessionTicket` imitation not verified |
| uTLS fingerprint pool | v1.8.x → now | have | `crates/segue-utls/`, `crates/segue-transport/src/utls_profiles.rs`; target's eleven-profile pool incl. `hellochrome_133` (`docs/xray-core-v26.7.28-migration-audit.md:34`) |
| Chrome 155+ default fingerprint | v26.11.9, #7259 | have | `crates/segue-utls/src/lib.rs`, `crates/segue-transport/src/utls_profiles.rs` (chrome-155 profiles present) |
| TLS ECH | v25.8.3 era client improvements | partial | 21 files match `encrypted_client_hello`/ECH (client-side); server/ECH-config surface not verified |
| TLS fragment | `freedom.fragment` → finalmask.tcp | have | `crates/segue-transport/src/fragment.rs` |
| UDP noise / Salamander mask | #5508 (v26.1.23) | have | `crates/segue-transport/src/udp_noise.rs`, `udp_mask/` |
| Finalmask (realm, XMC, XICMP, XDNS) | #5560/#5633 (v26.2.6), #5657+ (v26.3.27) | have | `crates/segue-transport/src/{realm,xmc,xicmp,xdns}/`, `crates/segue-config/src/parser/xdns/` |
| mKCP | original Xray | have | `crates/segue-transport/src/kcp/` |
| XHTTP / SplitHTTP | #3412 (v1.8.16) → #3955 (v24.10.31) | have | `crates/segue-transport/src/stream/xhttp/`, tests `stream_xhttp_{h2,transport}_tests/`; `maxConnections=3` explicit-defaults parity (`docs/xray-core-v26.7.28-migration-audit.md:41`) |
| WebSocket | original Xray (deprecated → XHTTP) | have | `crates/segue-transport/src/stream/{websocket.rs,websocket_frame.rs}` |
| HTTPUpgrade | original Xray (deprecated → XHTTP) | have | `crates/segue-transport/src/stream/httpupgrade.rs` |
| gRPC | original Xray (deprecated → XHTTP) | have | `crates/segue-transport/src/stream/grpc/` |
| H2 (extended CONNECT) | as XHTTP-H2; bare `http` network removed ae62a0fb | have | `crates/segue-transport/src/stream/{http2_connect.rs,h2_bdp.rs}` |
| TCP + header obfs (http) | original Xray | have | `crates/segue-transport/src/{header_custom/,stream/http_headers.rs}` |
| Browser masquerading headers | v26.3.27 ("Global HTTP headers' browser masquerading") | have | `crates/segue-transport/src/stream/masquerade.rs` |
| MASQUE (CONNECT-IP) | #6807, 7d3e44fe (2026-09) | have | `crates/segue-transport/src/masque/` |
| XDRIVE | #5645/#6748, 3461c511 (2026-09) | have | `crates/segue-transport/src/xdrive/` |
| Hysteria 2 + udphop + congestion | #5508 (v26.1.23), #5549 | have | `crates/segue-proxy/src/hysteria/`, `crates/segue-transport/src/hysteria/` |
| TUN inbound (Win/Linux/Android) | #5464/#5509 (v26.1.23) | have | `crates/segue-tun/`, `crates/segue-engine/src/tun*` |
| TPROXY / transparent sockopt | original Xray (Linux) | partial | `crates/segue-transport/src/socket_options.rs`, `crates/segue-config/src/model.rs`; no dedicated tproxy inbound module |
| SOCKS / HTTP inbounds | original Xray | have | `crates/segue-engine/src/{socks.rs,http.rs,http_forward.rs}` |
| VLESS Reverse Proxy | #5101 (v25.9.11) | have | `crates/segue-proxy/src/reverse.rs` |
| Tunnel inbound `portMap` | commit 146b14ab (v25.8.3) | partial | `crates/segue-config/src/{model.rs,surface.rs}` accept it; runtime mapping unverified |
| VMess | original Xray (deprecated → VLESS Enc.) | have | `crates/segue-proxy/src/vmess/` |
| Trojan | original Xray (deprecated) | have | `crates/segue-proxy/src/trojan/` |
| Shadowsocks + SS2022 | original Xray (deprecated) | have | `crates/segue-proxy/src/{shadowsocks,shadowsocks2022}/` |
| WireGuard | v1.8.x era | have | `crates/segue-wireguard/` |
| XUDP | original Xray | have | `crates/segue-proxy/src/vless/udp.rs` |
| Mux (mux.cool) | original Xray | have | `crates/segue-proxy/src/mux.rs` |
| DNS app + FakeDNS | original Xray | have | `crates/segue-engine/src/{dns.rs,dns_outbound.rs,fake_dns.rs}` |
| Routing geoip/geosite | original Xray | have | `crates/segue-routing/src/{mrs.rs,srs.rs,domain_matcher.rs,ip_range_set.rs}` |
| Observatory / BurstObservatory | v1.7-1.8 era | partial | `ObservatoryConfig` in `crates/segue-config/src/model.rs` + probes in `crates/segue-engine/src/health.rs`; no separate observatory service |
| Global gRPC API service | original Xray | missing | no match for a gRPC API server in `crates/` |
| Browser Dialer | #3484 (v1.8.21 era) | missing | 0 matches in `crates/` |
| QUIC / DomainSocket transports | removed upstream (v24.9.7) | missing by design | 0 matches; upstream dropped them |

Segue-side extras that upstream Xray does not have: TUIC and AnyTLS
(`crates/segue-proxy/src/{tuic.rs,anytls/}`), ShadowTLS
(`crates/segue-transport/src/shadowtls.rs`), Sudoku (Segue-original, interop
gated by `scripts/check-sudoku-interop.sh`), plus chrome-parrot and
penetrating-TLS shaping modules (`crates/segue-transport/src/{chrome_parrot.rs,penetrating_tls.rs}`).

## 6. Sources

- Release list and bodies: `gh release list -R XTLS/Xray-core -L 120`;
  bodies for v1.8.0, v1.8.6, v1.8.11, v1.8.16, v1.8.24, v24.9.7, v24.10.31,
  v24.11.30, v24.12.18, v25.1.30 … v26.11.9 (release-metadata author field,
  emergency-update notes, "See …" chains).
- Upstream checkout `/Volumes/dev/ci/xray/Xray-core` @ 676eaf66 (v26.11.9):
  README.md; `infra/conf/{transport_internet,transport_finalmask,vmess,trojan,shadowsocks,freedom,xray}.go`;
  `transport/internet/` module list and first-touch git history for
  reality/splithttp/finalmask/hysteria/masque/xdrive; `git log -S` for Vision
  (5e695327), XHTTP naming (b30e05d1), VLESS Encryption (7951a5c4).
- Open PRs/issues: `gh pr list -R XTLS/Xray-core -L 30 --state open`,
  `gh issue list -R XTLS/Xray-core -L 15 --state open` (2026-11-17/18).
- Segue: `rg` over `crates/` (this worktree, branch `bee/gen-xray`);
  `docs/xray-core-v26.7.28-migration-audit.md`.
