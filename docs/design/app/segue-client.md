# `segue-client`: the portable crate every Segue app links

Status: design. Owner: apps. Written 2026-11-17.
Related: [`docs/research/apps/tono-and-segue-app-suite.md`](../../research/apps/tono-and-segue-app-suite.md),
[`docs/design/ffi-kernel-embedding.md`](../ffi-kernel-embedding.md),
[`docs/design/ai-lock.md`](../ai-lock.md), [`docs/ffi.md`](../../ffi.md),
`crates/segue-kernel/src/`, `crates/segue-ffi/`.

Paths written `tono_core/src/…` and `apps/…`/`tooling/…` are Tono's, in the
read-only clone at `/Volumes/dev/ref/apps/tono`
(revision `006984ae211056ea2f921c93d0b6e74f6c7f3a5e`, the one the research doc
pins); everything else is relative to this repository.

Owner decisions this document is written against (2026-11-17): Segue is the
owner's own consumer product; macOS ships first, Windows and phones later; the
goal is a beta the owner can hand to users as fast as possible, so **Tono's
working code is reused rather than re-derived** — Tono is also the owner's own
product, so its source may be copied, not just its shape.

Two consequences run through everything below:

1. **The fastest macOS path is not the C ABI.** `segue-kernel` already runs as
   a process with a loopback control API and a token file
   (`crates/segue-kernel/src/config.rs:49`, `crates/segue-kernel/src/control.rs:1-33`).
   Tono's macOS helper already supervises a core child process and drives its
   control API over loopback (`tooling/scripts/core-helper/CoreManager.swift`,
   `apps/macos/Tono/Core/CoreControllerClient.swift`). So the macOS beta is
   Tono's app+helper with the core swapped, not a new FFI surface.
2. **`segue-client` is still worth building first**, because the control API
   moves between the process and embedded modes, and three shells must not
   each re-derive catalog admission, policy verification and the connect FSM
   in their own language — which is exactly what Tono ended up doing
   (`Catalog.swift`, `Catalog.kt`, `catalog.rs`, three hand-kept twins).

---

## 1. Scope

| Layer | Owns | Does not |
| --- | --- | --- |
| **`segue-client`** (new, portable Rust, `#![forbid(unsafe_code)]`) | Account/session wire models; catalog admission + cache; ticket + signed-policy handling; **`prepare()`** (catalog + policy + ticket → kernel config); the connect FSM and the user-intent rule; the update contract; the status snapshot the UI renders | Any OS call; any socket it did not receive through a trait; any privileged decision |
| **`segue-kernel`** (existing, proprietary) | In-tunnel enforcement: rule table, smart DNS/fake-IP, AI tier, kill-switch verdicts and posture, session exits/pinning | Arming a firewall; knowing whether the user has left; fetching anything |
| **`segue-ffi`** (existing, MPL-2.0) | The C ABI: engine mode today, kernel mode ABI 1.18 staged | Product policy |
| **App shell** (SwiftUI / Tauri+React / Compose, lifted from Tono) | Rendering, sign-in UI, exit picker, copy | Arming/disarming protection; deciding "connected" |
| **Privileged component** (macOS root LaunchDaemon; Windows LocalSystem service; none on iOS/Android) | Out-of-tunnel enforcement (PF/WFP/nftables), DNS, core supervision, the arm/disarm latch, the update executor | Routing decisions; catalog trust |

`segue-client` reaches the OS only through five injected ports, the same shape
that keeps `tono-core` portable and testable (`tono_core/src/auth.rs:892`,
`tono_core/src/credentials.rs:46`):

```rust
pub trait HttpTransport      { async fn send(&self, req: ApiRequest) -> Result<ApiResponse, TransportError>; }
pub trait CredentialStore    { fn get(&self, k: CredentialKey) -> Result<Option<Secret>, CredentialError>; /* … */ }
pub trait DataPlane          { fn apply(&self, plan: &KernelPlan) -> Result<(), DataPlaneError>; /* connect/probe/poll … */ }
pub trait Protector          { fn arm(&self, req: &ArmRequest) -> Result<ArmAck, ProtectorError>; fn disarm(&self, req: &DisarmRequest) -> Result<Ack, ProtectorError>; fn status(&self) -> ProtectorStatus; }
pub trait Clock              { fn now_unix(&self) -> u64; fn monotonic_ms(&self) -> u64; }
```

Production bindings: `HttpTransport` = the shell's HTTP client; `CredentialStore`
= macOS Keychain / Windows Credential Manager / Android Keystore-backed store;
`DataPlane` = the kernel binary's control API (macOS beta) or `segue-ffi` kernel
mode (mobile); `Protector` = the helper's IPC client. Test bindings are
in-memory, which is what makes the conformance vectors (§5) runnable.

---

## 2. Data model

All wire documents are compact UTF-8 JSON with `deny_unknown_fields`, a
`schemaVersion` integer, sorted object keys when signed, and a hard byte cap.
Unknown fields or versions are refused, never ignored — the rule Tono's update
contract states and its tests enforce (`tono_core/src/update_contract.rs:1-5`,
`tooling/scripts/tests/fixtures/update-protocol-v1/conformance.json`).

### 2.1 Account and device

| Thing | Shape | Notes |
| --- | --- | --- |
| Account session | `{account_id, plan, entitlement, access_token, refresh_token, expires_at}` | Access token in memory only; refresh token in `CredentialStore` (`tono_core/src/credentials.rs:23`, `:46`) |
| Device | `{device_id, name, platform, install_id}` | `device_id` is what tickets and the revocation list name (`crates/segue-relay/src/ticket.rs:37-56`) |
| Errors | The account/entitlement code table from `tono_core/src/auth.rs` (`endpoints`, `:28`) with Tono's semantics | `403 PLAN_EXPIRED`/`QUOTA_EXHAUSTED` = account hold, keep tokens; `401` = session ended. Reused verbatim minus the Tono host names |

### 2.2 Catalog

One signed, digest-pinned, revision-monotonic document: `{schemaVersion:1,
revision, issued_at, expires_at, ai_route, nodes[]}`. A node is

```json
{"id": 12, "name": "la-1", "region": "us",
 "outbound": { …one Xray-style outbound object… },
 "relay": "10.0.0.4:7443", "node_id": 12,
 "egress_group": "us-west", "roles": ["overseas"]}
```

`outbound` is exactly what `KernelConfig::parse_in` accepts
(`crates/segue-kernel/src/config.rs:322-327`); `relay`/`node_id`/
`egress_group` are exactly `session::Exit` fields
(`crates/segue-kernel/src/session/mod.rs:100-124`). **AI lock pins within
`egress_group`** and an absent group means the exit is its own group — that
rule already lives in the kernel (`Exit::group`, `crates/segue-kernel/src/session/mod.rs:113-121`) and
`ai-lock.md` §"Exit pin"; `segue-client` must not restate it, only carry it
into `prepare()`.

Admission, adapted from `tono_core/src/node.rs:1-40` (`admit_nodes` `:490`)
and `tono_core/src/catalog.rs:1-12`:

* revision strictly greater than the persisted high-water; same revision with a
  different digest is refused, same digest is idempotent (`CatalogTracker`,
  `tono_core/src/catalog.rs:304`);
* ≤ 200 nodes (`tono_core/src/node.rs:17`), digest over the exact bytes;
* node `name` unique, matching `[A-Za-z0-9._-]{1,64}`, never a reserved name
  (the kernel's route tags plus `auto` and `direct`);
* `relay` a literal IP:port; `outbound.server` a literal public IP; no
  user-supplied trust booleans, no `skip-cert-verify`-equivalent (`tono_core/src/node.rs` admission rules);
* only whitelisted node fields survive into the validated value;
* cache written atomically under the state dir, re-validated on read
  (`CatalogCache`, `tono_core/src/catalog.rs:470`).

### 2.3 Signed policy bundle

Unchanged from Segue Core: the `segue-policy` envelope (`crates/segue-policy/src/lib.rs:1-30`),
Ed25519 over `"segue-policy-v1\0" ‖ body`, body `{version, expires_at,
ai_domains, ai_cidrs, rules, default, chnroute}` (`crates/segue-kernel/src/policy.rs:1-38`).
`segue-client` **does not parse the body**. It:

* caps size at `MAX_BUNDLE_BYTES` (8 MiB, `segue-policy/src/lib.rs:29`);
* forwards the bytes to the data plane, which is the only verifier
  (`PolicyStore::install`, `crates/segue-kernel/src/policy.rs:476`);
* surfaces `PolicyError` (`:189`) as UI copy, and reads back `PolicyStatus`
  (`:363`: `valid`, `version`, `expires_at`, `high_water`) to show
  "policy expired" before the user sees a dead tunnel;
* only pre-reads `{version, expires_at}` — unverified, for UX ordering — and
  never treats that read as authority.

Rollback protection is the kernel's `high_water` plus atomic persistence
(`policy.rs:476-520`); expiry is `expires_at` against the injected clock. The
control plane rolls back by publishing a newer version; the client never
accepts an older one. Clock skew is a known exposure
(`ffi-kernel-embedding.md` §8 Q9): `segue-client` records the server `Date`
per response and refuses to install a bundle whose `expires_at` is behind the
last observed server time, so a wrong device clock cannot silently expire a
valid policy.

### 2.4 AI destination list updates

There is no separate channel. The AI list **is** `ai_domains`/`ai_cidrs` in the
bundle (`ai-lock.md`:34-41), merged by the kernel with the compiled-in list
(`crates/segue-kernel/src/rules.rs:194-200`, `data/ai-lock.txt`). The built-in
list is never version-gated and never removed — a bundle that omits
`claude.ai` still locks it. `segue-client`'s only job is to fetch a newer
bundle when `version` advances or on a slow refresh, and to keep serving the
last good one otherwise.

### 2.5 Tickets

`SGT1.` + base64url(payload) + `.` + base64url(signature), ≤ 2048 bytes
(`crates/segue-relay/src/ticket.rs:1-27`), claims `{v, key_id, device_id,
account_id, plan, exit_classes, ai_anchor_node_id, not_before, not_after}`.
A ticket is a bearer secret: `segue-client` writes it `0600` into the state dir
as the file the kernel's `ticket_file` names (`crates/segue-kernel/src/config.rs:421-433`),
keeps it out of the status snapshot, every log line and every error string, and
zeroises the buffer. Renewal is a control-plane call that returns a new ticket
before `not_after` minus a margin; a missing renewal is a *scheduled* expiry
that the UI states, not a connect failure.

---

## 3. Connect FSM

Nine states, one owner each. `segue-client` owns the FSM; the privileged
component owns whether protection is actually armed; the kernel owns posture.
`ClientStatus`'s `phase` is derived from all three and is the only thing the UI
renders (the `tono_core/src/connection.rs:63-100` shape: flags plus a derived
`UiState`, not a second state enum in the UI).

| State | Meaning | Armed | Tunnel held | Shows "connected" |
| --- | --- | --- | --- | --- |
| `Off` | Never connected this launch, or user disconnected | no | no | no |
| `Preparing` | Admission, cache read, `prepare()`, token/file writes | no | no | no |
| `Arming` | Protector arm sent, not acknowledged | **intent recorded** | yes (intent) | no |
| `Connecting` | Kernel `connect` + `probe`, waiting for a carrier | yes | yes | no |
| `Verifying` | Exit evidence + AI-route evidence collected | yes | yes | no |
| `Connected` | All of §3.2 verified | yes | yes | **yes** |
| `ProtectedOffline` | Armed, no carrier; auto-reconnect ladder with backoff | yes | yes | no |
| `Disarming` | Explicit release in flight | yes→no | yes | no |
| `Failed` | Failed **before** arm, or after an explicit release | no | no | no |

Transitions:

| From | Event | To | Side effect |
| --- | --- | --- | --- |
| `Off`/`Failed`/`ProtectedOffline` | user connect | `Preparing` | new `generation` (monotonic, per launch) |
| `Preparing` | catalog/policy/ticket invalid | `Failed` (or `Off` if never verified) | reason recorded, nothing armed |
| `Preparing` | `prepare()` ok | `Arming` | arm intent persisted **before** the call |
| `Arming` | arm ack ok | `Connecting` | kernel `set_user_enabled(1)`, `probe` |
| `Arming` | arm error | `Arming` (retry, surfaced) | arm intent stays recorded; **never** auto-disarm; the UI shows the protector's reason |
| `Connecting` | posture `Connected` | `Verifying` | |
| `Connecting` | posture `Error` and session verified | `ProtectedOffline` | backoff ladder (2/5/10/20/30 s, 30 min budget) |
| `Connecting` | posture `Error`, never verified | `Failed` | initial attempt releases (nothing to protect yet) |
| `Connected` | carrier lost / network change | `ProtectedOffline` | protection stays armed |
| `ProtectedOffline` | backoff tick, probe ok | `Connecting` | |
| `Connected`/`ProtectedOffline` | **explicit user disconnect** | `Disarming` | disarm intent with `intent: "user_disconnect"` |
| `Connected`/`ProtectedOffline` | sign-out / quit | `Disarming` | `intent: "sign_out"` / `"quit"` |
| `Disarming` | ack | `Off` | |
| `Disarming` | no ack | `Disarming` (retry, surfaced) | a lost disarm reply is **not** a release |
| any | crash / restart | `Off` **with persisted intent** | see §3.3 |

### 3.1 The user-intent rule

**Only an explicit user disconnect, sign-out or quit disarms protection.** No
timeout, crash, exhaustion, 4xx, revoked credential, update or catalog failure
does. This is `ai-lock.md`'s statement, `killswitch.rs`'s structure
(`KillSwitch::hold_tunnel`, `crates/segue-kernel/src/killswitch.rs:132-134`: the
tunnel is held in every posture but `Disconnected`) and Tono's decision 134
(`docs/decisions/134-2026-10-24-state-intent-rule.md`: intent survives later
tunnel events; a user stop writes no failure).

Mechanically:

* `ClientStatus.intent` records `{kind: connect|disconnect|sign_out|quit, generation, at}`;
  a later tunnel-side "down"/"failed" from the same generation cannot overwrite
  it (Tono's rule 1 and 6, `docs/contracts/state-intent-scenarios.json`).
* `DataPlane::disconnect` and `Protector::disarm` are reachable from exactly
  three call sites: `disconnect(UserDisconnect)`, `disconnect(SignOut)`,
  `disconnect(Quit)`. There is no `release()` on the public API.
* A failure path calls `Protector::arm` again, never `disarm`. An arm whose
  reply was lost leaves the intent recorded (Tono's most leak-prone edge,
  `KillSwitchService.arm`'s catch block; `HelperManager.cleanUpAbandonedUpgrade`).

### 3.2 What "connected" requires

All four, in this order, or the state stays `Verifying`:

1. **Arm ack** from the protector: rules installed and read back
   (`GET /v1/status` shows `armed` with this generation).
2. **Carrier**: kernel posture `Connected` from
   `xray_kernel_status_snapshot_json` (embedded) or `GET /v1/status` (process
   mode) — not "the process started", which is what "started" has always meant
   (`ffi-kernel-embedding.md` §2.2 and the `xray_core_start` caveat in the Tono
   doc §6.3).
3. **Protected exit evidence**: a probe *through* the tunnel that the protector
   also observes — Tono's stamped-reply rule
   (`TonoKit/Sources/TonoKit/TunnelConfirmation.swift`) and Windows
   SECURITY.md invariant 7. The app's own claim is not evidence.
4. **AI route evidence**: the policy is valid (`PolicyStatus.valid`) and the AI
   route resolves in `KernelPlan` (a flow to an `ai_domains` name would be
   `Proxy(ai)` in the current posture; asserted in `prepare()` against the
   catalog, not at runtime).

### 3.3 Signals the privileged component receives

Exactly two mutating signals plus one evidence channel. Everything else is a
read.

```
POST /v1/arm     {"schemaVersion":1, "generation":G, "intent":"user_connect",
                  "anchor_revision":R, "manifest_digest":"<hex>",
                  "egress":[{"ip":"…","port":443}, …],
                  "exit_ifaces":["utun4"], "strict":false,
                  "evidence":{"policy_version":V,"posture":"connecting"}}
POST /v1/disarm  {"schemaVersion":1, "generation":G,
                  "intent":"user_disconnect"|"sign_out"|"quit"}
GET  /v1/status  → {"armed":bool,"generation":G,"held":bool,
                    "rules_digest":"…","evidence":{"tcp_proof_ms":…,"dns_readback":bool},
                    "last_error":null}
```

Semantics, all lifted from Tono's helper because each encodes a shipped failure:

* **The protector decides, the app proposes.** `egress` and `exit_ifaces` are
  candidates; the helper validates them against its own admitted snapshot and
  refuses unknown fields (`validateKillSwitchArmFields`,
  `tooling/scripts/core-helper/main.swift:72-76`) and refuses to arm a strict
  grant when the core is not running (`SocketServer.swift:960-963`).
* **`disarm` is refused without an explicit intent**, and the only intents are
  `user_disconnect`, `sign_out` and `quit`. Tono's helper routes are
  `POST /killswitch/arm`, `/disarm`, `/release`, `/quit`
  (`SocketServer.swift:955-1005`); Segue ships the first two with `intent` in
  the body, so a client bug cannot silently release by omitting a field.
* **Evidence is measured by the protector**, not supplied by the app: the TCP
  proof to the egress endpoints (Tono's `TcpEndpointProof.swift`,
  `unarmed_probe.rs:1-8`) and the DNS restore read-back (Windows refuses to
  disarm unless the read-back succeeded; a timeout counts as unproven).
* **Release order is fixed**: DNS restored → then firewall withdrawn; an
  unproven restore is a failure, not a success.
* **Generations fence everything** (`HelperSessionGeneration.swift`): an arm or
  disarm from an older generation is refused, so a late request cannot touch a
  newer session.
* **A separate release daemon** exists on both desktops
  (`com.raydocs.tono.release`; `TonoRelease`) so a helper blocked in an update
  cannot delay "restore my internet". Reuse as-is.

In mobile there is no separate protector: iOS `NEPacketTunnelProvider` and
Android `VpnService` are the only enforcement point, so `Protector` is a local
implementation whose `arm`/`disarm` are the intent record plus
`includeAllNetworks`/always-on state, and `segue-client` must not claim
out-of-tunnel protection it does not have (`ai-lock.md`:136-142).

---

## 4. Public API and shell binding

### 4.1 Rust surface (sketch, not final)

```rust
pub struct Client { /* ports + state machine + caches */ }

impl Client {
    pub fn new(cfg: ClientConfig, ports: Ports) -> Result<Self, ClientError>;

    // account
    pub fn sign_in_email_start(&self, email: &str) -> …;
    pub fn sign_in_email_verify(&self, code: &str) -> …;
    pub fn sign_out(&mut self) -> …;                 // → Disarming { intent: SignOut }

    // content
    pub fn install_catalog(&self, bytes: &[u8]) -> Result<CatalogInstall, ClientError>;
    pub fn install_policy(&self, bytes: &[u8]) -> Result<PolicyView, ClientError>;
    pub fn install_ticket(&self, bytes: &[u8]) -> Result<TicketView, ClientError>;

    // data plane
    pub fn prepare(&self) -> Result<KernelPlan, ClientError>;   // pure; see 4.2
    pub fn connect(&mut self) -> Result<(), ClientError>;
    pub fn disconnect(&mut self, intent: DisarmIntent) -> Result<(), ClientError>;
    pub fn select_exit(&mut self, choice: ExitChoice) -> Result<(), ClientError>;

    // observation
    pub fn status(&self) -> ClientStatus;                        // the UI's one input
    pub fn poll_event(&mut self) -> Option<ClientEvent>;
    pub fn tick(&mut self, now_ms: u64) -> Vec<Effect>;          // backoff, deadlines
}
```

`prepare()` is the pure half and the replacement for Tono's
`build_owned_runtime` (`tono_core/src/config.rs:393`); `DataPlane::apply`
writes it and starts the data plane. Inputs are catalog + policy + ticket → one
`KernelPlan` consisting of the `KernelConfig` JSON
(`listen`, `outbounds`, `exits`, `segue` routes with `ticket_file`, `policy`
with `public_keys`/`installed`, `dns`, `udp`, and **no** inline `rules`/`default`
in product mode — `crates/segue-kernel/src/config.rs:491` refuses them) plus
the files to write. It is pure and total: the same inputs always produce the
same bytes, which is what the vectors in §5 pin.

`ClientStatus` is one JSON-able value: `{schemaVersion, phase, intent,
generation, connected_at, exit_choice, current_exit, exits[], policy{valid,
version, expires_at}, protection{armed, mode, held}, failure{code, stage,
retry_at}, user_copy}`. Failure codes stay internal; the UI gets `user_copy`
(Tono's rule 4 and 5: no silent no-op, no internal code on screen).

### 4.2 Binding per shell — C ABI for mobile, direct Rust or IPC for desktop

| Shell | How it links | Why |
| --- | --- | --- |
| **macOS (beta)** | Swift → **helper IPC** (§3.3); helper → `segue` kernel **process** (control API). No FFI at all in v1. | Zero new ABI work; both sides already exist (Tono helper + `segue-kernel` control server, `crates/segue-kernel/src/main.rs:95-108`) |
| **macOS (v2) / iOS** | Swift → **C ABI** (`segue-ffi`), kernel mode ABI 1.18 | Already the shipping shape: `XrayCore.swift:2` is `import XrayRust` over the checked-in header, 2227 lines of adapter with version/capability gates |
| **Windows** | Rust → `use segue_client` directly (Tauri command layer) | No ABI, no marshalling; Tono does the same (`tono-core = { path = … }`) |
| **Android** | Kotlin → **JNI over the same C ABI** | `platform/android/xraymobile/` already does this (`XrayCore.kt` 1302 lines) |
| **Linux** | Rust direct | As Windows |

**Rejected: UniFFI.** It would add a codegen toolchain to a repository that has
none (and a rule against installing one), produce a second ABI with its own
versioning rules alongside a header that already has an `nm` symbol test, a
capability-bit test and a `-Wall -Wextra -Werror -std=c11` C harness
(`docs/design/ffi-kernel-embedding.md` §7 items 1–3), and give Swift nothing
the existing adapter does not already do. **Rejected: cbindgen** — the header is
hand-maintained today on purpose (`crates/segue-ffi/include/segue_ffi.h:595-598`
uses `#ifdef` blocks that a generator does not express cleanly), and the
compile-time `_Static_assert` shim in `platform/apple/Sources/XrayKernelControl/XrayKernelControl.c`
is the real check.

### 4.3 ABI and versioning rules

Inherit `docs/ffi.md:8-50` unchanged:

1. Major stays `1`. Minor is additive and moves with every new symbol or
   capability bit (`XRAY_FFI_ABI_MINOR` is already feature-dependent, 17/18,
   `crates/segue-ffi/src/lib.rs:36-46`).
2. **No new `XrayStatus` values.** Kernel and client outcomes map onto the
   existing nine plus `PANIC` (`ffi-kernel-embedding.md` §3.3).
3. New client surface gets **one** capability bit (`1 << 37`,
   `XRAY_FFI_CAPABILITY_CLIENT`) and a **JSON-typed** surface — one
   `xray_client_*` call per verb plus `client_status_snapshot_json` — so adding
   a field never grows a struct. Only the two hot-path structs use
   `struct_size`.
4. A Swift adapter must check major, then the capability bit before calling an
   optional symbol — the pattern `XrayCore.swift` already implements.
5. `segue-client`'s own crate version is not the ABI version and must never be
   inferred as one (`docs/ffi.md:35-37`).

---

## 5. Conformance vectors

One directory, one format, three consumers:
`tests/fixtures/segue-client/v1/`.

| File | Drives |
| --- | --- |
| `catalog/accept.json`, `catalog/reject.json` | Admission: digest, revision, reserved names, non-public IP, >200 nodes, unknown field |
| `policy/accept.json`, `policy/reject.json` | Fixed synthetic Ed25519 pair; rollback, expiry, bad signature, oversized, unknown `key_id` |
| `fsm/transitions.json` | `(state, event) → (state, armed, held, shows_connected)`; includes every "a failure never disarms" row |
| `intent/scenarios.json` | The user-intent table: adapted from `apps/tono/docs/contracts/state-intent-scenarios.json`, with Segue's own rows and an `enforcement` field per shell (`enabled` / `expected-failure` / `todo` — todo is not a pass) |
| `status/snapshots.json` | Event sequence → `ClientStatus` JSON, byte-exact |
| `plan/plans.json` | catalog + policy + ticket → exact `KernelPlan` JSON (digest-pinned), and a refusal set |

Format rules, from Tono's fixtures
(`tooling/scripts/tests/fixtures/update-protocol-v1/conformance.json`):
`fixtureVersion`, named cases, **mutations by `find`/`replace` on a known-good
document** rather than hand-written invalid blobs (so a case cannot drift from
the real format), and synthetic data only — no live endpoint, UUID, key or
token ever lands in the repository (`AGENTS.md` commit rules;
`apps/windows/SECURITY.md` invariant 5).

How CI runs them (`crates/segue-client/tests/vectors.rs`, `include_str!`):

1. Rust: every file replayed by the crate's own unit tests — `cargo test -p segue-client`.
2. ABI: the same `status/` and `fsm/` files replayed through the C ABI by a
   Rust integration test in `crates/segue-ffi/tests/` with a fake `DataPlane`
   and `Protector`, so the exported surface cannot drift from the crate.
3. Shell copies: when a shell needs a local rule (an Apple widget or Android
   tile rendering status without the core), a copy under the shell's test
   resources is compared byte-for-byte with a `--check` script — Tono's
   `sync-desktop-routing.py --check` pattern. The goal is that this list stays
   empty, because shells call the crate instead of reimplementing it.
4. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
   already covers the new crate (`.github/workflows/ci.yml:333-334`); no new job.

---

## 6. Where it lives

**Recommendation: `crates/segue-client` in `segue-core`**, with
`license = "LicenseRef-Segue-Proprietary"` and `publish = false`, exactly as
`crates/segue-kernel/Cargo.toml:5-7` and the other three product crates do
("Segue's own code: not MPL. Kept in new files only"). Not a separate
repository.

For:

* it depends on `segue-kernel` and `segue-policy` **types** (KernelPlan is the
  kernel config; the bundle verifier is the kernel's). A separate repo needs
  either published proprietary crates or a submodule, and this workspace has
  `publish = false` everywhere.
* ABI lockstep: `segue-ffi`'s client surface and the crate must move together;
  one workspace makes that a compile error instead of a release note.
* CI cost today is one `cargo` invocation in an existing job; a new repo needs
  its own workflow, cache and supply-chain policy before it earns anything.
* The licence story does not improve by moving. The open question is shipping
  a proprietary static library inside the MPL-2.0 FFI artifact, and it is
  already open (`ffi-kernel-embedding.md` §5.1, §8 Q10) — a new repo does not
  close it, it duplicates it.

Against (accepted): the crate's bug fixes ride segue-core's weekly cadence
rather than the app's. Mitigation: it is a dependency of every shell, so a fix
ships with the next core version, and the shells' lockfiles pin it.

If the licence boundary ever forces a split, the crate moves out unchanged
except for its `path` dependencies becoming versioned ones — which is why the
crate must not re-export kernel types in its public API beyond `KernelPlan`
(bytes) and `PolicyStatus` (a plain struct).

---

## 7. What is reused from Tono, and how much

The owner's instruction is to reuse Tono's working code. Licensing is
uneven, so the table states the constraint per component: Tono's Rust crates
are `LicenseRef-Proprietary` (owner's own, direct copy fine), its Tauri app is
declared `GPL-3.0-only` (`apps/windows/app/package.json:4`) — copying that
into a Segue app shell would make the shell GPL, which is a decision, not a
default — and the macOS helper Swift has no licence file (owner's own).

### 7.1 Lift as-is (portable Rust, own licence, no OS calls)

| Tono path | Lines | Becomes | Adaptation |
| --- | --- | --- | --- |
| `crates/tono-core/src/connection.rs` | 890 | `client/fsm.rs` | Rename stages to Segue's; **delete** sing-box-specific stages (`ApplyingCloudPolicy`); keep `ConnectionStatus`/`UiState`/`ReconnectBackoff`/`ConnectionFsm`/`ShutdownCause` unchanged (`:16`, `:63`, `:76`, `:103`, `:218`, `:172`) |
| `crates/tono-core/src/auth.rs` | 3802 | `client/account.rs` | Replace `DEFAULT_BASE_URL`/`endpoints` with Segue's; drop Tono telemetry endpoints; keep 401→refresh-once, coalescing, error envelope |
| `crates/tono-core/src/credentials.rs` | 254 | `client/credentials.rs` | Trait unchanged; target names become `refresh-token.segue` |
| `crates/tono-core/src/catalog.rs` | 1382 | `client/catalog.rs` | Keep tracker/cache/atomic-write/safety checks (`:304`, `:470`); swap YAML for Segue JSON |
| `crates/tono-core/src/node.rs` | 1442 | `client/node.rs` | Keep admission *engine*; replace the VLESS/Hy2 field whitelist with Segue's outbound whitelist |
| `crates/tono-core/src/update_contract.rs` + `update_journal.rs` | 378 + 755 | `client/update_contract.rs` | Rename kinds/ids (`tonoUpdateManifest`→`segueUpdateManifest`, target ids); keep canonical-JSON rules and bounds verbatim |
| `crates/tono-core/src/network_disposition.rs` | 95 | `client/disposition.rs` | Keep the table; replace the AI-hold hook with `Protector::arm(mode: ai_only)` which *does* have a caller in Segue |
| `crates/tono-core/src/customer_failure.rs`, `protected_connectivity.rs` | 738 + 258 | `client/failure.rs` | Keep codes and copy; retranslate product strings |
| `crates/tono-core/src/unarmed_probe.rs`, `recovery.rs`, `heal.rs` | 321 + 72 + 1064 | `client/probe.rs`, `client/backoff.rs` | Keep TCP-proof and backoff logic; delete `hy2_*` modules (no Hysteria-shaped proof in Segue's exit model) |
| `crates/tono-core/tests/{update_contract,state_intent_contract}.rs` | 174 + 859 (all `tests/`) | `tests/vectors.rs` | Rehome as §5 consumers |
| `apps/windows/service/src/core/wfp_model.rs` | 3313 | `crates/segue-helper/src/wfp_model.rs` | No `windows-sys`, compiles off-Windows today: keeps the WFP rule model testable on the Linux CI runner |
| `apps/windows/service/src/core/{structure,desired,reconcile}.rs`, `update_wire.rs`, `release_wire.rs` | 1649 + 760 + 107 + 95 + 153 | `crates/segue-helper/src/…` | Pure wire/state; rename `Tono*` |
| `apps/windows/service/src/core/macos_kill_switch.rs` | 839 | `crates/segue-helper/src/pf.rs` | **Rust PF renderer that already exists** — this is the argument for one Rust privileged component (§7.3), not a new Swift one |
| `crates/tono-core/src/policy_signature.rs` | 146 | `client/policy.rs` | Keep `same_revision_transition` / `SignatureVerdict` **shape**; the verifier itself becomes `segue-policy` (different context string, different key) |

### 7.2 Adapt (same language, changed contract)

| Component | Lines | Adaptation size |
| --- | --- | --- |
| macOS helper `tooling/scripts/core-helper/*.swift` (PF, DNS, IPC, update, release) | 20 416 | **S**: the helper supervises a core *process* and talks HTTP over loopback. Segue's `segue-kernel` is such a process. Change: supervised binary + its config path, control-API calls (`CoreControllerClient` → `/v1/status|connect|disconnect|exit`), token file path, arm body fields. PF/DNS/update/release logic is untouched. |
| macOS app `apps/macos/Tono` | 178 Swift files | **M**: SwiftUI shell, sign-in, exit list, `AppState` domain extensions; replace catalog/route clients with a thin `segue-client`-shaped model fed by the helper; delete the LibreBox/sing-box glue |
| iOS `PacketTunnel/` + `TonoKit` | ~1 500 Swift | **L**: swap libbox for kernel-mode FFI; keep `TunnelConfirmation`, `SharedStatus`, `TunnelInputs`, `StatusFile` (flock/atomic) and the state-intent rule |
| Android `:vpn` + `PublicStatus` + `EngineWatch` | 883 + 292 + 188 | **L**: swap AIDL engine client for the JNI wrapper; keep the `:vpn` process split and status fencing |
| Windows service `wfp/mod.rs` (FFI), `windows_kill_switch/*`, `dns/*` | ~1 157 + 10 617 + ~10 000 | **XL**: genuine Windows work; not on the beta path |
| Control plane `services/control-plane` | 1 724 + 93 migrations | **XL**: keep auth/enrolment/devices/entitlement shape, replace catalog + policy compilation with Segue's signed bundle and ticket issuance |

### 7.3 Genuinely new

* `segue-client` itself (§4.1) — the glue that does not exist in either
  product: catalog → `KernelPlan`, policy/ticket lifecycle, the FSM bound to a
  `DataPlane`/`Protector` pair.
* The **arm/disarm intent protocol** with a generation fence and evidence
  (Tono's helper has the pieces; the two-intent contract is new).
* `prepare()` and its vectors.
* Client-side ticket handling (Segue tickets are a new object; Tono has no
  equivalent).
* A Beta macOS installer/notarization path for the Segue-named bundles.

**One privileged component, in Rust.** Tono wrote the macOS helper in Swift and
the Windows service in Rust with no shared code, and its decision log is full
of "macOS fixed it, Windows did not". Segue should not repeat that: the
release authority, session generation, update transaction, IPC envelope and
the PF renderer already exist as Rust in
`apps/windows/service/src/core/{macos_kill_switch,release,update_transaction}.rs`.
For the beta, ship the Swift helper (it works, it is tested, 20 k lines), but
put the *models* in Rust from day one so the Windows port is a front-end, not a
rewrite. This is the one place the fast path and the right path differ; the
recommendation is to take the fast path for v1 and record the decision in
`docs/decisions/`.

---

## 8. Staged plan (beta-oriented)

Sizes are relative effort for one engineer.

| # | PR | Size | Content | Unlocks |
| --- | --- | --- | --- | --- |
| 1 | `crates/segue-client` skeleton | M | Crate, licence header, five ports, `ClientStatus`/`ClientEvent` types, `prepare()` over existing kernel types, no network | Everything below; the §5 `fsm` and `intent` vector sets |
| 2 | Catalog admission + cache + account | L | §2.1–2.2, lifted with §7.1 substitutions; `install_catalog` | Real catalog in, `KernelPlan` out |
| 3 | Policy + ticket lifecycle | M | §2.3, §2.5; forwards to `PolicyStore`; never parses the body | End-to-end "signed content → plan" |
| 4 | Connect FSM + user-intent rule | M | §3, lifted from `connection.rs`; exhaustive transition table + `intent/scenarios.json` | Testable product behaviour with no OS |
| 5 | `segue-kernel` process-mode polish | S | Graceful `SIGTERM`, state-dir/log flags, control-API fields the helper needs (`policy` already there), documented exit codes | macOS beta integration |
| 6 | macOS: Segue app + Tono helper, process mode | XL | §7.2 row 1–2; bundle ids, signing, notarization, installer | **First hand-to-user beta** |
| 7 | Update contract + journal | M | Lifted; `releaseSequence` floor, private staging, per-component digests | "Can ship again" (G3/G4) |
| 8 | FFI client surface (ABI 1.19) | M | §4.3, capability bit 37, `client_status_snapshot_json`, vectors 2 | iOS/Android work starts |
| 9 | iOS app on kernel mode | XL | `ffi-kernel-embedding.md` stages 2–7 + §7.2 row 3 | Second beta |
| 10 | Android app on kernel mode | XL | §7.2 row 4 | Third beta |
| 11 | Windows service + WinTun backend | XXL | New TUN backend (`crates/segue-engine/src/tun_fd.rs:3458-3478` is `Unsupported` off Unix) + WFP port | Windows beta |

Deferred, explicitly: Windows, Linux, per-app routing, widgets/Control Center,
telemetry beyond the failure classifier, a second signature scheme, any
migration of Tono user data.

---

## 9. Open questions, each with a proposed default

1. **Where do the app shells live?** Default: `segue-apple` and `segue-windows`
   repositories (the research doc's split), created only when PR 6 starts. The
   crate stays in `segue-core`.
2. **Fail-open or fail-closed by default?** Default: **AI-only hold**
   (`strict: false`) — ordinary traffic is released on exhaustion, AI
   destinations stay blocked and the kernel refuses proxied flows in every
   posture but `Disconnected`. This is what `ai-lock.md` already specifies as
   the product's shape, and it is *stricter* than Tono's shipped behaviour —
   Tono's Windows build releases everything, because its selective-AI hook was
   never wired (`tono_core/src/network_disposition.rs:36`). Strict mode stays a
   user setting. The owner should confirm, because it is the product's failure
   feel.
3. **Must `segue-client` ever parse the policy body?** Default: no, except the
   unprefixed `version`/`expires_at` read for UX. Any richer read is a second
   implementation of `Verifier::compile` and will drift.
4. **Does the macOS beta use the C ABI at all?** Default: no. The helper talks
   to the kernel process; a second in-process FFI path on the same machine
   doubles the surface for no user-visible gain.
5. **The GPL-3.0 Tauri app.** Default: reuse its React pages as *design
   reference*, write the Segue shell fresh, so the app can carry the licence
   the owner chooses. If the owner wants the code, decide the app's licence
   first.
6. **`Xray*` wrapper names in a Segue product.** Default: keep C symbols
   (`xray_*` is the ABI and stays), rename only the new Swift/Kotlin types, and
   keep the existing adapter internal.
7. **Where does the decision log live?** Default: `docs/decisions/NNN-YYYY-MM-DD-slug.md`
   in this repository, `owner`/`provisional` status. PR 5 and PR 6 both need
   entries.
8. **Update protocol v1 scope.** Default: `releaseSequence` floor +
   per-component digests + private staging + Service-only adoption. Paired
   targets are not needed for one platform at a time.
9. **Apple CI.** Default: the app repositories reuse the self-hosted
   `segue-macos` runner this repository's `apple:` job already uses
   (`.github/workflows/ci.yml:803-810`), rather than buying hosted macOS
   minutes; a GitHub-hosted `macos-*` fallback is the answer only if that
   machine becomes a bottleneck.
10. **Clock skew for policy expiry.** Default: pin validity to the last
    observed server time (§2.3) and document it, rather than trusting the
    device clock.

## 10. Risks

* **Two control surfaces on one machine.** Process mode (helper → kernel HTTP)
  and embedded mode (FFI) both exist in the beta/next cycle. Mitigation: they
  are different *hosts*, never two data planes at once; `segue-client`'s
  `DataPlane` trait is the only place that knows which.
* **The kernel binary is a prototype.** No daemonization, one worker thread,
  stderr logging (`crates/segue-kernel/src/main.rs:85-86`, `:99-108`). PR 5 is
  small but load-bearing; without it the beta is fragile under sleep/wake.
* **The control API has loopback+token auth only** (`control.rs:1-12`), and the
  helper must hold the token, not the app, or any local process that finds the
  token file can drive the tunnel.
* **Copying Tono code imports its bugs.** `plan_failure` never runs because its
  selective-AI hook has no caller (`network_disposition.rs:36`); the
  `register_selective_ai_block` slot is process-wide and once-only. Segue must
  wire the hook to `Protector::arm` and test the table (§5 `fsm/transitions.json`).
* **Licence mixing.** Tono's Tauri app is GPL-3.0-only; Segue Core is MPL-2.0
  with four proprietary crates. Copy nothing from `apps/windows/app/` into a
  shell that must stay non-GPL, and record the choice.
* **`segue-client` becomes a god-crate.** Its only remit is product logic
  above the data plane; routing decisions stay in the kernel, enforcement stays
  in the protector. The first PR that adds a rule engine to it is the one to
  reject.
