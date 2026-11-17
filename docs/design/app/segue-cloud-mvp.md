# `segue-cloud` MVP: the smallest control plane that lets the macOS app ship

Status: design, 2026-11-17. Owner: cloud/app.
Related: [`../../research/apps/tono-and-segue-app-suite.md`](../../research/apps/tono-and-segue-app-suite.md)
§1.5, §3.4; [`../ai-lock.md`](../ai-lock.md);
[`../ffi-kernel-embedding.md`](../ffi-kernel-embedding.md) §4.3;
`crates/segue-kernel/src/policy.rs`; `crates/segue-policy/src/lib.rs`;
`crates/segue-relay/src/{ticket,revoke,policy}.rs`.

## 0. The one-paragraph version

Segue Core has a data plane and no control plane: the ticket, policy-bundle and
revocation formats exist, and the binaries that produce them are dev tools
(`crates/segue-relay/src/main.rs:9`, `crates/segue-kernel/src/main.rs:6`). Tono
already ships the control plane, the macOS helper and the updater for the same
product shape (sibling study, §1.5), and the owner has stated Tono is also his
product, so its code may be reused directly rather than redesigned. The MVP is
therefore **Tono's `services/control-plane` Worker, adapted to emit segue's
signed policy bundle and ticket instead of Tono's traffic-policy document and
catalog**, plus the minimum Tono macOS shell needed for a beta. Everything
else — billing automation, Tailscale enrolment, residential metering, the
diagnostics/R2 pipeline, node quality telemetry — is out of scope.

Reuse policy applied throughout: **lift as-is** = copy the file, change
imports/identifiers only. **Adapt** = the file's structure and tests carry over,
but the wire format or the data source changes, with an effort estimate.
**New** = nothing in Tono does it.

---

## 1. MVP scope for a macOS beta

### 1.1 In scope

| # | Capability | Shape | Where it comes from |
| --- | --- | --- | --- |
| 1 | Sign-in: email one-time code | `POST /api/v1/auth/email/{start,verify}` → access + refresh JWT, device row | Tono `src/login.ts`, `src/sessions.ts`, `src/index.ts:181-282` — **lift as-is** |
| 2 | Device enrolment and per-account device limit | `installationId` binds a device; `device_limit` (default 2) with LRU eviction; pending TTL | Tono `src/devices.ts`, `migrations/0001*`, `0011*` — **lift as-is**, minus Tailscale |
| 3 | Catalog issuance | One signed-and-encrypted exit catalog row, per-user filtered, digest-verified on read | Tono `src/catalog.ts`, `src/catalog-yaml.ts` — **adapt** (§4.1) |
| 4 | Policy compilation + Ed25519 signing | Compile a segue `Body` (JSON) from operator input, sign it with `segue-policy` envelope rules, serve the envelope | Tono `src/traffic-policy.ts`, `tooling/scripts/publish-traffic-policy.mjs` — **adapt** (§4.2) |
| 5 | AI destination list publishing | `ai_domains` / `ai_cidrs` inside the same signed bundle; no second document | `crates/segue-kernel/src/policy.rs:55-86`; **new wire content, existing envelope** |
| 6 | Ticket issuance and revocation | `SGT1.` tickets signed per device; complete-snapshot revocation list, `seq`-floored | `crates/segue-relay/src/ticket.rs`, `revoke.rs` — **new server code, existing formats** (§4.3) |
| 7 | Minimal ops page | Sign-in-code allowlist, device list/kill, catalog + policy publish with a diff and a checked preview, revocation state | Tono `services/ops-console/src/pages/settings/{Policy,Catalog}.tsx`, `pages/Customers.tsx` — **adapt, subset** (§4.4) |
| 8 | macOS beta shell | SwiftUI menu-bar app + privileged helper (PF, DNS) + root-owned updater, signing in and connecting through `segue-kernel` in kernel mode | Tono `apps/macos/`, `tooling/scripts/core-helper/` — **adapt** (§4.5) |

### 1.2 Explicitly out of scope for the beta

* **Windows and Linux clients.** The WinTun backend does not exist
  (`crates/segue-engine/src/tun_fd.rs:3458-3480` is `Unsupported` off Unix), and
  it is 3–4× the macOS shell's effort (study §3.4). Segue's second platform
  comes after macOS ships.
* **iOS/Android store apps.** The kernel-over-FFI work
  (`docs/design/ffi-kernel-embedding.md`) is a prerequisite and is not on this
  critical path.
* **Billing automation, plans, quotas in money.** A single `expires_at` on the
  account, set by hand in the ops page (§5).
* **Residential (Home) line metering and failover accounting.** `segue-relay`
  has the pool and the `home_bytes` counter
  (`crates/segue-relay/src/home.rs:1-20`, `metrics.rs:16`); the control plane
  does not need to ingest it for the beta.
* **Tailscale enrolment.** Tono's enrolment state machine
  (`src/enrollment.ts`, `src/tailscale.ts`) exists because its tunnel
  terminates on device peers. Segue's exits are operator-run relays reached
  directly; enrolment is an `installationId` and a device row.
* **Telemetry windows, diagnostics-log upload, routing-research snapshots,
  the API-relay probe, node quality timeseries** (`src/telemetry/`,
  `src/client-reports.ts`, `src/ops-timeseries.ts`, `src/api-relays.ts`).
  These are Tono's operator instrumentation and none is load-bearing for a
  user connecting.
* **Node provisioning automation.** `tono-node-provisioning` is the model
  (study §1.5); the beta fleet is small and hand-provisioned. Publishing a
  catalog is an ops-page action.
* **Anti-downgrade release manifests.** The macOS beta is notarized and
  distributed by the owner; the root-owned update transaction runs in "no
  update feed" mode until §4.5's updater is wired.

---

## 2. API, data, keys

### 2.1 Transport and auth

* HTTPS only, JSON, one Worker on a custom domain. Every response is
  `{"error": {"code", "message"}}` on failure — Tono's `ApiError`/`error()`
  helpers (`src/errors.ts`, `src/request.ts`) — **lift as-is**.
* Auth is a JWT access token (HS256, `JWT_SECRET`) plus an opaque refresh
  token whose SHA-256 is the session's unique key. On **every** request `auth()`
  joins session → user → device and re-checks status, so revocation never waits
  for token expiry. `src/auth.ts:25-66` — **lift as-is**.
* The client sends `X-Segue-Client: macos/<version>`; it is recorded on
  sign-in and catalog fetch only (`src/client-identity.ts`). No IP, ASN or
  path is stored in the MVP (the beta has one path).

### 2.2 Endpoints

The beta needs six. Everything else in Tono's `index.ts` (1724 lines) is
dropped.

| Method | Path | Auth | Request | Response |
| --- | --- | --- | --- | --- |
| GET | `/api/v1/health` | none | | `{ok, version, buildSha}` |
| POST | `/api/v1/auth/email/start` | none, rate-limited | `{email, deviceName, installationId, client_platform}` | `{challengeId, expiresAt}` |
| POST | `/api/v1/auth/email/verify` | none, rate-limited | `{challengeId, code, installationId, deviceName}` | `{accessToken, refreshToken, user, device}` |
| POST | `/api/v1/auth/refresh` | refresh token | `{refreshToken, installationId}` | `{accessToken, refreshToken}` |
| GET | `/api/v1/bootstrap` | access | | `{catalog, policy, tickets, notBefore, notAfter}` |
| GET | `/api/v1/me` | access | | `{user, devices}` |

`/bootstrap` is the one shape that differs materially from Tono, which serves
catalog and policy on separate routes (`index.ts:430`, `:439`). Segue's kernel
needs catalog + bundle + ticket together to reach `Connected`, and one round
trip is one place for the client to enforce "all three from the same
response revision".

Response shapes (abridged; the full schemas live in `src/api-paths.ts`-style
typed modules):

```jsonc
// GET /api/v1/bootstrap
{
  "revision": 41,                       // monotonic; the client refuses a lower one
  "catalog": {
    "revision": 41,
    "nodes": [                          // already per-user filtered
      {"name":"la","carrier":"reality-la","relay":"10.0.0.1:7443",
       "node_id":1,"egress_group":"iad","exit_class":"overseas","role":"proxy"},
      {"name":"ai","carrier":"reality-ai","relay":"10.0.0.3:7443",
       "node_id":3,"exit_class":"ai","role":"home"}
    ],
    "outbounds": {"reality-la": { /* one Xray-style outbound object */ }},
    "chnroute_revision": 7,
    "sha256": "…"
  },
  "policy": {"key_id":1, "body":"<base64>", "sig":"<base64>"},   // segue-policy envelope
  "tickets": {"overseas":"SGT1…", "ai":"SGT1…"},
  "not_before": 1767225600,
  "not_after": 1767312000
}
```

The ticket is a **bearer secret**. It is returned over TLS, never logged
(`crates/segue-relay/src/ticket.rs:5-7`), never put in an error string, and
never cached by the Worker (no `Cache-Control` reuse; `private, no-store`).

### 2.3 DB schema

SQLite dialect (D1 in the Tono choice, Postgres if §3 changes). Migrations are
append-only, numbered, one file per change — Tono's discipline
(`migrations/README.md`), **lift the convention as-is**.

```sql
-- 0001: accounts, sessions, devices  (Tono 0001/0002/0009/0011, trimmed)
CREATE TABLE users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  status TEXT NOT NULL DEFAULT 'pending'      -- pending | active | disabled
         CHECK(status IN ('pending','active','disabled')),
  plan TEXT,
  device_limit INTEGER NOT NULL DEFAULT 2 CHECK(device_limit BETWEEN 1 AND 25),
  expires_at INTEGER,                          -- NULL: no expiry (owner account)
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE auth_challenges (
  id TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK(kind = 'email_otp'),
  email TEXT COLLATE NOCASE NOT NULL,
  secret_hash TEXT NOT NULL,                   -- HMAC(challengeId, code)
  installation_id TEXT NOT NULL, device_name TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0, max_attempts INTEGER NOT NULL,
  expires_at INTEGER NOT NULL, consumed_at INTEGER, created_at INTEGER NOT NULL
);
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  installation_id TEXT NOT NULL, name TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','active','revoked')),
  pending_expires_at INTEGER, last_seen_at INTEGER,
  client_platform TEXT, client_version TEXT,
  created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
  UNIQUE(user_id, installation_id)
);
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  refresh_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL, revoked_at INTEGER, created_at INTEGER NOT NULL
);

-- 0002: issued artifacts
CREATE TABLE managed_catalog (            -- one row; segue 2.2's catalog
  singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
  revision INTEGER NOT NULL, ciphertext TEXT NOT NULL, nonce TEXT NOT NULL,
  content_sha256 TEXT NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE managed_ai_list (            -- operator-authored AI destinations
  singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
  revision INTEGER NOT NULL, domains_json TEXT NOT NULL, cidrs_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE policy_revisions (           -- append-only history of signed bodies
  version INTEGER PRIMARY KEY,            -- monotonic; never reused (rollback floor)
  body_json TEXT NOT NULL,                -- exact signed body bytes
  envelope_json TEXT NOT NULL,            -- {key_id, body, sig}
  expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE revocation_clock (           -- the seq the nodes are told about
  singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
  seq INTEGER NOT NULL, updated_at INTEGER NOT NULL
);

-- 0003: ticketing
CREATE TABLE issued_tickets (
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  key_id INTEGER NOT NULL, issued_at INTEGER NOT NULL, not_after INTEGER NOT NULL,
  claims_json TEXT NOT NULL                  -- non-secret claims, for ops display
);
CREATE TABLE device_rate (                 -- per-device counters, last window only
  device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
  window_start INTEGER NOT NULL, bytes INTEGER NOT NULL DEFAULT 0
);
```

Tono's catalog and policy are **encrypted** columns whose AES-GCM key is a
Worker secret (`migrations/0010`, `0013`). Keep that: it is the only thing
between a D1 read-only leak and every node's address. The AI list is
operator-authored, not secret in the same way, but encrypt it with the same
key for uniformity — one code path.

**Not in the schema, deliberately:** no table of user traffic, destinations,
SNI, IPs, DNS answers or per-session byte counts. §6.

### 2.4 Key management

Three Ed25519 roles, three lifetimes. The split is what makes a control-plane
compromise survivable.

| Key | Signs | Private key lives | Public key lives | Rotation |
| --- | --- | --- | --- | --- |
| **Policy key** (`key_id`) | segue `Body` JSON → `{key_id, body, sig}` | Owner's keychain, read at publish time by `publish-policy.mjs`. **Never in the Worker.** | Worker `var` (public by construction, readable/reviewable); kernel config `policy.public_keys`; relay config `policy.public_keys` | Add a new `key_id` to kernels + relays first, publish a policy signed by it, then retire the old id. `PolicyStore` accepts any configured id (`policy.rs:230-271`). |
| **Ticket key** (`key_id`) | device `Claims` → `SGT1.` | Worker secret (see below) | Every relay's `ticket_keys` (`crates/segue-relay/src/config.rs:46-51`) | Same add-then-retire; relays hold a list. |
| **Revocation signing** | — | none: the list is an unsigned snapshot with a `seq` floor | — | n/a |

**Why the policy key is offline.** If the Worker could sign policies, taking
the Worker would be enough to publish a policy that routes every user's traffic
wherever the attacker likes — the exact failure Tono's signing exists to
prevent (`tooling/scripts/publish-traffic-policy.mjs:7-14`,
`apps/macos/Tono/Core/ManagedTrafficPolicySignature.swift:10-15`). The Worker
therefore stores **only the envelope** an operator produced locally; publish is
two round trips: `POST /api/v1/ops/policy/preview` returns the canonical body
the Worker would serve, the operator signs those exact bytes, and
`POST /api/v1/ops/policy` re-canonicalises and re-verifies before storing. A
signature that verifies nowhere is refused and nothing is stored. Tono already
implements this flow end to end; **adapt the document shape only.**

**Why the ticket key is online.** A ticket is short-lived (≤ 24 h, §4.3) and
per-device; a Worker compromise lets an attacker mint tickets for devices the
*relays* will accept, which is bad but bounded by the revocation list and the
ticket window, and recoverable by rotating `key_id` on the relays. It is not
the same class of failure as a forged policy. The private key is a Worker
secret, never in the repository, and the `key_id` is in config so rotation is
a deploy plus a relay config change.

### 2.5 Rotation and rollback protection

Kernel and relay both implement rollback floors **already**; the control plane
must not defeat them:

* **Policy**: `version` is a monotonic counter stored in `policy_revisions`
  (`version INTEGER PRIMARY KEY`, append-only). `PolicyStore::install_at`
  refuses `version <= high_water` (`policy.rs:490-495`) and `load_startup`
  keeps the floor even from an expired bundle (`:535-545`). The control plane
  **rolls back by publishing a higher version with the old content**, never by
  re-serving an older envelope.
* **Revocation**: `revocation_clock.seq` increments on every revocation; the
  snapshot is complete or not served at all (`revoke.rs:1-20`). `seq` never
  goes back, one `seq` names one device set, `synced_at` is the freshness
  source. The Worker's `scheduled` handler writes the file every 5 min; a
  failure leaves the old one, which goes stale and fails closed on the relays
  after 5 min.
* **Tickets**: no floor. A new ticket supersedes the old for the same device
  (`issued_tickets` is keyed by device); relays accept any unexpired,
  unrevoked ticket.
* **Catalog**: `revision` monotonic; the client refuses a lower revision or a
  same-revision/different-digest response. Tono encodes exactly this
  (`src/catalog.ts:7-13`); **lift the rule, adapt the document.**

---

## 3. Tech stack

### 3.1 Recommendation

| Layer | Choice | Why |
| --- | --- | --- |
| Language/runtime | TypeScript on Cloudflare Workers | Tono's `services/control-plane` is 40 k lines of exactly this, tested (`vitest`, `@cloudflare/vitest-plugin`) and deployed. Reusing it is the fastest path; a rewrite in Rust would be a second control plane to keep in step with the first. |
| DB | Cloudflare D1 (SQLite) | The MVP's tables are a handful of rows per user; D1's single-digit-MB database is ample for a beta fleet, and every Tono migration is already D1 SQL. |
| Secrets | Worker secrets (`JWT_SECRET`, `CATALOG_ENCRYPTION_KEY`, `TICKET_SIGNING_KEY`) | Tono's pattern; nothing secret in the repo. |
| Public vars | `wrangler.jsonc` vars (`POLICY_PUBLIC_KEY`, `TICKET_KEY_ID`) | Public by construction, reviewable in the repo — Tono's `TRAFFIC_POLICY_PUBLIC_KEY` comment (`wrangler.jsonc`) says why. |
| Ops auth | Cloudflare Access in front of `/api/v1/ops/*`, verified again in the Worker | Tono `src/access.ts` — **lift as-is**. Operator identity is an email in `ACCESS_ADMIN_EMAILS`. |
| Email | Resend (Tono's provider) | One dependency already integrated (`src/login.ts`). |
| Hosting | Cloudflare, custom domain, `*/5 * * * *` cron | Tono `wrangler.jsonc` — **lift as-is**, change domain and database name. |
| Client | Segue Core + SwiftUI shell from Tono | §4.5. |

### 3.2 What to change from Tono's choices

1. **Serve segue formats, not Tono's.** The policy is a segue `Body` +
   `segue-policy` envelope (base64 body, `segue-policy-v1\0` context), not a
   Tono traffic-policy document with Tono's `tono-traffic-policy-v1\n` context
   (`src/crypto.ts:37`). The catalog is a segue `exits`/`outbounds` document
   the kernel config parser accepts (`crates/segue-kernel/src/config.rs:84-137`),
   not Clash/sing-box YAML. This is the single biggest adaptation and it is
   unavoidable — the kernel verifies a fixed format.
2. **Drop Tailscale.** Enrolment, the revocation outbox, orphan-node cleanup
   and the `revocation_jobs` table all exist to keep a tailnet in step
   (`src/devices.ts:1-8`). Replace with a device row and a revocation seq.
3. **One `/bootstrap`, not two artifacts on two routes.** The kernel needs all
   three together (see §2.2).
4. **Keep D1, but plan the escape hatch.** If device-count or usage ever needs
   real-time aggregation, D1's per-request row limits bite. The MVP's write
   volume is a few rows per sign-in and a 5-minute cron; that is comfortably
   inside D1. A Postgres move would be a port of the SQL, not a redesign.
5. **Delete Tono's operator surface you do not need.** 40 k lines of Worker
   and 39 k lines of console include diagnostics, timeseries, releases,
   metering and quality. The MVP Worker is the six routes above plus ops;
   the console is four pages. Do not deploy the rest.

---

## 4. Reuse inventory: what is lifted, what is adapted, what is new

Effort is engineering days for one person who has read this document plus the
cited Tono files.

### 4.1 Catalog issuance — **adapt**, ~3 d

* Lift: `src/catalog.ts:370-460` (`publicManagedCatalog` decrypt → digest
  check → per-user filter → serve), the
  `managed_exit_catalog` migration, and the AES-GCM helpers in
  `src/crypto.ts:1-25`.
* Change: the stored document is segue's catalog JSON (`exits` + `outbounds` +
  `chnroute_revision`), not Clash YAML. `filterCatalogYamlForUser` /
  `catalog-yaml.ts` (941 lines of YAML admission) is **not** used; a
  `filterCatalogJsonForUser` keeps only the exits this device's ticket names.
* New: the JSON admission function (whitelisted keys exactly like
  `catalog-yaml.ts:30-40` — reject unknown fields, reject reserved names, cap
  sizes) and a publish route `PUT /api/v1/ops/catalog` with a
  `content_sha256` and optimistic revision.
* Risk: a malformed catalog is delivered to every client. The kernel refuses
  an unknown route or a bad outbound at parse time (`config.rs:340-395`), so
  the failure is fail-closed, but test the admission with the kernel's own
  test vectors before the first publish.

### 4.2 Policy compilation + signing — **adapt**, ~4 d

* Lift: `src/traffic-policy.ts`'s two-phase publish (preview → sign →
  re-canonicalise → verify → store) and
  `tooling/scripts/publish-traffic-policy.mjs` wholesale — change the signature
  context constant to `segue-policy-v1\0`, the envelope to `{key_id, body,
  sig}` with base64 `body`/`sig`, and the keychain service name.
* The compiler turns operator intent into a segue `Body`:
  `/api/v1/ops/policy/preview` accepts `{default, rules[], ai_extra_domains[],
  ai_extra_cidrs[], chnroute_revision, ttl_hours}` and returns the canonical
  body JSON: `version` (allocated from `policy_revisions` at publish, not
  preview), `expires_at = now + ttl_hours`, `ai_domains` = published
  `managed_ai_list` ∪ extras, `ai_cidrs` likewise, `rules` exactly as
  `RuleSpec` serde expects (`crates/segue-kernel/src/rules.rs:378-388`),
  `default`, `chnroute` from the published set, and `ech_public_names` only if
  the operator set it.
* **New:** the body compiler itself. There is no Tono equivalent because
  Tono's policy is a different document. Size it honestly: the hard part is
  the *checks*, and they are the kernel's own rules restated —
  `default` must not be a home route (`policy.rs:337-343`), every proxy tag
  must be a known exit, AI entries must be `canonical_domain`-clean
  (`segue-policy/src/lib.rs:163-175`). Put those in a `policy-compile.ts` with
  a test that feeds the same vectors as
  `crates/segue-policy/src/lib.rs`'s `ai_classification_matches_relay`.
* Serving: `/api/v1/bootstrap` returns the newest **unexpired**
  `envelope_json` from `policy_revisions`. Expired and no successor means the
  kernel fails closed; the ops page shows a banner before that happens.

### 4.3 Ticket issuance and revocation — **new server code, existing formats**, ~5 d

* The formats are fixed and already tested on the relay side:
  `SGT1.` + base64url(payload) + `.` + base64url(sig), signature over
  `"segue-ticket-v1\n" || payload`, claims
  `{v, key_id, device_id, account_id, plan, exit_classes, ai_anchor_node_id,
  not_before, not_after}` (`crates/segue-relay/src/ticket.rs:11-50`).
  Cross-language trap: **tickets are base64url-no-pad** while **policy
  envelopes are standard base64**. Both are pinned by Rust's engine choices;
  encode accordingly and add a test that a ticket produced by the Worker
  verifies in `cargo test -p segue-relay` (the queen's CI has the Rust
  toolchain; this is a cross-check, not a unit test in the Worker).
* Ticket signing uses WebCrypto Ed25519 (`crypto.subtle.importKey('raw', …,
  'Ed25519')`), which Cloudflare Workers support. `issued_tickets` keeps the
  non-secret claims for ops; the ticket bytes themselves are not stored.
* TTL: `not_after = now + 12 h`, renewed on every `/bootstrap` and every
  successful refresh. A 12 h ticket plus a 5 min revocation poll bounds the
  damage of a stolen device to half a day, and the client re-fetches long
  before expiry.
* Revocation: `DELETE /api/v1/devices/:id` sets `status='revoked'`, revokes its
  sessions, deletes its ticket row and bumps `revocation_clock.seq`. A cron
  step writes the snapshot the relays read; node sync is a 30 s poll of a file
  the ops host writes (`crates/segue-relay/src/server.rs:28`, `:121-145`).
  **New:** the snapshot writer and the node-side fetch. Tono's
  `processRevocations` (`src/devices.ts`) is the model for the outbox shape;
  here the sink is a file, not the Tailscale API, so it is much smaller.
* **Live-session cut.** A relay cuts a revoked device's live sessions when it
  reloads the list (`server.rs:231-240`); the kernel additionally sees
  `REVOKED` on the control stream and reports `revoked` in `/v1/status`
  (`crates/segue-kernel/src/session/mod.rs:488-502`). So revocation is: delete
  the row, bump `seq`, wait ≤ 5 min + 30 s. Document that number in the ops
  page.

### 4.4 Minimal ops page — **adapt, subset**, ~3 d

* Lift: the React/Vite console shell, `src/pages/settings/{Policy,Catalog}.tsx`
  (286 + 251 lines: document gate, diff, canonical preview, refusal words),
  `pages/Customers.tsx` + `pages/customer/{Devices,ExpiryDrawer}.tsx`, and the
  Access verification in `src/access.ts`.
* Cut: nodes, today/digest, telemetry, diagnostics, finance, releases,
  inventory — everything under `pages/{node,nodes,today,diagnostics,clients}`.
* Replace the policy editor's document with segue's `Body` form: a JSON
  textarea plus the compiled-preview and signature-verification panel. The
  editor keeps Tono's rule that the **served** bytes are what gets signed; the
  operator never pastes a signature they made over their own file.
* One extra panel the beta needs and Tono does not: **AI list**. Edit
  `ai_domains`/`ai_cidrs`, see which built-in names the kernel adds anyway
  (`crates/segue-kernel/data/ai-lock.txt`), publish, which bumps the AI list
  revision and requires a new policy publish (they travel in one bundle).

### 4.5 macOS beta shell — **adapt**, ~15–20 d

This is the largest line item and the one where "reuse Tono" pays most.

* Lift almost verbatim: the helper's **PF rendering** (`KillSwitchPF.swift`,
  2210 lines, and its tests), the **IPC** (`SocketServer.swift`,
  `HelperHTTP.swift`, `helper-shared/PeerAuthorization.swift`, audit-token
  peer check), **protocol versioning + build gate**
  (`HelperProtocolVersion.swift`, `build-core-helper.sh`), **protected DNS**
  (`ProtectedDNSManager.swift`), the **release worker / restore-internet
  daemon** (`ReleaseWorker.swift`), and the **update transaction**
  (`UpdateTransaction.swift`, `UpdateExecutor.swift`,
  `apps/macos/Tono/NATIVE_UPDATE_V1.md`) — the last only if the owner wants
  self-update in the beta; otherwise ship notarized DMG builds.
* Adapt: `CoreManager.swift` starts Tono's mihomo/sing-box; it must instead
  start the **segue kernel**. That means the helper launches `segue-kernel`
  (or an FFI-embedded kernel later) with a config the app writes into the
  helper's state directory, and the app talks to the **kernel control API**
  (`GET /v1/status`, `POST /v1/connect|disconnect|exit`,
  `crates/segue-kernel/src/control.rs:1-30`) instead of the Clash-API websocket
  (`CoreWebSocket.swift`). Roughly: delete the Clash-shaped client, keep the
  supervisor/watchdog shape.
* Adapt: `AppState+Catalog.swift` (1351 lines) and
  `Catalog/ManagedCatalogProcessor.swift` become "verify `/bootstrap` and write
  the kernel config" — the catalog is now the kernel's `exits`/`outbounds`
  JSON, and the policy is installed with
  `PolicyStore::install`/`xray_kernel_install_policy_bundle` rather than
  Tono's `ManagedTrafficPolicyProcessor`. The **verification posture** carries
  over: digest before use, revision monotonic, refuse a same-revision digest
  change, keep the last good and fail closed.
* Adapt: `AccountSession+Auth.swift` (996 lines) — change the API paths and
  the wire models (`TonoAPIModels.swift`), keep the state machine, the
  keychain store (`KeychainStore.swift`), offline grant
  (`Account/OfflineGrant.swift`) and sign-in recovery. The user-visible
  behaviour is a direct port.
* **New:** the kernel mode itself over the FFI
  (`docs/design/ffi-kernel-embedding.md` stage 3). Until that lands, the
  helper can run the `segue-kernel` **binary** with a SOCKS front end and a
  helper-owned utun route, exactly as the `tun_lab` example does — viable for
  a beta, and it defers the FFI work. `segue-kernel` already builds the TUN
  entry point (`crates/segue-kernel/src/tun.rs:2258-2340`); the app wires the
  utun fd.
* **Delete, do not port:** sing-box/mihomo packaging, the Tailscale sidecar,
  `ThreeTierRoutingContract.swift` (8784 lines of generated routing for a
  different core), `Hy2AutoSwitch`, `SelectiveFailOpen`'s Tono network-
  disposition table (Segue's posture matrix is `ai-lock.md`'s, and the kernel
  owns it), diagnostics uploaders, widgets.

### 4.6 Genuinely new, and nothing else

1. The segue `Body` policy compiler and its admission checks (§4.2).
2. The source-to-target mapping: `exits`/`outbounds` in the config the app
   writes, from the served catalog (§4.1).
3. Ticket minting and the revocation snapshot writer (§4.3).
4. The AI-list editor and the fact that an AI list change re-signs a new
   policy version (§4.4).
5. `nix`-free deployment glue: a wrangler config, a database, a domain, an
   Access application, an email sender. Tono's `deploy-control-plane-main.sh`
   is the template.

---

## 5. Billing / subscriptions: the minimal hook — **owner decision**

**What the beta needs is `expires_at` and nothing else.** The account is
`active` unless `expires_at` is non-null and past; `auth()` refuses with
`ACCOUNT_EXPIRED` and the client shows "your plan has expired". That is
already Tono's `requireAccountEntitlement` (`src/accounts.ts:16-30`) —
**lift as-is** — and it is the only entitlement the beta enforces.

**What is deliberately not built:** plans, prices, invoices, proration, usage
metering that feeds a bill, a payment provider, tax, refunds, per-device
add-ons, and any automatic renewal. The ops page sets `expires_at` (a date
picker, `pages/customer/ExpiryDrawer.tsx` is the model) and the owner collects
money however they like outside the product.

**Why the hook and not the system:** a payment integration is a product
decision with tax and support consequences, and it delays the beta. `expires_at`
is the one field every billing design writes, so adding Stripe/RevenueCat later
is additive: webhook → `UPDATE users SET expires_at = ?`, and the same
`entitlement()` gate. No schema change.

**If quota-by-bytes is wanted later**, `device_rate` (§2.3) is the seam:
relays already count home bytes (`metrics.rs:16`) and per-device reclass
counts, and `users.quota_bytes`/`usage_bytes` exist in Tono's `0001` (dropped
from the MVP schema above). Say so in the ops page rather than implying
enforcement that is not there.

Open owner question (§8, Q1): does the beta have any paid tier at all, or is
it invite-only with `expires_at` far in the future?

---

## 6. Security and privacy

### 6.1 No traffic logs

The control plane **must not** be a place where a user's destinations exist.
Concretely:

* No table has a column for a domain, SNI, IP, DNS answer, URL, or per-session
  byte count. The schema in §2.3 is the complete list; a migration that adds
  one should be refused in review.
* No request handler parses a destination. The client sends: email (sign-in),
  installation id, device name, client platform/version, refresh token,
  catalog/policy revisions. Nothing else.
* Access logs: the Worker writes no request log of its own (only the
  `ops_api_path_daily` ASN rollup if that is kept, and the beta's sample size
  makes it a privacy liability — **drop it in the MVP**, keep the code for
  later). Cloudflare's edge logs are the operator's to configure; document that
  the beta should turn off edge request logging for `/api/v1/bootstrap` if the
  plan allows it.
* No client telemetry is uploaded in the beta. `AccountSession+Telemetry.swift`
  is not ported. If the owner wants crash reports, that is a separate,
  explicitly consented feature.
* **Tickets are secrets.** Not in logs, not in error text, redacted Debug
  (`crates/segue-kernel/src/session/mod.rs:133-140` is the precedent), and
  `/bootstrap` sets `Cache-Control: no-store`.

### 6.2 What is stored, per user

* Email, account status, plan name (free text), `expires_at`.
* Device: name, installation id (client-generated UUID), platform/version,
  first/last seen.
* Session: refresh-token hash (never the token), expiry.
* Ticket claims: device id, exit classes, validity window — no destination.
* Nothing else. Retention: devices are deleted on revoke after 30 days
  (Tono's `retention.ts` pattern); sessions on expiry; `policy_revisions`
  and `revocation_clock` are operator data and kept.

### 6.3 Abuse handling

* **Rate limits** on `auth/email/start` (per IP and per email) and
  `auth/email/verify` (per challenge), lifted from `src/login.ts:37-90`.
* **Device limit** enforced by a DB trigger *and* in the handler (Tono does
  both: `migrations/0011`, `src/devices.ts:142-160`); the trigger is the one
  that wins a race.
* **Email allowlist** for the beta: `pending` accounts cannot sign in; the
  owner promotes an email in the ops page. This is Tono's
  `DIRECT_SIGNUP_ALLOWLIST`/`publicSignup` pair, minus public signup.
* **Revocation is the kill switch for a device**, not an account ban. An
  account ban is `status='disabled'`, which `auth()` refuses on the next
  request. There is no per-request path for a user to learn why beyond the
  error code; that is deliberate.
* **No password, so no password database to leak.** The OTP is
  `HMAC(challengeId, code)` stored, single-use, attempt-capped, 10 min TTL.
* **Ops surface** is Access-gated twice (edge policy + Worker JWT check,
  `src/access.ts`); the admin token CLI path
  (`/api/v1/admin/*`) is **not** deployed in the MVP.

### 6.4 Trust boundaries

* The Worker can mint tickets and serve a policy an operator signed. It cannot
  author a policy. That is the whole point of §2.4.
* A relay trusts: its own ticket keys, the signed bundle, the revocation
  snapshot. It does not trust the client's `exit_class` hint
  (`crates/segue-relay/src/lib.rs:39-42`) and never dials direct
  (`crates/segue-relay/src/dial.rs` classification).
* The kernel trusts: the policy public keys compiled into its config, the
  relay's tickets (through the relay, not directly), and nothing the app says
  about being connected. Posture comes from the kernel
  (`ai-lock.md` "What the OS layer still has to do").
* The macOS helper is the only protection authority (§4.5); the app can arm
  and disarm, never weaken.

---

## 7. PR-sized staged plan

Ordered by "what unblocks the next thing". Sizes are S (≤ 1 d), M (2–4 d),
L (5–10 d). Every stage ends with something the owner can look at.

| Stage | PRs | Size | Exit criterion |
| --- | --- | --- | --- |
| **P0 — Fork the Worker** | Copy `services/control-plane` + `services/ops-console` into `segue-cloud`; delete telemetry/diagnostics/releases/metering/tailscale; strip routes to the six in §2.2; rename identifiers; `vitest` green on the remainder | M | The trimmed Worker builds, typechecks and passes its surviving tests; a health check answers on a dev deployment. |
| **P1 — Auth + devices** | Lift `login.ts`, `sessions.ts`, `devices.ts`, `accounts.ts` (entitlement only), migrations 0001–0003; email via Resend; allowlist; rate limits | M | A synthetic email signs in from `curl`, gets tokens, is refused a second device past the limit, and a revoked device's session dies on the next request. |
| **P2 — Catalog + policy publish** | Catalog JSON admission + `PUT /api/v1/ops/catalog`; `policy-compile.ts`; two-phase preview/sign/publish; `publish-policy.mjs` adapted | L | An operator publishes a catalog and a signed bundle from the ops page; a locally built `segue-kernel` loads the served bundle and reaches its routing table. |
| **P3 — `/bootstrap` + tickets + revocation** | Ticket minting (§4.3); `/bootstrap`; revocation seq + snapshot writer; cron | M | `curl /bootstrap` returns catalog + envelope + two tickets; a `segue-relay` accepts the ticket (cross-checked on the Rust side) and refuses a revoked device after one sync window. |
| **P4 — Ops page, cut down** | Four pages: catalog publish, policy publish (with diff/preview/sign-verify), AI list, devices/expiry | M | The owner can onboard an email, publish a bundle and revoke a device without a terminal. |
| **P5 — macOS shell, connect path** | Tono app skeleton + keychain + `AccountSession` ported; `/bootstrap` client; kernel config writer; helper starts `segue-kernel` with a utun; kernel control API client replacing the Clash websocket | L | A notarized-dev build signs in, receives `/bootstrap`, connects through a relay, and `curl` inside the tunnel uses the AI exit for an AI name. |
| **P6 — macOS protection** | Port PF (`KillSwitchPF`), IPC hardened (`SocketServer`, peer auth), protocol version gate, protected DNS, release worker | L | Kill switch survives quit, crash and reboot per `ai-lock.md`'s posture matrix; restore-internet works with the helper busy. |
| **P7 — Beta hardening** | Retention jobs, error codes surfaced in the UI, revocation banner, expiry enforcement copy, one end-to-end script from sign-in to connected to revoked | M | A second person completes the flow unaided; the owner's checklist in `docs/SHIP_PLAN` terms (G1–G4) passes. |

Stages P0–P4 are server-only and can proceed without a Rust toolchain on the
author's machine (the cross-check in P3 needs the queen's CI). P5–P6 need the
toolchain and are where the Tono reuse is heaviest.

**What is deferred even beyond P7:** Windows, iOS/Android, FFI kernel mode,
billing automation, node provisioning automation, self-update feed,
diagnostics, multi-region failover, residential metering.

---

## 8. Open questions, with a proposed default

| # | Question | Proposed default |
| --- | --- | --- |
| 1 | Any paid tier in the beta? (§5) | No. Invite-only, `expires_at` far out, owner sets a date when someone should lapse. Billing is a later, additive change. |
| 2 | Ticket TTL (§4.3) | 12 h, renewed on `/bootstrap` and every refresh. Short enough to bound a stolen device; long enough that an offline launch still connects. |
| 3 | Policy bundle TTL (§4.2) | 72 h, published by a daily cron from the newest `policy_revisions`. The cron re-signs **the same body** with a new `expires_at` and a new `version` — never reuses an envelope. |
| 4 | Policy key: one key or per-environment? | One production `key_id: 1`, plus a staging key in the kernel's test config. The playbook for rotation is in §2.4; do not build multi-key before it is needed. |
| 5 | Does the helper run `segue-kernel` as a binary or over the FFI? (§4.5) | Binary for the beta. It is a config file and a process; FFI mode is the post-beta path. |
| 6 | Is the catalog encrypted at rest? (§3) | Yes, same as Tono (`CATALOG_ENCRYPTION_KEY`). The cost is one AES-GCM call per read; the benefit is a D1 leak does not name the fleet. |
| 7 | Who can publish a policy? | The owner only, from their machine, via `publish-policy.mjs` against the Access-gated ops API. The Worker holds no signing key. |
| 8 | Is the AI list the signed bundle or a separate feed? | The signed bundle. It is the format the kernel and relay already read together (`crates/segue-policy/src/lib.rs:188-220`); a second feed would be a second thing to keep in step and a second bypass. |
| 9 | Do we keep Tono's `wallet`/`ops` admin token paths? | No. Access-gated `/api/v1/ops/*` only; a token CLI is a credential to leak. |
| 10 | What is the D1 size ceiling for the beta? | Assume ~10 MB. The schema stores no traffic; at 1000 users and 3 devices this is well under. Revisit only if metering is added. |

---

## 9. Risks

1. **Format drift between the Worker and the Rust crates is the top risk.**
   Tickets are base64url-no-pad, policy envelopes are standard base64, domains
   must be `canonical_domain`-clean or the bundle is refused, and the `Body`
   has `deny_unknown_fields`. Mitigation: a `tests/contract/` fixture pair —
   the Worker emits files, `cargo test -p segue-relay -p segue-kernel` reads
   them — run in CI on the queen's side. This is the only cross-language
   contract in the system and it is worth a dedicated test.
2. **The boundary between "kernel mode" and "engine mode" for the beta app is
   not built yet.** P5 assumes the binary path; if the embedding plan's stage 3
   lands first, P5 changes to an FFI call. Either way the app must not open a
   loopback `listen` it does not use (`ffi-kernel-embedding.md` §5, open
   question 4) — in binary mode the kernel needs its SOCKS/front door, so it
   is bound to loopback and the helper is the only permitted peer.
3. **Reusing Tono code means reusing Tono's inconsistencies.** The study's §1.3
   names two: `register_selective_ai_block` has no production caller, and the
   shipped fail-open behaviour is weaker than the design doc. Do not port a
   behaviour whose doc says one thing and whose code does another; where the
   two disagree, the kernel's own posture matrix (`ai-lock.md`) is the
   authority and the helper implements it, not Tono's `SelectiveFailOpen`.
4. **The catalog is an attack surface with a small admit list.** A bad `exits`
   entry names a route the kernel does not have and the whole config fails to
   parse — fail closed, but a total outage for every client on the next
   launch. Mitigation: the kernel's own config tests run against the published
   document in P2's exit criterion, and the ops preview shows the parsed
   `exits` table before publish.
5. **D1's write limits under a cron.** A 5-minute cron that writes revocation
   and policy rows is fine; a cron that loops per device is not. Keep the
   snapshot writer one statement, and the policy TTL re-sign one insert.
6. **The macOS beta carries the whole privileged surface.** PF, IPC and the
   version gate are the parts most likely to break in a way that looks like
   the network. The build gate (`HelperProtocolVersion` + `CONTRACT.sha256`)
   exists to catch exactly this and **must** be ported before the first beta
   install.
