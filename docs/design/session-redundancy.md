# Loss-resilient AI streams in the session layer

Status: Stages 1–3 implemented in-tree (`RedundancyMode::Dup { delay: 30 ms }` default for `ai_only = true` with a bound standby; `Off`/`Hedge` configurable). Owner: session. Related:
[`session-v0.5.md`](../protocol/session-v0.5.md) §4, §5, §10;
[`ai-lock.md`](./ai-lock.md); `.bees/wan-findings.md` (not in the repo).

## 0. Summary

On the measured path (172 ms RTT, ~15% loss in 2–4 packet bursts) a lost
packet costs the app at least one RTT, and often an RTO, before the next SSE
token arrives. The session layer cannot retransmit a lost *packet*: its
carriers are reliable byte streams, so a lost packet is a *late frame*, not a
lost one. The only lever at L5 is a second, independent carrier.

**Recommendation: duplicate small DATA frames on a second carrier bound to the
same session (option a)**, behind an additive, ignorable frame so a v5 relay
degrades gracefully. Do not build L5 FEC (b) now: over a reliable carrier it is
a bandwidth optimization of (a) with a group delay that hurts token streams,
and its real home is a datagram carrier that does not exist yet. Carrier racing
(c) is mostly already done below L5 (happy-eyeballs) and does not help
mid-stream loss. Relying on QUIC (d) is the baseline, but Segue's QUIC carriers
currently lose to sing-box on this path, so (d) needs its own work first.

## 1. The problem, measured

From `.bees/wan-findings.md` (2026-11-18, synthetic, queen-run; bees have no
server access). US residential → Lumen → China Telecom 163 → Aliyun Hangzhou,
RTT ~172 ms, ICMP loss 15% at peak, bursts of 2–4:

| combo | TTFB p50 | RR p50 | RR p99 | stalls>1s | 1MB Mbps |
|---|---|---|---|---|---|
| segue/reality | 1813 | 162 | 1000 | 2 | 5.3 |
| segue/hy2 | 338 | 167 | 929 | 0 | 7.6 |
| segue/tuic | 171 | 168 | 1045 | 3 | 15.8 |
| segue/trojan | 690 | 184 | 966 | 1 | 5.1 |
| singbox/hy2 | 175 | 171 | 388 | 0 | 15.3 |
| singbox/tuic | 176 | 173 | 439 | 0 | 15.3 |

What a loss costs, per carrier type:

- **TCP carrier (Reality/Trojan).** Fast retransmit needs three duplicate
  ACKs. A token stream has few packets in flight, so a loss is usually an RTO
  (≥200 ms, often 1 s+ with backoff). The app sees a 1–3 s stall.
- **QUIC carrier (hy2/tuic).** A QUIC *stream* is reliable and ordered, so a
  lost packet still blocks the stream for ~1 RTT. QUIC recovers faster than
  TCP (better RTT estimation, no cross-stream head-of-line) but does not make
  a loss free.
- **The session layer sees none of this.** `FrameDecoder` reads a byte stream
  (`codec.rs:1025`); the frame arrives late. The only loss it sees is a
  carrier death (`on_carrier_closed`, `on_carrier_stuck`, `client.rs:599-610`),
  which costs a full re-attach (RESUME + replay), far more than 1 RTT.

So the design target is: make a lost packet cost ~0 extra RTT for a small,
latency-critical frame, without a re-attach.

## 2. What the session layer already gives us

- **Offsets, replay, dedup.** `RecvHalf::on_data` trims duplicates
  (`end <= recv` → 0 new bytes, `flow.rs:645-647`), `SendHalf::on_ack`
  (`flow.rs:228-247`), `rewind` (`flow.rs:249-258`).
- **Multi-carrier attach.** `ClientSession::attach` (`client.rs:358-415`),
  `RelayTable::switch` (`relay.rs:633-670`), attach generations
  (`client.rs:3-6`).
- **The one-carrier invariant.** The client's `move_carrier` abandons the old
  carrier (`client.rs:465-478`); the relay drops every frame from a
  non-current carrier (`relay.rs:382-388`); `switch` closes the old carrier
  (`relay.rs:664-667`).
- **The client already dedups DATA from a *superseded* carrier**
  (`client.rs:682-688`), but the relay does not.

The gap is a second *live* carrier per session. Everything else (offsets,
dedup, replay) is already there.

## 3. Options

### (a) Duplicate small frames on two carriers

**Mechanism.** Bind a second carrier to the same session as a *redundant*
carrier (not a replacement). The sender writes qualifying DATA frames to both
carriers; the receiver dedups by offset (already implemented). The redundant
carrier is bidirectional, so it protects both the prompt upload and the token
downlink.

**Wire.** New frame `REDUNDANT_ATTACH` (0x3C, `FLAG_IGNORABLE`) as the first
frame on the second carrier: `session_id:16`, `resume_secret:32`,
`attach_gen:u32be`, `recv_offset:varint`, `max_offset:varint`. Reply
`REDUNDANT_OK` (0x3D): `attach_gen:u32be`, `recv_offset:varint`,
`max_offset:varint`. No change to OPEN/RESUME/DATA. **No version bump**: the
frame is additive and ignorable (`codec.rs:45`, `codec.rs:980`); a v5 relay
skips it, never answers, and the client closes the carrier after one RTT and
continues single-carrier. A version bump would be needed only if RESUME's
"switch" semantics changed, which they do not.

**Bandwidth.** 2× on duplicated frames only. Policy: duplicate DATA frames
below a threshold (e.g. 1 KiB) and only for sessions marked latency-critical
(`exit_class == EXIT_AI`, `crates/segue-kernel/src/session/mod.rs:74`). An SSE
stream at 100 B/token × 40 tokens/s = 4 KB/s duplicated = +4 KB/s, under 1% of
a 5 Mbps link. Bulk (16 KiB frames) is never duplicated.

**Credit/pool (rule 8).** Duplicates are deduped before buffering
(`flow.rs:645-647`), so they cost **no receive credit and no replay memory**.
They do cost one frame charge each way: the sender's second writer queue
(`WRITE_QUEUE` = 8 frames, `driver.rs:113`) and the receiver's frame read
(`take_charge`, `driver.rs:192-221`). Redundancy is **elastic, never a floor**:
it is shed first under pool pressure (the copy is skipped if the charge fails),
so admission floors (`lib.rs:151`, `flow.rs:60-64`) do not change and the 8 MB
pool still admits the same number of sessions.

**Which AI traffic.** SSE/WebSocket token streams, the prompt upload, tool-call
request/response headers. Not bulk downloads or long generations at 16 KiB
frames.

**Risks.** The two carriers must be *independent* paths (different transport
connections, ideally different protocols) or their loss is correlated. On a
single bottleneck, space the copies by ~5–10 ms so a 2–4 packet burst does not
take both. The redundant carrier must stay in the same egress group
(`Exit::group`, `crates/segue-kernel/src/session/mod.rs:115-124`) or the AI
vendor sees two IPs. A redundant carrier's death must not count against
`MAX_FRUITLESS` (`client.rs:109`) or trip the kill switch.

### (b) XOR/Reed-Solomon FEC over DATA frames

**Mechanism.** Group k DATA frames, send m parity frames; the receiver
reconstructs up to m losses per group without waiting for retransmission.

**Wire.** New `PARITY` frame (0x3C) with `group_id`, `k`, `m`, the covered
`(offset, len)` list, and parity bytes. Additive and ignorable, but the
*receiver* must hold frames out of order until a group is decodable, which
relaxes the `gap in data` invariant (`flow.rs:643`) — a semantic change, so a
version bump or a carefully scoped per-session opt-in.

**Bandwidth.** m/k (25% at 1/4, 12.5% at 1/8) on the protected stream.

**Credit/pool.** Parity is not application data, so it must not consume receive
credit; it needs a bounded per-session group buffer, which is *new* memory
outside the current `RecvHalf` grant. That is a rule-8 change: a group buffer
per session, charged to elastic, with a floor or a cap.

**Which AI traffic.** Bulk streams where a group delay is acceptable; not SSE,
where each token is wanted immediately and waiting for a group adds latency.

**Why not now.** Over a reliable carrier the session layer never sees a lost
frame, only a late one. Parity on the *same* carrier is useless (it is behind
the same head-of-line block). Parity on a *different* carrier is (a) with a
group delay and lower bandwidth. FEC's real home is a datagram carrier (QUIC
datagrams, Hysteria's FEC), and DGRAM is codec-only today
(`session-v0.5.md` §11).

### (c) Carrier racing

**Mechanism.** Open two carriers, keep the faster.

**Wire.** A probe first-frame (additive, ignorable) or a new `PROBE`/`PROBE_OK`
pair; the relay's `on_first` currently closes a carrier whose first frame is
not OPEN/RESUME/CTRL_HELLO (`relay.rs:489-627`).

**Bandwidth.** 2× connect cost and 2× carrier slots briefly; no data overhead.

**Credit/pool.** Two carriers briefly, then one; no lasting change.

**Which AI traffic.** Helps the *first* token (picks the better path at open),
not mid-stream loss.

**Why not the answer.** Happy-eyeballs already races TCP candidates below L5
(`crates/segue-transport/src/happy_eyeballs.rs`), and the kernel already picks
an exit (`pick`/`pick_ai`). Racing two *exits* is a routing decision, not a
session wire feature, and it does nothing for a loss that happens 10 s into a
stream.

### (d) Do nothing at L5, rely on QUIC carriers

**Mechanism.** None; the QUIC carrier's own loss recovery is the answer.

**Wire.** None. **Bandwidth.** None. **Credit/pool.** None.

**Which AI traffic.** All, in principle.

**Why not alone.** A QUIC *stream* is reliable and ordered, so a lost packet
still blocks the stream for ~1 RTT. QUIC recovers faster than TCP but does not
make a loss free. And Segue's QUIC carriers currently lose to sing-box on this
path (hy2 TTFB 2×, throughput ½, RR p99 2–3×, `.bees/wan-findings.md`), so (d)
is a prerequisite to fix, not a solution.

## 4. Comparison

| | (a) duplicate | (b) FEC | (c) racing | (d) QUIC only |
|---|---|---|---|---|
| wire | new ignorable frame | new frame + reorder | new probe frame | none |
| version bump | no | yes (or opt-in) | no | no |
| bandwidth | 2× duplicated frames | m/k | 2× connect | none |
| mid-stream loss | yes | yes (group delay) | no | carrier-dependent |
| SSE tokens | best | group delay hurts | first token only | 1 RTT per loss |
| bulk | no (2×) | maybe | no | fine |
| rule 8 | elastic, shed first | new group buffer | transient | none |
| effort | medium | high | low | high (carrier fixes) |

## 5. Recommendation

Do (a), after (d)'s carrier fixes are measured, and skip (b) until a datagram
carrier exists. (c) is already done below L5; do not add it at L5.

1. Fix the QUIC carrier's loss recovery first: it is the baseline for every
   option and the WAN numbers say it is 2× worse than sing-box.
2. Add the redundant carrier (a) for AI-class sessions, duplicating frames
   under 1 KiB, spaced ~5–10 ms, shed under pool pressure.
3. Re-measure; add (b) only if bulk streams show a tail problem that (a)
   cannot fix at acceptable bandwidth.

## 6. Staged plan

**Stage 0 — measure (done).** Reproducible impairment proxy + SSE & multi-turn
baselines live in `crates/segue-kernel/tests/redundancy_e2e.rs` and
`scripts/bench/session-redundancy.sh`, with per-connection `connection_seed`
loss/jitter decorrelation in `crates/segue-bench/src/impair.rs`.

**Stage 1 — redundant carrier, no duplication (done).** Wire:
`REDUNDANT_ATTACH`/`REDUNDANT_OK` (`0x3C`/`0x3D`, `FLAG_IGNORABLE`). Relay binds
without `switch`, accepts DATA/ACK/FIN/RST from either carrier, rescues a
`Detached` session on bound spare RX, and guards out-of-order swaps via
`promoted_in_gen`. `StandbyKeep` avoids swap-backoff churn and aborts cleanly on
`reattach`. Kernel adds non-racing `Exit.redundant_carrier` selection and
`MoveCounters` (`resumes`, swaps, promotions).

**Stage 2 — duplicate small frames (done).** `RedundancyConfig`
(`RedundancyMode::Dup { delay: 30 ms }` default, `Off` to disable, or
`Hedge { delay }`, `max_frame_bytes = 1024`, `ai_only = true`) wired through
`segue-relay` and `segue-session`. `DupQueue` (`DUP_QUEUE_CAP = 32`) delays and
duplicates small frames, raises a non-wedging `bulk_barrier` on frames above
`max_frame_bytes`, and seeds up to `8 * max_frame_bytes` of in-flight
`[acked, cursor)` segments at bind via `seed_inflight`. `FIN` mirrors only
when `acked == offset`, and mirrored writes skip carriers with
`demoted_at.is_some()`. See
[`session-token-stream.md`](../benchmarks/session-token-stream.md) for full
A/B (`off` vs `dup` vs `hedge`) and `conversation_baseline` measurements:
`cn163-offpeak` seed 2 improves p50 by 31x and p99 by 12.6x while 3 MiB uploads
add ~0.9% wire overhead, whereas `cn163-peak` still sees spare `resumes` so
tuning `cn163-peak` remains a tracked follow-up (`RedundancyMode::Off` disables
Stage 2 duplication when needed).

**Stage 3 — shed under pressure & compact memory (done).** Redundant writes
charge `Tier::Elastic` only (`drop_due` clears pending dup items under pool
pressure), `pressure_idle_after` tightens AI receive credit retention (`60 s`
default `idle_after_ai`) on pool pressure, and `CarrierFrame` boxing inside
`CarrierEv::Frame` keeps retained idle client memory at ~23 KiB/session (within
the 32 KiB limit in `tests/memory.rs`) and `memory_spent.rs` peak within budget.

**Stage 4 — optional parity (b) for bulk**, only if Stage 2's numbers justify
it.

**Stage 5 — QUIC carrier fixes (d)**, measured against sing-box on the same
profiles.

## 7. Test plan (impairment proxy)

Implemented test coverage across the workspace:

- **Unit & simulation (`segue-session`):** `flow.rs` unit tests (including
  `DupQueue` and `idle_after_ai`), `tests/sim.rs` (30 tests covering
  `stage2_dup_hides_primary_packet_loss_without_swapping`,
  `stage2_late_bind_and_drop_due_still_protect_streaming_tokens`,
  `stage2_mixed_bulk_and_small_frames_never_hit_data_gap`,
  `stage2_one_sided_swap_never_resets_on_mirrored_fin_or_dup_gap`,
  `primary_download_blackhole_self_heals_onto_live_spare_and_rst_mirrors`,
  `relay_detached_rescued_by_frame_on_bound_spare`, and randomized faults),
  `tests/driver.rs` (34 tests including
  `redundant_tx_sheds_under_pool_pressure_without_blocking_primary` and
  `reattach_aborts_in_flight_standby_dial_and_rearms`), `tests/redundant.rs`
  (5 tests), and `tests/timers.rs` (22 tests including
  `ai_idle_keepalive_fires_on_primary_and_standby_at_20s`).
- **Memory (`segue-session`):** `tests/memory.rs` (`FIXED = 32 * 1024`) and
  `tests/memory_spent.rs` (`FIXED = 24 * 1024`).
- **Kernel & E2E (`segue-kernel`):** `segue-kernel --lib` (219 tests including
  `exit_redundant_carrier_must_exist_and_not_be_home`,
  `ai_standby_promotes_without_waiting_for_a_dial`, and
  `standby_uses_redundant_carrier_without_racing`) and `tests/redundancy_e2e.rs`
  (`token_stream_baseline` and `conversation_baseline` driven by
  `SEGUE_REDUNDANCY=off|dup|hedge`).

## 8. Open questions

- **Spacing.** `RedundancyMode::Dup` defaults to `delay = 30 ms`
  (`Hedge` supports arbitrary `delay`). `cn163-offpeak` gains cleanly;
  `cn163-peak` tail behavior with spare-carrier `resumes` is tracked as a
  follow-up.
- **Second protocol / carrier.** `segue-kernel` now supports
  `Exit.redundant_carrier` so standby/redundant traffic can use a separate
  outbound in the same egress group without dial racing.
- **Trigger.** Defaults to `RedundancyMode::Dup { delay: 30 ms }` with
  `ai_only = true` (active when an AI session has a bound standby carrier;
  opt-out via `RedundancyMode::Off`). Relay capacity and per-session
  `CarrierFrame` memory remain bounded via `max_carriers` and `Tier::Elastic`
  (`drop_due`).
- **Correlated loss.** With `connection_seed` decorrelation on the synthetic
  impair proxy, two carriers avoid lockstep packet drops; under heavy peak
  bursts (`cn163-peak`), independent spare carrier stalls can still trigger
  `resumes`, increasing tail p99 until tuned.
