# Datagram redundancy for AI token streams

Status: design, no product code. Model: `segue-bench dgramsim` (seed 1).
Related: [`session-redundancy.md`](./session-redundancy.md),
[`session-v0.5.md`](../protocol/session-v0.5.md) §2.3, §2.7, §4.1, §11.

## 0. Recommendation

Send each small AI frame on **two independent UDP flows, carrying the last
2 unacked frames** (`dup/K=2/N=2` below). On this seed that is p99 added
delay 0.0 ms (Bernoulli) / 15.0 ms (Gilbert), no stall over 300 ms, residual
0.000% / 0.033%. A reliable stream on the same flat path still has p99
1015 / 1315 ms and 1–2 stalls over 1 s, and that model is optimistic (below).

If only one UDP flow is up, use **N=4 on that flow** (`dgram/N=4`: Gilbert
p99 40 ms, no stall over 300 ms). Do not ship N=1: its median (115 / 95 ms)
is worse than TCP fast retransmit, because a 1.5×RTT timer bubbles longer
than one RTT. Do not coalesce to 40 ms: the second fresh frame uses up the
RED slots, so `coal/N=2` has no redundancy, and even `coal/N=4` keeps a 20 ms
floor and a 1.133% Gilbert residual.

The reliable carrier stays the source of truth and is **not** one of these
UDP flows. Datagrams are an accelerator. Their loss is harmless.

## 1. Measurements this is built on

Not re-measured here. Beijing evening peak, four flows, 30 pkt/s, 100 B,
10 min, from the task brief:

- UDP round-trip loss 13.4–16.6% per flow. Runs are short: singles
  1820–2141, pairs 252–318, triples 26–56, 5–8 in a row 0–1 times, longest
  burst 167 ms. UDP RTT p50 162–175 ms, p99 229–239 ms.
- Two flows between the same hosts are independent: P(B lost | A lost) is
  13.0–15.9% at lag 0, 33, 100, 200 and 500 ms. Both lost: 1.9–2.3%.
- TCP at the same time: 74–82% of records > 200 ms late; RTT p50 611–720 ms
  (min 171–177), p99 2.2–3.3 s, max 3.7–4.7 s. Off-peak loss on this path
  is 0.2–0.3% and TCP is fine.

7.5% per direction is the model's marginal: `1 − (1 − 0.075)² ≈ 14.4%`
round trip, inside 13.4–16.6%.

## 2. What the model is

`segue-bench dgramsim [--seed N]`, default seed 1. Pure, no sockets.
3000 frames, 30–60 B, every 20 ms, 60 s, one-way delay 85 ms (RTT 170 ms).
In-order release: a frame is visible at `max(its arrival, previous release)`.
Added delay is that minus birth minus 85 ms. A stall is a gap between
releases. Residual is the share of frames **no original copy** delivered
(a later retransmit may still). Percentiles are nearest-rank.

Loss, per packet per direction: (a) independent Bernoulli 7.5%;
(b) Gilbert-Elliott, loss 0 in good and 1 in bad, bad→good 0.85
(mean bad run ≈ 1.18 packets, so P(L≥2) ≈ 0.15 and P(L≥3) ≈ 0.022, inside
the bins above), good→bad 0.06892, steady-state loss 0.075. Same
transition-then-drop order as `impair::LossModel`. K flows do not share state.

The TCP row is `impair`'s recovery, not a TCP stack and **not** the measured
600 ms queueing: fast retransmit when ≥ 3 later segments sit inside one RTT
(this pacing has 8), else a tail-loss probe at 2×RTT, then an RTO of
`max(200 ms, 3×RTT)` doubling per lost retransmission, cap 8 s, head-of-line.
Retransmission losses are drawn up front. The SYN rule is not applied.
Datagram retransmit is anything still unacked 1.5×RTT (255 ms) after first
send, redrawn when sent, capped at 16. An ACK rides the flow that got the data.

Wire bytes are an assumption: IPv4+TCP 40 or IPv4+UDP 28, 4 B datagram
header, 6 B per carried frame, ACK 2+4n, one TCP ACK per two segments
(dup-ACKs not counted). The table is one seed, not a mean. p99.9 is a
handful of samples. `dgram/N=3` Bernoulli residual 0.000% against
`dgram/N=4` 0.033% is one frame of noise, not a reason to prefer N=3.

## 3. Table (seed 1)

```
| scheme | loss | p50 ms | p99 ms | p99.9 ms | max ms | stalls>300ms | stalls>1s | residual | wire/payload | pkt/s |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| tcp | bern 7.5% | 0.0 | 1015.0 | 1555.0 | 1615.0 | 13 | 1 | 7.867% | 2.53 | 81.3 |
| dgram/N=1 | bern 7.5% | 115.0 | 490.0 | 510.0 | 510.0 | 15 | 0 | 8.033% | 2.98 | 112.5 |
| dgram/N=2 | bern 7.5% | 0.0 | 255.0 | 490.0 | 510.0 | 1 | 0 | 0.667% | 3.84 | 99.1 |
| dgram/N=3 | bern 7.5% | 0.0 | 20.0 | 40.0 | 40.0 | 0 | 0 | 0.000% | 4.99 | 96.5 |
| dgram/N=4 | bern 7.5% | 0.0 | 40.0 | 450.0 | 510.0 | 1 | 0 | 0.033% | 6.19 | 96.0 |
| dup/K=2 | bern 7.5% | 0.0 | 215.0 | 255.0 | 255.0 | 0 | 0 | 0.433% | 5.20 | 196.4 |
| dup/K=3 | bern 7.5% | 0.0 | 115.0 | 255.0 | 255.0 | 0 | 0 | 0.133% | 7.66 | 289.2 |
| dup/K=2/N=2 | bern 7.5% | 0.0 | 0.0 | 20.0 | 20.0 | 0 | 0 | 0.000% | 7.53 | 192.5 |
| coal/N=1 | bern 7.5% | 20.0 | 525.0 | 745.0 | 785.0 | 7 | 0 | 7.267% | 2.32 | 64.7 |
| coal/N=2 | bern 7.5% | 35.0 | 585.0 | 765.0 | 785.0 | 11 | 0 | 8.333% | 2.33 | 64.9 |
| coal/N=3 | bern 7.5% | 20.0 | 490.0 | 705.0 | 765.0 | 6 | 0 | 3.800% | 2.75 | 57.7 |
| coal/N=4 | bern 7.5% | 20.0 | 350.0 | 705.0 | 765.0 | 2 | 0 | 0.600% | 3.16 | 50.4 |
| tcp | gilbert | 5.0 | 1315.0 | 1595.0 | 1615.0 | 25 | 2 | 7.333% | 2.53 | 81.2 |
| dgram/N=1 | gilbert | 95.0 | 510.0 | 705.0 | 765.0 | 17 | 0 | 7.267% | 2.98 | 112.6 |
| dgram/N=2 | gilbert | 0.0 | 565.0 | 745.0 | 765.0 | 5 | 0 | 1.833% | 3.88 | 100.5 |
| dgram/N=3 | gilbert | 0.0 | 215.0 | 450.0 | 510.0 | 1 | 0 | 0.300% | 5.00 | 96.9 |
| dgram/N=4 | gilbert | 0.0 | 40.0 | 195.0 | 255.0 | 0 | 0 | 0.033% | 6.19 | 96.2 |
| dup/K=2 | gilbert | 0.0 | 235.0 | 255.0 | 255.0 | 0 | 0 | 0.533% | 5.22 | 197.5 |
| dup/K=3 | gilbert | 0.0 | 55.0 | 235.0 | 255.0 | 0 | 0 | 0.100% | 7.66 | 288.9 |
| dup/K=2/N=2 | gilbert | 0.0 | 15.0 | 195.0 | 255.0 | 0 | 0 | 0.033% | 7.53 | 192.4 |
| coal/N=1 | gilbert | 20.0 | 530.0 | 745.0 | 785.0 | 9 | 0 | 7.200% | 2.31 | 64.3 |
| coal/N=2 | gilbert | 20.0 | 605.0 | 960.0 | 1020.0 | 9 | 0 | 7.867% | 2.31 | 64.4 |
| coal/N=3 | gilbert | 20.0 | 470.0 | 725.0 | 785.0 | 5 | 0 | 3.333% | 2.72 | 56.9 |
| coal/N=4 | gilbert | 20.0 | 275.0 | 510.0 | 530.0 | 2 | 0 | 1.133% | 3.17 | 50.9 |
```

Why K=2 and N=2, not either alone. On one flow, Gilbert residual at N=2 is
1.833% against 0.667% Bernoulli: the two copies are the next two packets, and
a bad run of two eats both. K=2 stays near 0.5% on both arms, which is the
independence in §1. K=2 without N still waits one 255 ms retransmit at p99
(215 / 235 ms). K=3 spends 289 pkt/s to get a worse p99 than K=2/N=2.
N=4 on one flow is close on this seed (residual 0.033%, p99 40 ms) but a
run of 5, which the histogram's 5–8 bin allows (0–1 times in 10 min), deletes
every copy; the other flow does not share that run.

## 4. Carrier and binding

DGRAM is codec-only today (§2.3, §11): the relay refuses `Kind::Udp`.
Unreliable datagrams already exist under the session, not in it.
`Session::loses_datagrams` is true for Hysteria2, TUIC, SOCKS, WireGuard
and MASQUE, and false for VLESS mux, Trojan, VMess and AnyTLS
(`crates/segue-engine/src/outbound/datagram.rs`). Hy2/TUIC are QUIC datagrams;
vendored quinn-proto 0.11.19 queues them in `Datagrams::send`
(`vendor/quinn-proto/src/connection/datagrams.rs`). Stream-encapsulated UDP
is a reliable ordered pipe and is the wrong accelerator.

K=2 is two UDP 4-tuples to the same host (two Hy2 or TUIC connections), not
two packets on one connection. The measurement's independence is across flows.

The reliable carrier stays **current**. It should be a path that survives a
UDP blackout (a TCP tunnel), not a stream on the same QUIC connection as the
datagrams: a blackout would otherwise take the source of truth with the
accelerator. Every byte is still written, in order, on that carrier.
`REDUNDANT_ATTACH` / `REDUNDANT_OK` (§2.7) must not be reused. That spare is
promoted to current on stall. A datagram path is never current, never
promoted, and its death does not count toward `MAX_FRUITLESS` or a stall swap.

Binding, proposed, opcode left open: an ignorable frame on the reliable
carrier carries `session_id`, `attach_gen` and a nonce. Datagrams echo the
nonce. A generation mismatch drops that datagram only. No version bump if
the frame is `FLAG_IGNORABLE`, same idea as §2.7.

## 5. Frames

Datagram payload budget ≤ 1200 B (the brief's cap; quinn only promises a
little over 1 KB when the peer allows datagrams). Proposal:

```
type:u8     1 DATA, 2 ACK, 3 FIN
flags:u8
count:u8
repeat count:
  offset:varint
  len:varint          DATA only
  bytes               DATA only
ACK also carries recv_offset:varint and max_offset:varint (the window).
```

The sim's 4+6n header is smaller than this and has no `session_id`. A 16 B
id plus a 16 B MAC on every packet is about 32 × 192 ≈ 6 KB/s extra at the
recommended row (assumption, not resimulated). N=2 of 60 B frames is ~140 B
in the sim's header and fits. One 1024 B frame plus one 60 B block still
fits; two 1024 B blocks do not. The codec stops adding blocks at 1200 and
sends the rest on the reliable carrier only.

Receive: duplicates (`end ≤ recv_offset`) already trim to zero
(§4.1). A byte **past** `recv_offset` is the fatal `gap in data` on the
reliable path. The accelerator must not call that path. Park a non-contiguous
block (a few KB, bounded by N × 1 KiB) beside `RecvHalf`, apply it when it
becomes contiguous, and drop it when the reliable stream covers the offset.
That park is the in-order release the table measures.

ACK: the model sends one SACK per received data packet, on that flow.
Do that in S2. The reliable carrier keeps its own ACK rule (quarter-window
or 20 ms, §4.1) unchanged. The window rides in `max_offset`, so a datagram
ACK has to carry it or the sender only learns through the HOL-blocked stream.
FIN is one offset and is not charged to the window (§4.1): send it once per
datagram flow as well as on the reliable carrier. RST stays on the reliable
carrier only, so a reordered datagram cannot reset a live session.
OPEN, RESUME and bulk DATA are not duplicated.

## 6. When, and the cap

On for `EXIT_AI` only, frames ≤ 1 KiB, downlink tokens first (S2), uplink
small frames second (S3). Never bulk. Off-peak loss is 0.2–0.3%; redundancy
is pure overhead there. Leave it on anyway for AI sessions: the table's
zero-loss case adds no delay for this scheme, and detecting "peak" is a
separate question (§8).

`dup/K=2/N=2` is 7.53× payload and 192 pkt/s **for the accelerator alone**.
Mean frame 45 B × 50/s = 2250 B/s, so about 17 KB/s. The reliable carrier
is additional (the tcp row, 2.53× and 81 pkt/s in the model) and is not
part of this cap. Cap the accelerator at 32 KB/s and 200 pkt/s — an
assumption, set just above that row and far below bulk. Over the cap, shed
N first (keep the second flow), then drop to one flow at N=4, then send
nothing on UDP. Never drop reliable bytes to make room.

[RFC 9265](https://www.rfc-editor.org/info/rfc9265) (FEC and congestion
control): a recovered packet must still count as a loss to loss-based
congestion control, or redundancy hides the only congestion signal and the
flow outruns its share. The reliable carrier's controller sees its own
losses and is not told the path is clean because a datagram copy arrived.
Datagrams are a separate, capped rate. They are not a credit against the
bulk window. On a Hy2/TUIC connection that also carries other traffic, a
datagram recovered by the other flow is still a loss for the flow that
dropped it.

## 7. UDP blackout

The brief records minutes-long UDP blackouts on this carrier (measured
elsewhere, not in this sim). Fallback is the reliable carrier alone,
unchanged: same offsets, same ACK rules, no RESUME caused by the datagram
path going quiet. Stop sending datagrams once they have made no progress
across a few retx intervals while the reliable offset is still moving.
The timeout length is an assumption (§8); the blackout duration is not.
A later probe may turn the accelerator back on. Nothing in §2.7's stall
swap changes.

## 8. Stages

Each gate is a cell from §3, or the unit tests of the model.

| stage | what | acceptance on the S0 workload |
|---|---|---|
| S0 | this model | zero loss adds 0 ms for every scheme except coal's 0 or 20 ms hold; scheme 3, K=2, 14% loss, 100 000 packets, residual within 1.96% ± 0.4; seed 1 reprints §3 |
| S1 | codec + bind, no acceleration | datagrams dropped entirely: the session matches the tcp row (p99 1015 ms Bernoulli / 1315 ms Gilbert) and does not reset |
| S2 | downlink tokens, K=2 N=2 | Gilbert `dup/K=2/N=2`: p99 ≤ 15 ms, stalls>300 ms = 0, residual ≤ 0.033% |
| S3 | uplink frames that fit §5 | same three numbers |
| S4 | real-path A/B, `pairprobe` style | over 60 s, stalls>1 s = 0 (the dup rows; the tcp rows are 1 and 2) and p99 added delay ≤ 255 ms (the `dup/K=2` max, one retransmit) |

S4 will fail if real TCP queueing (p50 RTT 611–720 ms) also sits under the
datagrams. That is a useful failure: the model has no queue.

## 9. Open, and not verified

- `t_stall_ai` is named in the task brief and does not appear in
  `session-v0.5.md` or `session-redundancy.md`. The timers that do exist
  are `t_stall`, `t_live` and `t_detached_standby` (10 s, §2.7).
- One 60 s seed. The GE chain matches the burst **ratios**, it is not a
  replay of the capture. Header sizes, the 32 KB/s cap, the ~6 KB/s bind
  overhead and the blackout timeout are assumptions.
- The sim ACKs every data packet. The session's 20 ms delayed ACK was not
  swept; it would change pkt/s and spurious retransmits.
- The table's schemes are alternatives. Production runs the tcp row **and**
  the datagram row. §6 adds them; that sum was not a separate simulation.
- Flow independence is an input from §1. A shared queue that correlated the
  two UDP flows is not in the model.
- Not verified on the wire: Hy2/TUIC datagram MTU, whether two connections
  to one host stay independent at the table's 192 pkt/s, and any `pairprobe` run.
- In-order release matches an app that prints tokens in order. A consumer
  that could show a later token before a hole would beat the table; the
  current receive path cannot, because a gap is fatal (§4.1).
