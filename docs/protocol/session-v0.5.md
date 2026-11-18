# SESSION_PROTOCOL v0.5 — Segue L5 session protocol (reconstructed)

> **Status of this document.** The code cites "SESSION_PROTOCOL v0.5 §2/§4/§5/§9.2"
> (`crates/segue-session/src/codec.rs:1`, `flow.rs:1`, `client.rs:1`, `relay.rs:1`)
> but no spec file exists in this repository. This document reconstructs the
> protocol from the implementation, so the protocol has a source of truth in-repo.
> Every statement carries a `file:line` citation; where the code and this text
> disagree, the code wins and this file should be fixed.
>
> **Wire version.** v0.5 is wire version **5** (`crates/segue-session/src/codec.rs:39`,
> asserted by `tests/codec.rs:137`). Two module headers still say "v0.4"
> (`crates/segue-session/src/lib.rs:1`, `crates/segue-relay/src/lib.rs:2`) — stale
> comments from before the `t_stall_ms` field changed the OPEN/RESUME layout (r10 N3).
> Nothing older than version 5 was ever deployed, so there is no negotiation: a
> peer of another version answers `REJECT(version)` before reading any other field
> (`codec.rs:33-37`).
>
> **Relationship to other specs.** The code also cites `KERNEL_SPEC` (§5.4 exits,
> §5.5 exit rules, §5.6/§5.7 Home lines, §6.2 policy bundle, §6.3 memory pool,
> §6.4/§6.5, §7.2 timers "数据停滞"/"网络变化") and `CONTROL_PLANE_SPEC` (§3.3 ticket
> issuing, §4 revocation feed). Those sections are **not** part of this protocol;
> a citation index at the end keeps them apart. Numbered annotations in comments
> (`A1`, `A2`, `A8`, `B1`, `B2`, `B6`, `R2-1`, `R2-2b`, `R2-2c`, `r5 N9` … `r13`)
> refer to design-review rounds, not to sections of this spec.

## 1. Layering and roles

Segue adds a session layer (L5) between an outer transport and the application
stream. The layering, top to bottom:

```
application stream (TCP byte stream, one per flow)
        │  opened/read/written through KernelDialer / run_client
Segue session layer  (this spec: frames, offsets, replay, attach generations)
        │  frames ride an arbitrary byte stream called a *carrier*
carrier = any Xray-compatible outer stream: engine Reality / Hy2 outbound on the
          client side, loopback-forwarded inbound on the relay side
outer network (TLS/Reality/QUIC/Hy2 as configured)
```

Evidence:

- A carrier is "any `AsyncRead + AsyncWrite`" byte stream
  (`crates/segue-session/src/driver.rs:44`, `driver.rs:895-934`): the session
  layer never dials itself; the caller supplies a `Connector`
  (`driver.rs:60`).
- On the device, every carrier is an engine stream (Reality / Hy2) to the
  relay's loopback address on the node (`crates/segue-kernel/src/session/mod.rs:3-6`).
- On the node, the outer servers (Xray Reality, sing-box / Hysteria Hy2) forward
  their Segue inbound to the relay process on loopback; each forwarded stream is
  one session carrier (`crates/segue-relay/src/lib.rs:4-7`,
  `crates/segue-relay/src/server.rs`).

**Roles.**

- **Client** — the device side. Sans-IO state machine `ClientSession`
  (`crates/segue-session/src/client.rs:169`) driven by async glue `run_client` /
  `run_client_ctl` (`crates/segue-session/src/driver.rs:895`, `driver.rs:934`).
  In this repo the client is embedded in the kernel (`segue-kernel`) behind the
  `Dialer` seam (`crates/segue-kernel/src/session/mod.rs:1-3`).
- **Relay (node)** — Sans-IO session table `RelayTable`
  (`crates/segue-session/src/relay.rs:223`), driven by `run_relay` /
  `run_relay_ctl` (`crates/segue-session/src/driver.rs:1508`, `driver.rs:1519`),
  wired to the network by the `segue-relay` crate (`crates/segue-relay/src/server.rs`).
  The relay terminates the session layer and dials the real target ("site").
- **Anchor instance** — the relay *process* that owns a session's state. Each
  relay instance has an `instance_id` (random per process,
  `crates/segue-session/src/relay.rs:234`, exposed in OPENED/RESUMED and the
  CTRL_HELLO reply `codec.rs:476-481`). A session's state lives in exactly one
  instance; `anchor_instance_id` in OPEN/RESUME pins it (§9 below). An
  **anchor node** (`anchor_node_id`) is the catalog id of the node the device
  chooses (`crates/segue-session/src/client.rs:40-42`,
  `crates/segue-kernel/src/session/mod.rs:108-110`).

**Tickets.** Every OPEN and RESUME carries an opaque `ticket` blob. The session
crate only defines the `Authorizer` hook — `open()` maps (ticket, target, kind)
to a `Grant` (device id, exit-class bits, AI anchor node) or a REJECT code, and
`resume()` maps a ticket to a device id; both must be side-effect-free
(`crates/segue-session/src/relay.rs:59-64`). The production implementation is
`TicketAuth`: `SGT1.` base64url(JSON claims) `.` base64url(Ed25519 signature),
verified offline against public keys (`crates/segue-relay/src/ticket.rs:1-7`,
`ticket.rs:38-53`). See §6.

**Control stream.** Besides session carriers, a device keeps one or more
*control streams* to a relay: a carrier whose first frame is `CTRL_HELLO`
instead of OPEN/RESUME (`crates/segue-session/src/relay.rs:10-14`). It carries
PING/PONG liveness, `STALL` hints ("one of your sessions went DETACHED, move
it") and `REVOKED`. Client side: `run_control` (`crates/segue-session/src/driver.rs:1853`),
kernel wiring per exit (`crates/segue-kernel/src/session/mod.rs:32-37`).

## 2. Wire format (spec §2)

Source: `crates/segue-session/src/codec.rs` (module doc `codec.rs:1-39`,
encoder `codec.rs:569-676`, decoder `codec.rs:778-990`). The spec "lists the
fields of each frame but not their encodings" (`codec.rs:9-10`); the encodings
below are fixed by this crate.

### 2.1 Frame envelope

```
frame = type:u8 | flags:u8 | length:varint | payload[length]
```

- **Varints** are QUIC variable-length integers (RFC 9000 §16): 2-bit length
  prefix, 1/2/4/8 bytes, maximum value 2^62−1 (`codec.rs:2-3`, `codec.rs:49`,
  `put_varint` `codec.rs:300`, `get_varint` `codec.rs:323`).
- `length` ≤ **16384** (`MAX_PAYLOAD`, `codec.rs:43`); a longer frame is the
  fatal error `FrameTooLong` (`codec.rs:1065-1085`, checked in `next_frame`).
- **flags**: `0x80` = FLAG_IGNORABLE — an unknown frame type carrying it is
  skipped instead of fatal (`codec.rs:45`, `codec.rs:983-984`);
  `0x40` = FLAG_PADDED — DATA only, payload starts with `pad_len` (`codec.rs:47`).
- All integers inside payloads are varints unless noted; `attach_gen` and
  `park_gen` are **u32 big-endian**, `session_id` is **16 raw bytes**,
  `resume_secret` **32 raw bytes**, PING/PONG nonces **u64 big-endian**,
  `node_id`s inside CTRL_HELLO payloads **u64 big-endian** (`codec.rs:11-14`,
  `codec.rs:435-475`).
- Stream framing is incremental: `FrameDecoder` (`codec.rs:1025`) buffers at
  most one partial frame plus one read; errors from `next_frame` are fatal for
  the carrier (`codec.rs:1065-1070`).

### 2.2 Address encoding (`target`)

`atyp:u8` then (`codec.rs:417-422`, `Reader::target` `codec.rs:423-442`):

| atyp | meaning | layout |
|------|---------|--------|
| 1 | IPv4 | 4 address bytes, `port:u16` BE |
| 3 | domain | `len:u8` (1–255, non-empty), name bytes, `port:u16` BE |
| 4 | IPv6 | 16 address bytes, `port:u16` BE |

DGRAM accepts IP addresses only; a domain is malformed there (`codec.rs:444-449`).

### 2.3 Frame types

Type bytes (`codec.rs:51-76`). "Recognised, carried as `Frame::Control` with an
unparsed payload" (`codec.rs:35-37`) means: decodable, not fatal, handler lives
outside the session crate.

| type | frame | payload layout (in order) |
|------|-------|---------------------------|
| 0x01 | OPEN | see §2.4 |
| 0x02 | OPENED | `instance_id:varint`, `attach_gen:u32be`, `recv_offset:varint`, `max_offset:varint`, `window_cap:varint`, `ack_bytes:varint` (`codec.rs:603-611`) |
| 0x03 | RESUME | see §2.4 |
| 0x04 | RESUMED | `instance_id:varint`, `attach_gen:u32be`, `recv_offset:varint`, `max_offset:varint` (`codec.rs:621-626`) |
| 0x05 | REJECT | `code:u8`, `attach_gen:u32be`, then **iff `code == 9 (closed)`**: `close_code:u8`, `final_recv_offset:varint`, `final_sent_offset:varint` (`codec.rs:629-645`, `codec.rs:846-864`) |
| 0x10 | DATA | [`pad_len:varint` iff FLAG_PADDED], `offset:varint`, data bytes, `pad` zero bytes; `offset+len(data)` must be ≤ 2^62−1 (`codec.rs:647-664`, `codec.rs:866-884`) |
| 0x11 | ACK | `recv_offset:varint`, `max_offset:varint` (`codec.rs:665-670`) |
| 0x12 | FIN | `offset:varint` (`codec.rs:671`) |
| 0x13 | RST | `code:u8` (`codec.rs:672`) |
| 0x14 | PAD | `n` zero bytes; the payload length *is* the padding (`codec.rs:673`, `codec.rs:901`) |
| 0x20 | DGRAM | IP `target` (atyp 1/4 + addr + port), then datagram bytes to the end (`codec.rs:674-678`, `codec.rs:902-905`) |
| 0x30 | CTRL_HELLO | opaque here; sub-format §2.5 |
| 0x31 | PING | `nonce:u64be` (`codec.rs:679`) |
| 0x32 | PONG | `nonce:u64be`, optional opaque `extra` to the end (`codec.rs:680-683`) |
| 0x33 | WAKE | flags bit 0 = `full`; `count:varint`, then per entry `anchor_node_id:varint`, `session_id:16b`, `park_gen:u32be` (`codec.rs:684-693`) |
| 0x34 | PARK | `count:varint`, then per entry `session_id:16b`, `req_id:varint`, `attach_gen:u32be`, `c_recv_offset:varint`, `c_sent_offset:varint` (`codec.rs:694-703`) |
| 0x35 | PARK_ACK | `count:varint`, then per entry `session_id:16b`, `req_id:varint`, `attach_gen:u32be`, `accepted:u8` (0/1), `park_gen:u32be` (`codec.rs:704-716`) |
| 0x36 | STALL | `count:varint`, then per entry `session_id:16b`, `attach_gen:u32be` (`codec.rs:717-723`) |
| 0x37–0x3B | RESOLVE, RESOLVED, REFRESH, REFRESHED, REVOKED | recognised, payload unparsed by this crate (`codec.rs:970-976`); REVOKED payload is `[code:u8]` by writer convention (`crates/segue-session/src/relay.rs:991-997`) |

Entry `count`s are checked against the remaining payload length up front (every
entry is ≥ 16 bytes), so an absurd count is malformed before any allocation
(`Reader::count` `codec.rs:393-400`).

### 2.4 OPEN and RESUME

OPEN payload, in order (`codec.rs:594-602` encoder, `codec.rs:790-828` decoder):

```
version:u8                       must equal 5, else ProtoError::Version (§10)
ticket:varint-len + bytes        opaque to the session layer (§6)
session_id:16 bytes              client-chosen random (client.rs:245-251)
resume_secret:32 bytes           client-chosen random; proves re-attach (§3)
attach_gen:u32be                 generation of this attach (§4.4)
open_flags:u8                    bit 0 = retry, bit 1 = t_stall_ms present
anchor_instance_id:varint        0 = none (first OPEN carries 0)   (codec.rs:15-16)
kind:u8                          0 = TCP, 1 = UDP; anything else malformed
target                           §2.2
exit_class:u8                    client hint only; the relay classifies (R2-1)
[t_stall_ms:varint]              iff open_flags bit 1; 0 is malformed; 1..=2^62-1
first_data:rest                  optimistic payload of stream offset 0
```

RESUME payload (`codec.rs:612-619`, `codec.rs:830-848`):

```
version:u8
ticket:varint-len + bytes
anchor_node_id:varint
anchor_instance_id:varint        0 = unknown instance
session_id:16 bytes
resume_secret:32 bytes
attach_gen:u32be
recv_offset:varint               client's snapshot: all bytes before this are received
max_offset:varint                client's current advertised window edge
[t_stall_ms:varint]              optional trailing varint; absent = relay uses its own
```

`t_stall_ms` (the client's stall bound in milliseconds, r9/r10 N3) is the field
that made wire version 5: a version-4 decoder would read it as `first_data`
(OPEN) or trailing garbage (RESUME), so the version changed and a v4 peer gets
`REJECT(version)` (`codec.rs:24-33`). A value of 0 is malformed; the encoder
clamps out-of-range values to `1..=STALL_MS_MAX` instead of panicking
(`codec.rs:369-371`, tested `tests/codec.rs:155-189`). The largest DATA chunk
that fits one frame is `max_data_len(offset, pad) = MAX_PAYLOAD − pad_hdr −
varint_len(offset) − pad` (`codec.rs:1017-1020`).

### 2.5 CTRL_HELLO payloads

Client → relay (`CtrlHello`, `codec.rs:435-473`):
`version:u8` (must be 5), `ticket:lp`, `count:varint`, then `count × node_id:u64be`
(the `anchor_node_id`s the device has sessions at). Relay → client
(`CtrlHelloReply`, `codec.rs:476-507`): `node_id:u64be` (0 in this
implementation, `relay.rs:460-468`), `instance_id:u64be`,
`ticket_expired:u8` (0/1).

### 2.6 Worked byte examples

The tests assert round-trips and malformed-input behaviour, not fixed vectors
(`crates/segue-session/tests/codec.rs`). The examples below are derived from the
encoder (hand-computed; layout per §2.1–2.4), all with flags = 0x00:

```
PING(nonce = 0x0102030405060708):
  31 00 08 01 02 03 04 05 06 07 08

ACK(recv_offset = 4096, max_offset = 20480):
  11 00 06 50 00 80 00 50 00          # 4096 → 2-byte varint 0x5000,
                                      # 20480 → 4-byte varint 0x80005000

DATA(offset = 0, data = "hi"):
  10 00 03 00 68 69

FIN(offset = 5):        12 00 01 05
RST(code = 27):         13 00 01 1B
PAD(4):                 14 00 04 00 00 00 00

OPEN (version 5, ticket "t", session_id 0x01×16, resume_secret 0x02×32,
attach_gen 3, open_flags 0, anchor_instance_id 0, kind TCP,
target example.com:443, exit_class 1, no t_stall_ms, no first_data):
  01 00 40 4A                          # payload length 74 → varint 0x404A
  05 01 74                             # version, ticket len 1, 't'
  01×16  02×32                         # session_id, resume_secret
  00 00 00 03                          # attach_gen
  00                                   # open_flags
  00                                   # anchor_instance_id
  00                                   # kind = TCP
  03 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D 01 BB   # atyp 3, len 11, port 443
  01                                   # exit_class
```

## 3. Auth material and the control stream (spec §3)

Two things the code attributes to §3:

- **`resume_secret` comparison is constant-time.** A re-attach (OPEN retry or
  RESUME) must prove knowledge of the 32-byte secret chosen by the client in
  its first OPEN; the relay compares in constant time (`crates/segue-session/src/lib.rs:170-180`,
  used at `relay.rs:496` and `relay.rs:578`). The secret and ticket are never
  printed by any `Debug` impl (`codec.rs:162-201`, `client.rs:225-243`,
  `relay.rs:159-171`).
- **The control stream.** A carrier whose first frame is CTRL_HELLO belongs to
  a device, not a session (`crates/segue-session/src/relay.rs:10-14`,
  `relay.rs:421-474`). Relay behaviour:
  - CTRL_HELLO is ticket-checked (`Authorizer::resume`, `relay.rs:433-438`);
    a wrong wire version is answered `REJECT(version)` (`relay.rs:424-426`,
    spec §10), other malformed closes the carrier (`relay.rs:427`).
  - The reply is the `CtrlHelloReply` (node/instance ids, ticket state,
    `relay.rs:459-468`).
  - PING is answered by PONG while the outbound control queue is under 64
    frames (`CTRL_QUEUE`, `relay.rs:216-218`, `relay.rs:365-378`).
  - `STALL{session_id, attach_gen}` frames are queued on **every** control
    stream of the device when one of its sessions goes DETACHED (B1,
    `relay.rs:476-489`, `relay.rs:1085-1096`), batched ≤ 512 entries per frame
    (`STALL_BATCH`, `relay.rs:220`).
  - `REVOKED[code]` is queued and the stream closed on a device reset
    (`reset_device`, `relay.rs:978-1005`).
  - Bounds: ≤ 32 live control streams per device (`MAX_CTRL_PER_DEVICE`,
    `relay.rs:206`); at the cap only streams quiet for `t_ctrl_idle / 3` are
    replaced, never a live one (`ctrl_quiet`, `relay.rs:211-213`,
    `relay.rs:439-457`). A control stream is closed after `t_ctrl_idle`
    without a frame or `max_lifetime` after its CTRL_HELLO (`relay.rs:14-16`,
    `relay.rs:1039-1050`).

Client side, `run_control` (`crates/segue-session/src/driver.rs:1853-1949`):
send CTRL_HELLO, then PING every `ping_every` (5 s); a stream is *accepted*
only once the reply arrived; silence for `dead_after` (12 s) or a break on an
accepted stream is reported as `ControlHint::Dead` — "the channel is dead,
move every session" (`driver.rs:1825-1831`, `driver.rs:1885-1890`); a REJECT
with `version|auth|expired|revoked` is terminal (`ControlHint::Rejected`,
`control_reject_is_terminal` `driver.rs:1835-1845`); every reconnect waits
`retry` (2 s) first (`ControlTiming`, `driver.rs:1792-1809`). The kernel keeps
one control stream per configured exit that has sessions
(`crates/segue-kernel/src/session/mod.rs:32-37`, `ensure_channel`
`mod.rs:445`).

## 4. Flow control and replay (spec §4)

Source: `crates/segue-session/src/flow.rs` (module doc `flow.rs:1-14`),
`pool.rs`. Each session has two independent half-flows, one per direction:
client→relay ("uplink", the relay's `RecvHalf`) and relay→client ("downlink").

### 4.1 Offsets and sequencing

- Every byte of application data has a **u64 offset** starting at 0; DATA
  frames carry `offset` and may be re-sent with the same offsets on any
  carrier. Only contiguous data is accepted: an offset beyond `recv_offset`
  is the fatal `gap in data`; a frame ending beyond the advertised
  `max_offset` is the fatal `data beyond max_offset`; duplicates (end ≤
  `recv_offset`) are trimmed and counted as zero new bytes (`RecvHalf::on_data`,
  `flow.rs:631-657`).
- **FIN occupies one offset** (rule 7) and is *not* counted against the
  window — "requiring window for it could deadlock a peer whose app has
  stopped reading" (`flow.rs:13-15`, `on_fin` `flow.rs:660-678`). FIN must sit
  exactly at `recv_offset`; a second FIN at a different offset is fatal
  (`fin moved`, `flow.rs:663-667`). A session direction is done when
  `acked > fin` (`SendHalf::done`, `flow.rs:345-347`).
- **ACK** carries the receiver's `recv_offset` (all bytes before it are
  received) and `max_offset` (the window edge: the receiver commits to buffer
  up to here). Processing rules (rule 2): an ACK for bytes never sent
  (`recv > sent_hw`) is fatal; `max_offset` never shrinks the peer's window
  (`peer_max` only grows); a duplicate or old ACK is ignored
  (`SendHalf::on_ack`, `flow.rs:228-247`).
- Delayed ACKs (rule 8 mechanism): an ACK is due immediately once a quarter of
  the outstanding credit (or a 16 KiB window step) has arrived, or the peer's
  FIN; otherwise after `ack_delay` (20 ms default; the spec says
  `jitter × SRTT/2`, floor 20 ms, `lib.rs:63-64`) (`ack_deadline`,
  `flow.rs:797-816`). ACKs piggyback ahead of new data when something is
  sendable (`client.rs:873-876`, `relay.rs:841-844`).

### 4.2 The sending side: replay buffer

`SendHalf` keeps `[acked_offset, written)` plus a FIN marker, and **two send
positions** (`flow.rs:4-8`): `cursor` — the next offset to put on the *current*
carrier, rewound on re-attach — and `sent_hw` — the highest offset ever sent,
used for the fatal checks of rules 2 and 6. Sending is bounded by the peer's
advertised `max_offset` (`peer_max`): `poll_next` stops at
  `min(data_end, peer_max)` (`flow.rs:260-288`). New application bytes are
accepted only while the replay buffer (capped by `replay_cap`, default 2 MiB,
`lib.rs:139-156`) and the pool grant cover them — backpressure, never loss
(`write`/`write_capacity`, `flow.rs:127-205`).

### 4.3 The receiving side: credit and window growth

`RecvHalf` keeps `consumed_offset` (bytes handed to the app), `recv_offset`
and the advertised `adv_max` ("`max_offset` never decreases", `flow.rs:10-11`).
The **receive credit** is `max_offset − consumed_offset`; the pool grant always
covers it, so "the bytes a peer can make us buffer are bounded by the grant"
(rule 1, `flow.rs:9-12`).

Window growth (rule 8): the receiver estimates SRTT from its own window
advertisements — when data first ends beyond an advertised edge, at least one
round trip has passed since the next advertisement went out (`RateRtt`,
`flow.rs:363-405`, samples windowed over `RTT_WINDOW` = 2 s, `flow.rs:398`,
clamped to 2 s, new measurement after each carrier change `flow.rs:473-481`,
`new_path` `flow.rs:857-861`) — and a delivery rate per SRTT epoch. The target
window is `clamp(2 × delivery_rate × SRTT, initial_credit, window_cap)`;
"a window-limited sender delivers about `win` per RTT, so the target is about
`2 × win` and the window doubles each round trip until the link, the reader or
the cap limits it" (`flow.rs:519-535`). Growth is **not** taken back when the
app reads slowly (like TCP receive autotuning); the window falls back to the
initial credit only after `idle_after` (1 s) with no data (`update_credit`,
`flow.rs:709-775`). Under pool pressure the target is capped at the pool's fair
share (`flow.rs:742-744`).

### 4.4 Attach generations and what is retransmitted

- **Generations (A1):** each successful attach to a carrier increments
  `attach_gen`; at most one attach is in flight; a superseded carrier is
  frozen — no DATA, no ACK — and every non-DATA event from it is ignored,
  while its DATA is still deduplicated by offset (`client.rs:3-6`,
  `attach` `client.rs:358-415`, `on_frame_at` `client.rs:661-691`).
- **On re-attach** the client sends RESUME with its snapshot
  (`recv_offset`, `max_offset`), and the sender **replays from
  `max(peer.recv_offset, own.acked_offset)`**: the relay's RESUMED (or the
  client's own RESUME ACK state) rewinds the cursor (`SendHalf::rewind`,
  `flow.rs:249-258`). Bytes the peer already had are skipped by offset;
  duplicates that still arrive are dropped in `on_data` (`flow.rs:645-647`).
  "An old snapshot is not an error; one beyond anything ever sent is"
  (`resume offset beyond sent`, rule 6, `flow.rs:247-258`).
- **Relay side (atomic attach, §5.2):** `switch` snapshots the client's
  offsets, rewinds its downlink replay buffer, closes the old carrier, binds
  the new one and restarts RTT measurement — all before any frame goes out
  (`relay.rs:629-670`).
- **Optimistic data:** only the first OPEN of generation 0 may carry
  `first_data` before any answer (`client.rs:860-864`); an OPEN retry carries
  none, and a retry OPEN that reaches a relay which knows the session is
  treated as a resume with the client snapshot `(0, initial credit)`
  (R2-2b, `relay.rs:517-527`, `client.rs:736-748`).

### 4.5 The global pool (rule 8) and admission floors

All session memory comes from one process-wide pool counted in 4 KB blocks
(`BLOCK`, `pool.rs:51`); a session holds a `Grant` that grows and shrinks, the
sum of grants never exceeds the pool, and `try_resize` fails instead of
overcommitting (`pool.rs:1-10`). "Grants are charged for the memory a buffer
actually holds, not for the bytes in it" (`pool.rs:12-15`). The kernel uses one
8 MiB pool for session buffers, driver queues and the TUN stack's TCP buffers
(`crates/segue-kernel/src/session/mod.rs:76-86`).

**Admission floors (rule 8 arithmetic):** a session is admitted only if the
pool can cover its floors — the 16 KiB initial credit (`INITIAL_CREDIT`,
`lib.rs:151-153`), one replay block (`SEND_FLOOR` = one 4 KB block,
`flow.rs:65-70`) and one pipe block each way (`pipe.rs:1-13`) —
"`1000 × 4 KB floor = 4 MB of an 8 MB pool`" (`pool.rs:693-696`,
`tests/driver.rs:853-899`). If the pool cannot cover the initial credit the
side refuses: the client session is not created (`client.rs:245-252`), the
relay answers `REJECT(capacity)` (`relay.rs:540-549`).

**Tiers (deadlock-freedom).** *Elastic* grants (receive windows, replay
buffers, pipe and TUN ring growth, admission floors) stop at the Elastic tier
limit; *draining* buffers (a frame queued to or just read from a carrier, a
chunk on its way to the app/TUN) may use the higher Relay and Transport tiers.
"A tier's holders only ever wait for stages of a higher tier …, so the waits
form no cycle and a pool full of elastic grants still moves bytes"
(`pool.rs:17-32`, `Tier` `pool.rs:62-72`). The transport region is disjoint and
handed out in arrival order to tickets; a frame may hold it at most
`TRANSPORT_HOLD` = 2 s without a byte moving (30 s overall cap), after which
the carrier is dropped and its data replayed (`pool.rs:77-90`,
`pool.rs:33-43`).

**Growth budget.** Credit above the initial credit ("window growth") is taken
only while the elastic tier is less than half in use (`GROWTH_SHARE_DIV` = 2):
"credit once advertised cannot be revoked, so sessions that grew and then went
quiet without closing must not pin what admission needs" (`flow.rs:508-516`,
`update_credit` `flow.rs:747-766`). Under pressure (`under_pressure`,
`pool.rs:222`) a receiver's desired credit is capped at the pool's fair share
(`pool.rs:229`, `flow.rs:742-744`).
