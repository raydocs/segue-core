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
| 0x3C | REDUNDANT_ATTACH | **v0.6 draft**, `FLAG_IGNORABLE`. See §2.7 |
| 0x3D | REDUNDANT_OK | **v0.6 draft**, `FLAG_IGNORABLE`. See §2.7 |

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

### 2.7 Redundant carrier (v0.6 draft)

No version bump. Both frames are encoded with `FLAG_IGNORABLE` (`0x80`), so a
relay or client that does not know `0x3C`/`0x3D` skips them. The client closes
the spare carrier if no `REDUNDANT_OK` arrives within `t_attach` and continues
on the single current carrier. OPEN, RESUME and DATA are unchanged.

`REDUNDANT_ATTACH` is the first frame on the second carrier:

```
session_id:16
resume_secret:32
attach_gen:u32be          the session's current generation, not a new one
recv_offset:varint        client's snapshot
max_offset:varint         client's advertised window
```

`REDUNDANT_OK`, written on that same carrier:

```
attach_gen:u32be
recv_offset:varint        relay's snapshot (as in RESUMED)
max_offset:varint
```

Authentication is the RESUME proof: `session_id` plus `resume_secret`
(constant-time compare). There is no ticket. The relay accepts it only when
`attach_gen` equals the session's current generation.

Rules:

- The relay binds the carrier as **redundant** and does **not** call `switch`.
  The current carrier stays current and is not closed. At most one spare; a
  second `REDUNDANT_ATTACH` replaces the first and closes it.
- An unknown session, a tombstone, a bad secret, a wrong generation, or a
  snapshot past anything the relay has sent closes **that carrier only**.
- Binding reserves no session memory and does not change admission floors.
  The process carrier-slot limit (the relay's `max_carriers` semaphore)
  refuses the new connection before the session table sees it. A full relay
  never drops a session to free a slot for a spare.
- Until `REDUNDANT_OK` with the matching `attach_gen`, the client writes
  nothing but `REDUNDANT_ATTACH` on the spare. After that, DATA/ACK/FIN/RST
  on it are applied like on the current carrier. Receive dedup by offset
  makes a duplicate free. A gap or a bad offset on the spare is ignored;
  it does not reset the session. RST still resets the session.
- This stage does **not** duplicate DATA. The relay still writes session
  DATA only to the current carrier. ACKs (the window rides in them) may be
  written to both, from one function (`mirror_to_redundant`) so a later
  stage can extend it to small DATA.
- A spare that closes, sticks, fails to decode, or is REJECTed is dropped
  alone: no re-attach, no `MAX_FRUITLESS` count, no `Health::Failed`, no
  quality "carrier lost".
- If the **current** carrier is lost while a spare is bound, both sides
  **promote** it. Loss means the carrier closed, the transport hold gave it
  up (`on_carrier_stuck`), the client's `t_stall` fired, or the relay's
  `t_live` fired. Same `attach_gen`. **No RESUME and no other frame** is
  sent to announce the promotion.
- What crosses the wire is only what already did. `REDUNDANT_OK`'s
  `recv_offset` / `max_offset` is the relay's snapshot at bind time; later
  ACKs (mirrored onto the spare) move each side's acknowledged offset. On
  promotion each side replays unacked bytes from that offset
  (`SendHalf::rewind`). Receive dedup by offset drops a replay the peer
  already has, so the application sees neither a loss nor a duplicate.
- The relay ends up with the spare as current because it already
  authenticated that carrier at this generation. `on_carrier_closed` of the
  old current promotes the spare in place. `t_live` does the same instead of
  going DETACHED, and emits `STALL` so a client that has not noticed yet
  promotes too. The client closes the old carrier when it promotes, which is
  the signal a relay that has not timed out yet is waiting for. A `STALL`
  that arrives after the promotion, while the spare is still receiving, is
  about the carrier already left and is ignored. If that spare later goes
  quiet, the hint is a real loss: the session promotes a newer spare or
  re-attaches with RESUME, the ordinary way.
- After a promotion the client may ask again (`request_redundant`).
  `wants_redundant` is true once the session is active and no spare is
  attached. Nothing asks on its own.
- A move of the current carrier onto a third one (RESUME, including an OPEN
  retry the relay treats as resume, and a local `reattach`) **drops** the
  spare on both sides. The spare was authenticated at the old generation;
  leaving it bound would make that generation ambiguous.
- The client asks for a spare explicitly (`request_redundant` /
  `run_client_ctl_with_redundant`). Nothing turns it on by default, and the
  kernel does not.

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
  `first_data` before any answer (`client.rs:449-451`); an OPEN retry carries
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

## 5. State machines (spec §5)

Timers carry the spec's own defaults; the spec marks its §5 timers
"待仿真" ("to be simulated") and the `Timing` struct holds exactly those
defaults (`crates/segue-session/src/lib.rs:45-135`):

| timer | default | meaning (citing line) |
|-------|---------|------------------------|
| `t_attach` | 2 s | client: give up one attach attempt, retry on a new carrier (`lib.rs:48-49`) |
| `t_stall` | 1 s | client: unacked data and nothing received → re-attach (KERNEL_SPEC §7.2 数据停滞, `max(1 s, 4×SRTT)`; SRTT not modelled, `lib.rs:50-52`) |
| `t_live` | 3 s | relay: unacked downlink, no ACK progress → DETACHED (`lib.rs:53-54`) |
| `t_detached` | 30 s | both: how long a session may live without a working carrier (`lib.rs:55-56`) |
| `t_open_retry` | 15 s | client: how long OPEN may be retried before the local connection is reset (`lib.rs:57-58`) |
| `t_tomb` | 60 s | relay: tombstone lifetime (`lib.rs:59-60`) |
| `ack_delay` | 20 ms | delayed-ACK floor (`lib.rs:61-62`) |
| `idle_after` | 1 s | receive credit falls back to the floor after this idle (`lib.rs:63-64`) |
| `max_lifetime` | 24 h | relay: absolute lifetime from OPEN; RESUME does not extend it (§5.2 "会话超过最长寿命 → RST(max_lifetime)", `lib.rs:65-67`) |
| `t_ctrl_idle` | 30 s | relay: control stream closed after this with no frame (`lib.rs:68-72`) |
| `site_flush_idle` / `site_flush_max` | 30 s / 300 s | relay: bounds on handing the upload tail to the site; past either the session is reset (`site_reset`), never CLEAN (`lib.rs:73-82`) |

Client configuration is validated: `t_stall` ≥ 100 ms (`MIN_CLIENT_STALL`,
`lib.rs:89-92`, r10 N3) and its milliseconds must fit the wire field
(`validate_client`, `lib.rs:107-125`). The client sends `t_stall` as
`t_stall_ms`; the relay keeps a stalled session alive with keepalive ACKs at
half the **shorter** of its own and the announced bound, never below the
100 ms floor, so "a peer cannot make the relay send ACKs in a loop"
(`relay.rs:874-885`, `lib.rs:83-92`).

### 5.1 Channel health and channel death (§5.1 通道判死)

Sessions multiplex over a *channel* (control stream + carriers) to one relay.
A `STALL` for `(session_id, attach_gen)` from the control stream moves that
session to a new carrier at once — the relay holds unacknowledged data for it
(B1, `client.rs:481-491`). A control stream that answers nothing for
`dead_after`, or breaks after being accepted, means "the channel is dead,
move every session of that exit" (`ControlHint::Dead`, `driver.rs:1813-1831`;
kernel wiring `crates/segue-kernel/src/session/mod.rs:32-37`). Without the
STALL half "a download-only session has nothing unacknowledged upstream and
would never notice the stall" (`mod.rs:36-37`).

### 5.2 Relay session table (§5.2)

States per session (`SessionState`, `relay.rs:104-108`):
`Connecting → Active ⇄ Detached`, plus a **tombstone** after any end.

- **OPEN** creates the entry in `Connecting` and asks the caller (event
  `Connect`) to dial the site exactly once per session (A2): "the session
  entry exists before the connect starts, so an OPEN retry or a duplicate
  OPEN that arrives while connecting finds it" (`relay.rs:4-7`,
  `on_first` `relay.rs:540-566`). The site connect carries *that OPEN's* grant,
  so "a site connect is decided by the ticket of its own OPEN, never by
  per-device state another OPEN or RESUME may have changed" (`relay.rs:35-42`).
- **`connect_done(Ok)`** → `Active` (or `Detached` if the carrier was already
  lost); `connect_done(Err(code))` ends the session with that code and RST
  (`relay.rs:727-750`). Because OPENED is sent only after the site connect
  worked, "the app gets success only after the relay answered OPENED"
  (`crates/segue-kernel/src/session/mod.rs:17-20`) — a refused session is a
  dial error at the front end, never retried direct.
- **DETACHED:** the carrier is gone (closed, decode error, or superseded by a
  newer generation). The session survives `t_detached`; while DETACHED the
  relay stops reading the site (`site_read_capacity` returns 0, `relay.rs:916-921`)
  but keeps buffering downlink. `t_live` with unacked downlink and no ACK
  progress also marks DETACHED and emits `RelayEvent::Stall` + STALL frames on
  the device's control streams (B1, `relay.rs:1078-1090`).
- **Re-attach:** the first frame on a new carrier must be RESUME (or an OPEN
  retry); after tomb/instance/secret/ticket/generation checks the table
  performs the atomic `switch` (§4.4) and answers RESUMED (`on_first`
  `relay.rs:567-627`, `switch` `relay.rs:629-670`).
- **Ends:** any end writes a **tombstone** `{close_code, final_recv_offset,
  final_sent_offset}` kept for `t_tomb`, so a late re-attach of an ended
  session gets `REJECT(closed)` with the final offsets instead of
  `unknown_session` (`finish` `relay.rs:753-776`; `code::CLEAN` note
  `codec.rs:100-103`). Timeouts: `max_lifetime` from OPEN → `RST(max_lifetime)`
  ("RESUME does not extend it"); DETACHED longer than `t_detached` →
  `close(idle)`; site reset → tombstone `site_reset` (`handle_timeout`
  `relay.rs:1056-1112`, `site_reset` `relay.rs:936-942`).
- **Upload drain honesty:** with `confirm_site_flush(true)` (the driver's
  production mode) the client's FIN is acknowledged only after the site took
  every uploaded byte and the write side was shut down; a site that fails or
  never finishes is reset, "so a truncated upload is never reported clean"
  (`relay.rs:255-273`, `site_flushed` `relay.rs:964-976`,
  `held_fin` handling `relay.rs:672-700`; tests
  `crates/segue-session/tests/driver.rs:800`, `driver.rs:1245-1270`).

### 5.3 Client session (§5.3)

States (`State`, `client.rs:45-51`): `Opening → Active ⇄ Attaching`,
then `Closed(CloseReason)`. `CloseReason` (`client.rs:56-64`) is the **§8
local mapping** — how the *local* connection (to the app) must end:
`Clean` (local FIN), `Reset(code)` (local RST carrying the protocol code),
`Refused(code)` (never sent anywhere else, e.g. `capacity`,
`home_unavailable`) (`client.rs:54-55`, `from_reject` `client.rs:66-84`).

Transitions:

- `attach(carrier)`: first attempt sends OPEN (with `first_data` bounded by
  the frame budget minus the worst-case header, `client.rs:374-390`,
  `open_header_len` `client.rs:445-455`); a retry sends OPEN with
  `retry = true` and `anchor_instance_id = instance_hint`; after any OPENED
  it sends RESUME with the client snapshot and `attach_gen + 1`
  (`client.rs:358-412`).
- OPENED (matching generation) → `Active`; OPENED "proves the path (the relay
  reached the site)" and resets the recovery budget once per session
  (`client.rs:701-721`). RESUMED (or an OPEN retry answered as RESUME, R2-2b)
  → `Active`, replay rewound to the relay's snapshot; "a bare RESUMED is not
  progress — a path that answers RESUME and then stalls keeps counting against
  the bound" (`client.rs:723-748`).
- REJECT: `stale_gen` is ignored (an older generation answered);
  `anchor_unreachable` (B2) → drop the carrier and retry with backoff (≤ 5 s)
  until `t_detached`; `version` is accepted across generations (r10 N3, a v4
  peer cannot read our generation); anything else closes the session via
  `CloseReason::from_reject` — in particular `closed` maps to `Clean` only in
  the B6 case: the relay closed cleanly, our FIN reached it
  (`final_recv_offset == fin + 1`) and we already hold its FIN — "the only
  thing lost was an ACK" (`client.rs:750-782`; sim test
  `lost_final_ack_is_resolved_by_tombstone_as_clean`,
  `crates/segue-session/tests/sim.rs:552`).
- Carrier loss (closed, stuck — a frame held transport blocks too long —
  stall timer `t_stall`, STALL hint, unanswered attach after `t_attach`):
  redial. A carrier lost "while something was expected on it and nothing
  moved" counts against `MAX_FRUITLESS` = 8 with exponential backoff
  200 ms → 2 s (`client.rs:101-112`, `carrier_lost` `client.rs:555-597`);
  end-to-end progress or the one OPENED resets the count. The 8th fruitless
  carrier closes the session with `LOCAL_GIVE_UP` = `connect_timeout`
  (`client.rs:101`, `client.rs:585-590`).
- Timeouts (`handle_timeout`, `client.rs:1030-1075`): OPEN not answered within
  `t_open_retry` → local reset; detached longer than `t_detached` → local
  reset; attach unanswered within `t_attach` → new carrier (counts as
  expected-loss); confirmed + unacked + silent for `t_stall` → re-attach;
  receive idle → recompute credit.
- Clean end: both FINs acked and all data delivered → `Closed(Clean)`
  (`check_done` `client.rs:842-848`).

**Health reports** (for the caller's exit health, r9 F5): `Up` (OPENED, or
data moved end to end, refreshed every 1 s while moving), `Failed` (a carrier
was given up with something expected), `GaveUp`, and `Alive(rx_at)` — bytes
arrived that move nothing end-to-end (a partial frame, a keepalive ACK):
path liveness, not proof, never touching the recovery budget (`Health`
`client.rs:122-153`, `made_progress` `client.rs:797-813`, `alive`
`client.rs:815-831`).

### 5.4 UDP (§5.4)

`Kind::Udp` exists in OPEN and the DGRAM frame is fully specified (§2.3), but
UDP sessions are not implemented end to end: the relay's ticket check refuses
`Kind::Udp` with `exit_denied` ("This relay carries TCP only; Home UDP is
never offered (§5.5.5)", `crates/segue-relay/src/ticket.rs:233-241`), and the
kernel never carries UDP to a home-role route — "a fixed property of the Home
exit (§5.4), not a setting" (`crates/segue-kernel/src/session/mod.rs:41-43`,
`mod.rs:1050-1055`).

### 5.5 Close semantics (§5.5)

"Anything but a clean close is a local RST" (`crates/segue-kernel/src/session/stream.rs:5-7`):
the driver can only end its pipe with EOF, so `SessionStream` turns an EOF
whose reported reason is not `CloseReason::Clean` into `ECONNRESET` for the
SOCKS/TUN front end (`stream.rs:44-61`, `closed_err`/`closed_text`
`mod.rs:1012-1031`). On the relay side, the symmetric rule is the upload-drain
honesty of §5.2: a truncated upload or a failed site write/shutdown resets,
never reports clean (`tests/driver.rs:800`, `driver.rs:1245-1270`).

### 5.6 PARK and WAKE (§5.6, R2-2c)

PARK/WAKE as a whole is a later milestone (M9+). Implemented: the **request
matching rule** only (`crates/segue-session/src/park.rs:1-6`):

- at most one pending PARK per session; a new request supersedes the old
  (`park.rs:26-31`);
- a PARK_ACK counts only if its `req_id` equals the pending one **and** its
  `attach_gen` equals the generation the request was made at **and** that is
  still the current generation (`on_ack`, `park.rs:40-53`);
- anything else — late, stale, unsolicited, or after a re-attach — is
  `Ignored` (no effect) (`park.rs:12-21`);
- new data to send or a re-attach cancels the pending request without waiting
  for the ACK (`cancel`, `park.rs:34-36`; wired at `client.rs:1101` and, on
  every attach, `client.rs:376`).

The client may request a PARK only while `Active`, with nothing pending
uplink and nothing buffered downlink (`request_park`, `client.rs:1153-1167`).
WAKE, park generations and parked-state storage are not implemented.

### 5.7 Home lines (relay side)

KERNEL_SPEC §5.6/§5.7/D2, not session-protocol state, but it defines the
`home_unavailable` (29) code path: an AI-class session dials through the
device's primary Home (Decodo ISP SOCKS5) line; when that line is DOWN the
dial is refused with `home_unavailable` — "never sent direct and never moved
to another line unless failover is switched on"
(`crates/segue-relay/src/home.rs:1-7`, `crates/segue-relay/src/dial.rs:389-396`).

## 6. Ticket lifetime, REFRESH and revocation (spec §6)

- **Ticket format** (`crates/segue-relay/src/ticket.rs:1-7`): `SGT1.`
  base64url(payload JSON) `.` base64url(Ed25519 signature), no padding; the
  signature covers `"segue-ticket-v1\n" || payload`. Claims (`ticket.rs:38-53`):
  version, key id, device id, account id, plan, `exit_classes`, `ai_anchor_node_id`
  (0 = any node), `not_before`, `not_after`. The relay holds only public keys
  and verifies offline (`Verifier`, `ticket.rs:116-171`); a ticket is a bearer
  secret and is never logged (`ticket.rs:7-8`). Longest accepted ticket: 2048
  bytes (`MAX_TICKET`, `ticket.rs:25`).
- **Validity window and RESUME grace (§6):** an expired ticket still authorizes
  RESUME — never a new OPEN — for `RESUME_GRACE_SECS` = 1 h after `not_after`,
  *only while the revocation list is fresh* (`ticket.rs:26-28`, `check`
  `ticket.rs:203-223`: `resume && now < not_after + 3600 && revoked.is_fresh_at(now)`).
  A ticket for a revoked device is `revoked` regardless of grace
  (`ticket.rs:215-219`).
- **Revocation freshness (§6: 5 min):** the revocation list is a complete
  snapshot file (`seq`, `synced_at`, one device id per line, `end N` trailer)
  reloaded when it changes; a truncated or half-written file is refused
  (`crates/segue-relay/src/revoke.rs:1-20`). "Freshness (RESUME grace,
  SESSION_PROTOCOL §6) comes only from that `synced_at`: … the list goes stale
  5 min later however often the relay re-reads it" (`FRESH_FOR_SECS` = 300,
  `revoke.rs:28-31`, `is_fresh_at` `revoke.rs:223`). The accepted snapshot is
  persisted atomically so a restart never replays an older list
  (`revoke.rs:20-22`).
- **REFRESH is not implemented.** CTRL_HELLO with an expired ticket would get
  a control stream "for REFRESH (§6); REFRESH is not implemented, so it is
  refused like OPEN" (`crates/segue-session/src/relay.rs:426-438`). The
  REFRESH/REFRESHED frame types are codec-recognised only (§2.3).
- **Device reset:** revocation or admin resets every session of the device
  (RST with the code, tombstones) and sends `REVOKED[code]` on its control
  streams before closing them (`relay.rs:978-1005`, `RelayCtrl::ResetDevice`
  `driver.rs:107-111`). A client that sees REVOKED resets its live sessions
  locally with that code so "the reason reaches `closed` before the app stream
  ends, so the app sees a reset" (`ClientCtl::cancel`, `driver.rs:920-923`).

## 8. Error codes (spec §8) and their local mapping

Codes are one byte each (`codec.rs:77-103`). Producers cited; everything else
is closed with the code it carries.

| code | value | produced where |
|------|-------|----------------|
| `clean` | 0 | tombstone `close_code` for a clean close; "not a §8 code; it only appears inside `REJECT(closed)`" (`codec.rs:100-103`, `check_done` `relay.rs:816-824`) |
| `version` | 1 | wrong wire version in OPEN/RESUME/CTRL_HELLO (§10) — `relay.rs:404-407`, `relay.rs:424-426` |
| `auth` | 2 | bad ticket signature/shape, or resume secret / device mismatch — `relay.rs:496`, `relay.rs:578-584`, `ticket.rs:210-214` |
| `expired` | 3 | ticket past `not_after` without RESUME grace — `ticket.rs:206-209` |
| `unknown_session` | 4 | RESUME for an unknown session; OPEN retry for an unknown session (A2); §9.2 instance mismatch — `relay.rs:532-536`, `relay.rs:571-576` |
| `stale_gen` | 5 | OPEN/RESUME at a generation ≤ the current one, or a non-retry duplicate OPEN — `relay.rs:499-502`, `relay.rs:585-587` |
| `capacity` | 6 | pool cannot cover the admission floors — `relay.rs:540-549`; maps to `CloseReason::Refused` (`client.rs:66-68`) |
| `exit_denied` | 7 | ticket lacks the exit class; UDP on this relay — `ticket.rs:236-240`, `dial.rs` |
| `target_denied` | 8 | SSRF guard / policy refused the target — `crates/segue-relay/src/dial.rs` (9 uses), `guard.rs` |
| `closed` | 9 | session ended (tombstone) — carries `ClosedInfo` (`codec.rs:94-99`) |
| `anchor_unreachable` | 10 | client retried with backoff until `t_detached` (B2) — `client.rs:755-766` |
| `revoked` | 11 | device on the revocation list — `ticket.rs:215-219` |
| `rate_limited` | 12 | reserved (no producer in-tree) |
| `connect_refused` | 20 | site dial refused / generic site-connect error — `SiteError::code_of` `driver.rs:96-106`, `dial.rs:332-357` |
| `connect_timeout` | 21 | site dial timed out — `dial.rs:358`; also the client's local give-up code (`LOCAL_GIVE_UP`, `client.rs:101`) |
| `dns_failure` | 22 | relay-side resolve failed — `dial.rs:182` |
| `site_reset` | 23 | site reset the session; also the code for a local app abort (`client.rs:1119-1125`) — `relay.rs:936-942` |
| `idle` | 24 | DETACHED past `t_detached` — `relay.rs:1111` |
| `admin` | 25 | admin reset (no in-tree producer; available to `RelayCtrl::ResetDevice`) |
| `max_lifetime` | 26 | past the absolute lifetime — `relay.rs:1071-1074`, `relay.rs:1108-1110` |
| `protocol` | 27 | any `ProtoError` (malformed frame, violation) — `fail` `relay.rs:409-415`, `fatal` `client.rs:638-644` |
| `internal` | 28 | driver fallback when a session ends without a reason (`driver.rs:1307-1308`) |
| `home_unavailable` | 29 | Home line DOWN for an AI dial — `dial.rs:389-396`; maps to `CloseReason::Refused` (`client.rs:66-68`) |

**Local mapping (§8).** `CloseReason` (`client.rs:54-64`) decides how the app's
connection ends: `Refused` codes (`capacity`, `home_unavailable`) never reach
the wire; `Reset(code)` becomes a local RST (and, via `SessionStream`, an
`ECONNRESET` for SOCKS/TUN, §5.5); `Clean` a local FIN. The kernel surfaces
the code in dial errors ("session refused (code N)" / "session reset (code N)",
`crates/segue-kernel/src/session/mod.rs:1020-1031`).

## 9. Multi-instance (spec §9)

A relay process is an *instance* with a random `instance_id`
(`relay.rs:234`). A session lives in exactly one instance, learned by the
client from OPENED/RESUMED (`instance_id` field) or the CTRL_HELLO reply
(`codec.rs:476-507`) and echoed back as `anchor_instance_id` in OPEN retries
(the carrier's hello hint, `client.rs:40-42`, `client.rs:421-425`) and RESUME
(`attach` `client.rs:394-404`).

**§9.2 status: cross-instance hand-off is not implemented.** Any RESUME (or
OPEN retry) whose `anchor_instance_id` is non-zero and not this instance is
answered `REJECT(unknown_session)` (`relay.rs:568-571`,
"`§9.2 hand-off between instances is not implemented`"; same for OPEN retries
`relay.rs:502-504`). The client treats `unknown_session` on an OPEN retry as
"the session is gone here" and may re-open fresh (the kernel allows a pinned
fresh OPEN after UNKNOWN_SESSION, `crates/segue-kernel/src/session/mod.rs:22-26`,
`FRESH_OPENS` `mod.rs:90-91`). `anchor_node_id` (the node catalog id) is
carried but only advisory for instance selection today
(`client.rs:40-42`); cross-node forwarding is M9+ (`crates/segue-session/src/lib.rs:16-17`).

## 10. Versioning (spec §10)

Wire version 5 (`VERSION`, `codec.rs:39`). "Nothing older is deployed, so
there is no negotiation: a peer of another version answers `REJECT(version)`
before reading any other field" (`codec.rs:33-37`). Version is the first
payload byte of OPEN, RESUME and CTRL_HELLO; a mismatched value aborts
decoding of the rest of the frame (`ProtoError::Version`,
`codec.rs:790-795`, `codec.rs:830-836`, `codec.rs:451-454`) and the relay
answers `REJECT(version)` with generation 0 (`relay.rs:404-407`) — the client
accepts a version reject across generations for that reason (`client.rs:750-756`).
v5 is v4 plus `t_stall_ms` in OPEN/RESUME (r10 N3); the change is
incompatible, hence the bump (`codec.rs:24-33`, `tests/codec.rs:137-139`).

## 11. Implementation status (2026-11-17)

Legend: **implemented** (running in tests/integration), **codec-only** (frames
parse/encode, no behaviour), **hook-only** (interface exists, no producer),
**not started**.

| Feature | Status | Evidence |
|---------|--------|----------|
| TCP sessions (OPEN→OPENED→DATA/ACK/FIN) | implemented | `client.rs:699-795`, `relay.rs:489-725`, integration `tests/driver.rs:158`, `tests/sim.rs:441` |
| Carrier swap with replay (RESUME/RESUMED, offsets, generations) | implemented | `flow.rs:249-258`, `relay.rs:629-670`, `tests/sim.rs:458` (no loss/duplication), `tests/sim.rs:483`, `tests/driver.rs:171` |
| Flow control + global pool (rule 8) | implemented | `flow.rs:709-803`, `pool.rs`, `tests/driver.rs:701` (pool exhaustion), `tests/driver.rs:856` (8 MB pool, hundreds of flows), `tests/window_growth.rs:1` |
| Control stream (CTRL_HELLO, PING/PONG, STALL, REVOKED) | implemented | `driver.rs:1853-1949`, `relay.rs:421-487`, kernel wiring `crates/segue-kernel/src/session/mod.rs:445` |
| Tickets (SGT1/Ed25519, offline verify) | implemented (relay crate) | `crates/segue-relay/src/ticket.rs:195-247`; session crate sees only the `Authorizer` hook (`relay.rs:59-64`) |
| Revocation | implemented as a local-file stand-in; control-plane feed not | `crates/segue-relay/src/revoke.rs:68`, freshness `revoke.rs:223`; "control plane deferred" `crates/segue-relay/src/lib.rs:17-21` |
| Device reset (RST all sessions + REVOKED) | implemented | `relay.rs:978-1005`, `RelayCtrl::ResetDevice` `driver.rs:107-111`, client `ClientCtl::cancel` `driver.rs:920-923` |
| Client multi-exit, AI anchor pinning, kill switch | implemented (kernel) | `crates/segue-kernel/src/session/mod.rs:8-30`, `Exit::group` `mod.rs:115-124`, `killswitch.rs` |
| Health reports (Up/Failed/GaveUp/Alive) | implemented | `client.rs:122-153`, `HealthHook` `driver.rs:931` |
| UDP sessions (DGRAM) | **codec-only** | frames `codec.rs:674-678`, `codec.rs:902-905`; relay refuses `Kind::Udp` (`crates/segue-relay/src/ticket.rs:236-240`); kernel refuses UDP to home routes (`mod.rs:1050-1055`) |
| REFRESH / REFRESHED | **codec-only** | recognised, payload unparsed (`codec.rs:970-976`); "REFRESH is not implemented, so it is refused like OPEN" (`relay.rs:426-428`) |
| RESOLVE / RESOLVED | **codec-only** | `codec.rs:970-976`; the only non-codec mention is the relay's skip note ("RESOLVE, REFRESH, PARK are not implemented", `relay.rs:375-381`) |
| PARK / PARK_ACK | **hook-only** (matching rule implemented) | `park.rs:1-53`; client `request_park` `client.rs:1153-1167`; relay has no PARK handler ("RESOLVE, REFRESH, PARK are not implemented", `relay.rs:379-381`) |
| WAKE | **not started** (M9+) | frame defined `codec.rs:684-693`; "PARK/WAKE as a whole is M9+" (`lib.rs:9-11`, `lib.rs:16-17`) |
| Cross-instance hand-off (§9.2) | **not started** | any other `anchor_instance_id` → `unknown_session` (`relay.rs:568-571`, `relay.rs:502-504`) |
| Cross-node forwarding | **not started** (M9+) | `crates/segue-session/src/lib.rs:16-17`, `crates/segue-relay/src/lib.rs:19-21` |
| Redundant carrier, no DATA duplication (v0.6 draft, §2.7) | implemented, off by default | `REDUNDANT_ATTACH`/`REDUNDANT_OK`; relay binds without `switch`; a lost current carrier (close, hold, `t_stall`, `t_live`/`STALL`) promotes the spare with no RESUME; a move onto a third carrier drops the spare |
| Session layer on mobile (FFI) | **not shipped** | `segue-session`/`segue-kernel` are behind the `proprietary-kernel` feature, "Deliberately not enabled in platform/build scripts yet" (`crates/segue-ffi/Cargo.toml:14-20`); no reference in `platform/android` or `platform/apple` |

## 12. What this gives an AI app that Xray/sing-box/mihomo do not

Claims below are exactly what the code and its tests support.

1. **A stream survives its tunnel dying.** In Xray/sing-box/mihomo a proxy
   connection is bound to the transport connection it arrived on; when the
   outer TCP/Wi-Fi↔cellular switch kills it, the app's stream dies. Here the
   session layer holds the stream state (offsets, replay buffer) in the relay
   and re-attaches with RESUME on a fresh carrier: "a dropped carrier is
   replaced with RESUME, so the app connection survives the outer tunnel
   dying" (`crates/segue-kernel/src/session/mod.rs:3-6`). The property is
   tested as *no loss and no duplication*: cut mid-transfer, resume, both
   directions byte-exact (`tests/sim.rs:458-481` `assert_exact`,
   `tests/sim.rs:616` randomized faults, `tests/driver.rs:171`). A network
   change (epoch signal) moves sessions to a new carrier without the app
   noticing (`ClientCtl::reattach`, `driver.rs:905-908`).
2. **The relay notices stalls the client cannot.** A download-heavy AI client
   has nothing unacknowledged upstream, so a dead path looks like a slow
   download. The relay's `t_live` marks the session DETACHED and pushes
   `STALL` over the control stream; the client re-attaches (`relay.rs:1078-1096`,
   `client.rs:481-491`, rationale `crates/segue-kernel/src/session/mod.rs:36-37`).
   A black-holed channel (packets dropped, socket never closed) is detected
   by the control stream's `dead_after` and every session of that exit moves
   (`driver.rs:1885-1890`).
3. **Refusal is a dial error, not a hang or a silent fallback.** The app sees
   success only after OPENED, which the relay sends only after the site
   connect worked; a refused route (`exit_denied`, `target_denied`,
   `home_unavailable`, …) is an error at the front end and "nothing is ever
   retried direct" (`crates/segue-kernel/src/session/mod.rs:17-21`,
   `crates/segue-relay/src/dial.rs:1-3`).
4. **Close reasons survive the trip.** Reset vs clean vs refused-with-code
   reach the application (`CloseReason` `client.rs:54-64`, `SessionStream`
   `crates/segue-kernel/src/session/stream.rs:44-61`); a truncated upload is
   never reported clean (`relay.rs:255-273`, `tests/driver.rs:800`).
5. **Bounded, shared memory.** One 8 MB pool backs every session, driver
   queue and the TUN stack's TCP buffers; the pool size is "a hard bound on
   buffered session data" (`pool.rs:5-10`, `crates/segue-kernel/src/session/mod.rs:76-86`),
   and hundreds of flows fit it (`tests/driver.rs:856`).
6. **AI-specific anchoring.** `exit_class`/`ai_anchor_node_id` in tickets plus
   the kernel's exit groups pin an AI flow to one egress identity and never
   move it to a different egress on failure (`crates/segue-kernel/src/session/mod.rs:8-15`,
   `crates/segue-relay/src/ticket.rs:49-50`) — the ISP-Home property AI
   vendors verify by exit IP.

**Still missing to deliver this end to end today:**

- **Mobile.** `segue-ffi` links `segue-session`/`segue-kernel` only behind the
  non-default `proprietary-kernel` feature, "deliberately not enabled in
  platform/build scripts yet" (`crates/segue-ffi/Cargo.toml:14-20`; no
  reference under `platform/android` or `platform/apple`). An AI app on
  iOS/Android cannot reach the session layer through the shipped ABI; the
  resumable-stream property is currently delivered only inside the kernel
  (TUN/SOCKS front ends) and the CLI/bench harnesses.
- **Control plane.** Ticket issuing, revocation feed and Home-line credential
  sync are local-file stand-ins ("control plane deferred",
  `crates/segue-relay/src/lib.rs:17-21`); REFRESH for expired tickets does not
  exist (`relay.rs:426-428`), so a device must re-provision out of band after
  the 1 h RESUME grace (`ticket.rs:26-28`).
- **The M9+ set**: PARK/WAKE (battery-friendly parked sessions), UDP (DGRAM
  is codec-only), cross-instance hand-off and cross-node forwarding
  (`crates/segue-session/src/lib.rs:9-17`).
- **SRTT-driven stall bound.** `t_stall` is a fixed 1 s default; the spec's
  `max(1 s, 4 × SRTT)` is not modelled (`lib.rs:50-52`) even though the
  receiver-side SRTT estimate itself exists (`flow.rs:363-405`).

## Appendix A: citations that point at *other* specs

Collected so readers do not mistake them for SESSION_PROTOCOL sections:

- `KERNEL_SPEC` — §5.4 (UDP never via Home, `crates/segue-kernel/src/session/mod.rs:41`),
  §5.5 items 2/3/7 (exit checks, `crates/segue-relay/src/guard.rs:1`,
  `policy.rs:1-2`, `config.rs:27`), §5.5 B6 (clean close, §5.5 above),
  §5.6 item 5 / item 7 (`crates/segue-relay/src/dial.rs:282`,
  `metrics.rs:16`), §5.6/§5.7 D2 (Home lines, `home.rs:1-7`), §6.2 (policy
  bundle, `crates/segue-relay/src/policy.rs:2`), §6.3 (memory pool,
  `crates/segue-session/src/pool.rs:1`, `crates/segue-kernel/src/session/mod.rs:76`),
  §6.4/§6.5 (`crates/segue-relay/src/lib.rs:1`, `server.rs:341`), §7.2
  (数据停滞 / 网络变化 timers, `lib.rs:51`, `driver.rs:906`).
- `CONTROL_PLANE_SPEC` — §3.3 (ticket issuing, `crates/segue-relay/src/ticket.rs:1`),
  §4 (revocation feed, `crates/segue-relay/src/revoke.rs:1`).

## Appendix B: gaps in this reconstruction

- SESSION_PROTOCOL **§1, §7 and most of §9** are never cited in code; their
  content (if any distinct from what §2–§6, §8, §10 cover above) is not
  recoverable from the repository.
- §4's numbered rules are cited as rules 1, 2, 5, 6, 7 and 8
  (`flow.rs:6-13`, `flow.rs:226-247`, `flow.rs:630`, `flow.rs:708`); rules 3
  and 4 are never cited by number — their content, if distinct, is unknown.
- The spec's original §5 subsection titles are known only where code quotes
  them: §5.1 "通道判死" (`driver.rs:1820`), §5.2 (attach/lifetime rules,
  `relay.rs:631`, `lib.rs:66`), §5.3 (client, `client.rs:1`), §5.5 (close
  semantics, `crates/segue-kernel/src/session/stream.rs:6`), §5.6 R2-2c
  (PARK matching, `park.rs:1`).
- The spec itself lives outside this repository; if it is found, this file
  should be replaced by it and kept only as an implementation-accurate
  companion.
