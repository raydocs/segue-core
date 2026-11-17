# AnyTLS outbound

Status: implemented (client only). Owner: protocols.
Related: [`docs/research/2026-11-sing-box-1.15-and-mihomo.md`](../research/2026-11-sing-box-1.15-and-mihomo.md)
§4.4, `crates/segue-proxy/src/anytls/`, `crates/segue-engine/src/outbound/anytls/`,
`crates/segue-config/src/parser/anytls.rs`.

## 1. Why

AnyTLS is the highest-value protocol Segue lacks: TLS-only, a small framing
layer, and it reuses the existing TLS/REALITY carrier. Xray-core has no AnyTLS,
so there is no compatibility constraint on the config shape; the field names
follow sing-box's `option.AnyTLSOutboundOptions` and mihomo's `AnyTLSOption`,
which agree.

Reference implementations read for this design:

| Source | Revision | What it pins |
| --- | --- | --- |
| `/Volumes/dev/ref/sing-anytls` | `anytls/sing-anytls` HEAD, 2026-11-17 | `client.go`, `session/{frame,session,client,stream}.go`, `padding/padding.go`, `util/string_map.go` |
| `/Volumes/dev/ref/sing-box` | `0219500` | `protocol/anytls/outbound.go`, `option/anytls.go`; pins `sing-anytls v0.0.0-20260928104022` |
| `/Volumes/dev/ref/mihomo` | `3c0d10a` | `transport/anytls/`, `adapter/outbound/anytls.go` |
| sing module cache | `v0.8.10` | `common/uot/{protocol,client,conn}.go`, `common/metadata/serializer.go` |

## 2. Wire format

### 2.1 Session hello

The first bytes on the TLS carrier are:

```
+--------------------------+------------------+---------------------+
| SHA-256(password) 32 B   | padding length 2 | zero padding N B    |
+--------------------------+------------------+---------------------+
```

`padding length` is big-endian and comes from the padding scheme's counter-0
entry (30 bytes under the default scheme). A server that does not recognise the
digest hands the connection to its fallback, so the hello must be the first
write and must be flushed before any frame.

### 2.2 Frames

Every frame is a 7-byte header and a payload:

```
byte 0      command
bytes 1..5  stream id, big-endian u32
bytes 5..7  payload length, big-endian u16
```

| Command | Value | Direction | Meaning |
| --- | --- | --- | --- |
| `Waste` | 0 | both | padding; payload discarded |
| `Syn` | 1 | client | open a stream |
| `Push` | 2 | both | stream data |
| `Fin` | 3 | both | stream writer done |
| `Settings` | 4 | client | `key=value` lines |
| `Alert` | 5 | server | session refused; payload is the reason |
| `UpdatePaddingScheme` | 6 | server | replaces the client's scheme |
| `SynAck` | 7 | server | stream opened, or an error payload |
| `HeartRequest` | 8 | both | keepalive |
| `HeartResponse` | 9 | both | keepalive reply |
| `ServerSettings` | 10 | server | `v=2` |

A payload length is a `uint16`, so a write above 65 535 bytes becomes
consecutive `Push` frames in one buffer.

### 2.3 Stream open

A stream's first payload bytes are the destination as sing's `Socksaddr`:

```
0x00 | IPv4 (4) | port (2)
0x01 | IPv6 (16) | port (2)
0x02 | length (1) | domain | port (2)
```

The client sends `Syn`, then a `Push` whose payload starts with this address.
The server reads exactly that many bytes before it routes the stream.

### 2.4 Settings

The client's first frame is `Settings` with newline-separated `key=value`
lines: `client=<version>`, `padding-md5=<hex>`, `v=2`. The server compares the
MD5 with its own scheme and, on a mismatch, sends `UpdatePaddingScheme` with
its raw scheme. A v2 server answers with `ServerSettings` (`v=2`), after which
the client expects a `SynAck` for each stream within three seconds.

### 2.5 Padding scheme

The scheme is a text file:

```
stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
...
```

`stop` is the packet counter at which padding ends. Each other key is a packet
counter; its value is a comma-separated list of record sizes. `min-max` draws
from `[min, max)` (`rand.Int(max-min) + min`); `min-min` is exact; `c` is a
check mark that stops the scheme once the payload is spent.

For each write, the writer walks the counter's entries. A record smaller than
what is left is all payload. A record that holds the payload's tail is filled
with one `Waste` frame of `size - remaining - 7` payload bytes. A record with
no payload left is a `Waste` frame of `size` payload bytes plus its header.
Whatever remains after the entries goes out unpadded. The reference's quirks
are preserved deliberately, because a server's parser does not care but a
byte-for-byte oracle does.

### 2.6 UDP

AnyTLS has no datagram framing of its own. UDP rides sing's UDP-over-TCP on a
stream to the magic destination `sp.v2.udp-over-tcp.arpa`:

```
stream payload: Socksaddr(magic) | isConnect (1) | Socksaddr(destination)
each datagram:  length (2, big-endian) | payload
```

`isConnect = 1` fixes the destination for the stream, so datagrams carry no
address. Segue bounds a datagram at 8192 bytes, the same bound Trojan and
Shadowsocks use, and the TUN flow loop drops what a path cannot carry.

## 3. Mapping onto Segue

### 3.1 Layers

| Concern | Where |
| --- | --- |
| Frames, padding, `Socksaddr`, UoT | `crates/segue-proxy/src/anytls/` (pure, no I/O) |
| Session pool, stream multiplexing | `crates/segue-engine/src/outbound/anytls/session.rs` |
| Outbound, carrier, UDP session | `crates/segue-engine/src/outbound/anytls.rs` |
| Config | `crates/segue-config/src/parser/anytls.rs`, `model.rs` |

### 3.2 Carrier

`StreamCarrier::new(&config.stream, &settings.server, settings.port, false,
carrier::TROJAN_PATHS)` — `unencrypted_payload = false`, because AnyTLS is
TLS-only. The carrier gives TLS, REALITY, uTLS shaping, XHTTP, gRPC, mKCP,
fragment masks and socket options for free. The outbound refuses
`StreamSecurity::None` and `allowInsecure`, and the parser refuses them too.

### 3.3 Session pool

Modelled on `mux::Pool` but separate, because the wire protocol is unrelated:

* at most 8 sessions per outbound (`MAX_ANYTLS_IDLE_SESSIONS`), idle and busy;
* at most 128 streams per session;
* a session with no live stream goes to the idle list; the next open takes the
  oldest idle session and opens a stream on it without dialing;
* a cleanup task retires idle sessions older than `idle_session_timeout`,
  keeping the newest `min_idle_session`;
* both timings floor at 30 s, as the reference does;
* `close()` aborts the reader and writer tasks and clears every stream, so no
  task outlives the outbound; `join()` awaits them.

### 3.4 Back-pressure and memory

A stream's receive queue holds 8 frames. When it is full the session reader
waits on that stream's consumer, which blocks its siblings' downlink
(head-of-line blocking). This is what the Go pipe does, and it is the bound
that matters on iOS: a stalled consumer cannot make the process buffer
unboundedly. The writer queue holds 64 commands; a stream's `poll_write`
reserves a slot before it encodes, so a slow carrier applies back-pressure
instead of growing a queue.

Per-session state is two tasks, a `HashMap` of at most 128 stream senders and
one 64 KiB write queue. Eight sessions bound the protocol's own memory to a
few hundred kilobytes, independent of traffic.

### 3.5 Dispatch

Wired exactly as Trojan is: `TcpOutbound::AnyTls` / `UdpOutbound::AnyTls`,
`OutboundNodeKind::AnyTls`, a cached builder, the chained-connector path, the
DNS and TUN handshake-policy matches, and the debug-log label. `pools_tcp_flows`
stays false: AnyTLS has its own pool, not Mux.Cool, so the reverse-proxy and
XHTTP-sharing paths treat it as a per-flow carrier.

## 4. Config

```json
{
  "protocol": "anytls",
  "settings": {
    "address": "anytls.example",
    "port": 443,
    "password": "…",
    "idle_session_check_interval": "30s",
    "idle_session_timeout": "30s",
    "min_idle_session": 1,
    "client_metadata": "sing-anytls/0.0.13"
  },
  "streamSettings": {
    "network": "raw",
    "security": "tls",
    "tlsSettings": { "serverName": "anytls.example" }
  }
}
```

| Field | Type | Rule |
| --- | --- | --- |
| `address` | string | 1..255 bytes, no whitespace or controls |
| `port` | number | 1..65535 |
| `password` | string | nonempty; redacted in `Debug` |
| `idle_session_check_interval` | Go duration or ns | positive; zero/absent floors at 30 s |
| `idle_session_timeout` | Go duration or ns | positive; zero/absent floors at 30 s |
| `min_idle_session` | number | 0..=8 |
| `client_metadata` | string | no newlines or `=`; replaces the client version |
| `level` | number | 0..255 |

`streamSettings.security` must be `tls` or `reality`. Unknown fields fail
closed, as everywhere else in the parser.

## 5. Test plan

### 5.1 Unit tests (in tree)

* `crates/segue-proxy/src/anytls/tests.rs` — frame headers, command numbering,
  `Push` splitting at 65 535, settings round-trip, the SHA-256 credential, the
  default scheme's MD5 (`75cff2ad89aadf5e257059ee571ebe11`), every default
  counter's record sizes, malformed schemes, hello bytes, record splitting and
  `Waste` filling, `Socksaddr` for all three families, UoT requests and
  datagrams, and the jitter range.
* `crates/segue-engine/src/outbound/anytls/tests.rs` — over an in-memory
  carrier: Settings/Syn/Push/Waste ordering in the first padded record, the
  stream target as the first payload, session reuse without a second dial,
  server `Fin` at EOF, `SynAck` errors, `Alert`, heartbeats, a server padding
  scheme replacing the client's, a closed pool refusing opens, UoT framing, and
  the session bound.

### 5.2 Go oracle

`tools/anytls-oracle/` (to be added with the interop work) runs the real
`sing-anytls` client and server against a capture, the way `tools/kcp-oracle`
and `tools/masque-oracle` do:

1. `sing-anytls` client → capture → `sing-anytls` server, recording the hello,
   the first padded record and a stream's frames for a fixed password and a
   fixed jitter source.
2. The same capture replayed through `segue-proxy::anytls` must produce
   identical bytes.
3. A `sing-box` AnyTLS inbound as the peer for an end-to-end TCP and UDP test,
   as the existing `local_xray_interop_tests` do for Trojan.

The oracle needs a Go toolchain, which this machine does not have; it is
written and run in CI, not here.

## 6. Risks

* **Idle semantics vs. network changes.** A pooled session survives a network
  change and then fails on its next write. The reference has the same
  behaviour; sing-box calls `Reset()` on an interface update. Segue's
  `close_sessions` closes every pool on shutdown, but there is no
  interface-change hook yet. A failed write closes the session and the next
  open dials a fresh one, so the cost is one failed flow, not a stuck pool.
* **`SynAck` watchdog.** A v2 server that never acknowledges a stream closes
  the session after three seconds. A server that speaks v1 is not watched.
* **No server side.** This is client only; Segue cannot accept AnyTLS.
* **Padding is not a traffic-shaping guarantee.** It matches the reference
  byte for byte, which is what interop needs, not what defeats a determined
  classifier.
