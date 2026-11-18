# REALITY + Vision first-byte time: where the round trips go

Measured on the 2026-11-18 WAN run (`.bees/wan-findings.md`): Segue
VLESS+REALITY+Vision TTFB p50 **1813 ms** on a path whose RTT is **172 ms**.
That is ~10.5 RTT of wall clock for a flow that should cost 4–5 RTT. This note
counts the round trips and the waits in the Segue client, compares them with
Xray-core, and lists the fixes. Only the last one is implemented here; the
others are wire-compatible but need their own change and test.

## The flow, as Segue runs it

`crates/segue-engine/src/socks.rs::handle_socks_connect` →
`open_tcp_stream_with_resolvers_and_dialer` →
`crates/segue-engine/src/outbound.rs::open_vless_tcp_stream_with_resolver_and_dialer`
→ `carrier.rs::open` → `segue-transport/src/dialer.rs::connect_stream` →
`connect_resolved_with_alpn_policy` (REALITY arm) → `connect_candidates` →
`reality_runtime.rs::DeferredRuntimeRealityConnection::complete` →
`reality_rustls.rs::RustlsRealityTlsSession::complete_over` (rustls handshake)
→ `held_request_stream` (`first_payload.rs` + `vision_stream.rs`) → relay.

## RTT budget

| # | Step | RTT | Notes |
|---|------|-----|-------|
| 0 | DNS for the server name (if a domain) | 0–1 | Cached after the first flow; `address_port::resolve_server`. |
| 1 | TCP SYN → SYN-ACK | 1 | `connect_tcp_stream`; `TCP_NODELAY` set on the outbound socket (`lib.rs:670`). |
| 2 | ClientHello → ServerHello … Finished | 1 | One flight each way. REALITY adds no extra round trip: the session-id seal rides the ClientHello and the server's Finished carries the auth tag. |
| 3 | VLESS request header + first payload | 1 | Header is held by `HeldHeader` and merged with the first payload into one TLS record. |
| 4 | Server → target → first response byte | 1 | Server-side; not ours. |
| — | **Ideal total** | **4** | ≈ 690 ms at 172 ms RTT. |

Measured 1813 ms is ~6.5 RTT more than the ideal. The extra time is not in the
protocol; it is in waits and in loss recovery.

## Every wait on the path

1. **`FirstPayloadDeadline::for_vless` — one extra poll, not a timer.**
   `first_payload.rs:226`. VLESS does *not* take Xray-core's 500 ms
   `ReadMultiBufferTimeout`; the first read only yields once so a payload
   already buffered on the upload half shares the header's write, and the next
   read sends the header alone. This is correct and costs no wall clock. The
   500 ms wait survives only for the reverse-tunnel command
   (`VLESS_REVERSE_FIRST_PAYLOAD_WAIT`). **No fix needed.**

2. **Vision empty padding frame.** `vision_stream.rs:183`. When no payload is
   buffered, `queue_empty_padding_frame` emits a `Continue` frame with long
   padding (up to ~900 bytes, `vision.rs:130`) before the header leaves. This is
   the same bytes Xray-core sends when its 500 ms wait expires, so it is
   wire-compatible — but it is sent *immediately* here rather than after 500 ms,
   which is strictly better. **No fix needed.**

3. **`COPY_FLUSH_INTERVAL` = 2 ms.** `policy.rs:30`. The relay flushes a
   partial write after 2 ms. On a 172 ms path this is noise. **No fix needed.**

4. **Happy Eyeballs fallback delay = 300 ms.** `happy_eyeballs.rs:220`
   (`GO_FALLBACK_DELAY`). Only paid when the server name resolves to both
   families and the first family's SYN is lost. With a single A record (the
   WAN config uses an IP literal) it is never paid. **Watch item**, not a fix.

5. **`preconnect` (`testpre`) refill delay = 200 ms.** `preconnect.rs:31`.
   Only when `pre_connections` is configured; the WAN config does not set it.
   **No fix needed.**

6. **Inbound `TCP_NODELAY` — missing.** `socks.rs` and `http.rs` accept loops
   never called `set_nodelay`. Go's `net.TCPConn` sets it on every accepted
   connection, so Xray-core's SOCKS reply and `200 Connection established`
   never wait for a delayed ACK. Without it the reply can sit up to ~40 ms
   (macOS/Linux delayed-ACK timer) on a fresh flow, and the first downlink
   bytes can be held behind it. **Fixed in this change.**

7. **SYN retransmit under loss.** macOS's initial RTO is 1 s (RFC 6298, no
   Linux-style initial-RTO reduction). At 15 % loss a single lost SYN or
   ClientHello costs a full 1 s before the retransmit — which is exactly the
   `stalls>1s: 2` and the 1000 ms RR p99 in the WAN table. This is the single
   largest contributor to the 1813 ms p50 and the tail. It is a kernel
   behaviour, not a Segue bug; the mitigations are TCP Fast Open (below) and
   the server's BBR round.

## TCP Fast Open

- **Linux:** `socket_options.rs:433` sets `TCP_FASTOPEN_CONNECT` when
  `tcpFastOpen` is configured, which defers the handshake to the first write
  and lets the ClientHello ride the SYN when a cookie is cached. This is the
  right mechanism and matches Xray-core's `sockopt_linux.go`.
- **macOS:** `socket_options.rs:527` sets `TCP_FASTOPEN` with
  `TCP_FASTOPEN_CLIENT`, but Apple kernels accept `TCP_FASTOPEN` only on a
  *listening* socket, so a configured `tcpFastOpen` stops every later TCP
  option on the socket (`socket_options.rs:899`). TFO is therefore effectively
  unavailable on macOS for the client. This is a platform limit, not a bug.
- **Default:** `tcpFastOpen` is unset in the WAN config, so neither path is
  active. Enabling it on Linux would remove one RTT on repeat flows.

## Is the VLESS request on the first TLS app record?

Yes. `HeldHeader::poll_write` (`first_payload.rs:102`) appends the first
payload to the held header and hands both to the carrier in a single
`poll_write`, which rustls seals into one record. When no payload is buffered,
`FirstPayloadDeadline::for_vless` sends the header alone on the next read, and
Vision prepends its empty padding frame — the same bytes Xray-core sends on its
timeout path. So the request always rides the first app record, as in
Xray-core.

## Fixes, in order of value

1. **Inbound `TCP_NODELAY`** (done here). Removes up to ~40 ms per fresh flow
   and the delayed-ACK stall on the first downlink bytes. Wire-compatible: it
   changes no bytes, only when they leave.
2. **Enable `tcpFastOpen` on Linux clients** (config, not code). Removes one
   RTT on repeat flows. Needs a cookie cache and server support; document it
   rather than default it on.
3. **Server-side BBR** (already planned in the WAN findings). The 1 s SYN
   retransmit and the 1000 ms RR p99 are loss-recovery artefacts; BBR on the
   server plus a lower initial RTO on the client path is the real fix for the
   tail.
4. **Consider `pre_connections`** for latency-sensitive users. It moves the
   TCP+TLS handshake off the request path entirely, at the cost of idle
   connections. Not a default.

## What this change does not touch

The REALITY handshake itself is already one round trip and matches Xray-core's
`UClient` (`transport/internet/reality/reality.go:142`): the session-id seal
rides the ClientHello, the server's Finished carries the auth tag, and there is
no HelloRetryRequest in the normal path. The VLESS first-payload hold already
beats Xray-core's 500 ms wait. The remaining gap is loss recovery and the
missing inbound `TCP_NODELAY`, not protocol round trips.
