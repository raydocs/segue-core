# TUIC v5: why Segue's ping-pong p99 trails sing-box on a lossy 172 ms path

Measured 2026-11-18 on the WAN probe (`.bees/wan-findings.md`): US residential →
China Telecom 163 → Aliyun Hangzhou, RTT ~172 ms, 15 % ICMP loss at peak.
Round-trip p99 was 1045 ms for Segue TUIC against 439 ms for sing-box TUIC, with
3 stalls over 1 s against 0. Throughput and TTFB were already level (15.8 vs
15.3 Mbps, 171 vs 176 ms), so the gap is in the tail of small round trips, not
in bulk capacity.

The probe's `rr` loop (`/Volumes/dev/ci/wan/client/measure.py`) opens one SOCKS
flow, then sends a 1-byte write and waits for a 1-byte echo, 300 times, 50 ms
apart. Every iteration is therefore one request/response round trip on an
already-open TUIC stream. What matters is how many QUIC flights one iteration
costs and how long each waits.

## What Segue does today

Client: `crates/segue-engine/src/outbound/tuic.rs`, wire codec in
`crates/segue-proxy/src/tuic.rs`.

- **One bidi stream per TCP flow.** `Client::open_tcp` calls
  `connection.open_bi()` and writes a `CONNECT` header. There is no per-stream
  handshake or auth round trip: authentication is a single `Authenticate` uni
  stream per *connection* (`start_client`), and the connection is cached
  (`Owner::cached`). This matches sing-box, which also opens one stream per
  flow and authenticates once per connection.
- **Congestion control.** `congestion_control: bbr` maps to
  `H3Congestion::BbrStandard`, which with `STANDARD_RUNS_XRAY_BBR == false`
  installs `quinn_bbr()` — quinn's BBR with a 32 × 1280-byte initial window.
  sing-box's `bbr` installs `congestion_meta2.NewBbrSenderWithProfile(...,
  ProfileStandard)`, a port of quic-go's BBR. Both are BBR; the mapping is not
  wrong, though the two senders differ in detail (see below).
- **Heartbeat.** A 10 s `Heartbeat` datagram (`heartbeats`), the same default
  and the same command as sing-box's `loopHeartbeats`. Not a factor at 50 ms
  spacing.
- **Idle timeout.** 30 s (`max_idle_timeout`), against sing-box's default
  `IdleTimeout` of 30 s. Not a factor.
- **ACK delay.** quinn advertises `max_ack_delay = 25 ms` and, with no
  `ack_frequency_config`, does not send `ACK_FREQUENCY`; it ACKs every second
  ack-eliciting packet (`ack_eliciting_threshold = 1`) or on the 25 ms timer.
  quic-go does the same (`packetsBeforeAck = 2`, `MaxAckDelay = 25 ms`). Not a
  factor.
- **Pacing.** quinn paces from the controller's `pacing_rate`; BBR reports one.
  Not a factor for a single 1-byte write.

## The bug: the CONNECT header costs its own flight

`Client::open_tcp` used to write the `CONNECT` header with its own
`write_all` before returning the stream:

```rust
write.write_all(&header).await?;   // header leaves in its own packet
```

The relay then reads the client's first payload and writes it separately. On a
172 ms path that is two flights where one would do: the server cannot answer
until it has the request, and the payload arrives a round trip later. For the
probe's *first* ping-pong on each flow this is a full extra RTT; for the 20
fresh-flow TTFB samples it is the same. It does not explain the steady-state
`rr` p99 by itself, but it is a real, avoidable round trip on every new flow,
and it is the one place Segue's TUIC differs structurally from sing-box.

sing-box never does this. `clientConn.Write` in sing-quic's `tuic/client.go`
builds the `CONNECT` header and the first payload into one buffer and issues a
single `Stream.Write`; its relay (`route/conn.go`, `kickWriteHandshake`) gives
that write up to `C.ReadPayloadTimeout` (300 ms) of payload to merge with, and
only then sends the header alone.

Segue already has exactly this machinery for its other outbounds:
`HeldHeader` + `FirstPayloadDeadline` in
`crates/segue-engine/src/outbound/first_payload.rs`, used by VLESS, Trojan,
VMess and Shadowsocks. TUIC was the one outbound that did not use it.

### Fix

`open_tcp` now returns the stream wrapped in `coalesced(...)`, which holds the
`CONNECT` header and merges it with the first payload write, sending the header
alone after `TUIC_FIRST_PAYLOAD_WAIT` (300 ms, sing-box's
`ReadPayloadTimeout`) if no payload follows. Two unit tests pin it:
`connect_header_leaves_with_the_first_payload` and
`connect_header_leaves_alone_when_no_payload_follows`.

## What this does not explain, and the next things to try

The fix removes one round trip per new flow. It is unlikely to move the
steady-state `rr` p99 from 1045 ms to 439 ms on its own, because that loop
reuses one stream. The remaining candidates, in the order I would test them:

1. **BBR sender differences.** quinn's BBR and quic-go's BBR (which sing-box
   runs) differ in recovery-window handling and in how they treat
   application-limited sends. On a path with 15 % loss and 2–4 packet bursts,
   the recovery window after a loss event decides how many round trips a small
   write waits behind. Segue already ports quic-go's BBR as `XrayBbr`
   (`crates/segue-transport/src/quic_congestion.rs`); TUIC's `bbr` could run
   `BbrProfile::Standard` through it instead of `quinn_bbr()`. That is a
   one-line change at the `H3Congestion::BbrStandard` arm, but it changes
   behaviour for every BBR user, so it wants its own measurement.
2. **Initial RTT.** quinn starts at 333 ms, quic-go at 100 ms. Before the first
   sample this sets the PTO and the pacer's initial capacity. On a 172 ms path
   quinn's 333 ms is closer to reality than quic-go's 100 ms, so this probably
   favours Segue, not sing-box — worth confirming rather than assuming.
3. **Loss detection thresholds.** quinn uses `packet_threshold = 3` and
   `time_threshold = 9/8`; quic-go uses the same RFC 9002 values. Not a
   difference.
4. **The relay's 2 ms flush coalescing** (`COPY_FLUSH_INTERVAL` in
   `crates/segue-engine/src/policy.rs`) adds up to 2 ms per direction. That is
   noise against 172 ms and cannot produce a 600 ms tail.

The honest summary: the header coalescing is a clear, fixed bug worth one round
trip per flow; the p99 gap is most likely the BBR sender, and that needs a
measurement round with `bbr` pointed at the ported quic-go sender before
changing a default that every BBR user shares.

## References

- Segue: `crates/segue-engine/src/outbound/tuic.rs`,
  `crates/segue-engine/src/outbound/first_payload.rs`,
  `crates/segue-transport/src/stream/xhttp/h3.rs` (`build_quinn_config`),
  `crates/segue-transport/src/quic_congestion.rs`.
- sing-box: `protocol/tuic/outbound.go`; sing-quic `tuic/client.go`
  (`clientConn.Write`, `loopHeartbeats`), `tuic/congestion.go`;
  `route/conn.go` (`kickWriteHandshake`), `constant/timeout.go`.
- quic-go: `internal/ackhandler/received_packet_tracker.go`,
  `internal/utils/rtt_stats.go`, `internal/congestion/cubic_sender.go`.
