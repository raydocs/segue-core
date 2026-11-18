# Hysteria2 congestion control: Segue vs sing-box 1.15α

Audit of what Segue's Hysteria2 client announces in the auth request, which
congestion controller it then runs, and how that compares with sing-box
1.15.0-alpha.13 on the same lossy WAN path (`.bees/wan-findings.md`).

Sources read: `crates/segue-transport/src/hysteria/client.rs`,
`crates/segue-transport/src/stream/xhttp/h3.rs`,
`crates/segue-transport/src/quic_congestion.rs`,
`crates/segue-engine/src/outbound/hysteria.rs`,
`/Volumes/dev/ci/xray/Xray-core/transport/internet/hysteria/{dialer,hub,config}.go`,
`/Volumes/dev/ci/go/pkg/mod/github.com/sagernet/sing-quic@v0.7.2-…/hysteria2/{client,service}.go`
and `…/hysteria2/internal/protocol/http.go`.

## What Segue sends in the auth request

`auth_request` in `hysteria/client.rs` builds the POST to
`https://hysteria/auth` with exactly three headers:

| header | value |
| --- | --- |
| `Hysteria-Auth` | the configured auth string |
| `Hysteria-CC-RX` | `brutalDown` in bytes per second, `0` when unset |
| `Hysteria-Padding` | 256–2048 random alphanumeric bytes |

This matches Xray-core's dialer (`dialer.go:175`, which sends
`strconv.FormatUint(quicParams.BrutalDown, 10)`) and sing-quic's client
(`AuthRequestToHeader`, `http.go:43`, which sends `req.Rx` as a decimal).
Neither client ever sends `auto`; `auto` is a server-only reply value. Segue
sends `0` when no rate is configured, which is the same wire value sing-box
sends with no `up`/`down` set (`SendBPS`/`ReceiveBPS` default to 0).

`brutalDown` is parsed by `parse_quic_bandwidth` as bits per second with
binary multipliers and divided by 8, matching Xray's `Bandwidth.Bps()`
(`transport_method.go:708`), including the 65 536 B/s floor
(`transport_finalmask.go:1241`).

## What controller Segue then runs

`parse_auth_headers` reads the server's `Hysteria-CC-RX` reply (`auto` → 0)
and `H3QuicConfig::installed_controller` picks the controller
(`h3.rs:165`):

- `congestion: ""`/`brutal` (the default) with `brutalUp > 0` **and** a
  nonzero server rate → `Brutal` at `min(brutalUp, server rate)`.
- Otherwise → the profile's BBR. For the default `standard` profile that is
  `Installed::QuinnBbr`, i.e. **quinn's** BBR, not the port of Xray's sender
  (`STANDARD_RUNS_XRAY_BBR = false`, `quic_congestion.rs:410`).
- `bbr` → the profile's BBR; `reno` → quic-go's 32-packet NewReno;
  `force-brutal` → Brutal at `brutalUp` regardless of the reply.

The switch is installed after authentication (`client.rs:497`), so the
handshake and auth exchange run on the startup NewReno, as in Xray.

## What sing-box 1.15α does with no up/down configured

`sing-quic/hysteria2/client.go:596-608`:

```go
actualTx := authResponse.Rx
if actualTx == 0 || actualTx > c.sendBPS { actualTx = c.sendBPS }
if !authResponse.RxAuto && actualTx > 0 {
    quicConn.SetCongestionControl(hyCC.NewBrutalSender(actualTx, ...))
} else {
    quicConn.SetCongestionControl(congestion_meta2.NewBbrSenderWithProfile(..., c.bbrProfile))
}
```

With no `up`/`down`, `sendBPS` and `receiveBPS` are both 0, so `actualTx`
is 0 and sing-box runs **`congestion_meta2`'s BBR** — a port of the
quic-go/Chromium BBR sender, the same family as Xray's `bbr` package that
Segue ports as `XrayBbr`. It is *not* quinn's BBR.

So on the WAN run both clients were on BBR, but different implementations:
sing-box on the quic-go-lineage BBR, Segue on quinn's BBR. That is the most
likely explanation for the throughput gap (7.6 vs 15.3 Mbps) and the
round-trip p99 gap (929 vs 388 ms) on a path with 15 % loss and 2–4 packet
bursts: quinn's BBR is a simpler sender with a different loss/probe-bw
response, and Segue's `standard` profile deliberately keeps it.

## The TTFB gap (338 vs 175 ms) is not congestion control

`measure.py` times a fresh SOCKS5 CONNECT plus one byte echoed back. Segue's
SOCKS handler writes the success reply only after `open_tcp` returns
(`socks.rs:877`), and `open_tcp` waits for the server's TCP response header
(`hysteria/tcp.rs:79-101`). sing-box's `clientConn` is lazy: `Write` sends
the request and `Read` reads the response (`client.go:830-861`), so its
SOCKS reply can be written before the Hysteria stream handshake completes.

That is a one-RTT difference on the first byte, which is the ~163 ms gap
seen. It is a stream-open ordering question, not a CC one, and the
connection-pooling/stream-open path belongs to the `hy2-conn-reuse` bee.
Note also that Segue does reuse one QUIC connection across SOCKS flows
(`SessionOwner::client` caches a live `HysteriaClient`, `hysteria.rs:326`),
so the gap is not a new connection per flow.

## Changes made here

- Extracted the auth request into `auth_request` and added a unit test
  pinning the three headers, the `0`-not-`auto` receive rate, and the
  padding bounds. No behaviour change.
- No CC mismatch was found to fix: Segue's auth fields and Brutal/BBR
  selection already match Xray-core exactly.

## Open question for the owner

`STANDARD_RUNS_XRAY_BBR` is `false`, so the default Hysteria and XHTTP H3
connections run quinn's BBR while Xray-core (and sing-box) run the
quic-go-lineage BBR. The port is complete for `standard` too; flipping the
flag would align Segue with both references and is the single change most
likely to close the WAN throughput gap. It is left alone here because it
moves every default QUIC connection to another sender and the comment at
`quic_congestion.rs:405-410` says that waits for a decision.
