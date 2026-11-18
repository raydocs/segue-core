# Why mihomo and sing-box fail REALITY auth against Xray v26.11.9

Status: root cause reproduced locally on 2026-11-18. No WAN server access was
used; every claim below was reproduced against a local Xray v26.11.9 with the
same inbound shape as the WAN server.

## Summary

The WAN failure is **not** a credential, shortId, clock, version-field or
`dest` problem. It is the **key share** in the ClientHello.

Xray-core's REALITY server, through the `xtls/reality` library pinned by
v26.11.9, refuses any ClientHello that does not carry an `X25519MLKEM768`
(0x11ec) key share **before** any ordinary X25519 share. A ClientHello with
only X25519 is not authenticated at all: the server treats it as a fallback
connection and logs

```
REALITY: processed invalid connection from <addr>: authentication failed or validation criteria not met
```

That message is the *generic* failure branch. It is emitted whenever
`hs.c.conn != conn`, which includes "the hello had no hybrid share", so it
reads like a bad key or shortId when it is really a shape rejection.

- **mihomo 1.10.0**: a **config difference**. mihomo strips the hybrid share
  by default and only sends it when `reality-opts.support-x25519mlkem768: true`
  is set. The WAN client config omits that key; the bench harness config sets
  it.
- **sing-box 1.15.0-alpha.13**: a **client bug**. It unconditionally deletes the
  hybrid share from its own ClientHello, with no config option to keep it.
- **Xray v26.11.9**: the server requirement is intentional and documented in
  code. It is not a misconfiguration on our side.

## The server side

`xtls/reality` `tls.go` (pinned by Xray v26.11.9 as
`v0.0.0-20261108101329-4bb46b2afd8b`) scans the ClientHello key shares:

```go
if keyShare.group == X25519MLKEM768 && len(keyShare.data) == mlkem.EncapsulationKeySize768+32 {
    ...
    peerPub2 = keyShare.data[mlkem.EncapsulationKeySize768:]
    continue
}
if keyShare.group == X25519 && len(keyShare.data) == 32 {
    ...
    peerPub = keyShare.data
    break
}
...
if peerPub2 == nil {
    break // reject outdated/strange Client Hello that doesn't have X25519MLKEM768 before optional X25519
}
```

`peerPub2` is only set by the hybrid share. When it stays nil the loop breaks
before `hs.c.conn = conn` is ever assigned, so the connection falls through to
the fallback path and the generic error above is logged. The X25519 share is
accepted only as the *secondary* half of a hybrid pair, never on its own.

The check is not new in v26.11.9. This repository's own
[v26.9.8 migration audit](../xray-core-v26.9.8-migration-audit.md) records the
same requirement arriving with the REALITY dependency bump to
`8cdf7bf9c7f0`, so it predates v26.10.21. The v26.10.21 build pins
`reality v0.0.0-20261014101318-83f621788ca8` (see
`docs/benchmarks/results/2026-10-27-v26.10.21-migration/summary.json`), and
v26.11.9 pins `v0.0.0-20261108101329-4bb46b2afd8b`; both carry the check.
Servers older than the v26.9.8 bump accept an X25519-only hello.

v26.11.9 also makes Chrome 155 the default client fingerprint: `GetFingerprint("")`
returns `utls.HelloChrome_Auto`, which the pinned uTLS aliases to
`HelloChrome_155`. That is a client-side default and does not affect what the
server accepts.

## The client side

### mihomo 1.10.0 — config difference

`adapter/outbound/reality.go`:

```go
SupportX25519MLKEM768 bool `proxy:"support-x25519mlkem768,omitempty"`
```

`component/tls/reality.go`:

```go
if !realityConfig.SupportX25519MLKEM768 { // for X25519MLKEM768 does not work properly with the old reality server
    err = BuildRemovedX25519MLKEM768HandshakeState(uConn)
```

The flag defaults to `false`, so mihomo deletes both the `X25519MLKEM768`
entry from `supported_groups` and its key share, then rebuilds the hello. That
is a deliberate compatibility default for pre-v26.9.8 servers, and it is
exactly wrong for a current one.

The WAN client config (`mihomo.yaml`, `mihomo-ff.yaml`) sets only
`public-key` and `short-id`. The bench harness config
(`crates/segue-bench/src/lib.rs`, `mihomo_reality_config`) sets
`support-x25519mlkem768: true`. That single line is the whole difference
between "mihomo works in the loopback bench" and "mihomo fails on the WAN".

### sing-box 1.15.0-alpha.13 — client bug

`common/tls/reality_client.go` at tag `v1.15.0-alpha.13`:

```go
for _, extension := range uConn.Extensions {
    if ce, ok := extension.(*utls.SupportedCurvesExtension); ok {
        ce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {
            return curveID != utls.X25519MLKEM768
        })
    }
    if ks, ok := extension.(*utls.KeyShareExtension); ok {
        ks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {
            return share.Group != utls.X25519MLKEM768
        })
    }
}
err = uConn.BuildHandshakeState()
```

This runs unconditionally, before the REALITY session id is sealed, and there
is no option to disable it: `OutboundRealityOptions` has only `enabled`,
`public_key` and `short_id`. The client therefore cannot talk to any REALITY
server from the v26.9.8 bump on, whatever the fingerprint. The ref clone's
HEAD (2026-11-17) no longer contains this block, so the fix is upstream but is
not in the alpha.13 binary we tested.

## What was ruled out

The clients disagree on the session-id version bytes and still fail or succeed
purely by key share, so none of these are the cause:

| field | mihomo 1.10.0 | sing-box alpha.13 | segue |
| --- | --- | --- | --- |
| session id version bytes | `01 08 02` | `01 08 01` | `1a 0a 15` (`[26, 10, 21]`) |
| unix time | `PutUint64` at 0, then `[0..3]` overwritten | `PutUint32` at `[4:]` | big-endian at `[4..8]` |
| shortId | hex-decoded into `[8]byte` at offset 8 | same | same |
| AEAD | AES-256-GCM, nonce `random[20..32]`, AAD = raw hello | same | same |
| HKDF | `sha256`, salt `random[..20]`, info `"REALITY"` | same | same |
| ALPN | `h2`, `http/1.1` | `h2`, `http/1.1` | `h2`, `http/1.1` |

The version field is not checked: neither test server sets `minClientVer` or
`maxClientVer`, and the server only compares them when they are non-nil. The
three clients send three different values and the outcome tracks the key share
alone.

The `dest` is not involved: the failure happens before the server ever dials
the target, and sing-box fails identically against the bench fixture
(`dest www.google.com:443`) and against a `www.microsoft.com:443` fixture.

## Reproduction

Local Xray v26.11.9, `dest www.microsoft.com:443`, one 16-hex-char shortId,
`flow xtls-rprx-vision`, all on loopback. Captured ClientHellos (the leading
GREASE value varies per connection):

```
mihomo, no flag:   groups=[0x9a9a, 0x1d, 0x17, 0x18]  key_shares=[(0x9a9a,1), (0x1d,32)]
mihomo, flag:      groups=[0x8a8a, 0x11ec, 0x1d, ...] key_shares=[(0x8a8a,1), (0x11ec,1216), (0x1d,32)]
sing-box alpha.13: groups=[0xbaba, 0x1d, 0x17, 0x18]  key_shares=[(0xbaba,1), (0x1d,32)]
```

Results against the same server:

| client | config | result |
| --- | --- | --- |
| mihomo, `client-fingerprint: chrome` | no flag | fails, `REALITY authentication failed` |
| mihomo, `client-fingerprint: chrome` | `support-x25519mlkem768: true` | **200** |
| mihomo, `client-fingerprint: firefox` | no flag | fails |
| mihomo, `client-fingerprint: firefox` | `support-x25519mlkem768: true` | **200** |
| sing-box 1.15.0-alpha.13 | any fingerprint | fails, `reality verification failed` |

The fingerprint is irrelevant; only the key share matters. Both mihomo
fingerprints succeed once the hybrid share is present, which also confirms the
server's Chrome 155 default does not require a specific client profile.

## What to do

- **mihomo on the WAN**: add `support-x25519mlkem768: true` to `reality-opts`.
  This is a config fix, not a code change, and it matches what the bench
  harness already does.
- **sing-box**: no config workaround exists in 1.15.0-alpha.13. Use a build
  from after the strip was removed, or do not use sing-box REALITY against a
  server from the v26.9.8 bump on.
- **Segue**: no change needed. `crates/segue-utls` draws REALITY profiles only
  from the hybrid subset (`XRAY_REALITY_MODERN_FINGERPRINTS`), and
  `crates/segue-transport/src/utls_profiles.rs` resolves `chrome` to the
  Chrome 155 profile, so Segue's ClientHello carries the hybrid share. The
  config parser warns when a REALITY fingerprint lacks it
  (`crates/segue-config/src/parser/stream.rs`).

## Caveat

The WAN server was not reachable from this investigation, so the WAN result is
inferred from a local Xray v26.11.9 with the same inbound shape, not observed
directly. The mechanism is version-pinned in the server library and reproduced
byte-for-byte in the captured ClientHellos, so the inference is strong, but a
single WAN retry with the mihomo flag set would close it.
