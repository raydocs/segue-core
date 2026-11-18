# ShadowTLS v3 outbound

Segue implements **client-only ShadowTLS v3**, following SagerNet/metacubex's
`sing-shadowtls` v3 client (`v3_client.go`, `v3_conn.go`) and server
(`v3_server.go`). mihomo's `transport/shadowtls` is a conforming alternative
stack. Versions 1 and 2 are deliberately rejected, not silently downgraded.

## Layering

A ShadowTLS v3 relay is a stream security, not an outbound protocol. An ordinary
TCP proxy (usually Shadowsocks2022, but also VMess/VLESS without Vision
unwrapping) puts its bytes into the returned stream:

```
proxy request
  ShadowTLS HMAC data records
    real TLS ClientHello + relayed server TLS handshake
      raw TCP (with the ordinary TCP masks and happy-eyeballs candidate race)
```

This is the same inner-protocol composition as mihomo's `plugin: shadow-tls`
and sing-box's `detour`, expressed through Segue's `StreamCarrier` and
`ConnectorConfig`. `TransportLayer::Raw` prepares the connector first, opens the
already-accounted TCP candidate, then wraps that carrier in `ShadowTlsStream`.
XHTTP, WebSocket, gRPC, KCP, XDRIVE and UDP are rejected by the parser or by the
programmatic dialer. ShadowTLS does not need its own DNS, mux or proxy-chain
implementation; those remain properties of `StreamCarrier`.

## Wire processing

1. The shared `TlsConnector` builds the real certificate-verifying TLS config
   (including the existing uTLS profile). The ShadowTLS per-connection clone
   disables resumption and early data, and attaches a custom ClientHello
   finalizer. The profile and fingerprinters retain their greet bytes: the
   authentication lives in a 32-byte legacy session ID (28 random bytes and 4
   tag bytes), **not** replacing the TLS random or any key share.

   For `hello` including its handshake header but excluding the record header:
   `session_id = rand(28) || HMAC-SHA1(password, hello || session_id)[..4]`.

2. `HandshakeRelay` presents complete TLS records to rustls. The initial
   ServerHello seeds `H = HMAC-SHA1(password || server_random)` and
   `key = SHA256(password || server_random)`. Every transformed application
   record must carry `H(payload)[..4]`; payload is XORed with `key` before rustls
   reads the ordinary TLS record. Correct server authentication *and* this tag
   are needed to cut over. TLS 1.3 dummy records are consumed with the same
   handshake HMAC as sing-shadowtls' `readHMAC`/`hmacIgnore`, never exposed to
   the inner proxy. TLS 1.2's lack of a dummy proof follows the reference v3
   behavior.

3. Post-cutover data records are TLS-shaped `17 03 03` records. Four tag bytes
   sit between the TLS header and plaintext, with the inner byte stream capped
   at 16 KiB per record. Directional states start at
   `HMAC-SHA1(password || server_random || "C")` (client writes) and `..."S"`
   (server writes). Each consecutive tag is `tag = H(payload)[..4]`, followed by
   `H(tag)`. Tampered/truncated data is terminal; a failed MAC never updates
   local state. Encrypted read-ahead from the handshake retains bytes for the
   same transition and never lets dummy plaintext become proxy traffic.

The tests include independently computed ClientHello, XOR and directional
chained-HMAC vectors, plus a local genuine TLS 1.3 server behind a minimal in-test
record relay. The embedded relay verifies the hello signal, rewrites the dummy
TLS record and observes the data-frame transition. It is test code, not a
ShadowTLS server implementation exposed by Segue.

## Configuration (Segue only)

Use an existing raw-TCP outbound and configure its stream security as follows:

```json
{
  "protocol": "shadowsocks",
  "settings": { "address": "203.0.113.10", "port": 443 },
  "streamSettings": {
    "network": "tcp",
    "security": "shadowtls",
    "shadowtlsSettings": {
      "version": 3,
      "password": "replace-me",
      "serverName": "cover.example",
      "fingerprint": "chrome"
    }
  }
}
```

This is intentionally **not** an Xray field name, and the sample address/name
is not a live endpoint. The `settings` object must conform to the chosen
outbound's existing schema.

| Field | Meaning |
| --- | --- |
| `password` | Required, 1–4096 UTF-8 bytes. Authenticates the hello and both framed directions. Not logged. |
| `version` | Optional, default `3`; any other value is rejected. |
| `serverName` | Required nonempty cover TLS server's DNS/IP verification name; also its SNI. It is not inferred from the proxy address. |
| `fingerprint` | Existing Segue uTLS profile. Missing/empty means `chrome`; `unsafe` is rejected. |
| `alpn` | Optional TLS-shaped hello ALPN selection (Default list retains the profile's raw ALPN). The inner protocol is not ALPN-derived. |
| `pinnedPeerCertSha256` | Same comma-separated complete-certificate SHA-256 pin policy as TLS. |
| `verifyPeerCertByName` | Same comma-separated alternate certificate verification names as TLS. |

`allowInsecure` and `fromMitm` are unsupported. Resumption and early data are
disabled so every hello is independently authenticated.
