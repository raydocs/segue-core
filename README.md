# Segue Core

The transport engine behind Segue: a Rust client core for VLESS + REALITY
(with Vision) and Hysteria 2, built to run inside iOS, macOS and Android VPN
extensions with a small, steady memory footprint. It reads an Xray-style JSON
profile, routes each flow and dials the selected outbound.

Segue's own session layer, routing kernel and kill-switch are developed
separately and call this engine through a narrow dialer interface.

## Measured (same-host loopback, 4 vCPU Linux, 2026-11-12)

| | Segue Core | Xray-core 26.11.9 |
|---|---|---|
| Idle RSS (REALITY client) | ~15 MB | ~37 MB |
| 500 live REALITY flows | ~54 MB | ~105 MB |
| REALITY bulk throughput | 1025–1109 MB/s | 842–845 MB/s |
| CPU per GiB (REALITY) | 0.75–0.85 s | 1.04–1.10 s |

Loopback numbers say nothing about cross-border paths; those are measured
separately. The ClientHello carries X25519MLKEM768 like current Chrome, which
current REALITY servers require.

## Build and run

```sh
cargo build --locked --release -p segue-cli     # target/release/segue
target/release/segue config example vless-tls > client.json
target/release/segue config check --config client.json --json
target/release/segue run -config client.json
```

`config check` validates a profile without touching the network. A
credential-free smoke run: `cargo run --locked -p segue-cli -- run -config examples/freedom.json`
(SOCKS5 on `127.0.0.1:1080`, direct out); it runs until `Ctrl-C`, and on unix
`segue` stops as gracefully on SIGTERM, as in Xray-core. Never commit live
UUIDs, keys, short IDs or endpoints.

Mobile builds: `scripts/build-apple-xcframework.sh` and
`scripts/build-android-libs.sh`; the C ABI is in
`crates/segue-ffi/include/segue_ffi.h` ([contract](docs/ffi.md)).

## Layout

```text
crates/
├── segue-engine            lifecycle, inbounds, routing, outbound selection, DNS, TUN runtime
├── segue-transport         TCP, TLS, REALITY, Hysteria 2/QUIC, dialing, shaped ClientHellos
├── segue-proxy             client protocol wire formats (VLESS, Hysteria 2, SOCKS/HTTP, …)
├── segue-config            Xray JSON subset and geodata parser with path-aware diagnostics
├── segue-routing           routing matchers and policy evaluation
├── segue-ffi               C ABI with an embedded Tokio runtime
├── segue-cli               `segue` command: run, config check/example/contract
├── segue-tun / -utls / -vless-encryption / -wireguard / -runtime / -bench
platform/                   Swift package and Kotlin wrapper for VPN extensions
tools/                      Go oracles used to generate and verify wire fixtures
tests/ fuzz/ scripts/       fixtures, fuzz targets, interop and release checks
vendor/                     vendored, patched upstream crates
licenses/                   licence texts and third-party notices
docs/                       architecture, compatibility, evidence
```

## Testing

```sh
cargo test --workspace --locked
python3 scripts/gen-dependency-licenses.py   # refresh licenses/DEPENDENCIES.md
```

Interop checks against the Go Xray-core and sing-box live in `scripts/check-*-interop.sh`.

## Licence

Source files are under the Mozilla Public License 2.0. Licence texts,
third-party notices and the dependency list are in [`licenses/`](licenses/).
