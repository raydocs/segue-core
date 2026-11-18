**Docs**

- Added `docs/notes/reality-third-party-auth.md`: why mihomo 1.10.0 and
  sing-box 1.15.0-alpha.13 fail REALITY auth against Xray v26.11.9. The server
  requires an `X25519MLKEM768` key share before any ordinary X25519 share;
  mihomo strips it unless `support-x25519mlkem768: true` is set (a config
  difference), and sing-box alpha.13 strips it unconditionally (a client bug).
  Reproduced locally against Xray v26.11.9 with the WAN inbound shape.
