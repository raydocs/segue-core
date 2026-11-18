Core:
- Set `TCP_NODELAY` on accepted SOCKS and HTTP inbound connections, as Go's
  `net.TCPConn` does, so the SOCKS reply and `200 Connection established` no
  longer wait for a delayed ACK on a fresh flow. See `docs/notes/reality-ttfb.md`
  for the REALITY+Vision first-byte round-trip budget.
