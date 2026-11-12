# Real-process e2e (Mac, no root)

```
curl ─SOCKS5─► segue-kernel 127.0.0.1:1090
   rules: localhost → segue route "ai", 127.0.0.1 → segue route "overseas", default reject
   session carriers = VLESS+Reality+Vision ─► official Xray 26.11.9 server 127.0.0.1:8443
      freedom ─► segue-relay 127.0.0.1:7443 (tickets, independent AI classification, SSRF guard)
         overseas ─► direct ─► http_log.py 127.0.0.1:8091
         AI (relay whitelist: "localhost") ─► fake_decodo.py 127.0.0.1:1099 (RFC1929) ─► 8091
```

Run: `BIN=<target>/debug XRAY=<official xray> ./run.sh` → `out/result.txt`, logs in `out/`.
Lab-only: relay `dev_allow_cidrs: [127.0.0.1/32, ::1/128]` (SSRF guard otherwise refuses loopback targets).
Reality dest is www.microsoft.com:443, so the Mac needs internet.

## Result 2026-11-12 (integ/backend 4b5fa4b6, debug build) — 14/14 PASS

| Check | Result |
|---|---|
| overseas 1 MiB fetch, sha256 match | PASS |
| overseas never touched Home SOCKS | PASS |
| AI fetch sha match, seen at fake Decodo as `CONNECT cmd=1 atyp=1 127.0.0.1:8091` | PASS |
| Decodo never got a domain name (IPv4 CONNECT only) | PASS |
| Xray `kill -9` at ~63 MB of a 200 MiB rate-limited download; AI fetch refused in 0.04 s (curl rc=97) | PASS |
| overseas fetch while carrier down refused (rc=97) | PASS |
| target got 0 requests while carrier down (nothing direct) | PASS |
| Xray restarted → the 200 MiB download completed, sha256 identical | PASS |
| target saw exactly 1 GET for 200m.bin (resumed over RESUME, not refetched) | PASS |
| AI works again after recovery | PASS |
| Home UDP (SOCKS UDP ASSOCIATE to an AI target) refused, echo server got nothing | PASS |
| unmatched target rejected (default reject) | PASS |
| no ticket / SOCKS password in relay or kernel logs | PASS |

Relay metrics at end: connects_overseas 3, connects_home 2, home_unavailable 0, exit_denied 0.

## Not covered
- Hy2 carrier (only Reality here); multiple devices; revocation in-process (covered by relay unit/integ tests).
- "Overseas refused while down": the session's OPEN retry window is 20 s; the carrier was down the whole time, so it was refused. A short outage would let it succeed after reconnect (by design).
- Pitfall: stale xray/segue-kernel processes from older runs on 8443/1090 make the run invalid; check `lsof -iTCP:8443 -sTCP:LISTEN` first.
