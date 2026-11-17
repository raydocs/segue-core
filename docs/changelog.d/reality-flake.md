- REALITY interop no longer dials `www.google.com` (or the encryption
  oracle's five-second origin) as `dest` for the sudoku and VLESS-encryption
  matrices. Xray 26.11.9's detector (`github.com/xtls/reality`, commit
  `4bb46b2afd8b`) treats a placeholder `false` lens as "not ready" and
  `Server` then `time.Sleep`s five seconds; a trusted dest keeps that
  placeholder up for the probe's own five-second read, and the oracle origin
  closes the mirrored connection on the same deadline, which resets the
  client (`early eof`, gRPC "connection reset"). A self-signed local cover
  fails the probe's certificate check immediately, and it stays open for the
  handshake. The first sudoku REALITY flow is a warmup, the way the other
  REALITY interop tests already treat a consumed first connection.
- A gRPC dial inside REALITY waits 15 seconds, not 5. grpc-go's
  `MinConnectTimeout` is 5 seconds but the client retries out to a 19-second
  `MaxDelay`; one 5-second attempt is dropped in the middle of that sleep and
  the reset takes the next dial with it. Other gRPC dials stay at 5 seconds.
- Random ClientHellos for every REALITY hybrid fingerprint are checked
  against the server's parse rules (one record, session id at handshake
  offset 39, X25519MLKEM768's 1216-byte share before any X25519, no duplicate
  extension). The full cipher-suite list (upstream `405b8695`) does not move
  the session id — it sits before the cipher list — and does not reorder key
  shares. Ruled out as the flake: a server-chosen unimplemented suite (the
  REALITY server stays on TLS 1.3 and only AES-GCM / ChaCha20), and a
  hard-coded session-id offset (still 39, checked against the parsed hello).
