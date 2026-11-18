- VLESS encryption resumption confirmation is timed from the moment the client
  hello is written, not from when the 0-RTT handshake returns. Xray confirms a
  resumed session with the first response bytes and has no separate timer; a
  first-payload hold was burning that budget before the server had anything to
  answer, and a confirmation already buffered when the budget elapsed was
  reported as a timeout.
- A gRPC call whose uplink is already closed condemns the pooled connection
  immediately. The next VLESS open dials a fresh one instead of failing with
  "the gRPC uplink is closed". That happened when the REALITY cover probe's
  five-second server sleep (`GlobalPostHandshakeRecordsLens` in
  `github.com/xtls/reality`) outlasted the matrix warmup and the shared dial
  was reset underneath the following call. The warmup now waits 15s, the same
  bound the pool uses for a REALITY dial.
