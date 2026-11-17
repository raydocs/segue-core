- A TCP flow through a MASQUE or WireGuard outbound no longer stops for good
  while it uploads. The userspace stack went to sleep when its queue of
  outgoing packets was full and only WireGuard's engine told it when the queue
  had drained; over MASQUE it slept on with the queue empty and packets
  waiting to be read. The loop now waits for a transmit slot itself. A fast
  retransmit that met a full queue is no longer forgotten: it stays owed until
  the segment leaves, so a flow is not left with unacknowledged data and no
  timer. (upstream `06cbfecc`)
- A flight that loses several segments is repaired without the retransmission
  timer. The vendored smoltcp follows NewReno (RFC 6582): an ACK of new data
  short of what had been sent when a loss was found resends the next missing
  segment at once, a FIN included, and Reno halves its window once for the
  loss event. SACK blocks that report more than two segments beyond the
  cumulative ACK start a fast retransmit like a third duplicate ACK
  (RFC 6675), which finds the hole in what was sent during a recovery and a
  retransmission that was lost in its turn. After a timeout neither sign
  starts one until an ACK passes what had been sent before it.
  `Socket::set_retransmission_timeout_floor` replaces the one-second bound on
  request; the MASQUE stack asks for 200 ms past the round trip. (upstream
  `054ba5fd`)
- Loss recovery is a socket's choice: it lives behind `Socket::set_loss_recovery`
  and is off by default, so the sockets that terminate the TUN link keep
  treating a loss as before (a test pins that). The retransmission floor is a
  setting of the packet type a stack carries: 200 ms for a CONNECT-IP (MASQUE)
  tunnel, none for WireGuard, which keeps the second of RFC 6298. `reset`
  still clears a pending fast retransmit on every socket. (upstream `acd64f02`)
- TUN TCP and UDP flow lifecycle: a UDP flow's task permit is held by the flow
  in the table and handed to the flow that evicts it, so an eviction never
  waits for the runtime to drop the old task; a bridge that returns without
  sending a close still ends its flow; a TCP flow whose remote side is closed
  is reset after 30 s in FIN-WAIT-2 if the app keeps its side open, instead of
  holding its buffers and its place under the flow limit for as long as the
  app lives. (upstream `76f1a0e0`)
- TUN flow limits: one permit pool shared by DNS queries and UDP flows, sized
  for a full flow table plus every DNS query, so a full table no longer
  starves DNS. A closed TCP flow whose app stops taking data or never
  acknowledges the FIN is given `tcpGiveUpTicks` (four minutes) since its last
  progress. A UDP bridge that panics still ends its flow before the panic
  reaches its `JoinError`. (upstream `43ff4e67`)
- `vendor/smoltcp/XRAY-PATCH.diff` and `XRAY-PATCH.md` describe the combined
  patch set, Segue's resizable pooled TCP rings included; the diff applies to
  the checksum-pinned pristine 0.14.0 archive with zero fuzz and reproduces
  the vendored tree exactly.
