- QUIC security fixes from quinn-proto 0.11.19 and quinn 0.11.12, which
  replace the vendored 0.11.16 and 0.11.9. These carry the fixes for
  RUSTSEC-2026-0338, 0339, 0341, 0342, 0523 and 0524: a peer that answers a
  client's first Initial with a Retry whose token leaves no room in the
  packet could make a release build allocate more than 10 GiB and abort
  (0524), a peer could queue empty DATAGRAM frames without bound (0342) or
  open 2^40 streams with one MAX_STREAM_DATA frame (0523). Local patches
  (ChromeParrot handshake, BBR and congestion callbacks, pacing, ready ACKs,
  stream receive window, Hysteria DATAGRAM cap, the stopped/reset stream
  credit fix, quinn's bounded transmit quantum, receive batch and rebind
  grace) are rebased onto the new archives. Upstream commit `f35b091f`.
- The stopped-stream flow-control fix is now half upstream's: 0.11.19's
  `StreamsState::received_reset` credits a stopped stream only the bytes past
  its end, as our patch did; `Recv::stop` still double-credited a stream
  reset before it was stopped, so that half stays ours.
- A ChromeParrot client's lone Handshake ACK no longer counts as a packet in
  flight awaiting an acknowledgement, and a lost MTU probe reaches the
  congestion controller through its own callback. Upstream commit `44c48291`.
- QUIC loss and congestion accounting for Hysteria and XHTTP H3: `reno`
  starts at quic-go's 32-datagram window, Xray's BBR keys packets by their
  place in the connection instead of the packet number (which repeats per
  space), and a lost MTU probe no longer puts it into recovery. Upstream
  commit `a67f9b24`.
