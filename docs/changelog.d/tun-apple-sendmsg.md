- Apple: packets written to a utun descriptor go out in `sendmsg_x`
  batches of up to 64, instead of one `write`/`writev` per packet, when
  every frame still fits a 4 KiB mbuf cluster (4092 bytes of IP payload,
  plus the 4-byte utun header). A larger frame stays on the per-frame
  `writev`. A short `sendmsg_x` (fewer messages accepted than submitted)
  commits only that prefix; `EAGAIN` and `ENOBUFS` commit nothing, and a
  multi-message `ENOBUFS` or `EMSGSIZE` is retried as a smaller batch, so
  none of those paths drops or resends a packet. `SEGUE_TUN_BATCH=0`
  (`false`, `off` or empty) turns the batch off and leaves the single-packet
  write path exactly as it was. Raw-IP descriptors and every non-Apple
  platform never batch. `sendmsg_x` is private Darwin API and is declared
  next to `recvmsg_x`.
- Apple: batched and single utun writes are gated on the estimated utun
  input-chain depth, the way sing-tun does it. Past
  `net.utun.max_pending_input` (512) the kernel leaks one mbuf cluster per
  refused write until reboot, so the gate stops at 384 and, when the
  interface counter has not moved for 16 samples, lets at most 8 packets
  through as a probe that stays under the limit. A closed gate submits
  nothing — it does not fall through to `writev`. The gate arms only when
  the socket is in netif mode and its input counter can be read; otherwise
  there is nothing to estimate and writes are not held. An `ENOSPC` refusal
  realigns the estimate to just over the limit and is not retried. Based on
  sing-box 1.15 / sing-tun (`stack_go_io_darwin.go`).
