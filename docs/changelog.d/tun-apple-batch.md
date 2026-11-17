- Apple: packets are read from the utun descriptor in batches with
  `recvmsg_x`, instead of one `read(2)` per packet. The batch size is
  adaptive — it starts at 4, doubles while batches come back full and halves
  while they come back under half full — up to 32 packets on iOS and 64 on
  macOS; the batch arena is bounded at 272 KiB (94 KiB at a 1500-byte MTU).
  Packets are still carved out of one shared allocation, so a batch costs no
  per-packet allocation, and each packet is split off without a copy exactly
  as before. `SEGUE_TUN_BATCH=0` (also `false`, `off` or the empty value)
  turns batching off for the process and leaves the single-packet read path
  exactly as it was. `recvmsg_x` and `struct msghdr_x` are private Darwin API
  and are declared by hand. Raw-IP descriptors and every non-Apple platform
  keep reading one packet per call.
- Apple: a utun socket is now given `UTUN_OPT_MAX_PENDING_PACKETS`, derived
  from its receive buffer as sing-tun does (raised towards 8 MiB, then
  `SO_RCVBUF/8*7/(mtu+4)`, clamped to 64). When the limit is reached the
  interface pauses instead of letting the control socket drop packets with
  `ENOBUFS`. It is best effort: a kernel that does not know the option (or
  any other failure) is ignored. Based on sing-box 1.15 / sing-tun
  (`stack_go_io_darwin.go`, `tun_darwin.go`).
