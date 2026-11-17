- A TUN TCP flow's receive window is now a runtime-profile value instead of a
  fixed 32 KiB. The `Desktop` and `Throughput` profiles give each flow a
  256 KiB receive ring, which smoltcp scales by 3, so one flow is no longer
  capped at `32 KiB / RTT` (2.6 Mbit/s at 100 ms) but at 21 Mbit/s. `Mobile`,
  `MobilePlus` and `LowMemory` keep 32 KiB: the engine allocates the ring
  eagerly when the socket is created, so a larger maximum would cost every
  idle flow on a jetsam-limited extension. `Default` follows the target, as
  before. The MTU floor (`4 × MSS`) still applies on top of the profile value,
  and the ring is allocated per live flow, so the profile's flow limit bounds
  the total.
- The vendored smoltcp holds 16 disjoint reassembly ranges instead of 4
  (`ASSEMBLER_MAX_SEGMENT_COUNT`), so a lossy mobile path that delivers
  several segments out of order no longer exhausts the assembler and forces
  retransmission of data the peer already sent. The assembler is a fixed
  array, so a socket's reassembly state grows from 64 to 256 bytes and
  nothing is allocated. SACK still reports at most three blocks, as RFC 2018
  allows. `vendor/smoltcp/XRAY-PATCH.md` and `XRAY-PATCH.diff` record it; the
  diff still applies to the checksum-pinned pristine 0.14.0 archive with zero
  fuzz and reproduces the vendored tree exactly.
