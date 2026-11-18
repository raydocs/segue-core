**Kernel**

- `auto` exit choice now prefers the exit with the lower measured loss, then
  the lower RTT, instead of the first exit whose carrier is up. Each exit's
  path quality is measured in the session layer: smoothed RTT from control
  PING/PONG round trips, loss from bytes replayed onto a new carrier after a
  carrier died, and a stall count. Switching is hysteretic (a challenger must
  beat the incumbent by a loss or RTT margin for three consecutive samples),
  so a noisy sample cannot flap the choice; a failover when the incumbent is
  down is immediate. A named exit still pins, ignoring quality.
- `GET /v1/status` `exits` is now `[{"name", "quality": {"srtt_ms", "loss",
  "stalls"}}]` (it was a list of names), exposing the measurements behind the
  `auto` choice. `srtt_ms` is `null` until the first control PING/PONG.
