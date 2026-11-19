**Session**

- An AI session waits `t_stall_ai` (5 s) before unacked silence or a relay
  `STALL` hint gives up its carrier, whether or not a spare is bound. At 5 s
  a bound spare is swapped; with none the session re-attaches. A hard loss
  is still immediate, and a non-AI session still uses `t_stall` (1 s). The
  client announces that bound as `t_stall_ms` (5000 for AI, 1000 otherwise)
  so the relay's keepalive, half the shorter of its own `t_stall` and the
  announcement, stays inside the wait the client actually uses.
- The relay's give-up for an AI session is `t_live_ai` (5 s), the same wait,
  so it does not go DETACHED while the client is still holding the carrier.
  A `STALL` after a promotion is remembered and acted on once the new
  carrier is quiet, including a download with nothing unacked. Previously
  that hint was dropped, the relay stopped sending, and the token stream
  stayed open until the harness timed out.
