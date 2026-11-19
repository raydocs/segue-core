**Session**

- An AI session (`exit_class` 1) may stay detached for `t_detached_ai` (150 s)
  instead of `t_detached` (30 s), on the client and the relay. It still gives
  up with `connect_timeout` / `idle` once that bound elapses. Other sessions
  are unchanged. Losing carriers in a row no longer ends an AI session by
  count: `MAX_FRUITLESS` still backs off the next dial, and the session ends
  only when `t_detached_ai` has also elapsed.
- While an AI session is detached the relay keeps reading the site into the
  existing replay buffer, up to the credit and pool limits that already bound
  it, so a token stream is not stalled at the vendor during the outage. A
  non-AI session still stops reading the site while detached. `t_tomb` and the
  control-stream timers are unchanged.
