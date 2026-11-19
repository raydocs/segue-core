**Session**

- An AI session with no spare bound waits `t_stall_solo` (5 s) before unacked
  silence or a relay `STALL` hint abandons its only carrier. A bound spare
  still swaps at `t_stall` (1 s). A hard loss (closed, write or decode error,
  `REJECT`) is unchanged, and so is every non-AI session. The transport hold
  stays 2 s.
- A spare dropped because the session moved (RESUME) is redialled at once.
  A spare that failed to dial or bind, or that died, still backs off from 1 s
  to 30 s.
