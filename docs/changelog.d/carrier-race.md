**Kernel**

- A carrier dial that is still running after a short delay (1.5 × the exit's
  smoothed RTT, or 250 ms when that is unknown, clamped to 100 ms–2 s) starts
  a second dial to the same exit. The first to finish carries the session, so
  a lost SYN does not cost the macOS retransmit timeout. The loser is dropped.
  The exit is marked failed only when both attempts fail, or when the whole
  race hits the 10 s carrier timeout — a losing attempt's error is not a failure.
