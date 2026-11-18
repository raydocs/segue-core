**Docs**

- New design note `docs/design/session-redundancy.md`: how the session layer can
  make a lost packet cost less than one RTT for AI token streams on a lossy
  172 ms path. Compares duplicating small DATA frames on a second carrier,
  L5 FEC, carrier racing and relying on QUIC carriers, with wire changes,
  bandwidth, rule-8 pool interaction and a staged plan. Recommendation:
  duplicate small frames on a redundant carrier behind an ignorable frame
  (no version bump), after the QUIC carrier's own loss recovery is fixed.
