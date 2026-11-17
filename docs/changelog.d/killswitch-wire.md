- The kill switch is the decision on the data path. `protection_for_exit_class`
  maps an AI exit to Strict and an overseas exit to Wait; any other class fails
  closed. The session dialer and the SOCKS/TUN admission ask `KillSwitch::verdict`
  instead of a second AI-only check. A TCP flow that gets `Verdict::Wait` is
  accepted and held, not reset, until the posture is connected or `WAIT_DEADLINE`
  (12s) passes, and is then refused the same way a failed dial is refused. At most
  `WAIT_CAP` (64) flows are held; a SYN past that cap is reset. UDP is refused
  rather than held: a datagram flow has no handshake to keep the application
  waiting, and buffering it would pin memory for a flow the app has usually
  already abandoned. A strict (AI) flow is still refused at once while its exit
  is reconnecting.
