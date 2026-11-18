**Session**

- Stage 1 of session redundancy (v0.6 draft, no version bump): a session may
  bind a second carrier with ignorable `REDUNDANT_ATTACH` / `REDUNDANT_OK`
  (`0x3C` / `0x3D`). The relay does not switch or close the current carrier,
  and no DATA is duplicated yet. A spare that fails drops only that carrier;
  if the current carrier dies the spare is promoted and unacked bytes are
  replayed. A relay that ignores the frames falls back after `t_attach`.
  Off unless the caller asks.
