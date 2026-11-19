**Session**

- Added Stage 2 small-frame redundancy (`RedundancyConfig`, `RedundancyMode::Off | Dup { delay } | Hedge { delay }`, default `Dup { delay: 30 ms }`, `max_frame_bytes = 1024`, `ai_only = true`; opt-out via `Off` or `Hedge { delay }`) via `DupQueue` (`DUP_QUEUE_CAP = 32`, non-wedging `bulk_barrier`, and `seed_inflight` up to `8 * max_frame_bytes`).
- Added AI-class keepalive and credit-retention defaults (`t_keepalive_ai = 20 s`, `idle_after_ai = 60 s`) plus pressure-aware `pressure_idle_after`.
- Isolated redundant transmissions to `Tier::Elastic` in the session driver, fixed `StandbyKeep` swap backoff and `reattach` abort handling, compacted `CarrierEv::Frame` with `CarrierFrame` boxing (keeping retained idle memory under the `memory.rs` 32 KiB/session budget), and boxed session `MoveStats` lazily.
- Hardened carrier failover across client and relay: `Hold` hard-drop handling, `Detached` rescue on bound spare RX, `demoted_at` clear on RX and mirroring guard while demoted, `FIN` mirroring gated on `acked == offset`, primary-download blackhole self-heal, and `promoted_in_gen` out-of-order switch protection.
- Added `Exit.redundant_carrier` non-racing standby dial selection in `segue-kernel`, `Config.redundancy` in `segue-relay`, and `connection_seed` per-connection impairment decorrelation in `segue-bench`.
