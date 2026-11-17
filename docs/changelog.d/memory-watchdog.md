- A host can now give the core the memory budget its platform kills the
  process for exceeding, in bytes, through
  `TunRuntimeOptions::memory_limit` (50 MiB on iOS). When it is set, a
  watchdog samples the process footprint about once a second — Darwin's
  `task_info(TASK_VM_INFO)` physical footprint, which is what jetsam counts,
  and `/proc/self/statm` resident size on Linux — and, at `limit - 5 MiB` or
  when the growth rate projects the limit within the next second, asks the
  connection registry to close the oldest idle connections and drops the relay
  buffers the process keeps for reuse, logging what it did. Connections that
  are still moving data are closed only above the hard limit. Without a limit
  no task is started and nothing is sampled. The thresholds and the
  growth-rate projection follow sing-box's OOM killer
  (`service/oomkiller/timer.go`).
