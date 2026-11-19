**Kernel**

- AI sessions keep a standby carrier on the same exit once OPENED, so a lost current carrier is promoted with no new dial. The spare is replaced on a backoff (1 s, doubling to 30 s, reset after it stayed bound for 10 s). A standby dial failure or a spare death does not mark the exit failed. `KernelDialer::with_standby_ai(false)` is the previous one-carrier behaviour (the default is on).
