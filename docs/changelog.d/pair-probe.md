**Testing**

- `segue-bench pairprobe` measures whether two flows between the same hosts lose packets together. The server echoes UDP datagrams and length-prefixed TCP records and stops after `--max-seconds` (default 15 minutes) or `--max-bytes` (default 64 MiB). The client sends at most 200 probes/s of at most 1200 bytes and reports per-flow loss, burst length, and the chance that flow k is lost given that flow 0 was lost 0–500 ms earlier.
