**Bench**

- A one-shot TUN benchmark, `scripts/bench/tun-bench-macos.sh`, compares segue-kernel, sing-box 1.15.0-alpha.13 (`824dbcfb`) and mihomo (`3c0d10a`, system and mixed stacks) on a throwaway macOS VM. The workload dials 198.51.100.20 through the engine's TUN; an Xray-core v26.11.9 fixture redirects that flow to a local sink, and dummynet on lo0 impairs only the carrier port. It refuses unless `SEGUE_VM_BENCH=throwaway`, the host is a VM and the process is root. `--dry-run` prints the plan and does not change routes.
