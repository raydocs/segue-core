**Kernel**

- A tun setup failure is written to `--log` with the failing step, the command or ioctl, and the errno. Other fatal startup errors after the log is open are written there too; they used to reach stderr only, so a helper that reads `--log` saw nothing but the policy lines before exit code 4.
- An exit on loopback, or on an address assigned to a local interface, no longer gets a host route pulling it off the utun. Those addresses are not reached via the default route, and adding the route failed setup when the exit was an alias on the physical NIC (`192.0.2.10` on `en0`, `EEXIST`). `RTM_ADD` reporting that the route already exists is success and the route is left in place.
- A session carrier to `127.0.0.0/8` or `::1` is not bound to the physical NIC, so a kernel session to a segue-relay on loopback completes while `IP_BOUND_IF` is installed.
