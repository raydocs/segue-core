- `segue-kernel` process mode takes `SIGTERM` and `SIGINT`, flushes the
  fake-IP journal, deletes the control token and exits 0. `--state-dir` is
  the runtime directory for the token, the fake-IP journal and
  `policy.installed`; `--log` appends the same lines as stderr (mode 0600).
  Exit codes are 0 clean, 1 runtime, 2 usage, 3 config or state path, 4 tun
  setup (`docs/design/app/macos.md` appendix). Not an upstream port.
- macOS `segue-kernel run` with a `tun` object opens a utun
  (`com.apple.net.utun_control`), sets its address and MTU, and installs
  split default routes (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`)
  through a `PF_ROUTE` socket. Exit addresses are host routes via the
  physical gateway (`RTF_IFSCOPE`), installed first. Direct dials use
  `IP_BOUND_IF` on that interface; domestic DNS sockets do too. The utun fd
  is the existing Darwin packet pump. Routes are removed on every exit,
  including setup failure. `GET /v1/status` reports `tun.interface` and
  `tun.routes`. `/sbin/route` is not used: the message layout is the one
  sing-tun writes, and it can be checked without root.
