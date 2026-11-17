- `segue-kernel` process mode takes `SIGTERM` and `SIGINT`, flushes the
  fake-IP journal, deletes the control token and exits 0. `--state-dir` is
  the runtime directory for the token, the fake-IP journal and
  `policy.installed`; `--log` appends the same lines as stderr (mode 0600).
  Exit codes are 0 clean, 1 runtime, 2 usage, 3 config or state path, 4 tun
  setup (`docs/design/app/macos.md` appendix). Not an upstream port.
