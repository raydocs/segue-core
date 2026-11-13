# Real-utun lab for the TUN stack (macOS, needs sudo)

The unit and integration tests (`cargo test -p segue-kernel`) drive the TUN
stack with synthetic packets. This lab runs the same `TunStack::for_kernel`
on a real `utun` device so the macOS IP stack, curl, dig and Python sockets
talk to it. Nothing leaves the Mac:

```
curl/dig/python ─► route 198.51.100.0/24, 198.18.0.0/15, 192.0.2.53 ─► utunN
   ─► segue TunStack (smoltcp, pooled buffers, policy rules, sniff, fake-IP, smart DNS)
      TCP  ─► LabDialer ─► http.server 127.0.0.1:8099 (loopback, any tag)
      UDP  ─► LabDialer::dial_udp ─► in-process echo ("echo:" prefix)
      :53  ─► SmartDns (fake-IP answers from 198.18.0.0/15)
```

Lab rules (inline policy): `openai.com` → `ai` (refused for UDP like a Home
route), `blocked.test` → reject, `198.51.100.200` → reject,
`198.51.100.201` → `broken` (the lab dialer fails it), default → `lab`.

Run: `./run.sh` (builds `crates/segue-kernel/examples/tun_lab.rs`, asks for
sudo) → `out/result.txt`, stack log `out/tun.log` (one `DIAL` line per dial),
check output `out/checks.log`. The script removes its routes and stops the
stack on exit. Needs `curl`, `dig`, `python3`.

Checks: 1 MiB fetch via bare IP with sha256 match; sniffed HTTP Host routes a
bare IP by name (D8); IP reject refused at SYN and never dialled; failed
proxy reset once, never direct; UDP and TCP DNS hijack answer with the same
fake-IP and the fake-IP is dialled by name; UDP echoed via `dial_udp`; UDP
to the Home route answered with ICMP and never dialled; oversize DF UDP gets
ICMP frag-needed (the route MTU drops to 1500, so `send` fails EMSGSIZE).

Not yet run: needs the owner's sudo. No results are claimed here.
