- An mKCP connection on its own UDP socket, plain or introduced by `realm`,
  is put to the test when the host reports that the OS network changed,
  through the same request (`xray_core_rebind_hysteria`, `Core::rebind_quic`)
  that moves the QUIC carriers. Xray-core's mKCP server tells sessions apart
  by the client's address, port and conversation, so the session cannot
  move: the connection fails with `NetworkDown` at once if its datagrams now
  leave from another address than at the dial, and otherwise unless its
  server is heard within three seconds when segments are unacknowledged,
  fourteen when it is idle. Its flows end and the next flow dials a new
  connection; until now it sat out the 30-second dead-link timeout first. A
  connection that keeps its address and whose server still answers stays.
  The request's count includes these connections. mKCP over `xdns` or
  `xicmp` is left alone. Xray-core has no counterpart. Upstream commits
  `3eb92e35`, `579b752f`, `5cfcbffc` and `a0cbfbc3`.
- The `xicmp` mask works inside an Apple Network Extension. The client
  connected its ICMP sockets to the server, and XNU leaves a connected ICMP
  socket's local address empty, where connecting a UDP socket fills it in.
  Inside the extension such a flow matches the tunnel's policy, and NECP
  defuncts a connected socket with that result: on an iPhone each socket
  dialed while the tunnel came up, the first connection's among them, failed
  every send after its first echo request with `EPIPE` and read nothing, so
  mKCP over xicmp failed at its first exchange, while the macOS CLI and
  Android worked against the same server. On Apple systems the client's
  sockets are now bound to the wildcard and left unconnected, as Xray-core's
  are, and keep the replies from their server's address; where the bind is
  refused they are connected as before. Each also takes the interface the
  system scopes a UDP socket of the process to on its way to the same
  address, and asks again at most once a second while it sends, so it moves
  between Wi-Fi and cellular; Xray-core's server knows the client by its id
  and answers its latest address. Outside a Network Extension the system
  scopes no UDP socket and the socket stays unbound, and `sockopt.interface`
  still binds it. Android and Linux behave as before. Upstream commits
  `9870b64e` and `35681380`.
- After `Endpoint::rebind`, Quinn keeps reading the socket a connection moved
  away from for three seconds after the first packet on the new one, and
  comes back to it when the work limiter ended its poll with datagrams left.
  A peer's datagrams for the old path arrive after its first one for the new
  path whenever the old path is the slower one, and QUIC sends a DATAGRAM
  frame once: a MASQUE tunnel lost the answers that were in flight at the
  change, and a DNS lookup among them failed. Hysteria's UDP goes through the
  same sockets; XHTTP H3 retransmits its streams and lost only time. Upstream
  commit `07c8d874`.
- A system DNS lookup no longer holds `xray_core_free`. The lookup ran
  `getaddrinfo`, which cannot be cancelled, on the runtime's blocking pool,
  and freeing a handle waits for the handle's runtime, so a host stopping or
  restarting its tunnel on a network that had gone away could hang until the
  lookup gave up. The lookup now runs on a thread of its own, at most 64 at
  once: one still in flight finishes by itself after the call returns and
  calls no host callback. `xray_core_free` goes on waiting for the runtime's
  threads without a limit, so none of them is inside the socket-protect
  callback once it returns. Only a core that asks the system resolver was
  affected, as under the default `XRAY_DNS_BOOTSTRAP_MODE_SYSTEM`. Upstream
  commits `3079cddf` and `fad2f562`.
