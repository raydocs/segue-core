# Ported upstream outbound, Mux, routing, DNS and SOCKS fixes

- A SOCKS inbound gives a client its `handshake` timeout once, from the
  moment it connects. A client that sent its first byte just before the
  timeout used to get a second full timeout for the rest of the handshake,
  so a slow or stalled client could hold the connection for nearly twice as
  long; SOCKS 4 and HTTP on the SOCKS port had the same gap. Xray-core waits
  for the first byte without any limit. (upstream `bb0e8269`)
- `UDP ASSOCIATE` on a SOCKS inbound that listens on `::` with
  `allowUnauthenticatedLan` now works for IPv4 clients. The relay was bound
  to `::1` for them and the reply sent them there, where an IPv4 client
  cannot reach it. Like Xray-core, the relay now binds the IP the client
  connected to, in its IPv4 form for an IPv4 client, and a LAN client of a
  `0.0.0.0` listener gets a relay on the LAN address instead of on
  `127.0.0.1`. A link-local IPv6 control address keeps its scope id.
  (upstream `bb0e8269`, `71e5142e`)
- Another local process can no longer push a SOCKS client's UDP flows out
  of its association. Without a password, any sender's datagrams opened
  flows in it, and 128 targets were enough to evict the client's own. The
  association is now pinned as in Xray-core: to the endpoint the client
  declared, or to its TCP connection's IP and the port of its first
  datagram, and datagrams from anyone else are dropped. (upstream `053e7a04`)
- The SOCKS inbound's `ip` setting takes effect: the `UDP ASSOCIATE` relay
  binds that address and the reply names it, as in Xray-core. It was
  accepted and ignored before. A domain is refused, since Xray-core fails on
  it, and so is an address outside loopback unless `allowUnauthenticatedLan`
  is set. (upstream `053e7a04`)
- A VLESS UDP flow and a VLESS Mux connection send their request header
  together with the first XUDP or Mux frame, as a TCP flow already did and
  as Xray-core sends every request. The header used to go out on its own, so
  over TLS or REALITY the first record had a fixed, header-only size. With
  no frame within 500 ms the header goes alone, Vision padding it with an
  empty frame, as for TCP. (upstream `d130f49c`, `71e5142e`)
- VMess and Shadowsocks outbounds send their request header together with
  the first client payload, as Xray-core does and as VLESS and Trojan
  already did. The header used to go out on its own, so over TLS or REALITY
  the first record had a fixed, header-only size. With no payload the header
  goes alone after Xray-core's wait: 100 ms for VMess, on TCP, UDP and
  Mux/XUDP alike, and for the classic AEAD methods; none for Shadowsocks
  2022, which takes only a payload that is already there. A VMess
  `chacha20-poly1305` flow over plain TCP still sends its header eagerly.
  (upstream `32ff57aa`)
- A Mux child keeps the data it received before the server's End. An End
  carrying the error flag, or arriving while the child still had uplink data
  to send, used to fail the child at once, dropping up to 64 KiB of the
  response already queued and ending the read with an error. As in
  Xray-core's client, which closes the session's output gracefully whatever
  the flag, the reader now gets every queued byte and then EOF. Writes after
  the End fail at once, so a caller that frames its response itself and
  stops before EOF no longer hangs on its next write. (upstream `46857b63`,
  `e29add47`)
- A Mux open that fits on an existing parent no longer waits for another
  open's cold connect to a new parent. A slow or unreachable server used to
  hold every new flow of the outbound behind that dial, each spending its
  own handshake timeout there. Xray-core dials a new Mux connection in the
  background. (upstream `46857b63`)
- Routing parity with Xray-core, three corrections:
  - With sniffing `routeOnly`, rules see the original destination IP as well
    as the sniffed domain, as Xray-core keeps `ob.Target` beside
    `ob.RouteTarget`. An `ip` or `geoip` rule, such as `geoip:private` to
    `direct`, used to miss such a flow because routing saw only the domain.
    Under `IPOnDemand`, a failed lookup falls back to that IP. A fake IP
    still routes and dials by its domain. This covers SOCKS, HTTP and
    reverse sessions and TUN UDP; TUN TCP still routes a real IP by the IP
    alone. A loopback outbound routes such a flow again by both the domain
    and the IP; it used to see only the IP. (upstream `4886a7ec`, `95907603`)
  - A balancer whose strategy picks no member and that has no `fallbackTag`
    sends the connection to the default outbound, as Xray-core's dispatcher
    does, instead of failing it. A `fallbackTag` that names no outbound still
    fails. `random` and `roundRobin` skip unhealthy members only when the
    balancer has a `fallbackTag`, as in Xray-core; without one they keep
    picking among all members and no longer fail when every member is
    unhealthy. (upstream `4886a7ec`, `95907603`)
  - In one `ip` list, negated CIDRs and negated GeoIP codes (including
    `geoip:private`) are two matchers ORed together, as in Xray-core's
    `buildOptimizedIPMatcher`. `["!10.0.0.0/8", "!geoip:cn"]` used to match
    only an address outside both. (upstream `4886a7ec`)
- A MASQUE HTTP/2 dial that is abandoned while it waits for the response, as
  a Happy Eyeballs loser or a cancelled flow is, stops its connection driver
  and keepalive at once instead of leaving the keepalive until its next PING
  fails, up to 45 s later. (upstream `5d1173ad`)
- A DNS query sent over a carrier that can lose a datagram (SOCKS's UDP
  relay, Shadowsocks UDP outside Mux, Hysteria, WireGuard and MASQUE) goes
  out again every second until its answer comes or the server's time is
  over. One lost datagram used to fail the lookup after four seconds for
  every lookup of the name that had joined it. The resolver inside a
  WireGuard or MASQUE tunnel does the same; a stream carrier is sent the
  query once, as before. (upstream `8558001d`)
- A DNS exchange past the managed resolver's operation cap now waits for a
  place, for as long as its lookup's deadline allows, in a queue of four
  waiters per place, instead of being refused at once and answered with
  SERVFAIL. Past that queue it is still refused. (upstream `4759382a`)
- A Hysteria connect attempt to the last of the server's addresses, the only
  one for a server with one address, gets what is left of the dial's ten
  seconds, at most eight, where every attempt had three. Quinn's first probe
  timeout is a second against quic-go's 300 ms, so three seconds carried two
  Initials where Xray-core's client sends four or five, and a slow or lossy
  mobile path failed to connect where Xray-core connected. Attempts with
  further addresses waiting keep three seconds each. (upstream `3d0864d0`)
