- **Profile import.** `segue import <file> [--format clash|singbox] [-o out.json]` converts
  Clash/mihomo YAML and sing-box JSON profiles into Segue's Xray-style JSON, also exposed as
  `segue_config::import::import_profile`. Proxies/outbounds (VLESS incl. REALITY and Vision,
  VMess, Trojan, Shadowsocks 2022 and AEAD, Hysteria 2, WireGuard, AnyTLS, SOCKS, HTTP),
  transports (raw, ws, grpc, httpupgrade, xhttp), TLS/REALITY/ALPN/fingerprint, proxy groups
  (select/url-test/fallback/load-balance) as balancers plus an observatory, rules
  (DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR(6), GEOIP, GEOSITE, MATCH,
  port rules) and DNS (servers, fake-IP range and filters) are carried. Every field that
  cannot be expressed — TUIC, Shadowsocks plugins, process rules, remote or non-`.srs`
  rule-sets, `skip-cert-verify` — is reported as a warning naming its source path. The
  converted output is run through the parser before it is returned, so a profile Segue would
  refuse fails at import time.
