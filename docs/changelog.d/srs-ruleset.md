- Routing rules can name a local sing-box binary rule-set with `ext-srs:<path>`
  in `domain` or `ip` (not both). The path is resolved like `ext:` geodata:
  relative to a configured geodata directory, with no absolute path, `..` or
  symbolic link. Versions 1–5 are read. There is no remote download.
- A headless rule's destination domains (`domain`, `domain_suffix`,
  `domain_keyword`, `domain_regex`) and `ip_cidr` become the existing domain
  and IP matchers. `network` (`tcp`/`udp`), port, `port_range`, `source_port`,
  `source_port_range` and `source_ip_cidr` are applied too. Rules in the file
  are OR'd; the routing rule's other conditions are AND'd. A suffix written
  with a leading dot (`.com.cn`) matches names that end in it and not the apex,
  which `domain:` would also match.
- Items Segue cannot represent — process, package, wifi, AdGuard domain,
  network type, interface address, query type, invert, and a logical `and` of
  two domain or IP lists — are reported and that rule matches nothing. An empty
  rule, which sing-box would treat as matching every connection, matches
  nothing as well. The file is zlib-decoded as it is read, and both the file
  and the decompressed stream are capped at 128 MiB.
