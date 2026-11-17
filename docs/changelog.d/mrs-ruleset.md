- Routing rules can name a local mihomo binary rule-set with `ext-mrs:<path>`
  in `domain` or `ip` (not both, and not together with `ext-srs:` on the other
  field). The path is resolved like `ext:` geodata: relative to a configured
  geodata directory, with no absolute path, `..` or symbolic link. There is no
  remote download. Version 1 is read.
- Behaviour `domain` lowers the succinct domain set into the same matchers as a
  sing-box rule-set: an exact name, a `+.` name (the name and its subdomains),
  a leading-dot suffix (subdomains but not the apex) and `*` as one label.
  Behaviour `ipcidr` lowers the sorted address ranges, IPv4 stored IPv4-mapped,
  into CIDRs. `classical` is rejected; mihomo does not store it in `.mrs`.
- The file is one zstd frame, decoded with the pure-Rust `ruzstd` crate so iOS
  and Android builds do not link libzstd for this path. The file and the
  inflated bytes are capped at 128 MiB. A set that lowers to nothing matches
  nothing, rather than every connection.
