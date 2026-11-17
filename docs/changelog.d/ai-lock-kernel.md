- AI traffic is pinned to the connected IDC exit. A built-in suffix list
  (`crates/segue-kernel/data/ai-lock.txt`: anthropic.com, claude.ai,
  claude.com, openai.com, chatgpt.com, oaistatic.com, oaiusercontent.com)
  is merged with the signed bundle's `ai_domains` / `ai_cidrs` into a
  first-tier match. It beats every user rule, including direct and GEOIP,
  except an explicit reject. No client-facing CIDRs are shipped; the vendors
  have not published any (TODOs in that file).
- A connection to an AI CIDR, or whose sniffed TLS SNI is an AI name, is
  AI-class. A non-AI SNI cannot steer an AI address onto another proxy.
- DNS for an AI name is fake-IP (A) or an empty NOERROR (AAAA; the pool has
  no v6 range). It is not forwarded to a domestic upstream.
- QUIC and any other UDP to the AI (home) route is refused, so clients fall
  back to TCP.
- Under Auto an AI session pins one exit and may move only inside that
  exit's `egress_group` (optional per exit; absent means the exit alone).
  If that group is down the dial is refused, not failed over. `set_exit`
  replaces the pin. Overseas failover is unchanged.

Audit of the paths this closes: rule order (a forgotten AI name, or a
direct/CN rule, won first-match), IP literals with no domain, domestic DNS
including AAAA, QUIC if the name had been classified direct, Auto moving an
AI flow to another egress (r10), and posture only protecting flows the rule
table had already called AI. `Disconnected` still releases to the OS. The
kernel cannot see packets when it is not running; desktop needs an AI-only
PF/WFP layer and iOS only has `includeAllNetworks`. See `docs/design/ai-lock.md`.
