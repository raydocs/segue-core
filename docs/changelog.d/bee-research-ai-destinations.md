- AI lock destinations, checked 2026-11-17 against vendor docs and the
  Codex and Gemini CLI trees (`docs/research/ai-destinations.md`). The
  built-in list adds the account-bearing names those clients actually use
  (Claude user-content hosts, Cursor, Copilot's own hosts, Gemini's own
  hosts, xAI/Grok, and Codex's Sentry org host) and Anthropic's published
  inbound prefixes `160.79.104.0/23`, `153.61.224.0/22`, `2607:6bc0::/48`.
  Those prefixes are Anthropic, PBC allocations, not a CDN. OpenAI's
  published ranges are egress, and OpenAI, Cursor, Copilot, Gemini, and
  xAI terminate on shared edges, so they still have no CIDR. Shared
  telemetry and login front doors (Sentry, Datadog, Statsig SaaS,
  `github.com`, `accounts.google.com`, Cloudflare) stay off the list.
  This replaces the "no client-facing CIDR" note in
  `docs/changelog.d/ai-lock-kernel.md`.
