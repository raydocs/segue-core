# AI destinations for the lock

Retrieved **2026-11-17**. Public docs, DNS (`dig` against resolver `100.100.100.100`), WHOIS/RDAP, the Codex tree `openai/codex` @ `b8f6787e95a5006d91bc712f59d72af32ef9b205` (2026-11-17), Gemini CLI `google-gemini/gemini-cli` @ `2fd679bbfb4d2005031d9bef810afa6c1740bef6`, and the npm metadata for `@anthropic-ai/claude-code` **2.1.326**. Nothing was logged in. The Claude Code tarball was not executed. Client API keys, a Codex Statsig client key, a Sentry DSN, and a Gemini installed-app OAuth secret are in those trees and are **not** copied here.

The kernel list is `crates/segue-kernel/data/ai-lock.txt` (`suffix` / `cidr`, `#` comments). A suffix matches that name and every subdomain (`segue_policy::suffix_match`). A parent such as `googleapis.com` or `github.com` is never used: it would pin unrelated apps. A full hostname is used when the parent is shared (S3, Azure Web PubSub, one Sentry org).

CIDRs are destination matches. They are added only when the vendor publishes them **and** the block is that vendor's allocation, not a shared CDN or cloud. One vendor publishes client destinations that pass that test: Anthropic's inbound ranges.

## Anthropic (Claude apps, Claude Code, API, console)

### Hosts

Claude Code's required-URL table, [Enterprise network configuration](https://code.claude.com/docs/en/network-config) (fetched 2026-11-17; `docs.claude.com` 301s here):

| URL | What it is | In the list? |
| --- | --- | --- |
| `api.anthropic.com` | API, WebFetch safety check, feature flags, telemetry events | `anthropic.com` |
| `claude.ai` | claude.ai sign-in | `claude.ai` |
| `claude.com` | Sign-in page that redirects to `claude.ai`; doc fetches | `claude.com` |
| `platform.claude.com` | Console auth. OAuth token exchange, refresh, and revoke for claude.ai accounts too | `claude.com` |
| `sso.claude.com` | SSO sign-in | `claude.com` |
| `mcp-proxy.anthropic.com` | claude.ai MCP connectors | `anthropic.com` |
| `downloads.claude.ai` | Native installer, auto-update, plugin binaries | `claude.ai` |
| `bridge.claudeusercontent.com` | Claude in Chrome websocket | `claudeusercontent.com` |
| `*.frame.claudeusercontent.com` | Artifact file reads | `claudeusercontent.com` |
| `assets-proxy.anthropic.com` and other `*.claudeusercontent.com` | Desktop and claude.ai app code and user content. Blocking these with `claude.ai` allowed yields a blank page | both suffixes |
| `*.claudemcpcontent.com` | MCP App widgets inside a conversation | `claudemcpcontent.com` |
| `code.claude.com` | Docs lookups | `claude.com` |
| `support.claude.com` | Support (named on the Desktop page) | `claude.com` |

Same page, **not** listed, because the name is shared:

- `storage.googleapis.com` — plugin install counts; native updater before 2.1.116.
- `registry.npmjs.org` — npm/bun installs and plugin dependencies.
- `github.com`, `raw.githubusercontent.com` — plugin marketplaces and the changelog feed.
- `*-review.googlesource.com` — optional Gerrit lookup.
- `http-intake.logs.us5.datadoghq.com` — optional operational logs. Direct Anthropic API only. Off with `DISABLE_TELEMETRY` or `DO_NOT_TRACK`.
- `browser-intake-us5-datadoghq.com` — optional error reports, behind a server-side gate. Off with `DISABLE_ERROR_REPORTING` or `DISABLE_TELEMETRY`.
- `formulae.brew.sh` — Homebrew version check.
- Artifact font/library hosts: `fonts.googleapis.com`, `fonts.gstatic.com`, `cdnjs.cloudflare.com`, `cdn.jsdelivr.net`, `cdn.tailwindcss.com`, `code.jquery.com`, `unpkg.com`.

`statsig.anthropic.com` is **NXDOMAIN** (SOA `isla.ns.cloudflare.com`, 2026-11-17). The network page says feature flags and telemetry events go to `api.anthropic.com`. Older pages that still require `statsig.anthropic.com` and `sentry.io` are stale. The suffix `anthropic.com` still covers the name if it comes back. `sentry.io` is not listed.

`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` disables both Datadog hosts and the googlesource lookup. It does not remove the API, auth, or user-content hosts.

The npm package `@anthropic-ai/claude-code` 2.1.326 is a 7-file installer stub (`install.cjs`, `cli-wrapper.cjs`). It contains no destination host. The native optional dependency `@anthropic-ai/claude-code-darwin-arm64` is a ~350MB binary and was not downloaded or run. The network page is the vendor allowlist for this version's docs.

Desktop download URLs on [the Desktop page](https://code.claude.com/docs/en/desktop) are paths on `claude.ai` (`/api/desktop/.../latest/redirect`) and `https://claude.com/download`.

### IPs

[IP addresses](https://platform.claude.com/docs/en/api/ip-addresses) (also `https://platform.claude.com/docs/en/api/ip-addresses.md`), fetched 2026-11-17. The page says the addresses will not change without notice, and that they are for firewall rules for the Claude API and Claude Console.

**Inbound** (where Anthropic receives connections — these are client destinations):

- `160.79.104.0/23`
- `153.61.224.0/22`
- `2607:6bc0::/48`

**Outbound** (source addresses of Anthropic's own calls, for example MCP tool calls). Not client destinations. Not in the list:

- `160.79.104.0/21` (contains the inbound `/23` plus `160.79.106.0/23` and `160.79.108.0/22`)
- `153.61.208.0/20` (contains the inbound `/22`)

Claude Tag's [network requirements](https://claude.com/docs/claude-tag/admins/network-requirements) repeat `160.79.104.0/21` as egress and point back at the IP page. Claude Platform on AWS is a different inbound name (`aws-external-anthropic.{region}.api.aws`); that resolves to AWS ranges. Not listed.

**Phased out**, and they are Google Cloud addresses, so they must not be added: `34.162.46.92/32`, `34.162.102.82/32`, `34.162.136.91/32`, `34.162.142.92/32`, `34.162.183.95/32`.

Ownership, 2026-11-17:

- ARIN `NET-160-79-104-0-1`: `160.79.104.0/21`, OrgName Anthropic, PBC (`AP-2440`), direct allocation.
- ARIN `NET6-2607-6BC0-1`: `2607:6bc0::/32`, same org. The published inbound slice is the `/48`.
- APNIC RDAP for `153.61.224.1`: `153.61.0.0/16`, name `AP-2440`, registrant Anthropic, PBC.

DNS the same day (A / AAAA, no CNAME) for `api.anthropic.com`, `console.anthropic.com`, `claude.ai`, `claude.com`, `platform.claude.com`, `sso.claude.com`, `mcp-proxy.anthropic.com`, `assets-proxy.anthropic.com`, `code.claude.com`, `support.claude.com`, `bridge.claudeusercontent.com`, and `www.claudemcpcontent.com`: **`160.79.104.10`** and **`2607:6bc0::10`**. Both sit in the published inbound ranges. `claudeusercontent.com` was the same v4 address. `claudemcpcontent.com` (the apex) had no A; `www` did.

`downloads.claude.ai` was **not** in those ranges: `35.190.46.17` and `2600:1901:0:b25e::` (Google). The suffix still matches the name. An IP literal to that Google address, with no SNI, is not locked. That is intentional.

`anthropic.com` is served by Cloudflare **nameservers** (`isla.ns.cloudflare.com`, `randy.ns.cloudflare.com`). That is DNS hosting. The A/AAAA records above are Anthropic's own addresses, not Cloudflare proxy space (`104.16.0.0/12`, `172.64.0.0/13`, `162.159.0.0/16`, `2606:4700::/32`). CIDR blocking of the three inbound prefixes does not drag other Cloudflare customers.

The list ships the three inbound prefixes only. It does not ship the rest of the ARIN `/21`, the APNIC `/16`, or the v6 `/32`. Those larger blocks are either documented as outbound source space or simply not published as client destinations.

The customer [IP allowlist](https://support.claude.com/en/articles/13200993-restrict-access-to-claude-with-ip-allowlisting) is the opposite direction (which sources may call Claude). It is not a destination list.

## OpenAI (ChatGPT, Codex, API, auth)

### Hosts Codex actually calls

From `openai/codex` @ `b8f6787e` (sparse checkout of `codex-rs/{login,chatgpt,core/src,analytics,model-provider,model-provider-info,codex-api,backend-client,otel,feedback}`):

| Host | Where | In the list? |
| --- | --- | --- |
| `chatgpt.com` | `CHATGPT_CODEX_BASE_URL` = `https://chatgpt.com/backend-api/codex` (`codex-rs/model-provider-info/src/lib.rs`) | `chatgpt.com` |
| `api.openai.com` | API-key default `https://api.openai.com/v1` | `openai.com` |
| `auth.openai.com` | Issuer, `https://auth.openai.com/oauth/token`, revoke, `https://auth.openai.com/api/accounts` (`codex-rs/login`) | `openai.com` |
| `ab.chatgpt.com` | Built-in metrics: `https://ab.chatgpt.com/otlp/v1/metrics` (`codex-rs/otel/src/config.rs`). Statsig is reached through this OpenAI host, not `statsigapi.net` | `chatgpt.com` |
| `o33249.ingest.us.sentry.io` | Feedback upload DSN host (`codex-rs/feedback/src/lib.rs`). One Sentry org | that exact suffix |
| `platform.openai.com`, `chat.openai.com`, `us.api.openai.com`, `eu.api.openai.com`, `gov.chatgpt.com`, `gov.api.openai.com` | Present as production-shaped names | `openai.com` or `chatgpt.com` |

Staging, recognized by `validate_runtime_environment` and **not** listed: `auth.api.openai.org`, `api.openai.org`, `api.openai-staging.com`, `chatgpt-staging.com` (and `api.chatgpt-staging.com`, `workspace.chatgpt-staging.com`). `platform.api.openai.org` is the staging success-page check in `codex-rs/login`.

Already in the list from the web app, not from this CLI tree: `oaistatic.com` (static assets in the logged-in session), `oaiusercontent.com` (user files).

Codex does not hardcode `statsigapi.net`, `featureassets.org`, Datadog, or Segment. `mcp.sentry.dev` appears only as an example MCP server in a config test.

### IPs

[IP egress ranges](https://developers.openai.com/api/docs/guides/ip-addresses) publishes JSON of **source** addresses OpenAI uses when it calls you, not addresses clients dial:

- ChatGPT integrations and Private Safety Processing: `https://openai.com/chatgpt-connectors.json` (`creationTime` `2026-11-06T18:26:55.215535`, 289 prefixes on that fetch).
- Codex cloud: `https://openai.com/chatgpt-agents.json`.

Those prefixes are not destinations. They are not in the list. [IP allowlist](https://developers.openai.com/api/docs/guides/ip-allowlist) is the customer's own source allowlist for calls **to** `api.openai.com`.

DNS, 2026-11-17:

| Name | Result |
| --- | --- |
| `api.openai.com` | `172.66.0.243`, `162.159.140.245`, `2606:4700:7::f3`, `2a06:98c1:58::f3` (Cloudflare) |
| `auth.openai.com` | CNAME `auth.openai.com.cdn.cloudflare.net`, then `104.18.41.241`, `172.64.146.15` |
| `chatgpt.com`, `ab.chatgpt.com` | `104.18.32.47`, `172.64.155.209` |
| `cdn.oaistatic.com`, `files.oaiusercontent.com` | Cloudflare `104.18.*` / `172.64.*` |

`openai.com` NS is Azure DNS (`ns1-02.azure-dns.com` and siblings). HTTP is Cloudflare. A Cloudflare CIDR would pin every other tenant. No OpenAI CIDR is shipped. `104.18.32.47` is asserted **not** to match the built-in list.

## Cursor

[Network configuration](https://cursor.com/docs/enterprise/network-configuration), fetched 2026-11-17. The page says not to keep an IP list ("Rather than maintaining IP address lists (which can change)") and gives domain patterns: `*.cursor.sh`, `*.cursor-cdn.com`, `*.cursorapi.com`, `*.cursorvm.com`, `*.*.cursorvm.com`, plus `cursor.com` and `*.cursor.com`. A suffix covers nested names, so `cursorvm.com` is enough for both cursorvm patterns (Grok Bot uses nested hostnames).

Granular hosts on that page, all under those suffixes unless noted:

- API: `api2.cursor.sh` (most requests; connectivity test), `api5.cursor.sh` (agent and network-access layer) and `agent.api5.cursor.sh`, `agentn.api5.cursor.sh`, `agent.us.api5.cursor.sh`, `agentn.us.api5.cursor.sh`, `agent.global.api5.cursor.sh`, `agentn.global.api5.cursor.sh`.
- Tab / index: `api3.cursor.sh`, `repo42.cursor.sh`, `api4.cursor.sh`, `us-asia.gcpp.cursor.sh`, `us-eu.gcpp.cursor.sh`, `us-only.gcpp.cursor.sh`. HTTP/2 only.
- SSO: `adminportal42.cursor.sh`. Auth: `authenticate.cursor.sh`, `authenticator.cursor.sh`, `prod.authentication.cursor.sh`, `authentication.cursor.sh`.
- Updates and marketplace: `marketplace.cursorapi.com`, `cursor-cdn.com`, `downloads.cursor.com`, `anysphere-binaries.s3.us-east-1.amazonaws.com`, `cursor.blob.core.windows.net`.
- Agent file sync: `agent-stores.s3.us-east-1.amazonaws.com`, `agent-stores.s3.amazonaws.com`.

The S3 and Azure names are full-host suffixes. `amazonaws.com` and `windows.net` are not.

Sign-in, [Which domains does Cursor sign-in need?](https://cursor.com/help/troubleshooting/sign-in-domains), same day: sign-in is moving to `accounts.spacexsi.com`, replacing `authenticator.cursor.sh`. The fallback is "retired on November 30"; the page does not give the year (the next November 30 after this retrieval is 2026). Minimum hosts: `accounts.spacexsi.com`, `auth.grok.com`, `auth.grokusercontent.com`, `auth.grokipedia.com`. Wildcards they recommend: `*.spacexsi.com`, `*.grok.com`, `*.grokusercontent.com`, `*.grokipedia.com`. The network page also names `accounts.spacex.ai` and `accounts.x.ai` and says to exclude them from TLS inspection. `authenticator.cursor.sh` stays as the fallback, under `cursor.sh`.

DNS the same day: `api2.cursor.sh` → `api2geo.cursor.sh` → `api2direct.cursor.sh` → `3.92.129.183`, `34.225.159.174`, `52.21.130.202` (shared AWS). `cursor.com` and `cursor.sh` → `76.76.21.21` (Vercel anycast). `authenticator.cursor.sh` → WorkOS (`*.workosdns.com`) → Cloudflare `172.64.152.23`, `104.18.35.233`. No Cursor CIDR.

## GitHub Copilot

[Copilot allowlist reference](https://docs.github.com/copilot/reference/copilot-allowlist-reference), fetched 2026-11-17. No "last updated" on the page. The IDE list and the cloud-agent firewall list are on the same page; the agent firewall (Ubuntu archives, Maven, npm, Playwright CDNs, and similar) is **not** the user's Copilot account and is not listed.

Listed, because the hostname is Copilot-specific:

- `githubcopilot.com` — covers `api.githubcopilot.com`, `*.individual.githubcopilot.com`, `*.business.githubcopilot.com`, `*.enterprise.githubcopilot.com`.
- `copilot-proxy.githubusercontent.com`, `origin-tracker.githubusercontent.com`, `copilot-telemetry.githubusercontent.com`.
- `copilot-reports.github.com`.
- The seven Web PubSub hosts named on the page: `production-copilot-host.webpubsub.azure.com`, `production-copilot-host-centralus.webpubsub.azure.com`, `production-copilot-host-centralus-02.webpubsub.azure.com`, `production-copilot-host-eastasia.webpubsub.azure.com`, `production-copilot-host-austriaeast.webpubsub.azure.com`, `production-copilot-host-westus.webpubsub.azure.com`, `production-copilot-host-westus3.webpubsub.azure.com`. Not `*.webpubsub.azure.com`.

Not listed:

- `github.com`, `api.github.com`, `github.githubassets.com`, `avatars.githubusercontent.com`, `raw.githubusercontent.com`, `objects.githubusercontent.com`. Copilot OAuth and `/copilot/*` on `github.com` cannot be separated from the rest of GitHub by a suffix. This is the Copilot gap.
- `collector.github.com` — on the Copilot telemetry list, also used by GitHub itself.
- `default.exp-tas.com` — shared Microsoft experimentation. The page says it is not used on GHE.com.
- `copilot-reports-*.b01.azurefd.net`, `usagereports*.blob.core.windows.net`, `ai.azure.com`, `*.api.azureml.ms`, `amlwlrt4*.blob.core.windows.net`. The wildcards are shared Azure. The list has no glob.

DNS: `api.githubcopilot.com` CNAMEs to a `*.github.com` GLB (`140.82.114.22` in this lookup). That address is GitHub's edge, shared with `github.com`. `copilot-proxy.githubusercontent.com` was `138.91.182.224` (Azure). No Copilot CIDR.

## Google Gemini and Gemini CLI

No vendor page publishes a Gemini-only destination prefix. Google's published ranges are all of Google. DNS for `generativelanguage.googleapis.com`, `cloudcode-pa.googleapis.com`, and `gemini.google.com` was Google anycast (`172.217.*`, `142.251.*`). No Gemini CIDR.

From Gemini CLI @ `2fd679bb` (files under `packages/core/src/code_assist/` and `packages/core/src/core/contentGenerator.ts`, `packages/core/src/telemetry/`, `packages/cli/src/ui/utils/updateCheck.ts`):

| Host | Role | In the list? |
| --- | --- | --- |
| `cloudcode-pa.googleapis.com` | `CODE_ASSIST_ENDPOINT`. OAuth / "login with Google" model traffic (`v1internal`) | yes |
| Google GenAI SDK default | API-key mode constructs `GoogleGenAI` with no `baseUrl` unless `GOOGLE_GEMINI_BASE_URL` is set. The SDK README's endpoint table lists `generativelanguage.googleapis.com` for that path ([googleapis/js-genai](https://github.com/googleapis/js-genai), README on main, fetched 2026-11-17; npm `@google/genai` 3.4.0 the same day) | `generativelanguage.googleapis.com` |
| `aiplatform.us.rep.googleapis.com`, `aiplatform.eu.rep.googleapis.com` | Vertex only, when `GOOGLE_CLOUD_LOCATION` is `us` or `eu` | no — shared Vertex |
| `codeassist.google.com` | OAuth redirect `https://codeassist.google.com/authcode` | yes |
| `https://www.googleapis.com/oauth2/v2/userinfo` | Profile after login | no — `www.googleapis.com` is shared |
| `play.googleapis.com` | Clearcut: `https://play.googleapis.com/log?format=json&hasfast=true` | no — shared with Play |
| `accounts.google.com`, `oauth2.googleapis.com` | `google-auth-library` installed-app OAuth | no — every Google login |
| `registry.npmjs.org` | `latest-version` update check | no |
| `developers.google.com` | Static success/failure page after OAuth | no |

Also listed, as the consumer and console names, neither of which is a shared parent: `gemini.google.com`, `aistudio.google.com`.

The OAuth client id and secret in `oauth2.ts` are not recorded here.

## xAI / Grok

[Regions](https://docs.x.ai/developers/regions) publishes no CIDR. Hosts named in the API docs and on the Cursor sign-in page:

- `api.x.ai`, regional `us.api.x.ai` (and `<region>.api.x.ai`) — inference. Covered by `x.ai`.
- `management-api.x.ai`, `console.x.ai`, `accounts.x.ai`, `auth.x.ai` — covered by `x.ai`.
- `grok.com`, `auth.grok.com` — `grok.com`.
- `grokusercontent.com`, `grokipedia.com` — their own suffixes. Cursor's sign-in page says Grokipedia shares Grok accounts.

DNS: `api.x.ai`, `console.x.ai`, and `grok.com` were Cloudflare (`104.18.*`). `x.com` is not listed (the whole X network). No xAI CIDR.

## What is CDN-fronted

| Vendor | Client destinations on a shared edge? | CIDR in the list |
| --- | --- | --- |
| Anthropic API, console, claude.ai, claude.com, user-content hosts checked above | No. Own addresses inside the published inbound ranges. DNS is hosted at Cloudflare; HTTP is not proxied there | The three inbound prefixes |
| `downloads.claude.ai` | Yes, Google | No |
| OpenAI (`api`, `auth`, `chatgpt.com`, static, user content) | Yes, Cloudflare | No |
| Cursor API | Shared AWS. Marketing/docs on Vercel. Auth UI on Cloudflare via WorkOS | No. Vendor says not to pin IPs |
| Copilot API | GitHub's own edge, shared with github.com; proxy host on Azure | No |
| Gemini | Google anycast | No |
| xAI / Grok | Cloudflare | No |

## Still needs a packet capture on a real Mac

Do this signed in, on the machine that has the apps. Passive only: no TLS intercept, no proxy CA, no account export. A pcap contains SNI and destination IPs; do not commit it.

One app at a time, quit the others so the capture is that process. Replace the pid.

```sh
# Destination IPs of established TLS, while you send one prompt and open settings.
sudo lsof -nP -iTCP:443 -sTCP:ESTABLISHED -a -p PID

# 60 seconds of client hellos. SNI only; payloads stay encrypted.
sudo tcpdump -i any -n -s 256 -w /tmp/ai-lock.pcap -c 2000 'tcp port 443 and host not 127.0.0.1'
# If tshark is installed:
tshark -r /tmp/ai-lock.pcap -Y tls.handshake.extensions_server_name \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name | sort -u

# QUIC (UDP 443) will not show SNI once ECH is on. Record the peers anyway.
sudo tcpdump -i any -n -c 200 'udp port 443'

# DNS names the process asks for. Run during a cold start.
sudo tcpdump -i any -n -c 100 'port 53'
```

Repeat for: Claude Desktop, `claude` (Claude Code 2.1.x, one prompt and one `/login` if already signed in), ChatGPT, `codex`, and if those products are in scope Cursor, VS Code with Copilot, `gemini`, and Grok. Cold start matters more than a warm prompt: updates, feature flags, and crash reporters fire then.

Check the output against the list. In particular:

- Any Claude Code host other than the network-config table (the native binary was not strings-scanned).
- `downloads.claude.ai` and whether its Google address is stable.
- ChatGPT or Codex names outside `openai.com`, `chatgpt.com`, `oaistatic.com`, `oaiusercontent.com`, and `o33249.ingest.us.sentry.io` (candidates people hit that this tree did not: `chat.com`, `sora.com`).
- Whether `collector.github.com` or `default.exp-tas.com` fires only from Copilot.
- Gemini CLI actually dialing `generativelanguage.googleapis.com` on the API-key path, and whether Clearcut is the only telemetry host.
- Cursor sign-in after the November 30 fallback ends: confirm `accounts.spacexsi.com` and that `authenticator.cursor.sh` is gone.
- Whether `153.61.224.0/22` is ever a destination. It was published and unused by every name resolved here.

`sudo rm /tmp/ai-lock.pcap` when finished.
