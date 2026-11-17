# AI lock

AI traffic (Claude, Claude Code, Codex, ChatGPT, and the hosts in
`crates/segue-kernel/data/ai-lock.txt`) may leave only through the IDC exit
the user is connected to. It must not go direct, and it must not hop to an
exit with a different egress identity. Other traffic keeps working. This is
not a block-everything kill switch.

The kernel enforces that only while it is running and the flow is inside
Segue. What the OS still has to do is at the end.

## What could leak before this

Checked against the rule table, DNS, sniff, UDP and `KernelDialer::pick`
(Auto, "r10 failover").

1. **Rule order.** Signed `ai_domains` / `ai_cidrs` were ordinary rules
   inserted first, so they beat a later user rule. A name the bundle forgot
   (or an inline lab rule) did not. A GEOIP/CN or `direct` rule, or the
   default overseas proxy, then won. An explicit `reject` listed after the
   AI rule never ran, because first-match stopped at the AI proxy rule.
2. **IP literals.** A connection to an AI address with no domain was an IP
   rule or the default. Domain rules do not apply to IP targets. There were
   no built-in CIDRs, and the bundle's `ai_cidrs` are often empty.
3. **DNS.** `classify` followed the rule table. An AI name that was
   `direct` or unmatched was resolved on the domestic (ISP) upstream,
   A and AAAA. The real addresses could then be dialled outside the AI exit.
   Fake-IP covered only names that already had a proxy/reject rule.
4. **UDP/QUIC.** Home / AI routes refuse every UDP datagram
   (`dial_udp`, and `udp.refuse` always contains home tags). QUIC to a real
   IP is dropped (`looks_quic_first`) so the client can fall back to TCP,
   where SNI is sniffed. QUIC to an AI *name* was refused only because the
   name's route was the home tag. A name that had been classified direct
   would have carried QUIC direct.
5. **Auto failover.** `State::pick` is shared by every session route. When
   the exit an AI flow was using went down, the next AI OPEN moved to
   whichever exit had not failed lately — a different egress IP. Overseas
   failover is fine; for AI it is the leak (r10).
6. **Posture.** `Protection::Strict` already refuses an AI *proxy* action in
   `Connecting`, `Reconnecting` and `Error`, and `Disconnected` is `Release`.
   That only helps after the rule table has called the flow AI. A flow that
   matched `direct` was `Direct` in every posture except `Disconnected`.
7. **Startup.** Before the first channel the posture is `Connecting`. A
   strict proxy is `Refuse` at SOCKS/TUN, so it is not sent direct. The
   dialer's one recovery attempt (the retry window elapsed, nothing backing
   off) stays on the pinned exit; it is what brings that exit back. It is
   not a hop.
8. **User disconnect.** `Release`: the tunnel is down and the OS routes.
   The kernel, if it still sees a proxied flow, refuses it
   (`admission` of `Release` on a non-direct action). It does not dial direct.
9. **DoH / ECH.** A client that resolves AI names on its own (DoH to
   1.1.1.1) learns the real addresses. The follow-up TCP flow is AI only if
   the SNI is sniffed or the address is in an AI CIDR. Real ECH hides the
   name; a hidden name to an IP outside `ai_ips` is refused locally, not
   sent overseas. QUIC to that real IP is dropped.

## What the kernel does now

**Tier.** `RuleSet` has an AI tier (suffixes + CIDRs) in front of the user
rules. It matches before any user `direct` or `proxy`, including a GEOIP/CN
CIDR. A user rule that matches with `reject` still wins, even if a broader
allow is listed first. The tier is the built-in list plus the bundle's
existing `ai_domains` / `ai_cidrs`. Those fields are the policy's AI list;
there is no second `ai` object. They are not version-gated: an older bundle
that omits `claude.ai` must still lock it. Omitting the built-in list below
some version would re-open the leak.

The relay's `AiSet` is the signed list only. A name only the kernel locks is
sent to the AI exit; the relay's home whitelist may refuse the session.
That is a failed dial, not a direct connection.

Fail-closed (no bundle, or an expired one) still rejects everything,
built-in names included. Inline lab rules do not get the built-in list;
the product path is the signed bundle.

**IP and SNI.** A connection whose address is in an AI CIDR, or whose
sniffed TLS SNI (or QUIC-shaped TCP ClientHello SNI) is an AI suffix, is
AI-class. A non-AI SNI does not pull an AI address onto another proxy.
`sniffed_route` does this for SOCKS and TUN. No client-facing CIDR is
shipped: Anthropic and OpenAI do not publish the addresses clients dial
(see the TODOs in `data/ai-lock.txt`). An IP literal with no SNI and no
CIDR is still whatever the IP rules say. That is the remaining kernel gap.

**DNS.** An AI name is `Class::Fake`. A is a fake IPv4. AAAA is an empty
NOERROR: the fake-IP pool has no v6 range, so the client uses v4 through
the tunnel. The real AAAA is never returned, and the query is not sent to
a domestic upstream. Other types for that name are empty too.

**QUIC.** The AI route is home-role, so UDP to it is refused on every port,
including 443, in every posture. The client falls back to TCP and is sniffed.

**Exit pin.** Each exit has an optional `egress_group`. Absent means its
own name: it shares an egress with nobody. Under Auto the first AI session
pins the exit `pick` would use then, and stays there. It may move only to
an exit in the same group that is up. If the pin's group is down, the dial
is `Refuse` (Strict) immediately — it does not open on another group.
Naming an exit (`set_exit`) replaces the pin with that exit; switching back
to Auto clears it so the next AI flow pins again. The UNKNOWN_SESSION fresh
OPEN stays on the exit that answered, unless the user changed exit
(`choice_gen`). Overseas failover is unchanged.

The same-exit recovery attempt after `STRICT_RETRY_AFTER` is kept. It does
not change group. Without it an AI-only device could never bring a down
exit back.

## Posture matrix

`Strict` is the AI exit. `Wait` is overseas. DNS does not depend on posture:
if the kernel answers, it does not forward the AI name. QUIC to the AI tag
is refused by the UDP layer even when the kill switch would proxy a TCP flow.

| | Connecting | Connected | Reconnecting | Error | Disconnected |
| --- | --- | --- | --- | --- | --- |
| AI domain / IP literal / SNI | Refuse | Proxy(ai) | Refuse | Refuse | Release |
| AI DNS A | fake v4 | fake v4 | fake v4 | fake v4 | fake v4 |
| AI DNS AAAA | empty NOERROR | empty NOERROR | empty NOERROR | empty NOERROR | empty NOERROR |
| AI QUIC | Refuse | Refuse (no UDP on home) | Refuse | Refuse | Release (kernel still drops it) |
| non-AI direct | Direct | Direct | Direct | Direct | Release |
| non-AI overseas | Wait | Proxy(overseas) | Wait | Refuse | Release |

Invariant: no posture yields `Direct`, or a proxy on a different egress
group, for an AI-class flow, except `Disconnected` (the user turned Segue
off). `posture_matrix_ai_never_goes_direct` and
`ai_auto_does_not_leave_its_egress_group` lock that.

## What the OS layer still has to do

The kernel does not see packets when it is not running, or when the tunnel
is down (`Disconnected`, crash, before the first bind).

- **Desktop.** An AI-only PF (macOS) / WFP (Windows) layer that drops
  outbound AI-name and AI-CIDR traffic except through the tunnel, and does
  not block everything else. It has to be installed while Segue is on and
  removed on a user disconnect. Boot and crash behaviour should follow the
  survey: fail-closed while the process is up, and do not re-arm a leftover
  block across reboot unless the user asked for that.
- **iOS.** The only OS hook that covers "Segue is not the default path" is
  `includeAllNetworks` (and `enforceRoutes` where it exists). There is no
  per-app AI filter that survives the tunnel being down. Until that is on,
  an AI flow can leave direct during the gap the kernel is not capturing.
- **Android.** Always-on / lockdown is the same class of gap. `onRevoke`
  and reading `isLockdownEnabled` are app-suite work, not this crate.

Follow-up for the app suite, not this change.
