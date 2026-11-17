- The destination DNS cache now scales with the runtime memory profile: 1 024
  entries inside a phone or Network Extension and 4 096 on desktop, following
  mihomo's 4 096-entry default and sing-box's `max(CacheCapacity, 1024)`.
  A cached answer keeps at most 16 addresses, so one large upstream response
  cannot make a single entry's cost follow the response size; eviction is
  still least-recently-used over live entries.
- `dns.fakeIp` gains a Segue-only `exemptDomains` list of Xray domain rules.
  Names it matches keep real answers instead of a fake IP, so captive-portal
  checks, NTP and `.lan`/`.local` names work under fake-IP. The built-in
  default exempts `captive.apple.com`, `connectivitycheck.gstatic.com`,
  `www.msftconnecttest.com`, `*.ntp.org`, `time.apple.com`, `*.lan` and
  `*.local`; `"exemptDomains": []` exempts nothing, which is the behaviour
  without this field.
