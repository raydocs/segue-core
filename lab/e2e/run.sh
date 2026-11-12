#!/usr/bin/env bash
# Real-process e2e: segue-kernel → (VLESS+Reality, official Xray) → segue-relay
# → overseas direct / fake Decodo SOCKS5 → local HTTP file server. No root.
# Second exit: Hysteria2 carrier (sing-box server) → same relay.
# Usage: BIN=<cargo target>/debug XRAY=<xray> SINGBOX=<sing-box> ./run.sh
# (results in ./out/; SINGBOX unset skips the Hy2 cases)
set -u
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out; rm -rf "$OUT"; mkdir -p "$OUT/www"
BIN=${BIN:?set BIN to the dir with segue-kernel and segue-relay}
XRAY=${XRAY:?set XRAY to the official xray binary}
unset NO_PROXY no_proxy http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
SINGBOX=${SINGBOX:-}
KP=1090 RP=7443 XP=8443 HP=8091 DP=1099 UP=9999 YP=8444 CP_=7450 CN=8097
# Stale lab processes holding our ports make every case lie; clear them.
for p in $KP $RP 7444 $XP $HP $DP $CP_ $CN; do
  for pid in $(lsof -nP -tiTCP:$p -sTCP:LISTEN 2>/dev/null); do echo "killing stale pid $pid on :$p"; kill "$pid"; done
done
for p in $UP $YP; do for pid in $(lsof -nP -tiUDP:$p 2>/dev/null); do echo "killing stale pid $pid on udp :$p"; kill "$pid"; done; done
sleep 0.3
PASS=0 FAIL=0
ok()  { echo "PASS $*" | tee -a "$OUT/result.txt"; PASS=$((PASS+1)); }
bad() { echo "FAIL $*" | tee -a "$OUT/result.txt"; FAIL=$((FAIL+1)); }
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null; [ -n "${XPID:-}" ] && kill "$XPID" 2>/dev/null; [ -n "${YPID:-}" ] && kill "$YPID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT
waitport() { for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# Targets
head -c 1048576 /dev/urandom > "$OUT/www/1m.bin"
head -c 209715200 /dev/urandom > "$OUT/www/200m.bin"
python3 -I "$HERE/http_log.py" $HP "$OUT/www" "$OUT/http.log" & PIDS+=($!)
python3 -I "$HERE/fake_decodo.py" $DP "$OUT/decodo.log" lineuser linepass & PIDS+=($!)
python3 -I "$HERE/udp_echo.py" $UP "$OUT/udp.log" & PIDS+=($!)
# Reachable canary for refusal cases (127.0.0.1 and ::1): a refusal counts
# only if it is the expected SOCKS reply, in time, with no canary accept.
: > "$OUT/canary.log"; python3 -I "$HERE/canary.py" $CN "$OUT/canary.log" & PIDS+=($!)

# Routing policy: a signed bundle (dev key). `localhost` is an AI domain →
# the Home-role `ai` route; 127.0.0.1 → overseas; default reject. The user
# never edits rules. The relay verifies the same bundle with the same key
# and takes its AI set from it (it never downgrades an AI hint).
"$BIN/segue-kernel" policy-keygen "$OUT/policy.key" > "$OUT/policy.pub"
cat > "$OUT/policy-body.json" <<J
{"version":1,"expires_at":$(( $(date +%s) + 3600 )),"ai_domains":["localhost"],
 "rules":[{"ip_cidr":"127.0.0.1/32","action":{"type":"proxy","outbound":"overseas"}}],
 "default":{"type":"reject"}}
J
"$BIN/segue-kernel" sign-bundle --key "$OUT/policy.key" --key-id 1 "$OUT/policy-body.json" > "$OUT/policy.bundle"

# Relay: key, ticket (overseas+ai), config
"$BIN/segue-relay" keygen "$OUT/ticket.key" > "$OUT/ticket.pub"
"$BIN/segue-relay" issue-ticket --key "$OUT/ticket.key" --key-id 1 --device 42 --classes overseas,ai > "$OUT/device.ticket"
echo "lineuser:linepass" > "$OUT/line.cred"; printf 'seq 1\nsynced_at %s\n' "$(date +%s)" > "$OUT/revoked.txt"
cat > "$OUT/relay.json" <<J
{"listen":"127.0.0.1:$RP","node_id":1,"metrics_listen":"127.0.0.1:7444",
 "ticket_keys":[{"key_id":1,"public_key":"$(cat "$OUT/ticket.pub")"}],
 "revocation_file":"revoked.txt",
 "policy":{"public_keys":[{"key_id":1,"public_key":"$(cat "$OUT/policy.pub")"}],"bundle":"policy.bundle"},
 "home_lines":[{"id":"L1","server":"127.0.0.1:$DP","isp":"fake","credentials_file":"line.cred"}],
 "dev_allow_cidrs":["127.0.0.1/32","::1/128"]}
J
"$BIN/segue-relay" run "$OUT/relay.json" > "$OUT/relay.log" 2>&1 & PIDS+=($!)

# Node: official Xray Reality server; its freedom outbound reaches the relay.
sed "s/\"port\": 8443/\"port\": $XP/" ${SERVER_JSON:-/Users/rw/work/tono-next/lab/m05-loopback/server.json} > "$OUT/xray-server.json"
start_xray() { "$XRAY" run -c "$OUT/xray-server.json" >> "$OUT/xray.log" 2>&1 & XPID=$!; waitport $XP; }
start_xray

# Node 2: sing-box Hysteria2 server (self-signed cert, pinned by the client).
HY2=""
if [ -n "$SINGBOX" ] && [ -x "$SINGBOX" ]; then
  openssl ecparam -genkey -name prime256v1 -out "$OUT/hy2.key" 2>/dev/null
  openssl req -new -x509 -key "$OUT/hy2.key" -out "$OUT/hy2.crt" -days 2 -subj "/CN=hy2.segue.test" \
    -addext "subjectAltName=DNS:hy2.segue.test" 2>/dev/null
  CERT_SHA=$(openssl x509 -in "$OUT/hy2.crt" -outform der | shasum -a 256 | cut -d' ' -f1)
  cat > "$OUT/sb-server.json" <<J
{"log":{"level":"info"},
 "inbounds":[{"type":"hysteria2","listen":"127.0.0.1","listen_port":$YP,"up_mbps":500,"down_mbps":500,
   "users":[{"password":"e2e-hy2-pass"}],
   "tls":{"enabled":true,"alpn":["h3"],"certificate_path":"$OUT/hy2.crt","key_path":"$OUT/hy2.key"}}],
 "outbounds":[{"type":"direct"}]}
J
  start_sb() { "$SINGBOX" run -c "$OUT/sb-server.json" >> "$OUT/sing-box.log" 2>&1 & YPID=$!; sleep 0.5; }
  start_sb
  HY2=',"hy2":{"role":"proxy","protocol":"hysteria","settings":{"version":2,"address":"127.0.0.1","port":'$YP'},
   "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"hy2.segue.test","alpn":["h3"],"pinnedPeerCertSha256":"'$CERT_SHA'","verifyPeerCertByName":"hy2.segue.test"},"hysteriaSettings":{"version":2,"auth":"e2e-hy2-pass"}}}'
  NY=',{"name":"ny","carrier":"hy2","relay":"127.0.0.1:'$RP'","node_id":1}'
else
  echo "SINGBOX not set or not executable: Hy2 cases skipped" | tee -a "$OUT/result.txt"; NY=""
fi

# Client kernel: two exits (la = Reality, ny = Hy2), Auto by default.
cat > "$OUT/kernel.json" <<J
{"listen":"127.0.0.1:$KP",
 "outbounds":{"reality":{"role":"proxy","protocol":"vless",
   "settings":{"vnext":[{"address":"127.0.0.1","port":$XP,"users":[{"id":"152d5576-68f4-4214-87f3-51a8f3414a47","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"DLqdhZXgzck8NSVsw0HvlM00sf1MWKUm69NHPxLjlA4","shortId":"a1b2c3d4","spiderX":"/"}}}$HY2},
 "exits":[{"name":"la","carrier":"reality","relay":"127.0.0.1:$RP","node_id":1}$NY],
 "segue":{"overseas":{"ticket_file":"device.ticket","exit_class":"overseas"},
          "ai":{"ticket_file":"device.ticket","exit_class":"ai","role":"home"}},
 "policy":{"public_keys":[{"key_id":1,"public_key":"$(cat "$OUT/policy.pub")"}],
           "bundle":"policy.bundle","installed":"policy.installed","ai_route":"ai"},
 "control":{"listen":"127.0.0.1:$CP_","token_file":"control.json"},
 "udp":{"refuse":[]}}
J
"$BIN/segue-kernel" "$OUT/kernel.json" > "$OUT/kernel.log" 2>&1 & PIDS+=($!)
waitport $KP && waitport $RP && waitport $HP && waitport $DP && waitport $CP_ && waitport $CN || { bad "startup"; exit 1; }
TOKEN=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["token"])' "$OUT/control.json")
api() { curl -s --max-time 30 -X "$1" -H "Authorization: Bearer $TOKEN" ${3:+-d "$3"} "http://127.0.0.1:$CP_$2"; }
jf() { python3 -c 'import json,sys;d=json.load(sys.stdin);print(d'"$1"')'; }

# 0. Signed policy installed; control API needs the per-start token.
v=$(api GET /v1/status | jf '["policy"]["version"]')
[ "$v" = 1 ] && ok "signed policy bundle v1 installed (control API status)" || bad "policy not installed (version=$v)"
c=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$CP_/v1/status")
[ "$c" = 401 ] && ok "control API refuses requests without the token ($c)" || bad "control API without token: $c"
# Cases 1-7 exercise the kill switch on one carrier: pin exit la (with Auto a
# Reality kill would just fail over to the Hy2 exit, tested in case 8).
[ -n "$HY2" ] && api POST /v1/exit '{"exit":"la"}' > /dev/null

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
canary() { wc -l < "$OUT/canary.log" | tr -d ' '; }
lt() { python3 -c "import sys;sys.exit(0 if $1 < $2 else 1)"; }
# refuse <label> <want SOCKS REP hex> <host> <max secs>: one CONNECT to the
# canary through the kernel must get exactly that reply within max secs,
# and neither the canary nor the Home SOCKS may see a connection.
refuse() {
  local c0 d0 out kind code secs
  c0=$(canary); d0=$(grep -c CONNECT "$OUT/decodo.log")
  out=$(python3 -I "$HERE/socks_probe.py" $KP "$3" $CN $(( $4 + 10 )))
  read -r kind code secs _ <<<"$out"
  if [ "$kind" = REP ] && [ "$code" = "$2" ] && lt "$secs" "$4" \
     && [ "$(canary)" = "$c0" ] && [ "$(grep -c CONNECT "$OUT/decodo.log")" = "$d0" ]; then
    ok "$1: REP $code in ${secs}s, canary and Home untouched"
  else
    bad "$1: got '$out' (want REP $2 in <$4s); canary $c0→$(canary), Home CONNECT $d0→$(grep -c CONNECT "$OUT/decodo.log")"
  fi
}
# The canary is reachable directly on both addresses, and through the
# kernel where policy allows it, so a refusal below is the kernel's doing.
[ "$(curl -s --max-time 5 "http://127.0.0.1:$CN/")" = canary ] && [ "$(curl -s -g --max-time 5 "http://[::1]:$CN/")" = canary ] \
  && ok "canary reachable directly (127.0.0.1, ::1)" || bad "canary not reachable directly"
fetch() { curl -s --max-time "${3:-60}" --socks5-hostname 127.0.0.1:$KP -o "$2" -w '%{http_code} %{size_download}' "$1"; }

# 1. Overseas fetch
r=$(fetch "http://127.0.0.1:$HP/1m.bin" "$OUT/o1.bin")
[ "$(sha "$OUT/o1.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && ok "overseas fetch 1 MiB sha match ($r)" || bad "overseas fetch ($r)"
! grep -q CONNECT "$OUT/decodo.log" && ok "overseas did not touch Home SOCKS" || bad "overseas used Home"
c0=$(canary); out=$(python3 -I "$HERE/socks_probe.py" $KP 127.0.0.1 $CN 30)
[ "${out%% *}" = OK ] && [ "${out##* }" = canary ] && [ "$(canary)" -gt "$c0" ] \
  && ok "canary reachable through the kernel when allowed ($out)" || bad "canary via kernel: '$out'"

# 2. AI fetch goes through fake Decodo, by IPv4, with auth
r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/a1.bin")
[ "$(sha "$OUT/a1.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && ok "AI fetch sha match ($r)" || bad "AI fetch ($r)"
grep -q "CONNECT cmd=1 atyp=1 127.0.0.1:$HP" "$OUT/decodo.log" && ok "AI fetch seen at fake Decodo: $(grep CONNECT "$OUT/decodo.log" | tail -1)" || bad "AI fetch not via Decodo"
grep -q DOMAIN "$OUT/decodo.log" && bad "Decodo got a domain CONNECT" || ok "Decodo never got a domain name"

# 3. Kill the carrier mid-download, restart it: same sha
curl -s --max-time 120 --limit-rate 20M --socks5-hostname 127.0.0.1:$KP -o "$OUT/big.bin" "http://127.0.0.1:$HP/200m.bin" & CP=$!
sleep 3; s1=$(stat -f %z "$OUT/big.bin" 2>/dev/null || echo 0)
kill -9 "$XPID"; wait "$XPID" 2>/dev/null; XPID=
echo "carrier killed at $s1 bytes" >> "$OUT/result.txt"
# 4. While the carrier is down: AI refused at once, overseas refused, nothing direct.
sleep 0.5
before_h=$(wc -l < "$OUT/http.log")
# AI (strict): host unreachable at once. Overseas: tried for a bounded time
# (OPEN_WAIT 20 s), then host unreachable. Never direct, never Home.
refuse "AI refused while reconnecting" 04 localhost 1
refuse "overseas refused while carrier down" 04 127.0.0.1 25
[ "$(wc -l < "$OUT/http.log")" = "$before_h" ] && ok "no target request while carrier down (nothing went direct)" || bad "target got requests while carrier down"
start_xray; echo "carrier restarted" >> "$OUT/result.txt"
wait $CP; crc=$?
[ $crc = 0 ] && [ "$(sha "$OUT/big.bin")" = "$(sha "$OUT/www/200m.bin")" ] && ok "200 MiB download survived carrier kill, sha match" || bad "download after carrier kill (curl rc=$crc size $(stat -f %z "$OUT/big.bin"))"
[ "$(grep -c '200m.bin' "$OUT/http.log")" = 1 ] && ok "target saw one GET for 200m.bin (resumed, not refetched)" || bad "200m.bin GET count $(grep -c 200m.bin "$OUT/http.log")"

# 5. After recovery AI works again
sleep 3
r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/a3.bin")
[ "$(sha "$OUT/a3.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && ok "AI works after recovery ($r)" || bad "AI after recovery ($r)"

# 6. Home UDP refused (and session routes never carry UDP).
# home_udp <probe> <echo port>: 0 only when the echo answers directly, the
# probe ran cleanly (rc 0) through an accepted ASSOCIATE, got no reply, and
# the echo saw nothing from the kernel. Sets HU to a description.
udp_seen() { wc -l < "$OUT/udp.log" | tr -d ' '; }
home_udp() {
  local d u rc n0
  d=$(python3 -I "$1" direct 127.0.0.1 "$2"); rc=$?
  [ $rc = 0 ] && [ "$d" = REPLY ] || { HU="UDP echo not reachable directly (rc=$rc '$d')"; return 1; }
  n0=$(udp_seen)
  u=$(python3 -I "$1" $KP localhost "$2"); rc=$?
  sleep 0.3
  [ $rc = 0 ] || { HU="probe failed (rc=$rc '$u')"; return 1; }
  [ "$u" = NO_REPLY ] || { HU="probe result '$u', want NO_REPLY"; return 1; }
  [ "$(udp_seen)" = "$n0" ] || { HU="echo got $(( $(udp_seen) - n0 )) datagram(s) via the kernel"; return 1; }
  HU="ASSOCIATE accepted, datagram dropped, echo reachable directly and got nothing via the kernel"
}
home_udp "$HERE/udp_probe.py" $UP && ok "Home UDP refused ($HU)" || bad "Home UDP: $HU"
# The check itself must fail when the probe breaks or the echo is down.
# Probe that controls fine directly, then prints a refusal-looking result
# but exits nonzero through the kernel.
cat > "$OUT/broken_probe.py" <<P
import subprocess, sys
if sys.argv[1] == "direct":
    sys.exit(subprocess.call([sys.executable, "-I", "$HERE/udp_probe.py"] + sys.argv[1:]))
print("NO_REPLY"); sys.exit(3)
P
home_udp "$OUT/broken_probe.py" $UP && bad "self-test: probe exiting 3 counted as refusal" || ok "self-test: broken probe fails the check ($HU)"
for pid in $(lsof -nP -tiUDP:9998 2>/dev/null); do kill "$pid"; done
home_udp "$HERE/udp_probe.py" 9998 && bad "self-test: echo down counted as refusal" || ok "self-test: echo down fails the check ($HU)"

# 7. Rejected (default rule) never connects: ::1 matches no rule, and the
# canary listens there.
refuse "unmatched target rejected by policy" 02 ::1 1

# 8. Hy2 carrier: pin exit ny via the control API, take Reality away.
if [ -n "$HY2" ]; then
  s=$(api POST /v1/exit '{"exit":"ny"}' | jf '["current_exit"]')
  [ "$s" = ny ] && ok "control API set exit ny" || bad "set exit ny ($s)"
  kill "$XPID"; wait "$XPID" 2>/dev/null; XPID=
  r=$(fetch "http://127.0.0.1:$HP/1m.bin" "$OUT/h1.bin")
  [ "$(sha "$OUT/h1.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && ok "overseas over Hy2 sha match, Reality down ($r)" || bad "overseas over Hy2 ($r)"
  before_d=$(grep -c CONNECT "$OUT/decodo.log")
  r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/h2.bin")
  [ "$(sha "$OUT/h2.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && [ "$(grep -c CONNECT "$OUT/decodo.log")" -gt "$before_d" ] \
    && ok "AI over Hy2 → Home SOCKS sha match ($r)" || bad "AI over Hy2 ($r)"
  r=$(fetch "http://127.0.0.1:$HP/200m.bin" "$OUT/h3.bin" 120)
  [ "$(sha "$OUT/h3.bin" 2>/dev/null)" = "$(sha "$OUT/www/200m.bin")" ] && ok "200 MiB over Hy2 sha match ($r)" || bad "200 MiB over Hy2 ($r)"
  st=$(api GET /v1/status | jf '["state"]')
  [ "$st" = connected ] && ok "status connected on ny" || bad "status on ny: $st"
  # Hy2 down too: the probe notices, then AI is refused at once, nothing direct.
  kill -9 "$YPID"; wait "$YPID" 2>/dev/null; YPID=
  t0=$(python3 -c 'import time;print(time.time())')
  st=$(api POST /v1/connect | jf '["state"]')
  pt=$(python3 -c "import time;print(round(time.time()-$t0,2))")
  [ "$st" = reconnecting ] && ok "both carriers down: probe saw it in ${pt}s (state $st)" || bad "both down: state=$st after probe ${pt}s"
  refuse "both carriers down: AI refused" 04 localhost 1
  # Auto fails over: Reality back (Hy2 still down) → Auto picks la.
  start_xray
  api POST /v1/exit '{"exit":"auto"}' > /dev/null
  s=$(api POST /v1/connect | jf '["state"],d["current_exit"]')
  r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/h5.bin")
  [ "$s" = "connected la" ] && [ "$(sha "$OUT/h5.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] \
    && ok "Auto fails over ny→la, AI works ($s, $r)" || bad "Auto failover ($s, $r)"
  # Hy2 back, pin ny again: AI works over Hy2 once the carrier is back.
  start_sb
  api POST /v1/exit '{"exit":"ny"}' > /dev/null
  t0=$(python3 -c 'import time;print(time.time())')
  for _ in $(seq 12); do
    s=$(api POST /v1/connect | jf '["state"],d["current_exit"]'); [ "$s" = "connected ny" ] && break; sleep 1
  done
  rt=$(python3 -c "import time;print(round(time.time()-$t0,1))")
  r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/h6.bin")
  [ "$s" = "connected ny" ] && [ "$(sha "$OUT/h6.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] \
    && ok "Hy2 recovered after ${rt}s, AI over ny ($s, $r)" || bad "Hy2 recovery ($s after ${rt}s, $r)"
fi

# 9. Disconnect via control API: everything refused.
api POST /v1/disconnect > /dev/null
refuse "disconnected: overseas refused" 04 127.0.0.1 1
refuse "disconnected: AI refused" 04 localhost 1

curl -s http://127.0.0.1:7444/ > "$OUT/metrics.txt" 2>/dev/null
grep -i "alert\|secret\|linepass\|$(head -c 20 "$OUT/device.ticket")" "$OUT/relay.log" "$OUT/kernel.log" | grep -v '"msg":"dev' > "$OUT/secrets-grep.txt"
grep -q "linepass\|$(head -c 20 "$OUT/device.ticket")" "$OUT/relay.log" "$OUT/kernel.log" && bad "secret in logs" || ok "no ticket / SOCKS password in logs"
echo "TOTAL pass=$PASS fail=$FAIL" | tee -a "$OUT/result.txt"
[ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]
