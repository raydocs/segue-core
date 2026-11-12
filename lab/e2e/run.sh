#!/usr/bin/env bash
# Real-process e2e: segue-kernel → (VLESS+Reality, official Xray) → segue-relay
# → overseas direct / fake Decodo SOCKS5 → local HTTP file server. No root.
# Usage: BIN=<cargo target>/debug XRAY=<xray> ./run.sh   (results in ./out/)
set -u
HERE=$(cd "$(dirname "$0")" && pwd); OUT=$HERE/out; rm -rf "$OUT"; mkdir -p "$OUT/www"
BIN=${BIN:?set BIN to the dir with segue-kernel and segue-relay}
XRAY=${XRAY:?set XRAY to the official xray binary}
unset NO_PROXY no_proxy http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
KP=1090 RP=7443 XP=8443 HP=8091 DP=1099 UP=9999
PASS=0 FAIL=0
ok()  { echo "PASS $*" | tee -a "$OUT/result.txt"; PASS=$((PASS+1)); }
bad() { echo "FAIL $*" | tee -a "$OUT/result.txt"; FAIL=$((FAIL+1)); }
PIDS=()
cleanup() { kill "${PIDS[@]}" 2>/dev/null; [ -n "${XPID:-}" ] && kill "$XPID" 2>/dev/null; wait 2>/dev/null; }
trap cleanup EXIT
waitport() { for _ in $(seq 100); do nc -z 127.0.0.1 "$1" 2>/dev/null && return 0; sleep 0.1; done; return 1; }

# Targets
head -c 1048576 /dev/urandom > "$OUT/www/1m.bin"
head -c 209715200 /dev/urandom > "$OUT/www/200m.bin"
python3 -I "$HERE/http_log.py" $HP "$OUT/www" "$OUT/http.log" & PIDS+=($!)
python3 -I "$HERE/fake_decodo.py" $DP "$OUT/decodo.log" lineuser linepass & PIDS+=($!)
python3 -I "$HERE/udp_echo.py" $UP "$OUT/udp.log" & PIDS+=($!)

# Relay: key, ticket (overseas+ai), config
"$BIN/segue-relay" keygen "$OUT/ticket.key" > "$OUT/ticket.pub"
"$BIN/segue-relay" issue-ticket --key "$OUT/ticket.key" --key-id 1 --device 42 --classes overseas,ai > "$OUT/device.ticket"
echo "lineuser:linepass" > "$OUT/line.cred"; : > "$OUT/revoked.txt"
cat > "$OUT/relay.json" <<J
{"listen":"127.0.0.1:$RP","node_id":1,"metrics_listen":"127.0.0.1:7444",
 "ticket_keys":[{"key_id":1,"public_key":"$(cat "$OUT/ticket.pub")"}],
 "revocation_file":"revoked.txt",
 "ai":{"domains":["localhost"],"cidrs":[]},
 "home_lines":[{"id":"L1","server":"127.0.0.1:$DP","isp":"fake","credentials_file":"line.cred"}],
 "dev_allow_cidrs":["127.0.0.1/32","::1/128"]}
J
"$BIN/segue-relay" run "$OUT/relay.json" > "$OUT/relay.log" 2>&1 & PIDS+=($!)

# Node: official Xray Reality server; its freedom outbound reaches the relay.
sed "s/\"port\": 8443/\"port\": $XP/" ${SERVER_JSON:-/Users/rw/work/tono-next/lab/m05-loopback/server.json} > "$OUT/xray-server.json"
start_xray() { "$XRAY" run -c "$OUT/xray-server.json" >> "$OUT/xray.log" 2>&1 & XPID=$!; waitport $XP; }
start_xray

# Client kernel: rules send 127.0.0.1 to the overseas session route and
# `localhost` (AI-whitelisted at the relay) to the AI route; default reject.
cat > "$OUT/kernel.json" <<J
{"listen":"127.0.0.1:$KP",
 "outbounds":{"reality":{"protocol":"vless",
   "settings":{"vnext":[{"address":"127.0.0.1","port":$XP,"users":[{"id":"152d5576-68f4-4214-87f3-51a8f3414a47","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","fingerprint":"chrome","publicKey":"DLqdhZXgzck8NSVsw0HvlM00sf1MWKUm69NHPxLjlA4","shortId":"a1b2c3d4","spiderX":"/"}}}},
 "segue":{"overseas":{"carrier":"reality","relay":"127.0.0.1:$RP","ticket_file":"device.ticket","exit_class":"overseas"},
          "ai":{"carrier":"reality","relay":"127.0.0.1:$RP","ticket_file":"device.ticket","exit_class":"ai"}},
 "rules":[{"domain":"localhost","action":{"type":"proxy","outbound":"ai"}},
          {"ip_cidr":"127.0.0.1/32","action":{"type":"proxy","outbound":"overseas"}}],
 "default":{"type":"reject"},
 "udp":{"refuse":["ai"]}}
J
"$BIN/segue-kernel" "$OUT/kernel.json" > "$OUT/kernel.log" 2>&1 & PIDS+=($!)
waitport $KP && waitport $RP && waitport $HP && waitport $DP || { bad "startup"; exit 1; }

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
fetch() { curl -s --max-time "${3:-60}" --socks5-hostname 127.0.0.1:$KP -o "$2" -w '%{http_code} %{size_download}' "$1"; }

# 1. Overseas fetch
r=$(fetch "http://127.0.0.1:$HP/1m.bin" "$OUT/o1.bin")
[ "$(sha "$OUT/o1.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && ok "overseas fetch 1 MiB sha match ($r)" || bad "overseas fetch ($r)"
! grep -q CONNECT "$OUT/decodo.log" && ok "overseas did not touch Home SOCKS" || bad "overseas used Home"

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
before_d=$(grep -c CONNECT "$OUT/decodo.log"); before_h=$(wc -l < "$OUT/http.log")
t0=$(python3 -c 'import time;print(time.time())')
r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/a2.bin" 10); rc=$?
t1=$(python3 -c 'import time;print(time.time())')
dt=$(python3 -c "print(round($t1-$t0,2))")
[ $rc -ne 0 ] && [ "$(grep -c CONNECT "$OUT/decodo.log")" = "$before_d" ] && ok "AI refused while reconnecting in ${dt}s (curl rc=$rc)" || bad "AI not refused while down (rc=$rc $r)"
r=$(fetch "http://127.0.0.1:$HP/1m.bin" "$OUT/o2.bin" 30); rc=$?
[ $rc -ne 0 ] && ok "overseas refused while carrier down (curl rc=$rc)" || bad "overseas succeeded with carrier down ($r)"
[ "$(wc -l < "$OUT/http.log")" = "$before_h" ] && ok "no target request while carrier down (nothing went direct)" || bad "target got requests while carrier down"
start_xray; echo "carrier restarted" >> "$OUT/result.txt"
wait $CP; crc=$?
[ $crc = 0 ] && [ "$(sha "$OUT/big.bin")" = "$(sha "$OUT/www/200m.bin")" ] && ok "200 MiB download survived carrier kill, sha match" || bad "download after carrier kill (curl rc=$crc size $(stat -f %z "$OUT/big.bin"))"
[ "$(grep -c '200m.bin' "$OUT/http.log")" = 1 ] && ok "target saw one GET for 200m.bin (resumed, not refetched)" || bad "200m.bin GET count $(grep -c 200m.bin "$OUT/http.log")"

# 5. After recovery AI works again
sleep 3
r=$(fetch "http://localhost:$HP/1m.bin" "$OUT/a3.bin")
[ "$(sha "$OUT/a3.bin" 2>/dev/null)" = "$(sha "$OUT/www/1m.bin")" ] && ok "AI works after recovery ($r)" || bad "AI after recovery ($r)"

# 6. Home UDP refused (and session routes never carry UDP)
u=$(python3 -I "$HERE/udp_probe.py" $KP localhost $UP)
[ "$u" != REPLY ] && [ ! -s "$OUT/udp.log" ] && ok "Home UDP refused ($u, echo got nothing)" || bad "Home UDP leaked ($u)"

# 7. Rejected (default) never connects
r=$(fetch "http://10.255.255.1:$HP/x" "$OUT/r.bin" 5); rc=$?
[ $rc -ne 0 ] && ok "unmatched target rejected (rc=$rc)" || bad "unmatched target fetched"

curl -s http://127.0.0.1:7444/ > "$OUT/metrics.txt" 2>/dev/null
grep -i "alert\|secret\|linepass\|$(head -c 20 "$OUT/device.ticket")" "$OUT/relay.log" "$OUT/kernel.log" | grep -v '"msg":"dev' > "$OUT/secrets-grep.txt"
grep -q "linepass\|$(head -c 20 "$OUT/device.ticket")" "$OUT/relay.log" "$OUT/kernel.log" && bad "secret in logs" || ok "no ticket / SOCKS password in logs"
echo "TOTAL pass=$PASS fail=$FAIL" | tee -a "$OUT/result.txt"
