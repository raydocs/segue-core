#!/bin/bash
# Real-utun lab for the Segue TUN stack (macOS, needs sudo). Nothing leaves
# the Mac: TCP is "proxied" to a local HTTP server, UDP to an in-process echo.
# Usage: ./run.sh            (builds the example first)
#        BIN=<path to tun_lab> ./run.sh
set -u
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
OUT=out; mkdir -p "$OUT"; : > "$OUT/result.txt"
PORT=8099
if [ -z "${BIN:-}" ]; then
  (cd "$ROOT" && cargo build -q -p segue-kernel --example tun_lab) || exit 1
  BIN="$ROOT/target/debug/examples/tun_lab"
fi
pass=0; fail=0
check() { # name, command...
  local name=$1; shift
  if "$@" >>"$OUT/checks.log" 2>&1; then echo "PASS $name" | tee -a "$OUT/result.txt"; pass=$((pass+1))
  else echo "FAIL $name" | tee -a "$OUT/result.txt"; fail=$((fail+1)); fi
}

# Local target: static files over HTTP on loopback.
mkdir -p "$OUT/www"; head -c 1048576 /dev/urandom > "$OUT/www/1m.bin"
WANT=$(shasum -a 256 "$OUT/www/1m.bin" | cut -d' ' -f1)
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$OUT/www" >"$OUT/http.log" 2>&1 &
HTTP=$!

sudo "$BIN" --target "127.0.0.1:$PORT" >"$OUT/tun.log" 2>&1 &
for _ in $(seq 50); do grep -q '^UTUN ' "$OUT/tun.log" && break; sleep 0.1; done
UTUN=$(awk '/^UTUN /{print $2}' "$OUT/tun.log")
[ -n "$UTUN" ] || { echo "tun_lab did not start:"; cat "$OUT/tun.log"; kill $HTTP; exit 1; }
cleanup() {
  sudo route -q delete -net 198.51.100.0/24 >/dev/null 2>&1
  sudo route -q delete -net 198.18.0.0/15 >/dev/null 2>&1
  sudo route -q delete -host 192.0.2.53 >/dev/null 2>&1
  sudo pkill -f "$BIN --target" ; kill $HTTP 2>/dev/null
}
trap cleanup EXIT
# Interface MTU above the stack's 1500 so oversize packets reach it (PTB check).
sudo ifconfig "$UTUN" inet 172.19.0.2 172.19.0.1 mtu 9000 up
sudo route -q add -net 198.51.100.0/24 -interface "$UTUN"
sudo route -q add -net 198.18.0.0/15 -interface "$UTUN"
sudo route -q add -host 192.0.2.53 -interface "$UTUN"
grep '^BUDGET' "$OUT/tun.log" | tee -a "$OUT/result.txt"

log_has() { grep -qF "$1" "$OUT/tun.log"; }
log_lacks() { ! grep -qF "$1" "$OUT/tun.log"; }

# 1. Default route, bare IP: 1 MiB through the stack, sha256 intact.
fetch() { curl -s --max-time 20 -o "$OUT/got.bin" "http://198.51.100.10:$PORT/1m.bin" \
  && [ "$(shasum -a 256 "$OUT/got.bin" | cut -d' ' -f1)" = "$WANT" ]; }
check "tcp 1 MiB via default route, sha256 match" fetch
check "dialled as tag lab to the IP" log_has 'tag=Some("lab") target=Ip(198.51.100.10)'

# 2. Sniffed HTTP Host on a bare IP (D8): routed by name.
check "sniffed Host routes by name" curl -s --max-time 10 -o /dev/null \
  -H 'Host: chat.openai.com' "http://198.51.100.11:$PORT/1m.bin"
check "dialled as tag ai to the sniffed name" log_has 'tag=Some("ai") target=Domain("chat.openai.com")'

# 3. IP reject: SYN answered with RST (curl rc 7), nothing dialled.
rc_is() { local want=$1; shift; "$@"; [ $? -eq "$want" ]; }
check "IP reject refused at SYN (rc 7)" rc_is 7 curl -s --max-time 5 "http://198.51.100.200:$PORT/"
check "rejected IP never dialled" log_lacks 'Ip(198.51.100.200)'

# 4. Broken proxy: reset after the handshake, never retried direct.
broken() { curl -s --max-time 10 "http://198.51.100.201:$PORT/"; local rc=$?; [ $rc -eq 52 ] || [ $rc -eq 56 ]; }
check "failed proxy resets (rc 52/56)" broken
check "failed proxy dialled once, never direct" bash -c \
  "[ \$(grep -c 'Ip(198.51.100.201)' $OUT/tun.log) -eq 1 ] && ! grep -q 'tag=None.*198.51.100.201' $OUT/tun.log"

# 5. DNS hijack over UDP and TCP: fake-IP answers; the fake IP is dialled by name.
FAKE=$(dig +short +time=2 +tries=1 @192.0.2.53 api.openai.com A | head -1)
echo "fake-IP for api.openai.com: $FAKE" >>"$OUT/result.txt"
check "UDP DNS answered with a fake-IP" bash -c "[[ '$FAKE' == 198.1[89].* ]]"
TFAKE=$(dig +short +tcp +time=2 +tries=1 @192.0.2.53 api.openai.com A | head -1)
check "TCP DNS answered with the same fake-IP" bash -c "[ -n '$TFAKE' ] && [ '$TFAKE' = '$FAKE' ]"
check "fake-IP flow fetches" curl -s --max-time 10 -o /dev/null \
  --resolve "api.openai.com:$PORT:$FAKE" "http://api.openai.com:$PORT/1m.bin"
check "fake-IP dialled by name as tag ai" log_has 'tag=Some("ai") target=Domain("api.openai.com")'

# 6. UDP through the kernel path; Home (ai) UDP refused with ICMP.
udp() { python3 - "$@" <<'PY'
import socket, sys
host, port, expect = sys.argv[1], int(sys.argv[2]), sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
s.connect((host, port))
try:
    s.send(b"x"); s.recv(100) if expect != "refused" else None
    s.send(b"y"); got = s.recv(100)
    sys.exit(0 if expect == "echo" and got.startswith(b"echo:") else 1)
except ConnectionRefusedError:
    sys.exit(0 if expect == "refused" else 1)
except socket.timeout:
    sys.exit(1)
PY
}
check "UDP echoed through dial_udp" udp 198.51.100.10 3478 echo
check "UDP to the Home route refused (ICMP)" udp "$FAKE" 443 refused
check "Home UDP never dialled" log_lacks 'DIAL udp tag=Some("ai")'

# 7. Oversize DF datagram: ICMP frag-needed with MTU 1500 (PMTU learned).
ptb() { python3 - <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.IPPROTO_IP, 28, 1)  # IP_DONTFRAG (macOS)
s.connect(("198.51.100.12", 9999))
for _ in range(5):
    try:
        s.send(b"z" * 3000)
    except OSError as e:
        print("send:", e); sys.exit(0)  # EMSGSIZE once the route MTU dropped
    import time; time.sleep(0.3)
sys.exit(1)
PY
}
check "oversize DF UDP gets frag-needed (route MTU lowered)" ptb

echo "pass=$pass fail=$fail" | tee -a "$OUT/result.txt"
[ $fail -eq 0 ]
