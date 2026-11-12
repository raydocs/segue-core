# SOCKS5 UDP ASSOCIATE through the kernel, send one datagram to host:port,
# print REPLY / NO_REPLY / ASSOC_REFUSED <rep> and exit 0. With kport
# "direct": send straight to 127.0.0.1:port (reachability control).
# Anything else (handshake broken, socket error, crash) prints ERROR and
# exits 2, so a broken probe never reads as a refusal.
import socket, struct, sys

def via_kernel(kport, host, port):
    c = socket.create_connection(("127.0.0.1", kport), timeout=5)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00":
        raise RuntimeError("SOCKS method negotiation failed")
    c.sendall(b"\x05\x03\x00\x01" + b"\0" * 6)
    r = c.recv(10)
    if len(r) == 10 and r[0] == 5 and r[1] != 0:
        return "ASSOC_REFUSED " + r[1:2].hex()
    if len(r) < 10 or r[0] != 5 or r[3] != 1:
        raise RuntimeError(f"bad ASSOCIATE reply {r.hex()}")
    relay = (socket.inet_ntoa(r[4:8]), struct.unpack(">H", r[8:10])[0])
    hb = host.encode()
    pkt = b"\0\0\0\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port) + b"ping"
    return send(relay, pkt, c)

def send(to, pkt, keep=None):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
    u.sendto(pkt, to)
    try:
        u.recvfrom(2048); return "REPLY"
    except socket.timeout:
        return "NO_REPLY"

try:
    if sys.argv[1] == "direct":
        out = send(("127.0.0.1", int(sys.argv[3])), b"direct-ping")
    else:
        out = via_kernel(int(sys.argv[1]), sys.argv[2], int(sys.argv[3]))
except Exception as e:
    print("ERROR", type(e).__name__, e); sys.exit(2)
print(out)
