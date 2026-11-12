# Stand-in for the Decodo ISP SOCKS5 gateway: RFC 1929 auth, CONNECT only,
# logs every CONNECT target (one line per connect) to argv[2].
import socket, struct, sys, threading
PORT = int(sys.argv[1]); LOG = open(sys.argv[2], "a", buffering=1)
USER, PASS = sys.argv[3].encode(), sys.argv[4].encode()
def pump(a, b):
    try:
        while (d := a.recv(65536)): b.sendall(d)
    except OSError: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
def rx(c, n):
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d: raise EOFError
        b += d
    return b
def h(c):
    try:
        v, n = rx(c, 2); m = rx(c, n)
        if 2 not in m: c.sendall(b"\x05\xff"); return
        c.sendall(b"\x05\x02")
        _, ul = rx(c, 2); u = rx(c, ul); pl, = rx(c, 1); p = rx(c, pl)
        if (u, p) != (USER, PASS): c.sendall(b"\x01\x01"); LOG.write("AUTHFAIL\n"); return
        c.sendall(b"\x01\x00")
        _, cmd, _, at = rx(c, 4)
        if at == 1: host = socket.inet_ntoa(rx(c, 4))
        elif at == 4: host = socket.inet_ntop(socket.AF_INET6, rx(c, 16))
        elif at == 3: host = "DOMAIN:" + rx(c, rx(c, 1)[0]).decode()
        port, = struct.unpack(">H", rx(c, 2))
        LOG.write(f"CONNECT cmd={cmd} atyp={at} {host}:{port}\n")
        if cmd != 1 or at != 1: c.sendall(b"\x05\x07\x00\x01" + b"\0" * 6); return
        try: up = socket.create_connection((host, port), timeout=5)
        except OSError: c.sendall(b"\x05\x05\x00\x01" + b"\0" * 6); return
        up.settimeout(None)
        c.sendall(b"\x05\x00\x00\x01" + b"\0" * 6)
        threading.Thread(target=pump, args=(up, c), daemon=True).start(); pump(c, up)
    except Exception: pass
    finally: c.close()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", PORT)); s.listen(128)
while True:
    c, _ = s.accept(); threading.Thread(target=h, args=(c,), daemon=True).start()
