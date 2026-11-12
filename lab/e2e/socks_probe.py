# One SOCKS5 CONNECT through the kernel; prints how it ended and how long the
# answer took:  "REP <code-hex> <secs>" for a refusal, "OK <secs> <body>" when
# connected (sends a GET, prints the response body), "CLOSED <secs>" when the
# kernel closed without a reply, "TIMEOUT <secs>" when nothing came in time.
import ipaddress, socket, struct, sys, time
kport, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
limit = float(sys.argv[4]) if len(sys.argv) > 4 else 30
t0 = time.time()
el = lambda: "%.2f" % (time.time() - t0)
try:
    c = socket.create_connection(("127.0.0.1", kport), timeout=limit)
    c.sendall(b"\x05\x01\x00")
    if c.recv(2) != b"\x05\x00": print("CLOSED", el()); sys.exit(0)
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        addr = b"\x03" + bytes([len(host)]) + host.encode()
    c.sendall(b"\x05\x01\x00" + addr + struct.pack(">H", port))
    r = c.recv(4)
    if len(r) < 2: print("CLOSED", el()); sys.exit(0)
    if r[1] != 0: print("REP %02x" % r[1], el()); sys.exit(0)
    t = el()
    c.recv(4096)  # rest of the reply (bound address)
    c.sendall(b"GET / HTTP/1.0\r\n\r\n")
    body = b""
    while True:
        b = c.recv(4096)
        if not b: break
        body += b
    print("OK", t, body.split(b"\r\n\r\n", 1)[-1].decode(errors="replace"))
except socket.timeout:
    print("TIMEOUT", el())
except OSError as e:
    print("CLOSED", el(), e.__class__.__name__)
