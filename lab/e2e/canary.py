# Reachable canary target: TCP on 127.0.0.1 and ::1, logs every accepted
# connection (one line each) and answers a tiny HTTP response. A refusal
# case passes only if the canary saw no connection at all.
import socket, sys, threading
port, log = int(sys.argv[1]), open(sys.argv[2], "a", buffering=1)
def serve(fam, addr):
    s = socket.socket(fam, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if fam == socket.AF_INET6:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s.bind((addr, port)); s.listen(64)
    while True:
        c, peer = s.accept()
        log.write("accept %s\n" % (peer[0],))
        try:
            c.settimeout(2); c.recv(4096)
            c.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 6\r\n\r\ncanary")
        except OSError:
            pass
        c.close()
for fam, addr in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
    threading.Thread(target=serve, args=(fam, addr), daemon=True).start()
threading.Event().wait()
