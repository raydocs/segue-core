# SOCKS5 UDP ASSOCIATE through the kernel, send one datagram to host:port,
# print REPLY / NO_REPLY / ASSOC_REFUSED.
import socket, struct, sys
kport, host, port = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
c = socket.create_connection(("127.0.0.1", kport), timeout=5)
c.sendall(b"\x05\x01\x00"); assert c.recv(2) == b"\x05\x00"
c.sendall(b"\x05\x03\x00\x01" + b"\0" * 6); r = c.recv(10)
if len(r) < 10 or r[1] != 0: print("ASSOC_REFUSED", r[1:2].hex()); sys.exit(0)
relay = (socket.inet_ntoa(r[4:8]), struct.unpack(">H", r[8:10])[0])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(3)
hb = host.encode()
u.sendto(b"\0\0\0\x03" + bytes([len(hb)]) + hb + struct.pack(">H", port) + b"ping", relay)
try: u.recvfrom(2048); print("REPLY")
except socket.timeout: print("NO_REPLY")
