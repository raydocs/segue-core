# UDP echo that logs every datagram it gets (only the direct control may reach it).
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", int(sys.argv[1])))
log = open(sys.argv[2], "a", buffering=1)
while True:
    d, a = s.recvfrom(2048); log.write(f"GOT {len(d)} from {a}\n"); s.sendto(d, a)
