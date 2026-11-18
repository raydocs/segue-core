Transport:

- QUIC loss recovery on a bursty path. Before any RTT sample the probe timeout is twice the 100 ms initial RTT, matching quic-go, instead of about a second from the old 333 ms prior. The two PTO datagrams go out 10 ms apart so one short burst cannot erase both copies and force a doubled timeout.
