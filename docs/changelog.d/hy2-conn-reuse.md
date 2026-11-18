**Performance**

- Hysteria2 TCP no longer waits for the server's response header before the first client bytes can leave. The request and that payload share one QUIC write, and the status is read on the first read, as sing-box does. A fresh SOCKS flow on an already open connection was two round trips to the first byte; it is one.
