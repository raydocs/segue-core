# Static file server that logs each request with its peer (threaded).
import http.server, sys, functools
class H(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *a): LOG.write("%s %s\n" % (self.client_address[0], fmt % a))
LOG = open(sys.argv[3], "a", buffering=1)
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])),
    functools.partial(H, directory=sys.argv[2])).serve_forever()
