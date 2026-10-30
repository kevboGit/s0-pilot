#!/usr/bin/env python3
# A minimal IPv6 loopback HTTP listener. It exists only to make the sandbox's IPv6-egress
# probe conclusive: a non-agent user (the control) can reach it, while the filtered agent
# must not. It never touches the network beyond ::1 and serves no real content.
#
# Runs as root. Binds ::1 on an ephemeral port written to argv[1]. argv[2] is a heartbeat
# file whose contents are rewritten every second, so the probe can tell "the filter
# blocked a live listener" (heartbeat fresh, agent refused) from "the listener is gone"
# (heartbeat stale), and never record a refusal-by-absence as a pass.
import http.server
import os
import socket
import sys
import threading
import time


class Server(http.server.HTTPServer):
    address_family = socket.AF_INET6


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *args):
        pass


def write_atomic(path, text):
    # Write via a temp file and rename, so a reader never sees a half-written or empty
    # file (the probe fails closed on anything non-numeric, but never needs to here).
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def main():
    port_file, hb_file = sys.argv[1], sys.argv[2]
    srv = Server(("::1", 0), Handler)
    write_atomic(port_file, str(srv.server_address[1]))

    def heartbeat():
        while True:
            write_atomic(hb_file, str(int(time.time())))
            time.sleep(1)

    threading.Thread(target=heartbeat, daemon=True).start()
    srv.serve_forever()


if __name__ == "__main__":
    main()
