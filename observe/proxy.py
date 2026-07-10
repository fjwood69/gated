"""observe/proxy.py — the boundary observer: a minimal counting fail-responder.

Runs OUTSIDE the sandbox (a sidecar container on an --internal --disable-dns
network); the sandboxed artifact's only reachable endpoint. Every connection is a
real egress attempt: the proxy increments an in-memory counter, writes it to its
OWN filesystem (never a volume shared with the artifact), replies 503 (fail-ALWAYS
so the artifact exhausts its retry budget -> a deterministic count), and closes.

The executor reads the count from OUTSIDE via ``<rt> exec <proxy> cat <countfile>``
AFTER the sandbox exits — so the artifact can influence the count ONLY by issuing
real requests, and can neither forge nor erase it (NFR4). No shared writable state
between artifact and counter is the inviolable rule of this increment.

Deliberately dumb: raw sockets, no HTTP parsing, a bounded peek (no body read),
no logging of artifact-controlled data, a hard concurrency cap. The count must
reflect ONLY real connections — there is deliberately no debug/admin endpoint and
no way to increment the counter without opening a connection.

Usage (inside the proxy container): ``python3 proxy.py <port> <countfile>``
"""
from __future__ import annotations

import socket
import sys
import threading

_503 = (
    b"HTTP/1.1 503 Service Unavailable\r\n"
    b"Connection: close\r\nContent-Length: 0\r\n\r\n"
)
_200 = b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
_PEEK = 64           # read at most this many bytes (bound slowloris / OOM)
_MAX_INFLIGHT = 16   # hard concurrency cap


def serve(port: int, countfile: str, mode: str = "fail_always") -> None:
    """mode 'fail_always' -> every request gets 503 (budget-exhaustion). mode
    'fail_once' -> attempt 1 gets 503, attempts >=2 get 200 (the retry check: a
    retrying artifact reaches attempt 2 and succeeds; a non-retrying one stops at 1)."""
    count = 0
    lock = threading.Lock()
    sem = threading.Semaphore(_MAX_INFLIGHT)

    def write_count(n: int) -> None:
        # the count lives in the proxy's OWN fs — never shared with the artifact.
        with open(countfile, "w") as f:
            f.write(str(n))

    write_count(0)

    def handle(conn: socket.socket) -> None:
        nonlocal count
        try:
            conn.settimeout(5.0)
            try:
                conn.recv(_PEEK)  # bounded peek; deliberately NOT parsed
            except OSError:
                pass
            with lock:
                count += 1
                n = count
                write_count(count)
            resp = _200 if (mode == "fail_once" and n >= 2) else _503
            try:
                conn.sendall(resp)
            except OSError:
                pass
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
            sem.release()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(_MAX_INFLIGHT)
    while True:
        conn, _ = srv.accept()
        sem.acquire()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    serve(int(sys.argv[1]), sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "fail_always")
