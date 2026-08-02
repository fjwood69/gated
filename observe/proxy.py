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

import os
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
        #
        # ATOMIC BY RENAME, never truncate-then-write. ``open(countfile, "w")`` truncates FIRST and
        # the value lands only at flush, so a reader can observe an EMPTY file. That reader is
        # ``<rt> exec <proxy> cat <countfile>`` in ANOTHER PROCESS, and it parses with
        # ``int(stdout.strip())`` -> ``None`` on ValueError. The writes here serialise under ``lock``;
        # the reader holds no lock and CANNOT be made to, because it is not in this process. So the
        # window is closed by CONSTRUCTION rather than classified after the fact: a reader now sees
        # either the whole old value or the whole new one.
        #
        # MEASURED before the fix, hammering a writer thread against 4000 separate-process reads:
        # 2687 of 4000 read EMPTY and parsed to None; with the rename, 0 of 4000. The RATE is an
        # artifact of the hot loop (production writes once per connection) — what it establishes is
        # that the window is real, not how often it fires. No partial numeral was ever observed, so
        # the failure is a benign None, not a silently wrong count.
        #
        # SAME DIRECTORY IS LOAD-BEARING, which is why the temp is spelled as a suffix ON the
        # countfile rather than assembled from a temp dir: ``os.replace`` is atomic only WITHIN a
        # filesystem, and a temp under /tmp against a countfile on a mounted volume degrades to
        # copy-and-delete, silently reopening the exact window this exists to close.
        #
        # NO fsync, deliberately. The hazard is a CONCURRENT READER through the same kernel, which the
        # rename already orders. fsync buys durability across power loss — a different failure, and not
        # one this gate makes any claim about. (If fsync is ever added it must be file-fsync BEFORE the
        # rename AND directory-fsync AFTER; without the second the rename itself is not durable.)
        #
        # A FIXED temp name is safe because every write_count call is TOTALLY ORDERED: the readiness
        # write runs single-threaded before the accept loop, and every later write is under ``lock``. So
        # one process can never race its own temp. THE INVARIANT THAT MAKES THAT TRUE IS ONE PROXY
        # PROCESS PER COUNTFILE, stated here because nothing else states it. Two processes sharing a
        # countfile directory is already broken for a worse reason — the in-memory ``count`` races and
        # last-writer-wins — and the temp collision merely surfaces it as a loud FileNotFoundError out
        # of ``os.replace``, i.e. proxy death rather than a silently wrong verdict input.
        tmp = f"{countfile}.tmp"
        with open(tmp, "w") as f:
            f.write(str(n))
        os.replace(tmp, countfile)

    # NOTE: the initial write_count(0) is deliberately NOT here. The countfile is the READINESS
    # SIGNAL every caller polls (sandbox/observed.py waits for it, then starts the artifact), so it
    # must not appear until the socket is LISTENING — otherwise it witnesses "the process reached
    # this line", not "the proxy is serving", and a caller proceeding on it can have its first
    # connection REFUSED. A refused connection is never accept()ed, so it is never counted, and the
    # count is this gate's verdict input. Written immediately after listen(), below.

    def handle(conn: socket.socket, n: int) -> None:
        # the connection was ALREADY counted at accept (n is this attempt's number); handle only reads the
        # bounded peek and responds. A slow/silent client can no longer suppress its own count by stalling here.
        try:
            conn.settimeout(5.0)
            try:
                conn.recv(_PEEK)  # bounded peek; deliberately NOT parsed
            except OSError:
                pass
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
    # READINESS, established not asserted: the countfile appears ONLY once the socket is listening,
    # so "countfile exists" now entails "a connection will be accepted" — the property every caller
    # actually depends on. A bind/listen failure therefore leaves NO countfile and the caller times
    # out, rather than proceeding on a file that lied about readiness.
    #
    # The atomic-rename publication above SHARPENS this, and the sharpening is why readiness is named
    # as number-forming semantics rather than mere plumbing. Under truncate-then-write the countfile
    # could EXIST while momentarily empty, so the caller's poll (which reads content, not existence)
    # could see no-reading on a proxy that was already serving. Now the file's FIRST APPEARANCE
    # already carries its value: existence and readability become the same event.
    write_count(0)
    while True:
        conn, _ = srv.accept()
        # COUNT THE CONNECTION AT ACCEPT — before the concurrency gate and before any payload wait. The
        # telemetry contract counts CONNECTIONS (real egress attempts), not completed HTTP requests, so a
        # Slowloris client that connects and stalls cannot go uncounted by occupying a handler for the peek
        # timeout. The count/write is under ``lock`` so concurrent handlers see a consistent value.
        with lock:
            count += 1
            n = count
            write_count(count)
        sem.acquire()
        threading.Thread(target=handle, args=(conn, n), daemon=True).start()


if __name__ == "__main__":
    serve(int(sys.argv[1]), sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "fail_always")
