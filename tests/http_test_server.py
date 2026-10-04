"""Loopback HTTP servers and resolver aliases for the SafeHttpClient tests (never the live network)."""

import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

PUBLIC_ALIAS = 'public.test'


class ServerStats:
    """What the server saw: request paths and how many body bytes it managed to write."""

    def __init__(self) -> None:
        self.hits: List[str] = []
        self.bytes_written = 0
        self.aborted = False
        self.lock = threading.Lock()

    def wrote(self, n: int) -> None:
        with self.lock:
            self.bytes_written += n


Handler = Callable[[BaseHTTPRequestHandler, ServerStats], None]


@contextmanager
def serve(handle: Handler) -> Iterator[Tuple[int, ServerStats]]:
    """Run a threaded HTTP/1.0 server on 127.0.0.1; `handle` answers every GET/POST."""
    stats = ServerStats()

    class _Handler(BaseHTTPRequestHandler):
        def _dispatch(self) -> None:
            stats.hits.append(self.path)
            try:
                handle(self, stats)
            except (ConnectionError, OSError):
                # The client hung up mid-body: exactly what the size/deadline tests expect.
                stats.aborted = True

        do_GET = _dispatch
        do_POST = _dispatch

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), _Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, stats
    finally:
        server.shutdown()
        server.server_close()


def alias_public_host(monkeypatch: Any, aliases: Optional[Dict[str, str]] = None) -> None:
    """Make `public.test` (and any extra alias) resolve to loopback for the guarded backend only.

    This simulates a public host so the rest of the real stack (pool, redirects, decoding) runs
    end to end against a local server.
    """
    import secure_osint.utils.http_client as http_client

    mapping = {PUBLIC_ALIAS: '127.0.0.1', **(aliases or {})}
    real = http_client.resolve_public_addresses

    def fake(host: str, port: int = 443) -> List[str]:
        return [mapping[host]] if host in mapping else real(host, port)

    monkeypatch.setattr(http_client, 'resolve_public_addresses', fake)
