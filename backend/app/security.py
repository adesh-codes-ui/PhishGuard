"""Minimal, dependency-free ASGI hardening middleware.

Day 10 (API security hardening). Everything here is written as **pure ASGI
middleware** rather than ``BaseHTTPMiddleware`` so request bodies are never
buffered by the middleware layer and no extra dependency is required.

Contents
--------
* :class:`BodySizeLimitMiddleware` - rejects oversized request bodies *before*
  JSON parsing (declared ``Content-Length`` first, then a running byte count for
  chunked/streamed uploads).
* :class:`RateLimitMiddleware` - optional in-memory fixed-window limiter.
  **Per process only**; it does not protect multiple workers or a distributed
  deployment. It counts every HTTP request except CORS preflights and the
  exempt health path -- not just ``/api/*``. See the class docstring and
  ``eval/DAY10_REPORT.md``.
* :class:`SecurityHeadersMiddleware` - adds ``X-Content-Type-Options: nosniff``
  to responses (defence against MIME sniffing of JSON bodies).

None of this touches the analysis logic, scoring, or the response contract for
successful requests.
"""

from __future__ import annotations

import json
import math
import time
from collections import deque
from typing import Any, Awaitable, Callable, Iterable, MutableMapping, Sequence

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

_JSON_CONTENT_TYPE = b"application/json"


class _RequestBodyTooLarge(Exception):
    """Internal signal raised from the wrapped ``receive`` callable."""


async def _send_json(
    send: Send,
    status: int,
    payload: dict[str, Any],
    extra_headers: Sequence[tuple[bytes, bytes]] = (),
) -> None:
    """Send a minimal JSON response without going through the ASGI app."""
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type", _JSON_CONTENT_TYPE),
        (b"content-length", str(len(body)).encode("ascii")),
        *extra_headers,
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body, "more_body": False})


def client_identifier(scope: Scope) -> str:
    """Return a stable client key for rate limiting.

    Only the transport-level peer address (``scope["client"]``) is used.
    ``X-Forwarded-For`` and friends are deliberately **not** trusted here: they
    are attacker-controlled unless a trusted reverse proxy is configured to
    overwrite them, and trusting them blindly would make the limiter trivial to
    bypass. Behind a proxy, either enforce limits at the proxy/API gateway or
    extend this deliberately (see ``eval/DAY10_REPORT.md``).
    """
    client = scope.get("client")
    if client:
        return str(client[0])
    return "unknown"


class BodySizeLimitMiddleware:
    """Reject request bodies larger than ``max_bytes`` with HTTP 413.

    Two checks are applied:

    1. A declared ``Content-Length`` above the limit is rejected immediately,
       without reading the body into memory.
    2. Bodies without (or lying about) ``Content-Length`` are counted as they
       stream in; the limit is enforced mid-stream.

    The 413 body is ``{"detail": "..."}`` so the existing frontend error path
    (which reads ``detail``) keeps working unchanged.
    """

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.max_bytes
        for name, value in scope.get("headers", ()):
            if name == b"content-length":
                try:
                    declared = int(value)
                except (TypeError, ValueError):
                    await _send_json(
                        send, 400, {"detail": "Invalid Content-Length header."}
                    )
                    return
                if declared > limit:
                    await self._reject(send)
                    return

        received = 0
        response_started = False

        async def receive_wrapper() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body") or b"")
                if received > limit:
                    raise _RequestBodyTooLarge()
            return message

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive_wrapper, send_wrapper)
        except _RequestBodyTooLarge:
            if response_started:
                # The app already started responding; we cannot replace it.
                raise
            await self._reject(send)

    async def _reject(self, send: Send) -> None:
        await _send_json(
            send,
            413,
            {"detail": f"Request body is too large (max {self.max_bytes} bytes)."},
        )


class RateLimitMiddleware:
    """Fixed-window in-memory rate limiter (disabled by default).

    .. warning::
       State lives in this process only. Running ``uvicorn --workers N`` (or any
       horizontal scaling) gives each worker its own counter, so the *effective*
       limit is ``N x rate_limit_requests``. This is deliberately documented as
       best-effort abuse mitigation, **not** a security boundary. For real
       protection put a shared limiter (API gateway, reverse proxy, or a
       Redis-backed store) in front of the service.

    The limiter keys on the direct peer address (see :func:`client_identifier`)
    and counts **every** HTTP request except CORS preflights (``OPTIONS``) and
    the exempt paths (health probes). It is deliberately *not* restricted to
    ``/api/*``: any request that reaches the app (e.g. ``/docs`` in development,
    or an unknown path) spends the same budget. Excess traffic is answered with
    HTTP 429 plus a ``Retry-After`` header.
    """

    def __init__(
        self,
        app: Any,
        *,
        enabled: bool = False,
        requests: int = 60,
        window_seconds: int = 60,
        exempt_paths: Sequence[str] = ("/api/health",),
        max_tracked_clients: int = 10_000,
    ) -> None:
        if requests <= 0 or window_seconds <= 0:
            raise ValueError("requests and window_seconds must be positive")
        self.app = app
        self.enabled = enabled
        self.limit = requests
        self.window = window_seconds
        self.exempt_paths = tuple(exempt_paths)
        self.max_tracked_clients = max_tracked_clients
        self._buckets: dict[str, deque[float]] = {}

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if not self.enabled or scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        path = scope.get("path", "")
        # CORS preflights and health probes must never be rate limited.
        if method == "OPTIONS" or path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        retry_after = self._hit(client_identifier(scope), time.monotonic())
        if retry_after is not None:
            await _send_json(
                send,
                429,
                {"detail": "Rate limit exceeded. Try again later."},
                extra_headers=[(b"retry-after", str(retry_after).encode("ascii"))],
            )
            return

        await self.app(scope, receive, send)

    def _hit(self, key: str, now: float) -> int | None:
        """Record a hit; return ``Retry-After`` seconds when the limit is hit."""
        window_start = now - self.window
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self.max_tracked_clients:
                self._evict(now)
            bucket = deque()
            self._buckets[key] = bucket

        while bucket and bucket[0] <= window_start:
            bucket.popleft()

        if len(bucket) >= self.limit:
            return max(1, int(math.ceil(bucket[0] + self.window - now)))
        bucket.append(now)
        return None

    def _evict(self, now: float) -> None:
        """Bound memory: drop idle buckets, then the oldest if still full."""
        cutoff = now - self.window
        stale = [
            key
            for key, bucket in self._buckets.items()
            if not bucket or bucket[-1] <= cutoff
        ]
        for key in stale:
            self._buckets.pop(key, None)
        while len(self._buckets) >= self.max_tracked_clients and self._buckets:
            self._buckets.pop(next(iter(self._buckets)), None)


class SecurityHeadersMiddleware:
    """Add conservative response headers without overriding the app's own."""

    def __init__(self, app: Any, *, headers: Iterable[tuple[bytes, bytes]] | None = None) -> None:
        self.app = app
        self.headers: tuple[tuple[bytes, bytes], ...] = tuple(
            headers or ((b"x-content-type-options", b"nosniff"),)
        )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                present = {name.lower() for name, _ in headers}
                for name, value in self.headers:
                    if name not in present:
                        headers.append((name, value))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)
