"""The outermost HTTP middleware: request admission before auth, the database or money.

HTTP translation only; every decision is `application.ratelimit.limiter`. The client IP is the
ASGI peer (`scope["client"]`, what the load balancer connection reports). A forwarded-for header
is client-controlled and is never read here.
"""

from __future__ import annotations

import asyncio
import hmac
import json

from . import crypto
from .application.ratelimit import inflight, metrics
from .application.ratelimit.limiter import RequestFacts, limiter
from .config import get_settings
from .infra import request_scope


def _header(scope, name: bytes) -> str:
    for key, value in scope.get("headers") or ():
        if key.lower() == name:
            return value.decode("latin-1")
    return ""


def _presented_token(scope) -> str:
    token = _header(scope, b"x-treg-token")
    if token:
        return token
    auth = _header(scope, b"authorization")
    return auth[7:].strip() if auth[:7].lower() == "bearer " else ""


def _server_credential(token: str) -> bool:
    """Treg's own server-side tokens: the admin and blocklist tokens and the house-team tokens the
    deployment uses to call itself. Compared against settings, never trusted from a header."""
    s = get_settings()
    return any(secret and hmac.compare_digest(token.encode(), secret.encode())
               for secret in (s.admin_token, s.blocklist_admin_token, s.onboarding_treg_token,
                              s.jev_treg_token))


OVERLOAD_REASON = "overload_cap"
STREAM_OVERLOAD_REASON = "overload_cap_stream"


def _mcp_stream(scope) -> bool:
    path = scope.get("path", "")
    if path != "/mcp" and not path.startswith("/mcp/"):
        return False
    return scope.get("method") == "GET" or "text/event-stream" in _header(scope, b"accept")


def _overload_exempt(path: str) -> bool:
    return path in get_settings().rate_limit_exempt_path_set or path == "/admin" or path.startswith("/admin/")


class RateLimitMiddleware:
    def __init__(self, app):
        self.app = app
        self._overload: asyncio.Semaphore | None = None
        self._stream_cap: asyncio.Semaphore | None = None

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        inflight.enter()
        try:
            await self._capped(scope, receive, send)
        finally:
            inflight.leave()

    async def _capped(self, scope, receive, send):
        s = get_settings()
        if not s.overload_cap_enabled or _overload_exempt(scope.get("path", "")):
            return await self._admit(scope, receive, send)
        stream = _mcp_stream(scope)
        if stream:
            if self._stream_cap is None:
                self._stream_cap = asyncio.Semaphore(s.overload_cap_stream_size)
            sem, reason = self._stream_cap, STREAM_OVERLOAD_REASON
        else:
            if self._overload is None:
                self._overload = asyncio.Semaphore(s.overload_cap_size)
            sem, reason = self._overload, OVERLOAD_REASON
        if sem.locked():  # full: refuse now, never wait for a permit
            metrics.count("overload_stream_rejects" if stream else "overload_rejects")
            return await _reject(send, _Overloaded(s.overload_cap_retry_after_s, reason))
        await sem.acquire()  # cannot block: no await between locked() and here
        try:
            # A pure ASGI app returns only after the last body chunk (a stream included) is sent,
            # or the client went away, or it raised or was cancelled: the permit is held until then.
            await self._admit(scope, receive, send)
        finally:
            sem.release()

    async def _admit(self, scope, receive, send):
        slot: dict = {}
        scope[request_scope.RATE_LIMIT] = slot
        internal = scope.get(request_scope.INTERNAL)
        token = _presented_token(scope)
        client = scope.get("client")
        path = scope.get("path", "")
        trusted = bool(token and _server_credential(token))
        facts = RequestFacts(
            ip=(client[0] if client else "") or "unknown",
            path=path,
            key_id=request_scope.key_id(token, _header(scope, b"x-treg-org")) if token else None,
            key_hash=crypto.hash_token(token) if token else None,
            alias=(internal or {}).get("alias") or None,
            exempt=bool(internal) or trusted or path in get_settings().rate_limit_exempt_path_set,
            trusted=trusted,
        )
        rl = limiter()
        admission = await rl.admit(facts, slot)
        status = 500

        async def tracked(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            if admission.rejection is not None:
                return await _reject(tracked, admission.rejection)
            await self.app(scope, receive, tracked)
        finally:
            await rl.finish(admission, slot, status=status)


class _Overloaded:
    status = 503

    def __init__(self, retry_after_s: int, reason: str = OVERLOAD_REASON):
        self.headers = ((b"retry-after", str(retry_after_s).encode()),
                        (b"x-treg-overload-reason", reason.encode()))
        self.detail = {"error": "overloaded", "reason": reason, "retry_after_s": retry_after_s}


async def _reject(send, rejection) -> None:
    body = json.dumps({"detail": rejection.detail}, separators=(",", ":")).encode()
    await send({"type": "http.response.start", "status": rejection.status, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        *rejection.headers,
    ]})
    await send({"type": "http.response.body", "body": body})
