"""The outermost HTTP middleware: request rate limiting before auth, the database or money.

HTTP translation only; every decision is `application.ratelimit.limiter`. The client IP is the
ASGI peer (`scope["client"]`, what the load balancer connection reports). A forwarded-for header
is client-controlled and is never read here.
"""

from __future__ import annotations

import hmac
import json

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
    """Treg's own server-side tokens: the env admin token and the house-team tokens the
    deployment uses to call itself. Compared against settings, never trusted from a header."""
    s = get_settings()
    return any(secret and hmac.compare_digest(token.encode(), secret.encode())
               for secret in (s.admin_token, s.onboarding_treg_token, s.jev_treg_token))


class RateLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        slot: dict = {}
        scope[request_scope.RATE_LIMIT] = slot
        internal = scope.get(request_scope.INTERNAL)
        token = _presented_token(scope)
        client = scope.get("client")
        facts = RequestFacts(
            ip=(client[0] if client else "") or "unknown",
            key_id=request_scope.key_id(token, _header(scope, b"x-treg-org")) if token else None,
            alias=(internal or {}).get("alias") or None,
            exempt=bool(internal) or scope.get("path", "") in get_settings().rate_limit_exempt_path_set
            or bool(token and _server_credential(token)),
        )
        rl = limiter()
        admission = await rl.admit(facts, slot)
        try:
            if admission is not None and admission.rejection is not None:
                return await _reject(send, admission.rejection)
            await self.app(scope, receive, send)
        finally:
            await rl.finish(admission, slot)


async def _reject(send, rejection) -> None:
    body = json.dumps({"detail": {
        "error": "rate_limited", "layer": rejection.layer, "reason": rejection.reason,
        "retry_after_s": rejection.retry_after_s, "config_version": rejection.config_version,
    }}, separators=(",", ":")).encode()
    await send({"type": "http.response.start", "status": 429, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"retry-after", str(rejection.retry_after_s).encode()),
        (b"x-treg-ratelimit-layer", rejection.layer.encode()),
        (b"x-treg-ratelimit-reason", rejection.reason.encode()),
    ]})
    await send({"type": "http.response.body", "body": body})
