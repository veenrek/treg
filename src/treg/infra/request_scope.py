"""ASGI scope keys shared by the rate-limit middleware, auth, and treg's in-process clients.

Scope keys, not headers: a network client can send any header, but only code in this process
can put a key into the ASGI scope, so `INTERNAL` is a server-side credential rather than a claim.
"""

from __future__ import annotations

from .. import crypto

# A dict the rate-limit middleware puts in the scope. Auth reads `want_caller` and writes `caller`.
RATE_LIMIT = "treg.rate_limit"
# Set by `internal_app` on requests treg makes to itself (MCP tools, hub steps).
INTERNAL = "treg.internal"


def key_id(token: str, org_header: str = "") -> str:
    """The cache identity of a presented key. The team header is part of it because one identity
    token can act for any of its user's teams."""
    return crypto.hash_token(f"{token}\n{org_header}")


def internal_app(app, *, outer_token: str = ""):
    """Wrap treg's own ASGI app for an in-process client. The outer request was already counted;
    `alias` lets the inner request's auth result also teach the key cache the outer token."""
    marker = {"alias": key_id(outer_token) if outer_token else ""}

    async def wrapped(scope, receive, send):
        if scope.get("type") == "http":
            scope = {**scope, INTERNAL: marker}
        await app(scope, receive, send)

    return wrapped
