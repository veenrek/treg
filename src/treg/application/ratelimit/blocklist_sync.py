"""Loading the blocklist from Postgres, its only source, into `blocklist_state`.

Every `rate_limit_blocklist_refresh_s` each process reads the single-row `BlocklistVersion` by
primary key on the dedicated `ratelimit` pool (one connection, a statement timeout); only when the
version differs from the cached one does it read the active entries. A failed poll keeps the cached
list and logs and alerts once per distinct failure. No version row means nothing was ever blocked:
an authoritative empty list, unlike a failed read.

At startup `cold_start` retries the first load for up to `rate_limit_blocklist_cold_start_s`
before the app reports ready; after that the process fails open and the background loop keeps
retrying, reporting `blocklist_cache_empty` until a load succeeds.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import timezone

from sqlmodel import select

from ... import analytics
from ...config import get_settings
from ...domain.ratelimit import BlockEntry, Blocklist
from ...infra.db import ratelimit_session_maker
from ...models import BlocklistEntry, BlocklistVersion
from ...timeutil import utcnow_naive
from . import blocklist_state

log = logging.getLogger("treg.ratelimit")
_COLD_START_RETRY_S = 1.0
_last_problem: str | None = None


def _epoch(t) -> float:
    return t.replace(tzinfo=timezone.utc).timestamp()


async def poll_once() -> bool:
    """One poll. True when the cache now holds the current list (reloaded or unchanged)."""
    global _last_problem
    try:
        async with ratelimit_session_maker() as db:
            row = (await db.execute(select(BlocklistVersion.version).where(BlocklistVersion.id == 1))).first()
            version = int(row[0]) if row else 0
            held = blocklist_state.current()
            if held is not None and held.version == version:
                await db.commit()
                blocklist_state.touch()
                _last_problem = None
                return True
            now = utcnow_naive()
            rows = (await db.execute(select(BlocklistEntry).where(
                BlocklistEntry.revoked_at.is_(None), BlocklistEntry.expires_at > now))).scalars().all()
            await db.commit()
        entries = tuple(BlockEntry(r.kind, r.value, r.reason, _epoch(r.expires_at), r.approved_by)
                        for r in rows if r.kind in ("key_hash", "org_id"))
        blocklist_state.install(Blocklist.build(version, now.isoformat() + "Z", entries))
        _last_problem = None
        return True
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # noqa: BLE001 - a failed poll keeps the cache, never empties it
        blocklist_state.note_error()
        why = f"{type(exc).__name__}: {exc}"[:300]
        if why != _last_problem:
            _last_problem = why
            fields = {"event": "rate_limit_blocklist_load_failed", "reason": why,
                      "kept_version": blocklist_state.current().version if blocklist_state.current() else None}
            log.error("rate_limit_blocklist_load_failed %s", json.dumps(fields, separators=(",", ":")))
            analytics.capture(analytics.SERVER_DISTINCT_ID, "ratelimit_blocklist_load_failed", fields)
        return False


def report_empty() -> None:
    """While no list has loaded: the `blocklist_cache_empty` gauge, once per poll."""
    if blocklist_state.current() is None:
        log.warning("blocklist_cache_empty %s", json.dumps({"event": "blocklist_cache_empty", "value": 1},
                                                           separators=(",", ":")))
        analytics.capture(analytics.SERVER_DISTINCT_ID, "blocklist_cache_empty", {"value": 1})


async def cold_start(timeout_s: float | None = None) -> bool:
    """Retry the first load until it succeeds or the budget runs out. Never raises: past the budget
    the app starts anyway (fail open) and the background loop keeps trying."""
    budget = get_settings().rate_limit_blocklist_cold_start_s if timeout_s is None else timeout_s
    deadline = time.monotonic() + budget
    while True:
        if await poll_once():
            return True
        if time.monotonic() + _COLD_START_RETRY_S > deadline:
            report_empty()
            return False
        await asyncio.sleep(_COLD_START_RETRY_S)


def reset_for_tests() -> None:
    global _last_problem
    _last_problem = None
