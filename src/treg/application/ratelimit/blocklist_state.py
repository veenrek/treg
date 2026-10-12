"""The process's blocklist: one in-memory `Blocklist`, replaced only by the background sync.

`refresh_once` reads `rl:blocklist` every few seconds. An unreadable store, a missing key, a
payload that does not parse or an unknown `schema_version` all keep the last good list; the last
two alert. None of them is ever read as an empty list: before a first good read the process has
no list (`loaded` is false), which the status endpoint and gauge report. A missing key is flagged
for `background`, which restores it from Postgres.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time

from ... import analytics
from ...domain.ratelimit import Blocklist, InvalidBlocklist, parse_blocklist
from ...infra import kv

log = logging.getLogger("treg.ratelimit")
_clock = time.monotonic

_list: Blocklist | None = None
_loaded_at = 0.0
_missing = False
_last_problem: str | None = None
_counts = {"blocklist_invalid": 0, "blocklist_missing": 0, "blocklist_store_errors": 0}


def current() -> Blocklist | None:
    return _list


def missing() -> bool:
    return _missing


def counters() -> dict:
    return dict(_counts)


def status(*, now: float) -> dict:
    return {"blocklist_loaded": _list is not None,
            "blocklist_version": _list.version if _list else None,
            "blocklist_entries": _list.active(now=now) if _list else None,
            "blocklist_age_s": round(_clock() - _loaded_at) if _list else None}


def _note(kind: str, why: str, *, alert: bool) -> None:
    global _last_problem
    _counts[kind] += 1
    if why == _last_problem:
        return
    _last_problem = why
    fields = {"event": f"rate_limit_{kind}", "reason": why,
              "kept_version": _list.version if _list else None}
    if alert:
        log.error("rate_limit_%s %s", kind, json.dumps(fields, separators=(",", ":")))
        analytics.capture(analytics.SERVER_DISTINCT_ID, f"ratelimit_{kind}", fields)
    else:
        log.warning("rate_limit_%s %s", kind, json.dumps(fields, separators=(",", ":")))


async def refresh_once(store: kv.Store | None = None) -> Blocklist | None:
    global _list, _loaded_at, _missing, _last_problem
    if not kv.configured() and store is None:
        return _list
    store = store or kv.store()
    try:
        raw = await store.rl_get(kv.RL_BLOCKLIST_KEY)
    except kv.Unavailable as exc:
        _note("blocklist_store_errors", f"store unavailable: {exc}", alert=False)
        return _list
    _missing = raw is None
    if raw is None:
        _note("blocklist_missing", "missing", alert=False)
        return _list
    try:
        parsed = parse_blocklist(raw)
    except InvalidBlocklist as exc:
        digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
        _note("blocklist_invalid", f"invalid {digest}: {exc}", alert=True)
        return _list
    if _list is None or parsed.version != _list.version:
        log.info("rate_limit_blocklist_changed %s", json.dumps({
            "event": "rate_limit_blocklist_changed", "version": parsed.version,
            "previous_version": _list.version if _list else None,
            "entries": parsed.active(now=time.time()),
        }, separators=(",", ":")))
    _list, _loaded_at, _last_problem = parsed, _clock(), None
    return _list


def reset_for_tests() -> None:
    global _list, _loaded_at, _missing, _last_problem
    _list, _loaded_at, _missing, _last_problem = None, 0.0, False, None
    for k in _counts:
        _counts[k] = 0
