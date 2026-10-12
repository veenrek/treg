"""The one background task: refresh the policy from `rl:config`, emit the window's telemetry."""

from __future__ import annotations

import asyncio
import json
import logging
import time

from ... import analytics
from ...config import get_settings
from ...infra import kv
from . import config_state, metrics
from .limiter import limiter

log = logging.getLogger("treg.ratelimit")
_MEMORY_SAMPLE_KEYS = 500


async def emit() -> tuple[list[dict], dict]:
    rows, gauge = metrics.drain()
    state = config_state.current()
    gauge.update({
        "mode": state.config.mode, "config_version": state.version, "config_source": state.source,
        "config_fallback": state.fallback, "key_cache_size": len(limiter().cache),
        **config_state.counters(),
    })
    if kv.configured():
        try:
            gauge.update(await kv.store().rl_memory(_MEMORY_SAMPLE_KEYS))
        except kv.Unavailable:
            gauge["rl_memory_unavailable"] = True
    for row in rows:
        analytics.capture(analytics.SERVER_DISTINCT_ID, "ratelimit_decision", row)
        if row["paid"] and row["result"] in ("reject", "shadow_reject"):
            # The line a "paid org was refused" alert matches, independent of the analytics sink.
            log.warning("ratelimit_decision %s", json.dumps({"event": "ratelimit_decision", **row},
                                                            separators=(",", ":")))
    analytics.capture(analytics.SERVER_DISTINCT_ID, "ratelimit_gauge", gauge)
    log.info("ratelimit_gauge %s", json.dumps({"event": "ratelimit_gauge", **gauge},
                                              separators=(",", ":"), default=str))
    return rows, gauge


async def run() -> None:
    """Started by every role's lifespan. A failed pass never ends the loop."""
    s = get_settings()
    opened = time.monotonic()
    while True:
        try:
            await config_state.refresh_once()
            if time.monotonic() - opened >= s.rate_limit_metrics_emit_s:
                opened = time.monotonic()
                await emit()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - the limiter keeps its last policy
            log.exception("rate limit background pass failed")
        await asyncio.sleep(s.rate_limit_config_refresh_s)
