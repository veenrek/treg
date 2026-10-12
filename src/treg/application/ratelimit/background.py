"""The rate limiter's background work, started by every role's lifespan.

- `config_loop`: reads `rl:config` every `rate_limit_config_refresh_s`.
- `blocklist_loop`: polls the blocklist version in Postgres every `rate_limit_blocklist_refresh_s`
  (`blocklist_sync`), reporting `blocklist_cache_empty` until a list has loaded, and writes this
  process's heartbeat (versions and modes) to `rl:live:<instance>`, which the admin status reads.
- `maybe_restore`: when `rl:config` is missing (the store evicts by LRU), republishes it from
  Postgres on the `ratelimit` pool. A store claim limits that to once per
  `rate_limit_republish_interval_s` across every process; missing never means empty.
- `maintenance_loop`: flushes surge signals and emits the window's telemetry.

A failed pass never ends a loop. Nothing here runs on the request path.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from ... import analytics
from ...config import get_settings
from ...infra import kv
from ...infra.db import install_checkout_peaks, pool_snapshot, ratelimit_session_maker, take_checkout_peaks
from ...infra.money_timing import PROCESS_INSTANCE
from . import admin as config_admin
from . import blocklist_state, blocklist_sync, config_state, inflight, metrics, receipts, signals_flush
from .limiter import limiter

log = logging.getLogger("treg.ratelimit")
_MEMORY_SAMPLE_KEYS = 500
_last_restore: dict[str, float] = {}


def process_status() -> dict:
    state = config_state.current()
    age = config_state.age_s()
    return {
        "process_instance": PROCESS_INSTANCE, "mode": state.config.mode,
        "blocklist_mode": state.config.blocklist_mode, "config_version": state.version,
        "config_source": state.source, "config_fallback": state.fallback,
        "config_degraded": state.degraded, "config_age_s": None if age is None else round(age),
        **blocklist_state.status(now=time.time()),
    }


async def maybe_restore(name: str) -> int | None:
    """Republish `rl:<name>` from Postgres when it went missing, at most once per interval."""
    if name != "config" or not config_state.missing() or not kv.configured():
        return None
    interval = get_settings().rate_limit_republish_interval_s
    now = time.monotonic()
    if now - _last_restore.get(name, -interval) < interval:
        return None
    _last_restore[name] = now
    try:
        if not await kv.store().rl_claim(f"rl:restore:{name}", interval):
            return None  # another process restored it inside this interval
    except kv.Unavailable:
        return None
    async with ratelimit_session_maker() as db:
        version = await config_admin.restore(db)
    log.warning("rate_limit_%s_restored %s", name, json.dumps(
        {"event": f"rate_limit_{name}_restored", "version": version}, separators=(",", ":")))
    metrics.count(f"{name}_restores")
    return version


async def emit() -> tuple[list[dict], dict]:
    rows, gauge = metrics.drain()
    gauge.update({**process_status(), "key_cache_size": len(limiter().cache),
                  **config_state.counters(), **blocklist_state.counters()})
    if kv.configured():
        try:
            gauge.update(await kv.store().rl_memory(_MEMORY_SAMPLE_KEYS))
        except kv.Unavailable:
            gauge["rl_memory_unavailable"] = True
    for row in rows:
        analytics.capture(analytics.SERVER_DISTINCT_ID, "ratelimit_decision",
                          {**row, "process_instance": PROCESS_INSTANCE})
        if row["paid"] and row["result"] in ("reject", "shadow_reject", "log_only"):
            # The line a "paid org was refused" alert matches, independent of the analytics sink.
            log.warning("ratelimit_decision %s", json.dumps({"event": "ratelimit_decision", **row},
                                                            separators=(",", ":")))
    # The per-process version/mode metric: one gauge per process per window.
    analytics.capture(analytics.SERVER_DISTINCT_ID, "ratelimit_gauge", gauge)
    log.info("ratelimit_gauge %s", json.dumps({"event": "ratelimit_gauge", **gauge},
                                              separators=(",", ":"), default=str))
    return rows, gauge


async def _forever(interval_s: float, step) -> None:
    while True:
        try:
            await step()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - the limiter keeps its last good state
            log.exception("rate limit background pass failed")
        await asyncio.sleep(interval_s)


async def config_step() -> None:
    await config_state.refresh_once()
    await maybe_restore("config")


async def blocklist_step() -> None:
    await blocklist_sync.poll_once()
    blocklist_sync.report_empty()
    if kv.configured():
        try:
            await kv.store().rl_heartbeat(kv.RL_LIVE_PREFIX + PROCESS_INSTANCE,
                                          json.dumps(process_status(), separators=(",", ":")),
                                          int(get_settings().rate_limit_blocklist_refresh_s * 6))
        except kv.Unavailable:
            pass


async def maintenance_step() -> None:
    await signals_flush.flush()
    await emit()


async def config_loop() -> None:
    await _forever(get_settings().rate_limit_config_refresh_s, config_step)


async def blocklist_loop() -> None:
    await _forever(get_settings().rate_limit_blocklist_refresh_s, blocklist_step)


async def maintenance_loop() -> None:
    s = get_settings()
    await asyncio.sleep(s.surge_flush_s)
    await _forever(s.surge_flush_s, maintenance_step)


class InflightGauge:
    """Emits the window's true peaks every `inflight_gauge_emit_s`: in flight is updated on every
    request (`inflight.enter`), DB checkouts on every pool checkout (`install_checkout_peaks`); both
    reset at each emit. No I/O; a failed pass is swallowed."""

    def __init__(self) -> None:
        self.opened = time.monotonic()
        install_checkout_peaks()

    def emit(self) -> dict:
        snapshot = pool_snapshot()
        peaks = take_checkout_peaks(snapshot)
        row = {
            "event": "inflight_gauge", "pid": os.getpid(), "process_instance": PROCESS_INSTANCE,
            "window_s": round(time.monotonic() - self.opened, 1),
            "in_flight": inflight.current(), "in_flight_peak": inflight.take_peak(),
            "overload_cap_enabled": get_settings().overload_cap_enabled,
            "overload_cap_size": get_settings().overload_cap_size,
            **{f"db_{name}_checked_out": r["checked_out"] for name, r in snapshot.items()},
            **{f"db_{name}_peak": peaks.get(name, 0) for name in snapshot},
            **{f"db_{name}_capacity": r["capacity"] for name, r in snapshot.items()},
        }
        self.opened = time.monotonic()
        log.info("inflight_gauge %s", json.dumps(row, separators=(",", ":")))
        analytics.capture(analytics.SERVER_DISTINCT_ID, "inflight_gauge",
                          {k: v for k, v in row.items() if k != "event"})
        return row


async def inflight_loop() -> None:
    s = get_settings()
    if not s.inflight_gauge_enabled:
        return
    gauge = InflightGauge()
    while True:
        await asyncio.sleep(s.inflight_gauge_emit_s)
        try:
            gauge.emit()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - telemetry never stops or fails anything
            log.exception("inflight gauge pass failed")


async def run() -> None:
    tasks = [asyncio.create_task(loop())
             for loop in (config_loop, blocklist_loop, maintenance_loop, inflight_loop)]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        try:
            await signals_flush.flush()  # the last partial minute
            await receipts.drain()
        except Exception:  # noqa: BLE001
            pass


def reset_for_tests() -> None:
    _last_restore.clear()
    signals_flush.reset_for_tests()
    blocklist_sync.reset_for_tests()
