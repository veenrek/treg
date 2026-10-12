"""The process's rate-limit policy: one in-memory value, replaced only by the background refresh.

The request path reads `current()` and nothing else. `refresh_once` reads `rl:config` from the
shared store (never from Postgres, which only the admin write path touches), validates it, and
swaps it in. A bad or missing value keeps the last good policy; with none, the env defaults
serve and the fallback is logged and counted so it can alert.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from typing import Literal

from pydantic import ValidationError

from ...config import get_settings
from ...domain.ratelimit import RateLimitConfig
from ...infra import kv

log = logging.getLogger("treg.ratelimit")

Source = Literal["env", "store"]


@dataclass(frozen=True)
class ConfigState:
    config: RateLimitConfig
    version: int  # 0 = the env defaults
    source: Source
    # True while the shared store is configured but no valid document has ever been read.
    fallback: bool


class InvalidConfig(ValueError):
    """A policy document that must not be served or stored."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def validate(raw: object) -> RateLimitConfig:
    """Schema, ranges and the one cross-setting rule: a concurrency entry must outlive a request."""
    try:
        config = RateLimitConfig.model_validate(raw)
    except ValidationError as exc:
        raise InvalidConfig([
            f"{'.'.join(str(p) for p in e['loc']) or '<root>'}: {e['msg']}" for e in exc.errors()
        ]) from None
    timeout = get_settings().call_timeout_s
    if config.concurrency_ttl_s < timeout:
        raise InvalidConfig([f"concurrency_ttl_s: must be at least call_timeout_s ({timeout})"])
    return config


def parse_document(raw: str) -> tuple[int, RateLimitConfig]:
    """`rl:config` is `{"version": <positive int>, "config": {...}}`."""
    try:
        doc = json.loads(raw)
    except ValueError:
        raise InvalidConfig(["not JSON"]) from None
    if not isinstance(doc, dict):
        raise InvalidConfig(["not an object"])
    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise InvalidConfig(["version: must be a positive integer"])
    return version, validate(doc.get("config"))


def encode_document(version: int, config: RateLimitConfig, **meta) -> str:
    return json.dumps({"version": version, "config": config.model_dump(mode="json"), **meta},
                      separators=(",", ":"), sort_keys=True)


def _env_state() -> ConfigState:
    return ConfigState(get_settings().rate_limit_defaults, 0, "env", fallback=kv.configured())


_state: ConfigState | None = None
_last_good: ConfigState | None = None
_last_problem: str | None = None
_fallback_alerts = 0
_store_errors = 0


def current() -> ConfigState:
    global _state
    if _state is None:
        _state = _env_state()
        if _state.fallback:
            _alert_fallback("not loaded yet")
    return _state


def counters() -> dict:
    return {"config_fallback_alerts": _fallback_alerts, "config_store_errors": _store_errors}


def _swap(new: ConfigState) -> None:
    global _state
    old = _state
    _state = new
    if old is None or (old.version, old.source, old.fallback) != (new.version, new.source, new.fallback):
        log.info("rate_limit_config_changed %s", json.dumps({
            "event": "rate_limit_config_changed", "version": new.version, "source": new.source,
            "mode": new.config.mode, "previous_version": old.version if old else None,
            "fallback": new.fallback,
        }, separators=(",", ":")))


def _alert_fallback(why: str) -> None:
    global _fallback_alerts
    _fallback_alerts += 1
    log.error("rate_limit_config_env_fallback %s", json.dumps({
        "event": "rate_limit_config_env_fallback", "reason": why,
        "mode": get_settings().rate_limit_defaults.mode,
    }, separators=(",", ":")))
    from ... import analytics
    analytics.capture(analytics.SERVER_DISTINCT_ID, "ratelimit_config_fallback", {"reason": why})


def _keep(why: str) -> None:
    """Nothing usable was read: keep the last good policy, or serve the env defaults loudly."""
    global _last_problem
    if _last_good is not None:
        if why != _last_problem:
            log.warning("rate_limit_config_kept %s", json.dumps({
                "event": "rate_limit_config_kept", "reason": why, "version": _last_good.version,
            }, separators=(",", ":")))
        _last_problem = why
        _swap(_last_good)
        return
    fresh = _env_state()
    if fresh.fallback and why != _last_problem:
        _alert_fallback(why)
    _last_problem = why
    _swap(fresh)


async def refresh_once(store: kv.Store | None = None) -> ConfigState:
    global _last_good, _last_problem, _store_errors
    current()
    if not kv.configured() and store is None:
        _swap(_env_state())
        return _state
    store = store or kv.store()
    try:
        raw = await store.rl_config_get()
    except kv.Unavailable as exc:
        _store_errors += 1
        _keep(f"store unavailable: {exc}")
        return _state
    if raw is None:
        _keep("missing")
        return _state
    try:
        version, config = parse_document(raw)
    except InvalidConfig as exc:
        digest = hashlib.sha256(raw.encode()).hexdigest()[:12]
        _keep(f"invalid {digest}: {exc}")
        return _state
    _last_good = ConfigState(config, version, "store", fallback=False)
    _last_problem = None
    _swap(_last_good)
    return _state


def reset_for_tests() -> None:
    global _state, _last_good, _last_problem, _fallback_alerts, _store_errors
    _state = _last_good = _last_problem = None
    _fallback_alerts = _store_errors = 0
