"""The process's admission policy: one in-memory value, replaced only by the background refresh.

The request path reads `current()` and nothing else. `refresh_once` reads `rl:config` from the
shared store, validates it, and swaps it in. A bad, missing or unreadable value keeps the last good
policy, for at most `rate_limit_config_max_age_s`; past that an `enforce` policy is served as
`shadow` and the process alerts. With no good policy at all the env defaults serve (their mode is
`off` or `shadow` by construction) and the process alerts. A missing key is flagged for
`background`, which restores it from Postgres; this module never touches the database.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, replace
from typing import Literal

from pydantic import ValidationError

from ... import analytics
from ...config import get_settings
from ...domain.ratelimit import RateLimitConfig
from ...infra import kv

log = logging.getLogger("treg.ratelimit")

Source = Literal["env", "store"]
_clock = time.monotonic


@dataclass(frozen=True)
class ConfigState:
    config: RateLimitConfig
    version: int  # 0 = the env defaults
    source: Source
    # True while the shared store is configured but no valid document has been read.
    fallback: bool
    # True while serving a last good policy older than the max age, demoted to shadow.
    degraded: bool = False


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
_last_good_at = 0.0  # monotonic time of the last successful read
_last_problem: str | None = None
_missing = False
_alerts = {"config_fallback_alerts": 0, "config_stale_alerts": 0, "config_store_errors": 0}


def current() -> ConfigState:
    global _state
    if _state is None:
        _state = _env_state()  # until the first refresh; only a refresh that finds nothing alerts
    return _state


def missing() -> bool:
    """`rl:config` was absent at the last read: `background` should restore it from Postgres."""
    return _missing


def age_s() -> float | None:
    return None if _last_good is None else _clock() - _last_good_at


def counters() -> dict:
    return dict(_alerts)


def _swap(new: ConfigState) -> None:
    global _state
    old = _state
    _state = new
    if old is None or (old.version, old.source, old.fallback, old.degraded, old.config.mode) != (
            new.version, new.source, new.fallback, new.degraded, new.config.mode):
        log.info("rate_limit_config_changed %s", json.dumps({
            "event": "rate_limit_config_changed", "version": new.version, "source": new.source,
            "mode": new.config.mode, "blocklist_mode": new.config.blocklist_mode,
            "previous_version": old.version if old else None, "fallback": new.fallback,
            "degraded": new.degraded,
        }, separators=(",", ":")))


def _alert(kind: str, event: str, **fields) -> None:
    _alerts[kind] += 1
    log.error("%s %s", event, json.dumps({"event": event, **fields}, separators=(",", ":")))
    analytics.capture(analytics.SERVER_DISTINCT_ID, event.replace("rate_limit_", "ratelimit_"), fields)


def _keep(why: str) -> None:
    """Nothing usable was read: keep the last good policy (demoted past its max age), or serve the
    env defaults loudly."""
    global _last_problem
    first = why != _last_problem
    _last_problem = why
    if _last_good is not None:
        stale = _clock() - _last_good_at > get_settings().rate_limit_config_max_age_s
        if not stale:
            if first:
                log.warning("rate_limit_config_kept %s", json.dumps({
                    "event": "rate_limit_config_kept", "reason": why, "version": _last_good.version,
                }, separators=(",", ":")))
            _swap(_last_good)
            return
        demoted = _last_good.config
        if demoted.mode == "enforce":
            demoted = demoted.model_copy(update={"mode": "shadow"})
        if not current().degraded:
            _alert("config_stale_alerts", "rate_limit_config_stale", reason=why,
                   version=_last_good.version, age_s=round(_clock() - _last_good_at),
                   mode=demoted.mode)
        _swap(replace(_last_good, config=demoted, degraded=True))
        return
    fresh = _env_state()
    if fresh.fallback and first:
        _alert("config_fallback_alerts", "rate_limit_config_env_fallback", reason=why,
               mode=fresh.config.mode)
    _swap(fresh)


async def refresh_once(store: kv.Store | None = None) -> ConfigState:
    global _last_good, _last_good_at, _last_problem, _missing
    current()
    if not kv.configured() and store is None:
        _swap(_env_state())
        return _state
    store = store or kv.store()
    try:
        raw = await store.rl_get(kv.RL_CONFIG_KEY)
    except kv.Unavailable as exc:
        _alerts["config_store_errors"] += 1
        _keep(f"store unavailable: {exc}")
        return _state
    _missing = raw is None
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
    _last_good_at = _clock()
    _last_problem = None
    _swap(_last_good)
    return _state


def reset_for_tests() -> None:
    global _state, _last_good, _last_good_at, _last_problem, _missing
    _state = _last_good = _last_problem = None
    _last_good_at = 0.0
    _missing = False
    for k in _alerts:
        _alerts[k] = 0
