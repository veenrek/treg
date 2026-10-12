"""The shared key-value store: expiring counters and optional admission leases.

Render Key Value (Redis protocol) in production, an in-process dictionary when `TREG_KV_URL` is
unset (local development, tests, self-hosters without one). The store holds nothing that must
survive: every key expires, and every caller treats "unavailable" as a safe answer. Reads and
writes are bounded by `_TIMEOUT_S` so a slow store can never hold a call open.

Review-invitation budgets fail closed; money admission leases report unavailability explicitly
so the caller can retain PostgreSQL's original correctness path. New tenants add narrow methods,
not a generic get/set surface. Local counters do not pretend to provide distributed leases.
"""
from __future__ import annotations

import asyncio
import json
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Literal, Protocol

from ..config import get_settings

_TIMEOUT_S = 0.1
_LOCAL_MAX_KEYS = 10_000
log = logging.getLogger("treg.kv")
_clock = time.monotonic
_utcnow = lambda: datetime.now(timezone.utc).isoformat(timespec="milliseconds")
_lease_error_lock = threading.Lock()
_lease_errors: dict[tuple[str, str], dict] = {}
_lease_timings: dict[tuple[str, str], dict] = {}
_LEASE_OUTCOMES = {
    "acquire": {"acquired", "busy", "unavailable", "cancelled"},
    "renew": {"renewed", "lost", "unavailable", "cancelled", "deadline_expired"},
    "release": {"released", "lost", "not_owned", "unavailable", "cancelled"},
}
_LEASE_BUCKETS = (10, 50, 100, 200)

AcquireResult = Literal["acquired", "busy", "unavailable"]
RenewResult = Literal["renewed", "lost", "unavailable", "deadline_expired"]
ReleaseResult = Literal["released", "lost", "not_owned", "unavailable"]
_RENEW_LEASE = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0
"""
_RELEASE_LEASE = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""
# The rate limiter's admission (domain/ratelimit/policy.py runs the same algorithm in-process).
# ARGV[1] is the JSON plan with None fields omitted, because cjson decodes null to a sentinel.
# KEYS lists the layer keys in plan order; the per-second request counters derive from them.
_RL_ADMIT = """
local spec = cjson.decode(ARGV[1])
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local tight = false
local distinct = -1
local h = spec.hll
if h then
  redis.call('PFADD', h.key, h.member)
  redis.call('EXPIRE', h.key, h.ttl_s)
  distinct = redis.call('PFCOUNT', h.key)
  if h.eligible == 1 and h.threshold and distinct > h.threshold then tight = true end
end
local out = {}
local tokens = {}
local all_ok = true
local sec = math.floor(now / 1000)
for i, l in ipairs(spec.layers) do
  local key = KEYS[i]
  local rate = l.rate
  local cap = l.cap
  if tight then
    if l.trate then rate = l.trate end
    if l.tcap then cap = l.tcap end
  end
  local ok = 1
  local value = 0
  local retry = 0
  if l.kind == 'bucket' then
    local qk = key .. ':q:' .. sec
    value = redis.call('INCR', qk)
    redis.call('PEXPIRE', qk, 2000)
    if rate and cap then
      local b = redis.call('HMGET', key, 't', 'ts')
      local tok = tonumber(b[1])
      local ts = tonumber(b[2])
      if not tok then tok = cap; ts = now end
      tok = math.min(cap, tok + math.max(0, now - ts) * rate / 1000)
      tokens[i] = {tok, math.ceil(cap / rate * 1000) + 1000}
      if tok < 1 then ok = 0; retry = math.ceil((1 - tok) * 1000 / rate) end
    end
  else
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now - spec.ttl_ms)
    value = redis.call('ZCARD', key) + 1
    if cap and value > cap then ok = 0; retry = spec.retry_ms end
  end
  if ok == 0 then all_ok = false end
  out[i] = {ok, value, cap or -1, retry}
end
local admitted = all_ok or spec.enforce ~= 1
if admitted then
  for i, l in ipairs(spec.layers) do
    local key = KEYS[i]
    if l.kind == 'bucket' then
      local st = tokens[i]
      if st then
        local tok = st[1]
        if tok >= 1 then tok = tok - 1 end
        redis.call('HSET', key, 't', tostring(tok), 'ts', tostring(now))
        redis.call('PEXPIRE', key, st[2])
      end
    else
      redis.call('ZADD', key, now, spec.member)
      redis.call('PEXPIRE', key, spec.ttl_ms)
    end
  end
end
return cjson.encode({admitted = admitted and 1 or 0, tight = tight and 1 or 0,
                     distinct = distinct, layers = out})
"""
# Publish `rl:config` unless the stored document is a newer version (two admin writes racing).
_RL_CONFIG_SET = """
local cur = redis.call('GET', KEYS[1])
if cur and ARGV[3] ~= '1' then
  local ok, doc = pcall(cjson.decode, cur)
  if ok and type(doc) == 'table' and tonumber(doc.version) and tonumber(doc.version) > tonumber(ARGV[2]) then
    return 0
  end
end
redis.call('SET', KEYS[1], ARGV[1])
return 1
"""
RL_CONFIG_KEY = "rl:config"


class Unavailable(Exception):
    """The store cannot answer a rate-limit operation; the caller fails open."""


class Store(Protocol):
    async def take(self, key: str, limit: int, ttl_s: int) -> bool:
        """Count one use of `key` inside a window that starts at its first use and lasts `ttl_s`.
        True while the window holds `limit` or fewer uses, False past it OR when the store cannot
        answer: a budget that cannot be checked is spent, never free."""

    async def ping(self) -> bool: ...

    async def acquire_lease(self, key: str, token: str, ttl_ms: int) -> AcquireResult: ...

    async def renew_lease(self, key: str, token: str, ttl_ms: int, *,
                          deadline: float | None = None) -> RenewResult: ...

    async def release_lease(self, key: str, token: str) -> ReleaseResult: ...

    # Rate limiting raises `Unavailable` instead of answering for the store; see application/ratelimit.
    async def rl_admit(self, keys: list[str], spec: dict) -> dict: ...

    async def rl_release(self, keys: list[str], member: str) -> None: ...

    async def rl_config_get(self) -> str | None: ...

    async def rl_config_set(self, value: str, version: int, *, force: bool = False) -> bool: ...

    async def rl_memory(self, max_keys: int) -> dict: ...

    async def aclose(self) -> None: ...


class LocalStore:
    """Per-process fallback with the same contract. Bounded so a flood of keys cannot grow it."""

    def __init__(self) -> None:
        self._windows: dict[str, tuple[float, int]] = {}

    async def take(self, key: str, limit: int, ttl_s: int) -> bool:
        now = time.monotonic()
        expires, count = self._windows.get(key, (0.0, 0))
        if expires <= now:
            if len(self._windows) >= _LOCAL_MAX_KEYS:
                self._evict(now)
            expires, count = now + ttl_s, 0
        count += 1
        self._windows[key] = (expires, count)
        return count <= limit

    def _evict(self, now: float) -> None:
        live = {k: v for k, v in self._windows.items() if v[0] > now}
        if len(live) >= _LOCAL_MAX_KEYS:
            live = dict(sorted(live.items(), key=lambda kv: kv[1][0])[_LOCAL_MAX_KEYS // 2:])
        self._windows = live

    async def ping(self) -> bool:
        return True

    async def acquire_lease(self, key: str, token: str, ttl_ms: int) -> AcquireResult:
        return "unavailable"  # Local counters cannot promise cross-process exclusion.

    async def renew_lease(self, key: str, token: str, ttl_ms: int, *,
                          deadline: float | None = None) -> RenewResult:
        return "unavailable"

    async def release_lease(self, key: str, token: str) -> ReleaseResult:
        return "unavailable"

    # No shared store: the limiter runs its own per-process evaluator and the env defaults.
    async def rl_admit(self, keys: list[str], spec: dict) -> dict:
        raise Unavailable("no shared store")

    async def rl_release(self, keys: list[str], member: str) -> None:
        raise Unavailable("no shared store")

    async def rl_config_get(self) -> str | None:
        raise Unavailable("no shared store")

    async def rl_config_set(self, value: str, version: int, *, force: bool = False) -> bool:
        raise Unavailable("no shared store")

    async def rl_memory(self, max_keys: int) -> dict:
        raise Unavailable("no shared store")

    async def aclose(self) -> None:
        self._windows.clear()


class RedisStore:
    def __init__(self, url: str) -> None:
        import redis.asyncio as redis  # server extra; imported here so the light CLI never loads it

        self._client = redis.Redis.from_url(
            url, socket_timeout=_TIMEOUT_S, socket_connect_timeout=_TIMEOUT_S,
            decode_responses=True,
        )

    async def take(self, key: str, limit: int, ttl_s: int) -> bool:
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                async with self._client.pipeline(transaction=True) as pipe:
                    pipe.incr(key)
                    pipe.expire(key, ttl_s, nx=True)  # the window starts at the first use
                    count, _ = await pipe.execute()
            return int(count) <= limit
        except Exception as exc:  # noqa: BLE001 — a store fault is a spent budget, never a call fault
            _note_fault(exc)
            return False

    async def ping(self) -> bool:
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                return bool(await self._client.ping())
        except Exception as exc:  # noqa: BLE001
            _note_fault(exc)
            return False

    async def acquire_lease(self, key: str, token: str, ttl_ms: int) -> AcquireResult:
        """A short-lived admission lease, never the authority for a money write.

        Unavailable is deliberately distinct from contention. Lease callers aggregate faults;
        unlike optional invitation budgets, an outage must not discard a pending settlement.
        """
        started = _clock()
        outcome = "cancelled"
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                acquired = await self._client.set(key, token, nx=True, px=ttl_ms)
            outcome = "acquired" if acquired else "busy"
            return outcome
        except Exception as exc:  # noqa: BLE001 - cancellation still propagates to the owning scope
            outcome = "unavailable"
            _record_lease_error("acquire", exc, started)
            return "unavailable"
        finally:
            _record_lease_timing("acquire", outcome, started)

    async def renew_lease(self, key: str, token: str, ttl_ms: int, *,
                          deadline: float | None = None) -> RenewResult:
        """Retry one transient fault with the original token; never recreate an expired lease.

        The gate supplies the earliest held lease's absolute time.monotonic() deadline.
        Check it before each EVAL: a cooperative timeout may arrive late or be translated
        into a transient error by driver cleanup. These budgets cannot preempt a pause.
        A lost reply may have extended the TTL, but only a confirmed renewal retains ownership.
        """
        stop_at = time.monotonic() + _TIMEOUT_S * 4
        if deadline is not None:
            stop_at = min(stop_at, deadline)
        for attempt in range(2):
            now = time.monotonic()
            if deadline is not None and now >= deadline:
                return "deadline_expired"
            remaining = stop_at - now
            if remaining <= 0:
                break
            started = _clock()
            outcome = "cancelled"
            validity_limited = stop_at == deadline and remaining <= _TIMEOUT_S * 2
            attempt_timeout = asyncio.timeout(min(remaining, _TIMEOUT_S * 2))
            try:
                async with attempt_timeout:
                    renewed = await self._client.eval(_RENEW_LEASE, 1, key, token, ttl_ms)
                outcome = "renewed" if renewed else "lost"
                return outcome
            except Exception as exc:  # noqa: BLE001 - cancellation and ownership loss never retry
                if isinstance(exc, TimeoutError) and attempt_timeout.expired() and validity_limited:
                    outcome = "deadline_expired"
                    return "deadline_expired"
                outcome = "unavailable"
                _record_lease_error("renew", exc, started)
                if deadline is not None and time.monotonic() >= deadline:
                    return "deadline_expired"  # Retain the actual failed attempt above.
                if attempt or not _transient_lease_error(exc):
                    return "unavailable"
            finally:
                _record_lease_timing("renew", outcome, started, retry=bool(attempt))
        return "unavailable"

    async def release_lease(self, key: str, token: str) -> ReleaseResult:
        """Retry one ambiguous transient failure with the same owner-checked delete.

        A retry that finds no matching owner cannot distinguish a lost reply after DEL from an
        expired/replaced lease. It is safe cleanup, but not evidence that this owner lost its
        lease while working. No retry may delete a later owner's token.
        """
        loop = asyncio.get_running_loop()
        deadline = loop.time() + _TIMEOUT_S * 4
        for attempt in range(2):
            if loop.time() >= deadline:
                break
            started = _clock()
            outcome = "cancelled"
            try:
                async with asyncio.timeout_at(min(deadline, loop.time() + _TIMEOUT_S * 2)):
                    released = await self._client.eval(_RELEASE_LEASE, 1, key, token)
                outcome = "released" if released else ("not_owned" if attempt else "lost")
                return outcome
            except Exception as exc:  # noqa: BLE001 - cancellation never retries
                outcome = "unavailable"
                _record_lease_error("release", exc, started)
                if attempt or not _transient_lease_error(exc):
                    return "unavailable"
            finally:
                _record_lease_timing("release", outcome, started, retry=bool(attempt))
        return "unavailable"

    async def rl_admit(self, keys: list[str], spec: dict) -> dict:
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                raw = await self._client.eval(_RL_ADMIT, len(keys), *keys, json.dumps(spec))
            return json.loads(raw)
        except Exception as exc:  # noqa: BLE001 - cancellation still propagates
            raise Unavailable(type(exc).__name__) from exc

    async def rl_release(self, keys: list[str], member: str) -> None:
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                async with self._client.pipeline(transaction=False) as pipe:
                    for key in keys:
                        pipe.zrem(key, member)
                    await pipe.execute()
        except Exception as exc:  # noqa: BLE001
            raise Unavailable(type(exc).__name__) from exc

    async def rl_config_get(self) -> str | None:
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                return await self._client.get(RL_CONFIG_KEY)
        except Exception as exc:  # noqa: BLE001
            raise Unavailable(type(exc).__name__) from exc

    async def rl_config_set(self, value: str, version: int, *, force: bool = False) -> bool:
        try:
            async with asyncio.timeout(_TIMEOUT_S * 2):
                stored = await self._client.eval(_RL_CONFIG_SET, 1, RL_CONFIG_KEY, value,
                                                 str(version), "1" if force else "0")
            return bool(stored)
        except Exception as exc:  # noqa: BLE001
            raise Unavailable(type(exc).__name__) from exc

    async def rl_memory(self, max_keys: int) -> dict:
        """A bounded sample of what `rl:` keys occupy, next to the store's total, so a reader can
        see the limiter crowding money-admission leases out of an LRU-evicting store."""
        try:
            async with asyncio.timeout(_TIMEOUT_S * 20):
                keys: list[str] = []
                async for key in self._client.scan_iter(match="rl:*", count=200):
                    keys.append(key)
                    if len(keys) >= max_keys:
                        break
                sizes: list = []
                if keys:
                    async with self._client.pipeline(transaction=False) as pipe:
                        for key in keys:
                            pipe.memory_usage(key)
                        sizes = await pipe.execute()
                info = await self._client.info("memory")
            return {"rl_keys_sampled": len(keys), "rl_bytes_sampled": sum(int(s or 0) for s in sizes),
                    "rl_sample_truncated": len(keys) >= max_keys,
                    "kv_used_memory": int(info.get("used_memory", 0))}
        except Exception as exc:  # noqa: BLE001
            raise Unavailable(type(exc).__name__) from exc

    async def aclose(self) -> None:
        try:
            await self._client.aclose()
        except Exception:  # noqa: BLE001
            pass


def _transient_lease_error(exc: Exception) -> bool:
    from redis import exceptions as errors

    # Authentication errors inherit ConnectionError, but retrying them cannot recover a lease.
    if isinstance(exc, (errors.AuthenticationError, errors.AuthorizationError, errors.NoPermissionError)):
        return False
    return isinstance(exc, (TimeoutError, errors.TimeoutError, errors.ConnectionError))


def _record_lease_timing(phase: str, outcome: str, started: float, *, retry: bool = False) -> None:
    """Fixed-cardinality command-attempt summaries; no IDs, I/O or per-command events."""
    try:
        if outcome not in _LEASE_OUTCOMES.get(phase, ()):
            return
        elapsed_ms = max(0.0, _clock() - started) * 1000
        bucket = next((f"bucket_le_{limit}_ms" for limit in _LEASE_BUCKETS if elapsed_ms <= limit),
                      "bucket_gt_200_ms")
        with _lease_error_lock:
            row = _lease_timings.setdefault((phase, outcome), {
                "event": "kv_lease_gauge", "phase": phase, "outcome": outcome,
                "count": 0, "retry_count": 0, "elapsed_total_ms": 0.0, "elapsed_max_ms": 0.0,
                **{f"bucket_le_{limit}_ms": 0 for limit in _LEASE_BUCKETS}, "bucket_gt_200_ms": 0,
            })
            row["count"] += 1
            row["retry_count"] += int(retry)
            row["elapsed_total_ms"] += elapsed_ms
            row["elapsed_max_ms"] = max(row["elapsed_max_ms"], elapsed_ms)
            row[bucket] += 1
    except Exception:  # noqa: BLE001 - observation must not change money admission behavior
        pass


def drain_lease_timings() -> list[dict]:
    """Disjoint duration buckets per attempt; only the existing background runner drains them."""
    with _lease_error_lock:
        rows = list(_lease_timings.values())
        _lease_timings.clear()
    return rows


def _record_lease_error(phase: str, exc: Exception, started: float) -> None:
    """Only bounded memory work on the caller; never retain an exception or its message."""
    try:
        from redis import exceptions as errors

        if phase not in {"acquire", "renew", "release"}:
            return
        if isinstance(exc, TimeoutError):
            error_type = "deadline_exceeded"
        elif isinstance(exc, errors.TimeoutError):
            error_type = "redis_timeout"
        elif isinstance(exc, errors.AuthenticationError):
            error_type = "authentication"
        elif isinstance(exc, (errors.NoPermissionError, errors.AuthorizationError)):
            error_type = "permission"
        elif isinstance(exc, errors.ConnectionError):
            error_type = "connection"
        elif isinstance(exc, errors.ResponseError):
            error_type = "response"
        else:
            error_type = "other"
        elapsed_ms = round(max(0.0, _clock() - started) * 1000, 3)
        failed_at = _utcnow()
        with _lease_error_lock:
            # Three phases times seven fixed types; unknown exception classes share "other".
            row = _lease_errors.setdefault((phase, error_type), {
                "event": "kv_lease_error", "phase": phase, "error_type": error_type,
                "count": 0, "first_failed_at": failed_at, "last_failed_at": failed_at,
                "elapsed_max_ms": 0.0, "socket_timeout_ms": _TIMEOUT_S * 1000,
                "operation_deadline_ms": _TIMEOUT_S * 2000,
            })
            row["count"] += 1
            row["last_failed_at"] = failed_at
            row["elapsed_max_ms"] = max(row["elapsed_max_ms"], elapsed_ms)
    except Exception:  # noqa: BLE001 - diagnostics cannot alter lease/fallback behavior
        pass


def drain_lease_errors() -> list[dict]:
    """Minute/worker-exit summaries for the existing background diagnostic log sink."""
    with _lease_error_lock:
        rows = list(_lease_errors.values())
        _lease_errors.clear()
    return rows


def _note_fault(exc: BaseException) -> None:
    from .. import analytics  # lazy: analytics imports config, and this module is imported early

    log.warning("kv unavailable: %s: %s", type(exc).__name__, exc)
    analytics.capture_fault(exc, component="kv")


_store: Store | None = None


def store() -> Store:
    """The process-wide store, built on first use from `TREG_KV_URL`."""
    global _store
    if _store is None:
        url = get_settings().kv_url
        _store = RedisStore(url) if url else LocalStore()
    return _store


def configured() -> bool:
    return bool(get_settings().kv_url)


async def close() -> None:
    global _store
    if _store is not None:
        await _store.aclose()
        _store = None
