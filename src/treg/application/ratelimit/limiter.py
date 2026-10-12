"""Admit or refuse one request before auth, the database or money admission see it.

The request path touches only memory and, for a request it counts, one store round trip
(`rl_admit`) plus one more at the end (`rl_release`). Config is never read here: `current()` is
the value the background task last swapped in. A store fault fails open to `LocalLimiter`, and
a short cooldown keeps an outage from adding a timeout to every request.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
import uuid
from dataclasses import dataclass, field

from ...config import get_settings
from ...domain.ratelimit import (
    REASONS,
    Caller,
    KeyCache,
    LayerResult,
    LocalLimiter,
    Plan,
    Verdict,
    plan,
)
from ...infra import kv
from . import config_state, metrics

log = logging.getLogger("treg.ratelimit")


@dataclass(frozen=True)
class RequestFacts:
    ip: str
    key_id: str | None  # infra.request_scope.key_id of the presented key, never the key
    alias: str | None = None  # the outer request's key id, on treg's own in-process requests
    exempt: bool = False


@dataclass(frozen=True)
class Rejection:
    layer: str
    reason: str
    retry_after_s: int
    config_version: int


@dataclass
class Admission:
    state: config_state.ConfigState
    learn: tuple[str, ...]
    plan: Plan | None = None
    verdict: Verdict | None = None
    member: str = ""
    backend: str = ""
    rejection: Rejection | None = None
    released: bool = field(default=False)


def _spec(p: Plan, member: str, enforce: bool) -> tuple[list[str], dict]:
    layers = []
    for layer in p.layers:
        row: dict = {"kind": layer.kind}
        for name, value in (("rate", layer.rate), ("cap", layer.cap),
                            ("trate", layer.tight_rate), ("tcap", layer.tight_cap)):
            if value is not None:
                row[name] = value
        layers.append(row)
    spec: dict = {"layers": layers, "ttl_ms": p.ttl_ms, "retry_ms": p.retry_ms, "member": member,
                  "enforce": 1 if enforce else 0}
    if p.hll is not None:
        spec["hll"] = {"key": p.hll.key, "member": p.hll.member, "ttl_s": p.hll.ttl_s,
                       "eligible": 1 if p.hll.eligible else 0}
        if p.hll.threshold is not None:
            spec["hll"]["threshold"] = p.hll.threshold
    return [layer.key for layer in p.layers], spec


def _verdict(p: Plan, raw: dict) -> Verdict:
    results = tuple(
        LayerResult(layer.name, bool(ok), int(value), None if cap == -1 else int(cap), int(retry))
        for layer, (ok, value, cap, retry) in zip(p.layers, raw["layers"])
    )
    distinct = int(raw.get("distinct", -1))
    return Verdict(bool(raw["admitted"]), results, bool(raw.get("tight")),
                   None if distinct < 0 else distinct)


class RateLimiter:
    def __init__(self) -> None:
        s = get_settings()
        self.cache = KeyCache(ttl_s=s.rate_limit_key_cache_ttl_s, max_size=s.rate_limit_key_cache_size)
        self.local = LocalLimiter(max_keys=s.rate_limit_local_max_keys)
        self._store_skip_until = 0.0
        self._clock = time.time

    # ---- the request path -----------------------------------------------------------------
    async def admit(self, facts: RequestFacts, slot: dict) -> Admission | None:
        state = config_state.current()
        if state.config.mode == "off":
            return None
        now = self._clock()
        learn = tuple(k for k in (facts.key_id, facts.alias) if k)
        caller = self.cache.get(facts.key_id, now=now) if facts.key_id else None
        if any(self.cache.get(k, now=now) is None for k in learn):
            slot["want_caller"] = True
        admission = Admission(state, learn)
        if facts.exempt:
            metrics.count("exempt_requests")
            return admission
        metrics.ip_seen(facts.ip)
        if facts.key_id and caller is None:
            metrics.count("unknown_key_requests")  # includes the post-deploy cold start
        p = plan(state.config, caller, facts.ip, now_s=now)
        enforce = state.config.mode == "enforce"
        member = uuid.uuid4().hex
        verdict, backend = await self._evaluate(p, member, enforce, now)
        admission.plan, admission.verdict, admission.member, admission.backend = p, verdict, member, backend
        self._observe(admission, caller, facts, enforce)
        if enforce and not verdict.admitted:
            first = verdict.first_blocked
            admission.rejection = Rejection(first.name, REASONS[first.name],
                                            max(1, math.ceil(first.retry_ms / 1000)), state.version)
        return admission

    async def finish(self, admission: Admission | None, slot: dict) -> None:
        """Always runs after the downstream app, whatever it raised: give back the concurrency
        slots, then let auth's answer teach the key cache."""
        if admission is None:
            return
        try:
            await self._release(admission)
        finally:
            caller = slot.get("caller")
            if isinstance(caller, dict):
                now = self._clock()
                for key_id in admission.learn:
                    self.cache.put(Caller(key_id=key_id, org_id=caller["org_id"],
                                          org_slug=caller["org_slug"], paid=caller["paid"],
                                          org_created_at=caller["org_created_at"]), now=now)

    # ---- internals ------------------------------------------------------------------------
    async def _evaluate(self, p: Plan, member: str, enforce: bool, now: float) -> tuple[Verdict, str]:
        if kv.configured() and time.monotonic() >= self._store_skip_until:
            keys, spec = _spec(p, member, enforce)
            started = time.monotonic()
            try:
                raw = await kv.store().rl_admit(keys, spec)
                metrics.latency((time.monotonic() - started) * 1000)
                return _verdict(p, raw), "store"
            except kv.Unavailable as exc:
                self._store_fault("admit", exc)
        metrics.count("local_decisions")
        return self.local.admit(p, member=member, enforce=enforce, now_ms=int(now * 1000)), "local"

    def _store_fault(self, op: str, exc: Exception) -> None:
        metrics.count("store_errors")
        self._store_skip_until = time.monotonic() + get_settings().rate_limit_store_cooldown_s
        metrics.event_log(logging.WARNING, "rate_limit_store_unavailable", {"op": op, "error": str(exc)},
                          budget=get_settings().rate_limit_log_max_per_window)

    async def _release(self, admission: Admission) -> None:
        if admission.released or admission.verdict is None or not admission.verdict.admitted:
            return
        admission.released = True
        keys = [layer.key for layer in admission.plan.layers if layer.kind == "conc"]
        if admission.backend == "local":
            self.local.release(tuple(keys), admission.member)
            return
        try:
            await kv.store().rl_release(keys, admission.member)
        except kv.Unavailable as exc:
            # The entry ages out after concurrency_ttl_s; until then it overcounts by one.
            metrics.count("release_errors")
            self._store_fault("release", exc)
        except asyncio.CancelledError:
            metrics.count("release_cancelled")
            raise

    def _observe(self, a: Admission, caller: Caller | None, facts: RequestFacts, enforce: bool) -> None:
        v, p, cfg = a.verdict, a.plan, a.state.config
        subjects = {"key": caller.key_id[:16] if caller else "", "org": caller.org_slug if caller else "",
                    "ip": facts.ip, "global": "global"}
        for r, layer in zip(v.layers, p.layers):
            scope = metrics.SCOPES[r.name]
            metrics.peak(r.name, "rate" if layer.kind == "bucket" else "concurrency", subjects[scope], r.value)
        if v.distinct_orgs is not None:
            metrics.peak("ip_concurrency", "distinct_orgs", facts.ip, v.distinct_orgs)
        paid = bool(caller and caller.paid)
        tier = "tightened" if v.tightened else p.tier
        if not v.blocked:
            metrics.decision(layer="all", reason="none", result="allow", tier=tier, paid=paid,
                             version=a.state.version)
            return
        blocked = (v.first_blocked,) if enforce else v.blocked
        budget = get_settings().rate_limit_log_max_per_window
        for r in blocked:
            result = "reject" if enforce else "shadow_reject"
            metrics.decision(layer=r.name, reason=REASONS[r.name], result=result, tier=tier,
                             paid=paid, version=a.state.version)
            metrics.event_log(
                logging.WARNING if paid else logging.INFO,
                "rate_limit_reject" if enforce else "rate_limit_would_block",
                {"layer": r.name, "reason": REASONS[r.name], "tier": tier, "paid": paid,
                 "mode": cfg.mode, "config_version": a.state.version, "backend": a.backend,
                 "key_hash": caller.key_id[:12] if caller else None,
                 "org": caller.org_slug if caller else None, "ip": facts.ip,
                 "value": r.value, "cap": r.cap, "distinct_orgs": v.distinct_orgs},
                budget=budget, always=paid,
            )


_limiter: RateLimiter | None = None


def limiter() -> RateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = RateLimiter()
    return _limiter


def reset_for_tests() -> None:
    global _limiter
    _limiter = None
    config_state.reset_for_tests()
    metrics.drain()
