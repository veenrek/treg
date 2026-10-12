"""Admit or refuse one request before auth, the database or money admission see it.

Order: the blocklist by key hash (before auth, and by org when the key's org is already cached),
then the global concurrency ceiling, last. After auth, `access.require_member` calls the slot's
`check_org` so an org on the blocklist is refused even on a key's first request.

The request path reads only memory (`config_state.current()`, `blocklist_state.current()`, the key
cache) plus, for the ceiling, one store round trip in and one out. A store fault fails open to
`LocalCeiling`, and a short cooldown keeps an outage from adding a timeout to every request.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass, field

from ...config import get_settings
from ...domain.ratelimit import (
    BLOCKLIST_REASONS,
    GLOBAL_REASON,
    BlockEntry,
    Caller,
    GlobalVerdict,
    KeyCache,
    LocalCeiling,
    retry_seconds,
)
from ...infra import kv
from . import blocklist_state, config_state, metrics, signals

log = logging.getLogger("treg.ratelimit")


@dataclass(frozen=True)
class RequestFacts:
    ip: str
    path: str = ""
    key_id: str | None = None  # request_scope.key_id: the cache identity, never the key
    key_hash: str | None = None  # SHA-256 of the key, the blocklist's `key_hash`
    alias: str | None = None  # the outer request's key id, on treg's own in-process requests
    exempt: bool = False  # the global ceiling and signals skip it
    trusted: bool = False  # a server-side credential: the blocklist skips it too


@dataclass(frozen=True)
class Rejection:
    status: int
    headers: tuple[tuple[bytes, bytes], ...]
    detail: dict


@dataclass
class Admission:
    state: config_state.ConfigState
    learn: tuple[str, ...]
    caller: Caller | None = None
    verdict: GlobalVerdict | None = None
    member: str = ""
    backend: str = ""
    rejection: Rejection | None = None
    visit: signals.Visit | None = None
    blocked: bool = False
    released: bool = field(default=False)


def _tier(caller: Caller | None) -> str:
    return "unknown" if caller is None else ("paid" if caller.paid else "unpaid")


class RateLimiter:
    def __init__(self) -> None:
        s = get_settings()
        self.cache = KeyCache(ttl_s=s.rate_limit_key_cache_ttl_s, max_size=s.rate_limit_key_cache_size)
        self.local = LocalCeiling()
        self._store_skip_until = 0.0
        self._clock = time.time

    # ---- the request path -----------------------------------------------------------------
    async def admit(self, facts: RequestFacts, slot: dict) -> Admission:
        state = config_state.current()
        cfg = state.config
        now = self._clock()
        learn = tuple(k for k in (facts.key_id, facts.alias) if k)
        caller = self.cache.get(facts.key_id, now=now) if facts.key_id else None
        if any(self.cache.get(k, now=now) is None for k in learn):
            slot["want_caller"] = True
        a = Admission(state, learn, caller=caller)

        if cfg.blocklist_mode != "off" and not facts.trusted:
            slot["check_org"] = lambda org_id: self._check_org(a, facts, org_id)
            hit = self._match("key_hash", facts.key_hash)
            kind = "key_hash"
            if hit is None and caller is not None:
                hit, kind = self._match("org_id", str(caller.org_id)), "org_id"
            if hit is not None:
                a.rejection = self._blocked(a, facts, kind, hit)
                if a.rejection is not None:
                    return a

        if facts.exempt:
            metrics.count("exempt_requests")
            return a
        metrics.ip_seen(facts.ip)
        if facts.key_id and caller is None:
            metrics.count("unknown_key_requests")  # includes the post-deploy cold start
        a.visit = signals.enter(facts.ip, caller.org_id if caller else None, facts.key_id, facts.path,
                                unknown=bool(facts.key_id) and caller is None)
        if cfg.mode == "off":
            return a
        # A key not yet cached is counted but never refused: refused before auth it would never be
        # learned, so a paid org's first request after a deploy could be refused forever.
        enforce = cfg.mode == "enforce" and caller is not None
        a.member = uuid.uuid4().hex
        a.verdict, a.backend = await self._ceiling(a.member, cfg.global_cap(_tier(caller)), cfg, enforce, now)
        self._observe_ceiling(a, facts, enforce)
        if not a.verdict.admitted:
            retry = retry_seconds(a.verdict.retry_ms)
            a.rejection = Rejection(429, (
                (b"retry-after", str(retry).encode()),
                (b"x-treg-ratelimit-layer", b"global_concurrency"),
                (b"x-treg-ratelimit-reason", GLOBAL_REASON.encode()),
            ), {"error": "rate_limited", "layer": "global_concurrency", "reason": GLOBAL_REASON,
                "retry_after_s": retry, "config_version": state.version, "mode": cfg.mode})
        return a

    async def finish(self, a: Admission, slot: dict, *, status: int) -> None:
        """Always runs after the downstream app, whatever it raised: give back the ceiling slot,
        record the signal, then let auth's answer teach the key cache."""
        try:
            await self._release(a)
        finally:
            caller = slot.get("caller")
            org_id = a.caller.org_id if a.caller else (caller.get("org_id") if isinstance(caller, dict) else None)
            signals.leave(a.visit, status=status, org_id=org_id, blocked=a.blocked or bool(slot.get("blocked")))
            if isinstance(caller, dict):
                now = self._clock()
                for key_id in a.learn:
                    self.cache.put(Caller(key_id=key_id, org_id=caller["org_id"],
                                          org_slug=caller["org_slug"], paid=caller["paid"],
                                          org_created_at=caller["org_created_at"]), now=now)

    # ---- the blocklist ----------------------------------------------------------------------
    def _match(self, kind: str, value: str | None) -> BlockEntry | None:
        bl = blocklist_state.current()
        if bl is None or not value:
            return None
        return bl.match(kind, value, now=self._clock())

    def _check_org(self, a: Admission, facts: RequestFacts, org_id: int) -> dict | None:
        """Called by auth once it knows the org. Returns the 403 detail when it must refuse."""
        hit = self._match("org_id", str(org_id))
        if hit is None:
            return None
        rejection = self._blocked(a, facts, "org_id", hit, org_id=org_id)
        return rejection.detail if rejection is not None else None

    def _blocked(self, a: Admission, facts: RequestFacts, kind: str, entry: BlockEntry, *,
                 org_id: int | None = None) -> Rejection | None:
        cfg, bl = a.state.config, blocklist_state.current()
        enforce = cfg.blocklist_mode == "enforce_403"
        reason = BLOCKLIST_REASONS[kind]
        a.blocked = True
        paid = bool(a.caller and a.caller.paid)
        metrics.decision(layer="blocklist", reason=reason, result="reject" if enforce else "log_only",
                         tier=_tier(a.caller), paid=paid, version=a.state.version, mode=cfg.blocklist_mode)
        metrics.event_log(logging.WARNING, "rate_limit_blocklist_match", {
            "match": kind, "reason": reason, "mode": cfg.blocklist_mode, "enforced": enforce,
            "blocklist_version": bl.version if bl else None, "config_version": a.state.version,
            "key_hash": facts.key_hash[:12] if facts.key_hash else None,
            "org_id": org_id or (a.caller.org_id if a.caller else None), "ip": facts.ip, "paid": paid,
        }, budget=get_settings().rate_limit_log_max_per_window, always=paid)
        if not enforce:
            return None
        # Only the fixed code: the operator's reason text stays in the audit record, so a refused
        # caller learns nothing about what was detected.
        return Rejection(403, ((b"x-treg-block-reason", reason.encode()),), {
            "error": "blocked", "reason": reason, "blocklist_version": bl.version if bl else None,
        })

    # ---- the global ceiling -----------------------------------------------------------------
    async def _ceiling(self, member: str, cap: int | None, cfg, enforce: bool, now: float) -> tuple[GlobalVerdict, str]:
        ttl_ms, retry_ms = cfg.concurrency_ttl_s * 1000, cfg.concurrency_retry_after_s * 1000
        if kv.configured() and time.monotonic() >= self._store_skip_until:
            started = time.monotonic()
            try:
                admitted, ok, n = await kv.store().rl_admit_global(member, cap, ttl_ms, enforce)
                metrics.latency((time.monotonic() - started) * 1000)
                return GlobalVerdict(admitted, ok, n, cap, 0 if ok else retry_ms), "store"
            except kv.Unavailable as exc:
                self._store_fault("admit", exc)
        metrics.count("local_decisions")
        return self.local.admit(member=member, cap=cap, ttl_ms=ttl_ms, retry_ms=retry_ms,
                                enforce=enforce, now_ms=int(now * 1000)), "local"

    def _store_fault(self, op: str, exc: Exception) -> None:
        metrics.count("store_errors")
        self._store_skip_until = time.monotonic() + get_settings().rate_limit_store_cooldown_s
        metrics.event_log(logging.WARNING, "rate_limit_store_unavailable", {"op": op, "error": str(exc)},
                          budget=get_settings().rate_limit_log_max_per_window)

    async def _release(self, a: Admission) -> None:
        if a.released or a.verdict is None or not a.verdict.admitted:
            return
        a.released = True
        if a.backend == "local":
            self.local.release(a.member)
            return
        try:
            await kv.store().rl_release(a.member)
        except kv.Unavailable as exc:
            # The entry ages out after concurrency_ttl_s; until then it overcounts by one.
            metrics.count("release_errors")
            self._store_fault("release", exc)
        except asyncio.CancelledError:
            metrics.count("release_cancelled")
            raise

    def _observe_ceiling(self, a: Admission, facts: RequestFacts, enforce: bool) -> None:
        v, cfg, caller = a.verdict, a.state.config, a.caller
        metrics.peak("global", "concurrency", "global", v.in_flight)
        paid, tier = bool(caller and caller.paid), _tier(caller)
        if v.ok:
            metrics.decision(layer="all", reason="none", result="allow", tier=tier, paid=paid,
                             version=a.state.version, mode=cfg.mode)
            return
        result = "reject" if enforce else "shadow_reject"
        metrics.decision(layer="global_concurrency", reason=GLOBAL_REASON, result=result, tier=tier,
                         paid=paid, version=a.state.version, mode=cfg.mode)
        metrics.event_log(
            logging.WARNING if paid else logging.INFO,
            "rate_limit_reject" if enforce else "rate_limit_would_block",
            {"layer": "global_concurrency", "reason": GLOBAL_REASON, "tier": tier, "paid": paid,
             "mode": cfg.mode, "config_version": a.state.version, "backend": a.backend,
             "key_hash": facts.key_hash[:12] if facts.key_hash else None,
             "org": caller.org_slug if caller else None, "ip": facts.ip,
             "in_flight": v.in_flight, "cap": v.cap},
            budget=get_settings().rate_limit_log_max_per_window, always=paid,
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
    blocklist_state.reset_for_tests()
    signals.reset_for_tests()
    metrics.drain()
