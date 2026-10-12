"""Request rate limiting: the config schema, the layer plan, and the in-process evaluator.

Pure rules, no I/O. The Redis evaluator (`infra/kv.py` `_RL_ADMIT`) and `LocalLimiter` below run
the same two-phase algorithm over the same `Plan`: phase one reads every layer, phase two consumes
a token from each bucket and adds the request to each concurrency set, but only when every layer
allowed it or the mode is not `enforce`. A layer whose threshold is unset is still measured.

Layers are evaluated in `LAYERS` order and the global ceiling is last, so a request the key, org
or IP layer would refuse never occupies a global slot that a paid org could use. The global layer
holds `global_paid_reserve` slots that only paid orgs may take.
"""

from __future__ import annotations

import math
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Mode = Literal["off", "shadow", "enforce"]
Tier = Literal["paid", "unpaid", "unknown"]

LAYERS = ("key_rate", "key_concurrency", "org_rate", "org_concurrency",
          "ip_concurrency", "global_concurrency")
# One label per layer, prefixed so a reader can tell treg's limiter from any other mitigation.
REASONS = {layer: f"treg_rl.{layer}" for layer in LAYERS}

# Write-time sanity ceilings: a value past one of these is a typo, not a policy.
MAX_RATE_PER_S = 10_000.0
MAX_BURST = 100_000
MAX_CONCURRENCY = 10_000
MAX_GLOBAL_CONCURRENCY = 100_000
MAX_ORG_OVERRIDES = 1_000
MAX_WINDOW_S = 3_600
MAX_TTL_S = 3_600

_Rate = Annotated[float, Field(gt=0, le=MAX_RATE_PER_S)]
_Burst = Annotated[int, Field(ge=1, le=MAX_BURST)]
_Concurrency = Annotated[int, Field(ge=1, le=MAX_CONCURRENCY)]
_Slug = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,99}$")]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def _paired(model: BaseModel, scope: str) -> None:
    rate, burst = getattr(model, f"{scope}_rate_per_s"), getattr(model, f"{scope}_burst")
    if (rate is None) != (burst is None):
        raise ValueError(f"{scope}_rate_per_s and {scope}_burst must be set together")


class TierLimits(_Strict):
    """One tier's thresholds. None = the layer is measured but never refuses."""

    key_rate_per_s: _Rate | None = None
    key_burst: _Burst | None = None
    key_concurrency: _Concurrency | None = None
    org_rate_per_s: _Rate | None = None
    org_burst: _Burst | None = None
    org_concurrency: _Concurrency | None = None

    @model_validator(mode="after")
    def _pairs(self) -> TierLimits:
        _paired(self, "key")
        _paired(self, "org")
        return self


class OrgOverride(_Strict):
    """Replaces the org layer's thresholds for one team, whatever its tier."""

    org_rate_per_s: _Rate | None = None
    org_burst: _Burst | None = None
    org_concurrency: _Concurrency | None = None

    @model_validator(mode="after")
    def _pairs(self) -> OrgOverride:
        _paired(self, "org")
        return self


class RateLimitConfig(_Strict):
    """The whole runtime policy. Every field is required, so a stored document is complete and
    the env defaults are the only place a default value comes from."""

    mode: Mode
    paid: TierLimits
    unpaid: TierLimits
    # Applied instead of `unpaid` to an unpaid org younger than `new_org_age_s` whose IP has seen
    # more than `ip_distinct_orgs_threshold` distinct orgs in the current `ip_window_s` window.
    tightened: TierLimits
    new_org_age_s: int = Field(ge=0, le=365 * 86_400)
    ip_window_s: int = Field(ge=60, le=MAX_WINDOW_S)
    ip_distinct_orgs_threshold: int | None = Field(ge=2, le=MAX_GLOBAL_CONCURRENCY)
    ip_concurrency: int | None = Field(ge=1, le=MAX_GLOBAL_CONCURRENCY)
    global_concurrency: int | None = Field(ge=1, le=MAX_GLOBAL_CONCURRENCY)
    global_paid_reserve: int = Field(ge=0, le=MAX_GLOBAL_CONCURRENCY)
    concurrency_ttl_s: int = Field(ge=30, le=MAX_TTL_S)
    concurrency_retry_after_s: int = Field(ge=1, le=300)
    org_overrides: dict[_Slug, OrgOverride] = Field(max_length=MAX_ORG_OVERRIDES)

    @model_validator(mode="after")
    def _reserve(self) -> RateLimitConfig:
        if self.global_concurrency is None:
            if self.global_paid_reserve:
                raise ValueError("global_paid_reserve needs global_concurrency")
        elif self.global_paid_reserve >= self.global_concurrency:
            raise ValueError("global_paid_reserve must be below global_concurrency")
        return self


@dataclass(frozen=True)
class Caller:
    """What auth established about a key, cached by `key_id` (a hash, never the key)."""

    key_id: str
    org_id: int
    org_slug: str
    paid: bool
    org_created_at: float  # epoch seconds


@dataclass(frozen=True)
class LayerSpec:
    name: str
    kind: Literal["bucket", "conc"]
    key: str
    rate: float | None = None
    cap: int | None = None  # burst for a bucket, the in-flight cap for a concurrency set
    tight_rate: float | None = None
    tight_cap: int | None = None


@dataclass(frozen=True)
class HllSpec:
    key: str
    member: str
    ttl_s: int
    threshold: int | None
    eligible: bool


@dataclass(frozen=True)
class Plan:
    tier: Tier
    layers: tuple[LayerSpec, ...]
    hll: HllSpec | None
    ttl_ms: int
    retry_ms: int


@dataclass(frozen=True)
class LayerResult:
    name: str
    ok: bool
    value: int  # requests in the current second (bucket) or in flight including this one (conc)
    cap: int | None
    retry_ms: int


@dataclass(frozen=True)
class Verdict:
    admitted: bool  # the counters were taken; release() must run
    layers: tuple[LayerResult, ...]
    tightened: bool
    distinct_orgs: int | None

    @property
    def blocked(self) -> tuple[LayerResult, ...]:
        return tuple(r for r in self.layers if not r.ok)

    @property
    def first_blocked(self) -> LayerResult | None:
        return next((r for r in self.layers if not r.ok), None)


def plan(config: RateLimitConfig, caller: Caller | None, ip: str, *, now_s: float) -> Plan:
    """The layers one request is checked against. A request with no known key is checked at the
    IP layer only and never creates a per-key, per-org or global counter."""
    ttl_ms = config.concurrency_ttl_s * 1000
    retry_ms = config.concurrency_retry_after_s * 1000
    ip_layer = LayerSpec("ip_concurrency", "conc", f"rl:ip:{ip}:c", cap=config.ip_concurrency)
    if caller is None:
        return Plan("unknown", (ip_layer,), None, ttl_ms, retry_ms)

    tier: Tier = "paid" if caller.paid else "unpaid"
    limits = config.paid if caller.paid else config.unpaid
    tight = config.tightened
    is_new = now_s - caller.org_created_at < config.new_org_age_s
    eligible = not caller.paid and is_new
    override = config.org_overrides.get(caller.org_slug)
    key = f"rl:k:{caller.key_id[:32]}"
    org = f"rl:o:{caller.org_slug}"

    def tightenable(name: str, rate_attr: str | None, cap_attr: str, *, use_override: bool) -> LayerSpec:
        source = override if (use_override and override is not None) else limits
        rate = getattr(source, rate_attr) if rate_attr else None
        cap = getattr(source, cap_attr)
        if use_override and override is not None:
            # An operator's per-org figure is deliberate; IP tightening does not second-guess it.
            t_rate, t_cap = rate, cap
        else:
            t_rate = getattr(tight, rate_attr) if (eligible and rate_attr) else None
            t_cap = getattr(tight, cap_attr) if eligible else None
        prefix = key if name.startswith("key") else org
        kind = "bucket" if name.endswith("rate") else "conc"
        suffix = "b" if kind == "bucket" else "c"
        return LayerSpec(name, kind, f"{prefix}:{suffix}", rate=rate, cap=cap,
                         tight_rate=t_rate if t_rate is not None else rate,
                         tight_cap=t_cap if t_cap is not None else cap)

    g = config.global_concurrency
    global_cap = None if g is None else (g if caller.paid else g - config.global_paid_reserve)
    layers = (
        tightenable("key_rate", "key_rate_per_s", "key_burst", use_override=False),
        tightenable("key_concurrency", None, "key_concurrency", use_override=False),
        tightenable("org_rate", "org_rate_per_s", "org_burst", use_override=True),
        tightenable("org_concurrency", None, "org_concurrency", use_override=True),
        ip_layer,
        LayerSpec("global_concurrency", "conc", "rl:g:c", cap=global_cap),
    )
    window = int(now_s // config.ip_window_s)
    hll = HllSpec(f"rl:ip:{ip}:orgs:{window}", str(caller.org_id), config.ip_window_s * 2,
                  config.ip_distinct_orgs_threshold, eligible)
    return Plan(tier, layers, hll, ttl_ms, retry_ms)


def bucket_ttl_ms(rate: float, burst: int) -> int:
    """Past this an untouched bucket is full again, so its key may expire."""
    return int(math.ceil(burst / rate * 1000)) + 1000


class LocalLimiter:
    """Per-process evaluator used when the shared store cannot answer. Same plan, same two
    phases; per-process counters, so across processes it is looser than the shared one. It has no
    HyperLogLog, so IP tightening never applies here. Bounded: past `max_keys` the oldest entries
    are dropped, which can only make it more permissive."""

    def __init__(self, max_keys: int) -> None:
        self.max_keys = max_keys
        self._buckets: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self._qps: OrderedDict[str, tuple[int, int]] = OrderedDict()
        self._conc: OrderedDict[str, dict[str, int]] = OrderedDict()

    def _bound(self, table: OrderedDict) -> None:
        while len(table) > self.max_keys:
            table.popitem(last=False)

    def admit(self, p: Plan, *, member: str, enforce: bool, now_ms: int) -> Verdict:
        results: list[LayerResult] = []
        pending_tokens: dict[str, float] = {}
        for layer in p.layers:
            if layer.kind == "bucket":
                sec = now_ms // 1000
                seen_sec, count = self._qps.get(layer.key, (sec, 0))
                count = count + 1 if seen_sec == sec else 1
                self._qps[layer.key] = (sec, count)
                self._qps.move_to_end(layer.key)
                self._bound(self._qps)
                ok, retry = True, 0
                if layer.rate is not None and layer.cap is not None:
                    tokens, ts = self._buckets.get(layer.key, (float(layer.cap), now_ms))
                    tokens = min(layer.cap, tokens + max(0, now_ms - ts) * layer.rate / 1000)
                    pending_tokens[layer.key] = tokens
                    if tokens < 1:
                        ok = False
                        retry = int(math.ceil((1 - tokens) * 1000 / layer.rate))
                results.append(LayerResult(layer.name, ok, count, layer.cap, retry))
            else:
                members = self._conc.get(layer.key, {})
                cutoff = now_ms - p.ttl_ms
                for m in [m for m, started in members.items() if started <= cutoff]:
                    members.pop(m)
                value = len(members) + 1
                ok = layer.cap is None or value <= layer.cap
                results.append(LayerResult(layer.name, ok, value, layer.cap, 0 if ok else p.retry_ms))
        admitted = all(r.ok for r in results) or not enforce
        if admitted:
            for layer in p.layers:
                if layer.kind == "bucket":
                    if layer.key in pending_tokens:
                        tokens = pending_tokens[layer.key]
                        self._buckets[layer.key] = (tokens - 1 if tokens >= 1 else tokens, now_ms)
                        self._buckets.move_to_end(layer.key)
                        self._bound(self._buckets)
                else:
                    self._conc.setdefault(layer.key, {})[member] = now_ms
                    self._conc.move_to_end(layer.key)
                    self._bound(self._conc)
        return Verdict(admitted, tuple(results), False, None)

    def release(self, keys: tuple[str, ...], member: str) -> None:
        for key in keys:
            members = self._conc.get(key)
            if members is not None:
                members.pop(member, None)
                if not members:
                    self._conc.pop(key, None)


@dataclass
class KeyCache:
    """Valid key hashes -> `Caller`, for `ttl_s`. Bounded LRU; a miss means the key is unknown."""

    ttl_s: float
    max_size: int
    _rows: OrderedDict[str, tuple[float, Caller]] = field(default_factory=OrderedDict)

    def get(self, key_id: str, *, now: float) -> Caller | None:
        row = self._rows.get(key_id)
        if row is None:
            return None
        if row[0] <= now:
            self._rows.pop(key_id, None)
            return None
        self._rows.move_to_end(key_id)
        return row[1]

    def put(self, caller: Caller, *, now: float) -> None:
        self._rows[caller.key_id] = (now + self.ttl_s, caller)
        self._rows.move_to_end(caller.key_id)
        while len(self._rows) > self.max_size:
            self._rows.popitem(last=False)

    def __len__(self) -> int:
        return len(self._rows)
