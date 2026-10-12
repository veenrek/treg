"""Rate-limit rules with no I/O: the policy schema, the layer plan and the in-process evaluator."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from treg.config import get_settings
from treg.domain.ratelimit import (
    LAYERS,
    REASONS,
    Caller,
    KeyCache,
    LocalLimiter,
    RateLimitConfig,
    TierLimits,
    plan,
)

NOW = 2_000_000_000.0
DAY = 86_400


def _config(**update) -> RateLimitConfig:
    base = get_settings().rate_limit_defaults.model_dump(mode="json")
    base.update(update)
    return RateLimitConfig.model_validate(base)


def _caller(*, paid: bool, age_s: float = 30 * DAY, org: str = "acme", key: str = "k") -> Caller:
    return Caller(key_id=key * 64, org_id=hash(org) % 10_000, org_slug=org, paid=paid,
                  org_created_at=NOW - age_s)


@pytest.mark.parametrize("bad", [
    {"paid": {"key_rate_per_s": 0, "key_burst": 1}},
    {"paid": {"key_rate_per_s": -1, "key_burst": 1}},
    {"paid": {"key_rate_per_s": 5, "key_burst": 0}},
    {"paid": {"key_rate_per_s": 1e9, "key_burst": 5}},
    {"paid": {"key_concurrency": 0}},
    {"paid": {"key_concurrency": 10_000_000}},
    {"paid": {"key_rate_per_s": 5}},  # rate without burst
    {"paid": {"key_concurrency": True}},
    {"paid": {"key_concurrency": "5"}},
    {"paid": {"surprise": 1}},
    {"global_concurrency": 10, "global_paid_reserve": 10},
    {"global_concurrency": None, "global_paid_reserve": 1},
    {"ip_concurrency": 0},
    {"ip_window_s": 1},
    {"mode": "panic"},
    {"concurrency_ttl_s": 5},
    {"org_overrides": {"Not A Slug": {"org_concurrency": 1}}},
])
def test_write_time_ranges_reject_typos(bad):
    with pytest.raises(ValidationError):
        _config(**bad)


def test_a_document_must_be_complete():
    with pytest.raises(ValidationError):
        RateLimitConfig.model_validate({"mode": "shadow"})


def test_every_layer_has_its_own_reason():
    assert set(REASONS) == set(LAYERS)
    assert len(set(REASONS.values())) == len(LAYERS)
    assert all(r.startswith("treg_rl.") for r in REASONS.values())


def test_unknown_key_is_planned_at_the_ip_layer_only():
    p = plan(_config(ip_concurrency=3, global_concurrency=10), None, "1.2.3.4", now_s=NOW)
    assert [layer.name for layer in p.layers] == ["ip_concurrency"]
    assert p.hll is None
    assert p.tier == "unknown"


def test_global_ceiling_is_the_last_layer_and_reserves_slots_for_paid_orgs():
    cfg = _config(global_concurrency=10, global_paid_reserve=3)
    paid = plan(cfg, _caller(paid=True), "ip", now_s=NOW)
    unpaid = plan(cfg, _caller(paid=False), "ip", now_s=NOW)
    assert [layer.name for layer in paid.layers] == list(LAYERS)
    assert paid.layers[-1].name == "global_concurrency"
    assert paid.layers[-1].cap == 10
    assert unpaid.layers[-1].cap == 7


def test_unpaid_orgs_get_the_unpaid_tier():
    cfg = _config(paid={"key_rate_per_s": 50, "key_burst": 100},
                  unpaid={"key_rate_per_s": 5, "key_burst": 10})
    assert plan(cfg, _caller(paid=True), "ip", now_s=NOW).layers[0].rate == 50
    assert plan(cfg, _caller(paid=False), "ip", now_s=NOW).layers[0].rate == 5


def test_ip_tightening_is_only_offered_to_unpaid_new_orgs():
    cfg = _config(unpaid={"key_rate_per_s": 5, "key_burst": 10, "org_concurrency": 8},
                  paid={"key_rate_per_s": 5, "key_burst": 10, "org_concurrency": 8},
                  tightened={"key_rate_per_s": 1, "key_burst": 1, "org_concurrency": 1},
                  new_org_age_s=7 * DAY, ip_distinct_orgs_threshold=5)
    new_unpaid = plan(cfg, _caller(paid=False, age_s=DAY), "ip", now_s=NOW)
    old_unpaid = plan(cfg, _caller(paid=False, age_s=30 * DAY), "ip", now_s=NOW)
    new_paid = plan(cfg, _caller(paid=True, age_s=DAY), "ip", now_s=NOW)
    assert new_unpaid.hll.eligible and (new_unpaid.layers[0].tight_rate, new_unpaid.layers[0].tight_cap) == (1, 1)
    assert new_unpaid.layers[3].tight_cap == 1
    for p in (old_unpaid, new_paid):
        assert not p.hll.eligible
        assert all(layer.tight_rate == layer.rate and layer.tight_cap == layer.cap for layer in p.layers)
    # Every known org is still counted toward its IP's distinct-org figure.
    assert new_paid.hll.member and new_paid.hll.threshold == 5


def test_org_override_replaces_the_org_layer_and_is_not_tightened():
    cfg = _config(unpaid={"org_rate_per_s": 5, "org_burst": 5},
                  tightened={"org_rate_per_s": 1, "org_burst": 1},
                  org_overrides={"acme": {"org_rate_per_s": 100, "org_burst": 200, "org_concurrency": 40}})
    p = plan(cfg, _caller(paid=False, age_s=0), "ip", now_s=NOW)
    org_rate, org_conc = p.layers[2], p.layers[3]
    assert (org_rate.rate, org_rate.cap, org_rate.tight_rate, org_rate.tight_cap) == (100, 200, 100, 200)
    assert (org_conc.cap, org_conc.tight_cap) == (40, 40)


def test_local_bucket_allows_the_burst_then_refuses_with_a_retry():
    cfg = _config(paid={"key_rate_per_s": 2, "key_burst": 2})
    p = plan(cfg, _caller(paid=True), "ip", now_s=NOW)
    lim = LocalLimiter(max_keys=100)
    first, second, third = (lim.admit(p, member=f"m{i}", enforce=True, now_ms=1_000) for i in range(3))
    assert first.admitted and second.admitted and not third.admitted
    assert third.first_blocked.name == "key_rate"
    assert third.first_blocked.retry_ms == 500
    assert lim.admit(p, member="later", enforce=True, now_ms=1_600).admitted  # refilled


def test_enforce_takes_nothing_when_a_later_layer_refuses_but_shadow_measures_everything():
    cfg = _config(paid={"key_rate_per_s": 1, "key_burst": 1}, ip_concurrency=1)
    p = plan(cfg, _caller(paid=True), "ip", now_s=NOW)
    lim = LocalLimiter(max_keys=100)
    assert lim.admit(p, member="held", enforce=True, now_ms=0).admitted
    # The bucket has refilled, but the IP slot is held: refused, and the token must not be spent.
    refused = lim.admit(p, member="x", enforce=True, now_ms=10_000)
    assert [r.name for r in refused.blocked] == ["ip_concurrency"]
    lim.release(tuple(layer.key for layer in p.layers if layer.kind == "conc"), "held")
    assert lim.admit(p, member="y", enforce=True, now_ms=10_000).admitted
    shadow = lim.admit(p, member="z", enforce=False, now_ms=10_000)
    assert shadow.admitted and [r.name for r in shadow.blocked] == ["key_rate", "ip_concurrency"]


def test_paid_reserve_under_the_global_ceiling():
    cfg = _config(global_concurrency=3, global_paid_reserve=1)
    lim = LocalLimiter(max_keys=100)
    unpaid = [plan(cfg, _caller(paid=False, org=f"u{i}", key=str(i)), f"ip{i}", now_s=NOW) for i in range(3)]
    assert lim.admit(unpaid[0], member="a", enforce=True, now_ms=0).admitted
    assert lim.admit(unpaid[1], member="b", enforce=True, now_ms=0).admitted
    shed = lim.admit(unpaid[2], member="c", enforce=True, now_ms=0)
    assert not shed.admitted and shed.first_blocked.name == "global_concurrency"
    paid = plan(cfg, _caller(paid=True, org="p", key="p"), "ip9", now_s=NOW)
    assert lim.admit(paid, member="d", enforce=True, now_ms=0).admitted
    assert not lim.admit(paid, member="e", enforce=True, now_ms=0).admitted  # the ceiling itself


def test_local_concurrency_entries_age_out_after_the_ttl():
    cfg = _config(paid={"key_concurrency": 1})
    p = plan(cfg, _caller(paid=True), "ip", now_s=NOW)
    lim = LocalLimiter(max_keys=100)
    assert lim.admit(p, member="leaked", enforce=True, now_ms=0).admitted
    assert not lim.admit(p, member="x", enforce=True, now_ms=1).admitted
    assert lim.admit(p, member="y", enforce=True, now_ms=p.ttl_ms + 1).admitted


def test_key_cache_expires_and_is_bounded():
    cache = KeyCache(ttl_s=60, max_size=2)
    for key in ("a", "b", "c"):
        cache.put(Caller(key, 1, "o", False, 0), now=0)
    assert cache.get("a", now=1) is None and len(cache) == 2
    assert cache.get("b", now=59) is not None
    assert cache.get("b", now=61) is None


def test_tier_limits_accept_integer_rates():
    assert TierLimits(key_rate_per_s=3, key_burst=5).key_rate_per_s == 3
