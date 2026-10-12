"""Admission rules with no I/O: the policy schema, the global ceiling, the blocklist payload."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from treg.config import get_settings
from treg.domain.ratelimit import (
    BLOCKLIST_REASONS,
    GLOBAL_REASON,
    Caller,
    InvalidBlocklist,
    KeyCache,
    LocalCeiling,
    RateLimitConfig,
    parse_blocklist,
)

KEY = "a" * 64


def _config(**update) -> RateLimitConfig:
    base = get_settings().rate_limit_defaults.model_dump(mode="json")
    base.update(update)
    return RateLimitConfig.model_validate(base)


def _payload(**update) -> str:
    doc = {"schema_version": 1, "version": 7, "updated_at": "2026-10-12T09:00:00Z",
           "entries": [{"type": "key_hash", "value": KEY, "reason": "flood", "approved_by": "ops",
                        "expires_at": "2099-01-01T00:00:00Z"},
                       {"type": "org_id", "value": "42", "reason": "flood", "approved_by": "ops",
                        "expires_at": "2000-01-01T00:00:00Z"}]}
    doc.update(update)
    return json.dumps(doc)


@pytest.mark.parametrize("bad", [
    {"global_concurrency": 0},
    {"global_concurrency": -5},
    {"global_concurrency": 10_000_000},
    {"global_concurrency": True},
    {"global_concurrency": "50"},
    {"global_concurrency": 10, "global_paid_reserve": 10},
    {"global_concurrency": None, "global_paid_reserve": 1},
    {"global_paid_reserve": -1},
    {"concurrency_ttl_s": 5},
    {"concurrency_retry_after_s": 0},
    {"mode": "panic"},
    {"blocklist_mode": "enforce"},
    {"surprise": 1},
])
def test_write_time_ranges_reject_typos(bad):
    with pytest.raises(ValidationError):
        _config(**bad)


def test_a_document_must_be_complete():
    with pytest.raises(ValidationError):
        RateLimitConfig.model_validate({"mode": "shadow"})


def test_each_refusing_layer_has_its_own_reason():
    labels = [GLOBAL_REASON, *BLOCKLIST_REASONS.values()]
    assert len(set(labels)) == 3
    assert GLOBAL_REASON.startswith("treg_rl.") and all(r.startswith("treg_blocklist.") for r in BLOCKLIST_REASONS.values())


def test_paid_orgs_keep_a_reserved_share_of_the_global_ceiling():
    cfg = _config(global_concurrency=10, global_paid_reserve=3)
    assert cfg.global_cap("paid") == 10
    assert cfg.global_cap("unpaid") == cfg.global_cap("unknown") == 7
    assert _config(global_concurrency=None).global_cap("paid") is None


def test_local_ceiling_sheds_unpaid_first_and_takes_nothing_when_enforcing_a_refusal():
    cfg = _config(global_concurrency=3, global_paid_reserve=1)
    ceiling = LocalCeiling()
    admit = lambda m, tier: ceiling.admit(member=m, cap=cfg.global_cap(tier), ttl_ms=60_000,
                                          retry_ms=1_000, enforce=True, now_ms=0)
    assert admit("u1", "unpaid").admitted and admit("u2", "unpaid").admitted
    shed = admit("u3", "unpaid")
    assert not shed.admitted and not shed.ok and shed.retry_ms == 1_000
    assert len(ceiling) == 2
    assert admit("p1", "paid").admitted
    assert not admit("p2", "paid").admitted


def test_shadow_measures_past_the_ceiling_without_refusing():
    ceiling = LocalCeiling()
    v = [ceiling.admit(member=str(i), cap=1, ttl_ms=60_000, retry_ms=1_000, enforce=False, now_ms=0)
         for i in range(3)]
    assert all(x.admitted for x in v) and [x.ok for x in v] == [True, False, False]
    assert v[-1].in_flight == 3


def test_local_ceiling_entries_age_out():
    ceiling = LocalCeiling()
    ceiling.admit(member="leaked", cap=1, ttl_ms=1_000, retry_ms=1, enforce=True, now_ms=0)
    assert not ceiling.admit(member="x", cap=1, ttl_ms=1_000, retry_ms=1, enforce=True, now_ms=500).admitted
    assert ceiling.admit(member="y", cap=1, ttl_ms=1_000, retry_ms=1, enforce=True, now_ms=1_001).admitted


def test_key_cache_expires_and_is_bounded():
    cache = KeyCache(ttl_s=60, max_size=2)
    for key in ("a", "b", "c"):
        cache.put(Caller(key, 1, "o", False, 0), now=0)
    assert cache.get("a", now=1) is None and len(cache) == 2
    assert cache.get("b", now=59) is not None
    assert cache.get("b", now=61) is None


def test_blocklist_payload_parses_and_expired_entries_stop_matching():
    bl = parse_blocklist(_payload())
    assert bl.version == 7
    assert bl.match("key_hash", KEY, now=0).reason == "flood"
    assert bl.match("org_id", "42", now=2_000_000_000) is None  # expired in 2000
    assert bl.match("org_id", "43", now=0) is None
    assert bl.active(now=2_000_000_000) == 1


@pytest.mark.parametrize("raw", [
    "{nope",
    json.dumps([]),
    _payload(schema_version=2),
    _payload(schema_version=None),
    _payload(version=0),
    _payload(version="7"),
    _payload(updated_at="yesterday"),
    _payload(entries="all"),
    _payload(entries=[{"type": "ip", "value": "1.2.3.4", "reason": "x", "approved_by": "o",
                       "expires_at": "2099-01-01T00:00:00Z"}]),
    _payload(entries=[{"type": "key_hash", "value": "short", "reason": "x", "approved_by": "o",
                       "expires_at": "2099-01-01T00:00:00Z"}]),
    _payload(entries=[{"type": "org_id", "value": "42", "reason": "x", "approved_by": "o",
                       "expires_at": "2099-01-01T00:00:00"}]),  # no UTC offset
])
def test_a_bad_or_unknown_blocklist_payload_is_refused_not_read_as_empty(raw):
    with pytest.raises(InvalidBlocklist):
        parse_blocklist(raw)
