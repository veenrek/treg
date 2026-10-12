"""The admission policy a process serves: env defaults, the `rl:config` refresh, last good, max age."""

from __future__ import annotations

import asyncio
import json
import logging

import pytest
from pydantic import ValidationError

from treg import analytics
from treg.application.ratelimit import background, config_state, limiter
from treg.config import Settings, get_settings
from treg.domain.ratelimit import RateLimitConfig
from treg.infra import kv
from tests.fake_rate_limit_store import install


@pytest.fixture(autouse=True)
def _fresh():
    get_settings.cache_clear()
    limiter.reset_for_tests()
    background.reset_for_tests()
    yield
    limiter.reset_for_tests()
    background.reset_for_tests()
    get_settings.cache_clear()


@pytest.fixture
def alerts(monkeypatch):
    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(analytics, "capture", lambda _id, event, props=None, **_: events.append((event, props)))
    return events


def _doc(version: int, **update) -> str:
    base = get_settings().rate_limit_defaults.model_dump(mode="json")
    base.update(update)
    return config_state.encode_document(version, RateLimitConfig.model_validate(base))


def _changes(caplog) -> list[dict]:
    return [json.loads(r.getMessage().split(" ", 1)[1]) for r in caplog.records
            if r.getMessage().startswith("rate_limit_config_changed ")]


def test_env_refuses_enforce():
    with pytest.raises(ValidationError, match="enforce is set only through the audited admin endpoint"):
        Settings(rate_limit_mode="enforce")


def test_the_blocklist_mode_is_not_part_of_the_policy():
    """It lives on the blocklistversion row; a policy document carrying it is refused."""
    doc = get_settings().rate_limit_defaults.model_dump(mode="json")
    assert "blocklist_mode" not in doc
    with pytest.raises(ValidationError):
        RateLimitConfig.model_validate({**doc, "blocklist_mode": "enforce_403"})


@pytest.mark.parametrize("mode", ["off", "shadow"])
def test_env_accepts_off_and_shadow(mode):
    assert Settings(rate_limit_mode=mode).rate_limit_defaults.mode == mode


def test_env_defaults_hardcode_no_capacity():
    defaults = Settings().rate_limit_defaults
    assert defaults.global_concurrency is None and defaults.global_paid_reserve == 0
    assert defaults.mode == "off"


@pytest.mark.parametrize("bad", [
    {"rate_limit_global_concurrency": 0},
    {"rate_limit_global_concurrency": 10, "rate_limit_global_paid_reserve": 10},
    {"rate_limit_global_concurrency": 10_000_000},
    {"rate_limit_concurrency_ttl_s": 5},
])
def test_env_defaults_are_range_checked_at_boot(bad):
    with pytest.raises(ValidationError):
        Settings(**bad)


async def test_a_valid_document_is_loaded_and_its_version_logged(monkeypatch, caplog):
    store = install(monkeypatch)
    store.docs[kv.RL_CONFIG_KEY] = _doc(3, global_concurrency=40, global_paid_reserve=10)
    caplog.set_level(logging.INFO, logger="treg.ratelimit")
    state = await config_state.refresh_once()
    assert (state.version, state.source, state.fallback, state.degraded) == (3, "store", False, False)
    assert state.config.global_cap("unpaid") == 30
    change = _changes(caplog)[-1]
    assert (change["version"], change["mode"]) == (3, "off")


async def test_the_version_is_logged_on_every_change_and_only_then(monkeypatch, caplog):
    store = install(monkeypatch)
    caplog.set_level(logging.INFO, logger="treg.ratelimit")
    store.docs[kv.RL_CONFIG_KEY] = _doc(3, mode="shadow")
    await config_state.refresh_once()
    await config_state.refresh_once()
    store.docs[kv.RL_CONFIG_KEY] = _doc(4, mode="off")
    await config_state.refresh_once()
    loaded = [c for c in _changes(caplog) if c["source"] == "store"]
    assert [(c["version"], c["mode"], c["previous_version"]) for c in loaded] == [
        (3, "shadow", 0), (4, "off", 3)]


@pytest.mark.parametrize("bad", [
    "{not json",
    json.dumps([1, 2]),
    json.dumps({"version": 9, "config": {"mode": "shadow"}}),
    json.dumps({"version": 9, "config": {"mode": "enforce", "surprise": 1}}),
    json.dumps({"version": "9", "config": {}}),
    json.dumps({"version": 0, "config": {}}),
])
async def test_a_bad_document_keeps_the_last_good_policy(monkeypatch, caplog, bad):
    store = install(monkeypatch)
    store.docs[kv.RL_CONFIG_KEY] = _doc(3, global_concurrency=40)
    await config_state.refresh_once()
    store.docs[kv.RL_CONFIG_KEY] = bad
    caplog.set_level(logging.WARNING, logger="treg.ratelimit")
    state = await config_state.refresh_once()
    assert (state.version, state.config.global_concurrency) == (3, 40)
    assert any(r.getMessage().startswith("rate_limit_config_kept") for r in caplog.records)


async def test_an_out_of_range_value_in_the_store_keeps_the_last_good_policy(monkeypatch):
    store = install(monkeypatch)
    store.docs[kv.RL_CONFIG_KEY] = _doc(3)
    await config_state.refresh_once()
    doc = json.loads(_doc(4))
    doc["config"]["global_concurrency"] = 0
    store.docs[kv.RL_CONFIG_KEY] = json.dumps(doc)
    assert (await config_state.refresh_once()).version == 3
    store.docs[kv.RL_CONFIG_KEY] = _doc(5, concurrency_ttl_s=30)  # shorter than a request may last
    assert (await config_state.refresh_once()).version == 3


async def test_a_missing_document_keeps_the_last_good_policy_and_asks_for_a_restore(monkeypatch, alerts):
    store = install(monkeypatch)
    store.docs[kv.RL_CONFIG_KEY] = _doc(3)
    await config_state.refresh_once()
    del store.docs[kv.RL_CONFIG_KEY]
    state = await config_state.refresh_once()
    assert (state.version, state.source) == (3, "store")
    assert config_state.missing()
    assert not alerts


async def test_with_nothing_good_the_env_defaults_serve_and_alert(monkeypatch, caplog, alerts):
    install(monkeypatch)
    caplog.set_level(logging.ERROR, logger="treg.ratelimit")
    state = await config_state.refresh_once()
    assert (state.version, state.source, state.fallback) == (0, "env", True)
    assert state.config == get_settings().rate_limit_defaults
    assert state.config.mode in ("off", "shadow")
    assert any(r.getMessage().startswith("rate_limit_config_env_fallback") and r.levelno == logging.ERROR
               for r in caplog.records)
    assert alerts == [("ratelimit_config_env_fallback", {"reason": "missing", "mode": "off"})]
    _, gauge = await background.emit()
    assert gauge["config_fallback"] is True and gauge["config_source"] == "env"


async def test_store_down_keeps_the_cached_policy(monkeypatch, alerts):
    store = install(monkeypatch)
    store.docs[kv.RL_CONFIG_KEY] = _doc(3, global_concurrency=40)
    await config_state.refresh_once()
    store.down = True
    state = await config_state.refresh_once()
    assert (state.version, state.config.global_concurrency, state.fallback) == (3, 40, False)
    assert config_state.counters()["config_store_errors"] == 1
    assert not alerts


async def test_past_the_max_age_an_enforcing_last_good_drops_to_shadow_and_alerts(monkeypatch, caplog, alerts):
    store = install(monkeypatch)
    clock = [1_000.0]
    monkeypatch.setattr(config_state, "_clock", lambda: clock[0])
    store.docs[kv.RL_CONFIG_KEY] = _doc(3, mode="enforce", global_concurrency=40)
    assert (await config_state.refresh_once()).config.mode == "enforce"
    store.down = True
    clock[0] += get_settings().rate_limit_config_max_age_s - 1
    assert (await config_state.refresh_once()).config.mode == "enforce"  # still inside 30 minutes
    clock[0] += 2
    caplog.set_level(logging.ERROR, logger="treg.ratelimit")
    state = await config_state.refresh_once()
    assert (state.version, state.config.mode, state.degraded) == (3, "shadow", True)
    assert state.config.global_concurrency == 40
    stale = [e for e in alerts if e[0] == "ratelimit_config_stale"]
    assert len(stale) == 1 and stale[0][1]["version"] == 3
    await config_state.refresh_once()
    assert len([e for e in alerts if e[0] == "ratelimit_config_stale"]) == 1  # alerts once
    store.down = False
    assert (await config_state.refresh_once()).config.mode == "enforce"  # a fresh read restores it


async def test_without_a_shared_store_the_env_policy_is_normal_not_an_alert(alerts):
    state = await config_state.refresh_once()
    assert (state.source, state.fallback) == ("env", False)
    assert not alerts


async def test_the_config_loop_refreshes_on_its_interval(monkeypatch):
    monkeypatch.setenv("TREG_RATE_LIMIT_CONFIG_REFRESH_S", "7")
    get_settings.cache_clear()
    store = install(monkeypatch)
    store.docs[kv.RL_CONFIG_KEY] = _doc(5)
    sleeps: list[float] = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:
            raise asyncio.CancelledError

    monkeypatch.setattr(background.asyncio, "sleep", fake_sleep)
    with pytest.raises(asyncio.CancelledError):
        await background.config_loop()
    assert sleeps == [7.0, 7.0, 7.0]
    assert store.calls[f"rl_get:{kv.RL_CONFIG_KEY}"] == 3
    assert config_state.current().version == 5


async def test_a_slow_store_is_a_miss_within_the_budget(monkeypatch):
    """Slow but not failing: past `rate_limit_store_timeout_ms` the call is a miss (Unavailable),
    so the ceiling falls back to the per-process one and a read keeps its last good copy."""
    import time

    class SlowClient:
        async def eval(self, *a):
            await asyncio.sleep(0.5)
            return [1, 1, 1]

        async def get(self, key):
            await asyncio.sleep(0.5)

    store = kv.RedisStore.__new__(kv.RedisStore)
    store._client = SlowClient()
    started = time.monotonic()
    with pytest.raises(kv.Unavailable):
        await store.rl_admit_global("m", 5, 60_000, False)
    assert time.monotonic() - started < 0.2  # the 30 ms default budget, not the store's pace
    with pytest.raises(kv.Unavailable):
        await store.rl_get(kv.RL_CONFIG_KEY)
