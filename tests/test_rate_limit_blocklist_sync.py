"""The blocklist comes from Postgres only: a version poll, an in-process cache, a bounded cold start."""

from __future__ import annotations

import logging
from datetime import timedelta

import pytest
from sqlalchemy import event

from treg import analytics
from treg.application.ratelimit import background, blocklist_state, blocklist_sync, limiter
from treg.config import get_settings
from treg.infra import db as infra_db
from treg.infra.db import session_maker
from treg.models import BlocklistEntry, BlocklistVersion
from treg.timeutil import utcnow_naive


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
    events: list = []
    monkeypatch.setattr(analytics, "capture", lambda _id, e, p=None, **_: events.append((e, p)))
    return events


async def _write(version: int, *orgs: str, revoked: bool = False) -> None:
    async with session_maker() as db:
        now = utcnow_naive()
        for org in orgs:
            db.add(BlocklistEntry(kind="org_id", value=org, reason="r", approved_by="o", evidence={"q": 1},
                                  created_by="t", created_at=now, expires_at=now + timedelta(hours=1),
                                  revoked_at=now if revoked else None))
        row = await db.get(BlocklistVersion, 1)
        if row is None:
            db.add(BlocklistVersion(id=1, version=version, updated_at=now))
        else:
            row.version = version
        await db.commit()


def _statements():
    seen: list[str] = []

    def before(conn, cursor, statement, *_):
        seen.append(statement)

    event.listen(infra_db._ratelimit_engine.sync_engine, "before_cursor_execute", before)
    return seen, lambda: event.remove(infra_db._ratelimit_engine.sync_engine, "before_cursor_execute", before)


async def test_no_version_row_is_an_authoritative_empty_list(clients):
    assert await blocklist_sync.poll_once()
    bl = blocklist_state.current()
    assert bl is not None and bl.version == 0 and bl.active(now=0) == 0


async def test_the_list_reloads_only_when_the_version_changes(clients):
    await _write(3, "41", "42")
    assert await blocklist_sync.poll_once()
    assert blocklist_state.current().version == 3 and blocklist_state.current().active(now=0) == 2
    seen, stop = _statements()
    try:
        assert await blocklist_sync.poll_once()  # unchanged: one primary-key read, no entry scan
    finally:
        stop()
    assert len(seen) == 1 and "blocklistversion" in seen[0] and "blocklistentry" not in seen[0]
    await _write(4, "43")
    assert await blocklist_sync.poll_once()
    assert blocklist_state.current().version == 4 and blocklist_state.current().active(now=0) == 3
    assert blocklist_state.counters()["blocklist_reloads"] == 2


async def test_revoked_and_expired_entries_are_not_loaded(clients):
    await _write(5, "51", revoked=True)
    async with session_maker() as db:
        now = utcnow_naive()
        db.add(BlocklistEntry(kind="org_id", value="52", reason="r", approved_by="o", evidence={"q": 1},
                              created_by="t", created_at=now - timedelta(days=2), expires_at=now - timedelta(days=1)))
        await db.commit()
    assert await blocklist_sync.poll_once()
    assert blocklist_state.current().active(now=0) == 0


async def test_a_failed_poll_keeps_the_cache_and_alerts_once(clients, monkeypatch, alerts, caplog):
    await _write(3, "41")
    assert await blocklist_sync.poll_once()
    good = blocklist_state.current()

    def broken():
        raise ConnectionError("database unreachable")

    monkeypatch.setattr(blocklist_sync, "ratelimit_session_maker", broken)
    caplog.set_level(logging.ERROR, logger="treg.ratelimit")
    for _ in range(3):
        assert await blocklist_sync.poll_once() is False
    assert blocklist_state.current() is good  # never emptied, never replaced
    assert blocklist_state.counters()["blocklist_load_errors"] == 3
    assert [e for e, _ in alerts].count("ratelimit_blocklist_load_failed") == 1
    assert sum(r.getMessage().startswith("rate_limit_blocklist_load_failed") for r in caplog.records) == 1


async def test_cold_start_retries_until_the_first_load_succeeds(clients, monkeypatch):
    real = blocklist_sync.ratelimit_session_maker
    attempts = []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise ConnectionError("not yet")
        return real()

    sleeps: list[float] = []

    async def fake_sleep(s):
        sleeps.append(s)

    monkeypatch.setattr(blocklist_sync, "ratelimit_session_maker", flaky)
    monkeypatch.setattr(blocklist_sync.asyncio, "sleep", fake_sleep)
    assert await blocklist_sync.cold_start(timeout_s=30) is True
    assert len(attempts) == 3 and sleeps == [1.0, 1.0]
    assert blocklist_state.current() is not None


async def test_cold_start_gives_up_after_its_budget_then_fails_open_and_reports_empty(clients, monkeypatch, alerts):
    def down():
        raise ConnectionError("database unreachable")

    clock = [0.0]

    async def fake_sleep(s):
        clock[0] += s

    monkeypatch.setattr(blocklist_sync, "ratelimit_session_maker", down)
    monkeypatch.setattr(blocklist_sync.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(blocklist_sync.time, "monotonic", lambda: clock[0])
    assert await blocklist_sync.cold_start(timeout_s=30) is False
    assert 29 <= clock[0] <= 30  # retried for about the whole budget, then gave up
    assert blocklist_state.current() is None
    assert ("blocklist_cache_empty", {"value": 1}) in alerts
    assert background.process_status()["blocklist_cache_empty"] is True
    # Fail open: requests are served with no list.
    r = await clients.get("/tools")
    assert r.status_code == 200
    # The background loop keeps retrying and reporting empty until the database answers.
    alerts.clear()
    await background.blocklist_step()
    assert ("blocklist_cache_empty", {"value": 1}) in alerts
    monkeypatch.setattr(blocklist_sync, "ratelimit_session_maker", infra_db.ratelimit_session_maker)
    alerts.clear()
    await background.blocklist_step()
    assert blocklist_state.current() is not None and not [e for e, _ in alerts if e == "blocklist_cache_empty"]
    assert background.process_status()["blocklist_cache_empty"] is False


async def test_startup_waits_for_the_first_load(monkeypatch):
    from treg import bootstrap
    calls = []

    async def fake_cold_start():
        calls.append("cold_start")
        return True

    monkeypatch.setattr(bootstrap.rate_limit_blocklist_sync, "cold_start", fake_cold_start)
    from treg.bootstrap import create_app
    app = create_app("control")
    async with app.router.lifespan_context(app):
        assert calls == ["cold_start"]


def test_the_ratelimit_pool_has_a_statement_timeout(monkeypatch):
    captured = {}
    monkeypatch.setattr(infra_db, "create_async_engine", lambda url, **kw: captured.update(kw) or _Engine())
    monkeypatch.setattr(infra_db.money_trace, "install_engine", lambda *a, **k: None)
    infra_db._new_engine("ratelimit", "postgresql+asyncpg://u:p@db/treg")
    assert captured["connect_args"] == {"server_settings": {"statement_timeout": "2000"}}
    assert captured["pool_size"] == 1 and captured["max_overflow"] == 0


class _Engine:
    sync_engine = None
