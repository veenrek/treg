"""The admin write paths: the blocklist (guards, audit, publish, receipt, readback) and the policy."""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import update
from sqlmodel import select

from treg import crypto
from treg.application.ratelimit import (
    background,
    blocklist_state,
    config_state,
    limiter,
    metrics,
    receipts,
)
from treg.config import get_settings
from treg.infra import kv, request_scope
from treg.infra.db import session_maker
from treg.models import BlocklistAudit, BlocklistEntry, CreditBlock, Org, RateLimitConfigVersion
from treg.timeutil import utcnow_naive
from tests.fake_rate_limit_store import install

ADMIN = "test-admin-token"
BOT = "test-blocklist-bot-token"


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv("TREG_ADMIN_TOKEN", ADMIN)
    monkeypatch.setenv("TREG_BLOCKLIST_ADMIN_TOKEN", BOT)
    monkeypatch.setenv("TREG_BLOCKLIST_RECEIPT_SLACK_TOKEN", "xoxb-test")
    monkeypatch.setenv("TREG_BLOCKLIST_RECEIPT_SLACK_CHANNEL", "U-OPS")
    get_settings.cache_clear()
    limiter.reset_for_tests()
    background.reset_for_tests()
    yield
    limiter.reset_for_tests()
    background.reset_for_tests()
    get_settings.cache_clear()


@pytest.fixture
def store(monkeypatch):
    return install(monkeypatch)


@pytest.fixture
def slack(monkeypatch):
    sent: list[tuple[str, str, str]] = []

    async def fake_post(token, channel, text):
        sent.append((token, channel, text))

    monkeypatch.setattr(receipts, "post", fake_post)
    return sent


BOT_H = {"X-Treg-Token": BOT}


def _body(*targets, **extra) -> dict:
    return {"entries": [{"type": k, "value": v} for k, v in targets], "reason": "flood from one IP",
            "approved_by": "ops-lead", "evidence": {"query": "select ... from surgesignal", "orgs": 1},
            **extra}


async def _new_org(client, email: str | None = None) -> tuple[int, str]:
    """A fresh, unpaid org and a managed key of it (whose hash is an `ApiKey.key_hash`)."""
    body = (await client.post("/users", json={"email": email or f"{uuid.uuid4().hex[:8]}@example.dev"})).json()
    minted = await client.post(f"/orgs/{body['org_id']}/api-keys", json={"name": "bot target"},
                               headers={"X-Treg-Token": body["token"]})
    assert minted.status_code == 200, minted.text
    return body["org_id"], minted.json()["secret"]


async def _pay(org_id: int) -> None:
    async with session_maker() as db:
        db.add(CreditBlock(id=uuid.uuid4().hex, org_id=org_id, kind="purchased", amount_micro=5_000_000,
                           remaining_micro=5_000_000, stripe_payment_intent=f"pi_{uuid.uuid4().hex}"))
        await db.commit()


async def _age(org_id: int, days: int) -> None:
    async with session_maker() as db:
        await db.execute(update(Org).where(Org.id == org_id).values(created_at=utcnow_naive() - timedelta(days=days)))
        await db.commit()


async def _rows(model):
    async with session_maker() as db:
        return (await db.execute(select(model).order_by(model.id))).scalars().all()


# ---- auth -------------------------------------------------------------------------------------
async def test_the_blocklist_token_opens_the_blocklist_and_nothing_else(clients, store, slack):
    assert (await clients.get("/admin/blocklist", headers={"X-Treg-Token": ""})).status_code == 401
    assert (await clients.get("/admin/blocklist", headers=BOT_H)).status_code == 200
    assert (await clients.get("/admin/blocklist", headers={"X-Treg-Token": ADMIN})).status_code == 200
    assert (await clients.get("/admin/stats", headers=BOT_H)).status_code in (401, 403)
    assert (await clients.put("/admin/rate-limit/config", headers=BOT_H, json={})).status_code in (401, 403, 422)
    # A member's own key is not a blocklist credential.
    assert (await clients.get("/admin/blocklist")).status_code in (401, 403)


# ---- the guards --------------------------------------------------------------------------------
async def test_an_unpaid_new_org_is_accepted_with_one_audit_row_and_a_receipt(clients, store, slack):
    org_id, _ = await _new_org(clients)
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["published"] is True and out["ttl_s"] == 86_400
    [entry] = out["entries"]
    assert entry["value"] == str(org_id) and entry["approved_by"] == "ops-lead"
    audits = await _rows(BlocklistAudit)
    assert len(audits) == 1 and audits[0].id == out["audit_id"] == out["version"]
    assert audits[0].entry_ids == [entry["id"]] and audits[0].actor == "blocklist-token"
    assert audits[0].evidence["query"].startswith("select")
    doc = json.loads(store.docs[kv.RL_BLOCKLIST_KEY])
    assert doc["schema_version"] == 1 and doc["version"] == out["version"]
    assert doc["entries"][0]["type"] == "org_id" and doc["entries"][0]["value"] == str(org_id)
    await receipts.drain()
    [(token, channel, text)] = slack
    assert (token, channel) == ("xoxb-test", "U-OPS")
    assert f"version {out['version']}" in text and f"audit {out['audit_id']}" in text
    assert "TTL 86400 s" in text and str(org_id) in text


async def test_a_paid_org_is_rejected(clients, store, slack):
    org_id, _ = await _new_org(clients)
    await _pay(org_id)
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))
    assert r.status_code == 400
    assert any("has paid" in e for e in r.json()["detail"]["errors"])
    assert not await _rows(BlocklistEntry) and not await _rows(BlocklistAudit)
    assert kv.RL_BLOCKLIST_KEY not in store.docs and not slack


async def test_an_old_org_is_rejected(clients, store, slack):
    org_id, _ = await _new_org(clients)
    await _age(org_id, days=get_settings().blocklist_new_org_max_age_s // 86_400 + 1)
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))
    assert r.status_code == 400
    assert any("older than the new-org window" in e for e in r.json()["detail"]["errors"])
    assert not await _rows(BlocklistEntry)


async def test_a_key_is_judged_by_its_org(clients, store, slack):
    new_org, new_token = await _new_org(clients)
    paid_org, paid_token = await _new_org(clients)
    await _pay(paid_org)
    ok = await clients.post("/admin/blocklist", headers=BOT_H,
                            json=_body(("key_hash", crypto.hash_token(new_token))))
    assert ok.status_code == 200, ok.text
    paid = await clients.post("/admin/blocklist", headers=BOT_H,
                              json=_body(("key_hash", crypto.hash_token(paid_token))))
    assert paid.status_code == 400
    unknown = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("key_hash", "f" * 64)))
    assert unknown.status_code == 400 and "no such key" in unknown.json()["detail"]["errors"][0]


async def test_one_paid_target_refuses_the_whole_call(clients, store, slack):
    good, _ = await _new_org(clients)
    paid, _ = await _new_org(clients)
    await _pay(paid)
    r = await clients.post("/admin/blocklist", headers=BOT_H,
                           json=_body(("org_id", str(good)), ("org_id", str(paid))))
    assert r.status_code == 400
    assert not await _rows(BlocklistEntry)


async def test_at_most_n_entries_per_call(clients, store, slack, monkeypatch):
    monkeypatch.setenv("TREG_BLOCKLIST_MAX_ENTRIES_PER_CALL", "2")
    get_settings.cache_clear()
    orgs = [str((await _new_org(clients))[0]) for _ in range(3)]
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(*[("org_id", o) for o in orgs]))
    assert r.status_code == 400 and "at most 2 per call" in r.json()["detail"]["errors"][0]
    ok = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(*[("org_id", o) for o in orgs[:2]]))
    assert ok.status_code == 200 and len(ok.json()["entries"]) == 2
    assert len(await _rows(BlocklistAudit)) == 1  # one audit row for the call


@pytest.mark.parametrize("ttl,status", [(None, 200), (3600, 200), (59, 400), (8 * 86_400, 400), (True, 400)])
async def test_every_entry_expires_and_the_ttl_is_bounded(clients, store, slack, ttl, status):
    org_id, _ = await _new_org(clients)
    extra = {} if ttl is None else {"ttl_s": ttl}
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id)), **extra))
    assert r.status_code in ((status,) if status == 200 else (400, 422)), r.text
    if status == 200:
        [row] = await _rows(BlocklistEntry)
        expected = ttl or 86_400
        assert abs((row.expires_at - row.created_at).total_seconds() - expected) < 1


@pytest.mark.parametrize("bad", [
    {"reason": ""}, {"approved_by": " "}, {"evidence": {}}, {"entries": []},
    {"entries": [{"type": "ip", "value": "1.2.3.4"}]}, {"entries": [{"type": "org_id", "value": "abc"}]},
])
async def test_malformed_calls_are_rejected_with_a_reason(clients, store, slack, bad):
    org_id, _ = await _new_org(clients)
    r = await clients.post("/admin/blocklist", headers=BOT_H, json={**_body(("org_id", str(org_id))), **bad})
    assert r.status_code == 400 and r.json()["detail"]["errors"]


async def test_the_endpoint_is_rate_limited(clients, store, slack, monkeypatch):
    monkeypatch.setenv("TREG_BLOCKLIST_WRITES_PER_HOUR", "2")
    get_settings.cache_clear()
    org_id, _ = await _new_org(clients)
    codes = [(await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))).status_code
             for _ in range(3)]
    assert codes == [200, 200, 429]


# ---- write order, receipt, unblock, readback ------------------------------------------------------
async def test_postgres_commits_before_the_store_is_written(clients, store, slack, monkeypatch):
    org_id, _ = await _new_org(clients)
    seen: list[int] = []
    real = store.rl_publish

    async def publish(key, value, version, *, force=False):
        async with session_maker() as db:  # a separate session sees only committed rows
            seen.append(len((await db.execute(select(BlocklistAudit))).scalars().all()))
        return await real(key, value, version, force=force)

    monkeypatch.setattr(store, "rl_publish", publish)
    assert (await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))).status_code == 200
    assert seen == [1]


async def test_a_failed_publish_keeps_the_write_and_says_so(clients, store, slack):
    org_id, _ = await _new_org(clients)
    store.down = True
    store.windows.clear()
    real_take = store.take

    async def take(key, limit, ttl_s):  # the write budget answers; only the publish fails
        store.down = False
        try:
            return await real_take(key, limit, ttl_s)
        finally:
            store.down = True

    store.take = take
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))
    assert r.status_code == 200 and r.json()["published"] is False
    assert len(await _rows(BlocklistEntry)) == 1


async def test_a_failing_receipt_never_undoes_or_delays_the_write(clients, store, monkeypatch):
    org_id, _ = await _new_org(clients)
    metrics.drain()

    async def broken(token, channel, text):
        raise RuntimeError("slack down")

    monkeypatch.setattr(receipts, "post", broken)
    r = await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))
    assert r.status_code == 200
    await receipts.drain()
    assert len(await _rows(BlocklistEntry)) == 1
    _, gauge = metrics.drain()
    assert gauge["blocklist_receipt_failures"] == 1

    hang = asyncio.Event()

    async def slow(token, channel, text):
        await hang.wait()

    monkeypatch.setattr(receipts, "post", slow)
    other, _ = await _new_org(clients)
    r = await asyncio.wait_for(
        clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(other)))), timeout=5)
    assert r.status_code == 200
    hang.set()
    await receipts.drain()


async def test_unblock_is_one_action_and_republishes(clients, store, slack):
    org_id, _ = await _new_org(clients)
    blocked = (await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))).json()
    entry_id = blocked["entries"][0]["id"]
    r = await clients.post(f"/admin/blocklist/{entry_id}/unblock", headers=BOT_H,
                           json={"approved_by": "ops-lead", "reason": "false positive"})
    assert r.status_code == 200
    assert r.json()["version"] > blocked["version"]
    assert json.loads(store.docs[kv.RL_BLOCKLIST_KEY])["entries"] == []
    audits = await _rows(BlocklistAudit)
    assert [a.action for a in audits] == ["block", "unblock"]
    assert (await clients.get("/admin/blocklist", headers=BOT_H)).json()["entries"] == []
    assert (await clients.post("/admin/blocklist/999999/unblock", headers=BOT_H,
                               json={"approved_by": "o", "reason": "r"})).status_code == 404
    await receipts.drain()
    assert "unblock" in slack[-1][2]


async def test_the_version_readback_is_live_only_once_every_process_serves_it(clients, store, slack):
    org_id, _ = await _new_org(clients)
    version = (await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))).json()["version"]
    before = (await clients.get(f"/admin/blocklist/status?version={version}", headers=BOT_H)).json()
    assert before["pg_version"] == before["store_version"] == version
    assert before["live"] is False  # no process has loaded it yet
    await background.blocklist_step()
    after = (await clients.get(f"/admin/blocklist/status?version={version}", headers=BOT_H)).json()
    assert after["live"] is True
    assert after["processes"][0]["blocklist_version"] == version
    assert after["processes"][0]["blocklist_entries"] == 1
    status = (await clients.get("/admin/rate-limit/status", headers=BOT_H)).json()
    assert {"config_version", "mode", "blocklist_version", "blocklist_mode"} <= status["processes"][0].keys()


async def test_an_evicted_blocklist_is_restored_from_postgres_at_most_once_per_interval(clients, store, slack):
    org_id, _ = await _new_org(clients)
    version = (await clients.post("/admin/blocklist", headers=BOT_H, json=_body(("org_id", str(org_id))))).json()["version"]
    await blocklist_state.refresh_once()
    del store.docs[kv.RL_BLOCKLIST_KEY]  # allkeys_lru evicted it
    await blocklist_state.refresh_once()
    assert blocklist_state.current().version == version  # missing is not empty
    assert await background.maybe_restore("blocklist") == version
    assert json.loads(store.docs[kv.RL_BLOCKLIST_KEY])["version"] == version
    del store.docs[kv.RL_BLOCKLIST_KEY]
    await blocklist_state.refresh_once()
    assert await background.maybe_restore("blocklist") is None  # this minute's restore is spent
    background.reset_for_tests()
    assert await background.maybe_restore("blocklist") is None  # and another process's claim holds


# ---- the policy ---------------------------------------------------------------------------------
ADMIN_H = {"X-Treg-Token": ADMIN}


def _policy(**update) -> dict:
    doc = get_settings().rate_limit_defaults.model_dump(mode="json")
    doc.update(update)
    return doc


@pytest.mark.parametrize("bad", [
    {"global_concurrency": 0}, {"global_concurrency": -1}, {"global_concurrency": 10**9},
    {"global_concurrency": 10, "global_paid_reserve": 10}, {"concurrency_ttl_s": 31}, {"mode": "loud"},
])
async def test_policy_writes_are_range_checked(clients, store, bad):
    r = await clients.put("/admin/rate-limit/config", headers=ADMIN_H, json={"config": _policy(**bad), "note": "x"})
    assert r.status_code == 422 and r.json()["detail"]["errors"]
    assert not await _rows(RateLimitConfigVersion)


async def test_enforce_needs_a_recorded_approval(clients, store):
    r = await clients.put("/admin/rate-limit/config", headers=ADMIN_H,
                          json={"config": _policy(mode="enforce"), "note": "x"})
    assert r.status_code == 422
    r = await clients.put("/admin/rate-limit/config", headers=ADMIN_H,
                          json={"config": _policy(mode="enforce", global_concurrency=50), "note": "go",
                                "enforce_approval": "approved in the ops channel"})
    assert r.status_code == 200
    assert (await _rows(RateLimitConfigVersion))[0].enforce_approval == "approved in the ops channel"


async def test_policy_writes_are_audited_and_published(clients, store):
    first = (await clients.put("/admin/rate-limit/config", headers=ADMIN_H,
                               json={"config": _policy(global_concurrency=80, global_paid_reserve=20),
                                     "note": "from shadow peak"})).json()
    second = (await clients.put("/admin/rate-limit/config", headers=ADMIN_H,
                                json={"config": _policy(blocklist_mode="enforce_403"), "note": "403 on",
                                      "base_version": first["version"]})).json()
    rows = await _rows(RateLimitConfigVersion)
    assert [(r.id, r.action, r.actor, r.previous_version) for r in rows] == [
        (first["version"], "set", "env-admin", None), (second["version"], "set", "env-admin", first["version"])]
    assert json.loads(store.docs[kv.RL_CONFIG_KEY])["version"] == second["version"]
    stale = await clients.put("/admin/rate-limit/config", headers=ADMIN_H,
                              json={"config": _policy(), "note": "x", "base_version": first["version"]})
    assert stale.status_code == 409


async def test_revert_to_shadow_is_one_audited_action(clients, store):
    await clients.put("/admin/rate-limit/config", headers=ADMIN_H, json={
        "config": _policy(mode="enforce", global_concurrency=50), "note": "go", "enforce_approval": "ok"})
    r = await clients.post("/admin/rate-limit/config/revert-to-shadow", headers=ADMIN_H, json={"note": "paging"})
    assert r.status_code == 200
    latest = (await _rows(RateLimitConfigVersion))[-1]
    assert (latest.action, latest.mode, latest.config["global_concurrency"]) == ("revert_to_shadow", "shadow", 50)
    assert json.loads(store.docs[kv.RL_CONFIG_KEY])["config"]["mode"] == "shadow"


async def test_an_evicted_policy_is_restored_from_postgres(clients, store):
    v = (await clients.put("/admin/rate-limit/config", headers=ADMIN_H,
                           json={"config": _policy(global_concurrency=70), "note": "x"})).json()["version"]
    await config_state.refresh_once()
    del store.docs[kv.RL_CONFIG_KEY]
    assert (await config_state.refresh_once()).version == v
    assert await background.maybe_restore("config") == v
    assert (await config_state.refresh_once()).config.global_concurrency == 70
