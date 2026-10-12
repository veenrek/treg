"""Writing the blocklist: Postgres first (entry plus audit row), then `rl:blocklist`.

The only writer of `BlocklistEntry` and `BlocklistAudit`. Every change inserts one audit row and
commits before anything is published; the audit row's id is the published `version`, and the
payload is rebuilt whole from the active entries, so the store can never hold a list Postgres does
not. A failed publish leaves the change committed and reports `published: false`; the background
restore (`restore`) or the next write publishes it. The caller (an operator bot) reads the version
back and treats an entry as live only once `status` shows every serving process on it. After each
write the server posts a receipt (`receipts`), best-effort and never part of the write.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import func, select

from ...config import get_settings
from ...domain.ratelimit import BLOCKLIST_SCHEMA_VERSION, valid_entry_value
from ...infra import kv
from ...models import ApiKey, BlocklistAudit, BlocklistEntry, CreditBlock, Membership, Org
from ...timeutil import utcnow_naive
from . import receipts

log = logging.getLogger("treg.ratelimit")


class Rejected(ValueError):
    """A call outside the guards; the whole call is refused and nothing is written."""

    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class UnknownEntry(Exception):
    pass


def _iso(t: datetime) -> str:
    return t.replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _entry_out(e: BlocklistEntry) -> dict:
    return {"id": e.id, "type": e.kind, "value": e.value, "reason": e.reason,
            "approved_by": e.approved_by, "evidence": e.evidence, "created_by": e.created_by,
            "created_at": _iso(e.created_at), "expires_at": _iso(e.expires_at),
            "revoked_at": _iso(e.revoked_at) if e.revoked_at else None, "revoked_by": e.revoked_by,
            "revoke_reason": e.revoke_reason}


async def _version(db: AsyncSession) -> int:
    return int((await db.execute(select(func.max(BlocklistAudit.id)))).scalar() or 0)


async def _active(db: AsyncSession, now: datetime) -> list[BlocklistEntry]:
    return list((await db.execute(
        select(BlocklistEntry).where(BlocklistEntry.revoked_at.is_(None), BlocklistEntry.expires_at > now)
        .order_by(BlocklistEntry.id)
    )).scalars().all())


def _payload(version: int, entries: list[BlocklistEntry], now: datetime) -> str:
    return json.dumps({
        "schema_version": BLOCKLIST_SCHEMA_VERSION, "version": version, "updated_at": _iso(now),
        "entries": [{"type": e.kind, "value": e.value, "reason": e.reason,
                     "expires_at": _iso(e.expires_at), "approved_by": e.approved_by} for e in entries],
    }, separators=(",", ":"), sort_keys=True)


async def _publish(db: AsyncSession, *, force: bool) -> tuple[int, bool]:
    """Read the current version and active entries, release the session, then write the store."""
    now = utcnow_naive()
    version = await _version(db)
    entries = await _active(db, now)
    await db.commit()
    if not kv.configured() or version == 0:
        return version, False
    try:
        stored = await kv.store().rl_publish(kv.RL_BLOCKLIST_KEY, _payload(version, entries, now),
                                             version, force=force)
    except kv.Unavailable as exc:
        log.error("rate_limit_blocklist_publish_failed version=%s error=%s", version, exc)
        return version, False
    if not stored:
        log.warning("rate_limit_blocklist_publish_skipped version=%s (store holds a newer version)", version)
    return version, stored


def _required(name: str, value: object, errors: list[str], *, limit: int = 500) -> str:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{name}: required")
        return ""
    if len(value) > limit:
        errors.append(f"{name}: at most {limit} characters")
    return value.strip()


async def _orgs_for(db: AsyncSession, targets: list[tuple[str, str]], errors: list[str]) -> dict[int, Org]:
    """Resolve each target to its org; a key hash treg does not know cannot be shown to be unpaid
    and new, so it is refused rather than trusted."""
    hashes = [v for k, v in targets if k == "key_hash"]
    key_orgs: dict[str, int] = {}
    if hashes:
        # Managed keys first; the membership column covers tokens not yet registered as keys.
        key_orgs.update((await db.execute(select(Membership.token_hash, Membership.org_id).where(
            Membership.token_hash.in_(hashes)))).all())
        key_orgs.update((await db.execute(select(ApiKey.key_hash, ApiKey.org_id).where(
            ApiKey.key_hash.in_(hashes)))).all())
    org_ids = {int(v) for k, v in targets if k == "org_id"} | set(key_orgs.values())
    orgs = {o.id: o for o in (await db.execute(select(Org).where(Org.id.in_(org_ids)))).scalars().all()}
    resolved: dict[int, Org] = {}
    for i, (kind, value) in enumerate(targets):
        org_id = int(value) if kind == "org_id" else key_orgs.get(value)
        org = orgs.get(org_id) if org_id is not None else None
        if org is None:
            errors.append(f"entries[{i}]: no such {'org' if kind == 'org_id' else 'key'}")
        else:
            resolved[i] = org
    return resolved


async def _net_paid(db: AsyncSession, org_ids: set[int]) -> dict[int, int]:
    """Completed Stripe top-ups per org. treg records no refund or chargeback amount, so this is
    the gross paid figure; any payment at all makes an org unblockable here."""
    if not org_ids:
        return {}
    return dict((await db.execute(
        select(CreditBlock.org_id, func.coalesce(func.sum(CreditBlock.amount_micro), 0))
        .where(CreditBlock.org_id.in_(org_ids), CreditBlock.kind == "purchased",
               CreditBlock.stripe_payment_intent.is_not(None))
        .group_by(CreditBlock.org_id))).all())


async def block(db: AsyncSession, *, actor: str, entries: list[dict], reason: str,
                approved_by: str, evidence: dict, ttl_s: int | None = None) -> dict:
    """Block up to `blocklist_max_entries_per_call` keys or orgs in one audited call. Every target
    must belong to an org that has never paid and was created inside the new-org window; one
    target outside that refuses the whole call."""
    s = get_settings()
    errors: list[str] = []
    reason = _required("reason", reason, errors)
    approved_by = _required("approved_by", approved_by, errors, limit=200)
    if not isinstance(evidence, dict) or not evidence:
        errors.append("evidence: a non-empty object (findings, query text, targets)")
    elif len(json.dumps(evidence)) > 64_000:
        errors.append("evidence: at most 64 kB")
    ttl = s.blocklist_default_ttl_s if ttl_s is None else ttl_s
    if not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= s.blocklist_max_ttl_s:
        errors.append(f"ttl_s: between 60 and {s.blocklist_max_ttl_s} seconds")
    if not isinstance(entries, list) or not entries:
        errors.append("entries: at least one")
        entries = []
    elif len(entries) > s.blocklist_max_entries_per_call:
        errors.append(f"entries: at most {s.blocklist_max_entries_per_call} per call")
    targets: list[tuple[str, str]] = []
    for i, e in enumerate(entries):
        kind, value = (e.get("type"), e.get("value")) if isinstance(e, dict) else (None, None)
        if kind not in ("key_hash", "org_id") or not isinstance(value, str) or not valid_entry_value(kind, value):
            errors.append(f"entries[{i}]: type key_hash (64-hex sha256) or org_id (decimal)")
        else:
            targets.append((kind, value))
    if len(set(targets)) != len(targets):
        errors.append("entries: duplicates")
    if errors:
        raise Rejected(errors)

    now = utcnow_naive()
    orgs = await _orgs_for(db, targets, errors)
    paid = await _net_paid(db, {o.id for o in orgs.values()})
    oldest = now - timedelta(seconds=s.blocklist_new_org_max_age_s)
    for i, org in orgs.items():
        if paid.get(org.id, 0) > 0:
            errors.append(f"entries[{i}]: org {org.id} has paid; paid orgs cannot be blocked here")
        if org.created_at < oldest:
            errors.append(f"entries[{i}]: org {org.id} is older than the new-org window "
                          f"({s.blocklist_new_org_max_age_s} s)")
    if errors:
        raise Rejected(errors)

    rows = [BlocklistEntry(kind=kind, value=value, reason=reason, approved_by=approved_by,
                           evidence=evidence, created_by=actor, created_at=now,
                           expires_at=now + timedelta(seconds=ttl)) for kind, value in targets]
    db.add_all(rows)
    await db.flush()
    audit = BlocklistAudit(entry_ids=[r.id for r in rows], action="block", actor=actor,
                           approved_by=approved_by, reason=reason, evidence=evidence, ttl_s=ttl,
                           created_at=now)
    db.add(audit)
    await db.flush()
    out = [_entry_out(r) for r in rows]
    audit_id = audit.id
    await db.commit()  # entries and audit exist before the store can serve them
    log.info("rate_limit_blocklist_written action=block audit=%s entries=%s actor=%s",
             audit_id, len(rows), actor)
    version, published = await _publish(db, force=False)
    result = {"entries": out, "audit_id": audit_id, "version": version, "published": published,
              "ttl_s": ttl}
    receipts.send("block", result)
    return result


async def unblock(db: AsyncSession, entry_id: int, *, actor: str, approved_by: str, reason: str) -> dict:
    """The one action that ends a block before it expires."""
    errors: list[str] = []
    reason = _required("reason", reason, errors)
    approved_by = _required("approved_by", approved_by, errors, limit=200)
    if errors:
        raise Rejected(errors)
    entry = await db.get(BlocklistEntry, entry_id)
    if entry is None:
        raise UnknownEntry()
    now = utcnow_naive()
    if entry.revoked_at is None:
        entry.revoked_at, entry.revoked_by, entry.revoke_reason = now, actor, reason
    audit = BlocklistAudit(entry_ids=[entry.id], action="unblock", actor=actor, approved_by=approved_by,
                           reason=reason, evidence={}, created_at=now)
    db.add(audit)
    await db.flush()
    out, audit_id = _entry_out(entry), audit.id
    await db.commit()
    log.info("rate_limit_blocklist_written action=unblock audit=%s entry=%s actor=%s", audit_id, entry_id, actor)
    version, published = await _publish(db, force=False)
    result = {"entries": [out], "audit_id": audit_id, "version": version, "published": published}
    receipts.send("unblock", result)
    return result


async def listing(db: AsyncSession) -> dict:
    now = utcnow_naive()
    version = await _version(db)
    entries = [_entry_out(e) for e in await _active(db, now)]
    await db.commit()
    return {"version": version, "entries": entries}


async def restore(db: AsyncSession) -> int | None:
    """The background repair for an evicted `rl:blocklist`. Never over a newer document."""
    version, published = await _publish(db, force=False)
    return version if published else None


async def store_version() -> int | None:
    """What `rl:blocklist` holds now, for the admin readback."""
    if not kv.configured():
        return None
    try:
        raw = await kv.store().rl_get(kv.RL_BLOCKLIST_KEY)
    except kv.Unavailable:
        return None
    try:
        return int(json.loads(raw)["version"]) if raw else None
    except (ValueError, KeyError, TypeError):
        return None
