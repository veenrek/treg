"""Request admission rules: the policy schema, the global ceiling, the blocklist contract.

Pure rules, no I/O. Batch 1 of the design (docs/context/architecture/rate-limit.md):

- The **global concurrency ceiling** is the only counting layer. It is evaluated after every other
  check, and `global_paid_reserve` of its slots are usable by paid orgs only, so unpaid traffic is
  shed first. Its mode is `off`, `shadow` or `enforce`.
- The **blocklist** refuses a key hash before auth and an org id after auth. Its entries come from
  `rl:blocklist`, whose payload `parse_blocklist` validates; its mode is `off`, `log_only` or
  `enforce_403`.
"""

from __future__ import annotations

import json
import math
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Mode = Literal["off", "shadow", "enforce"]
BlocklistMode = Literal["off", "log_only", "enforce_403"]
Tier = Literal["paid", "unpaid", "unknown"]
MatchType = Literal["key_hash", "org_id"]

# One label per refusing layer, distinct from any other mitigation's labels.
GLOBAL_REASON = "treg_rl.global_concurrency"
BLOCKLIST_REASONS = {"key_hash": "treg_blocklist.key_hash", "org_id": "treg_blocklist.org_id"}

# Write-time sanity ceilings: a value past one of these is a typo, not a policy.
MAX_GLOBAL_CONCURRENCY = 100_000
MAX_TTL_S = 3_600
BLOCKLIST_SCHEMA_VERSION = 1
MAX_BLOCKLIST_ENTRIES = 10_000
_KEY_HASH = re.compile(r"^[0-9a-f]{64}$")
_ORG_ID = re.compile(r"^[1-9][0-9]{0,18}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RateLimitConfig(_Strict):
    """The whole runtime policy. Every field is required, so a stored document is complete and the
    env defaults are the only place a default value comes from."""

    mode: Mode
    blocklist_mode: BlocklistMode
    # None = measured, never refused. Set from measured peak in-flight concurrency, not a guess.
    global_concurrency: int | None = Field(ge=1, le=MAX_GLOBAL_CONCURRENCY)
    global_paid_reserve: int = Field(ge=0, le=MAX_GLOBAL_CONCURRENCY)
    concurrency_ttl_s: int = Field(ge=30, le=MAX_TTL_S)
    concurrency_retry_after_s: int = Field(ge=1, le=300)

    @model_validator(mode="after")
    def _reserve(self) -> RateLimitConfig:
        if self.global_concurrency is None:
            if self.global_paid_reserve:
                raise ValueError("global_paid_reserve needs global_concurrency")
        elif self.global_paid_reserve >= self.global_concurrency:
            raise ValueError("global_paid_reserve must be below global_concurrency")
        return self

    def global_cap(self, tier: Tier) -> int | None:
        if self.global_concurrency is None:
            return None
        return self.global_concurrency if tier == "paid" else self.global_concurrency - self.global_paid_reserve


@dataclass(frozen=True)
class Caller:
    """What auth established about a key, cached by `key_id` (a hash, never the key)."""

    key_id: str
    org_id: int
    org_slug: str
    paid: bool
    org_created_at: float  # epoch seconds


@dataclass(frozen=True)
class GlobalVerdict:
    admitted: bool  # the slot was taken; it must be released
    ok: bool  # within the ceiling
    in_flight: int  # including this request
    cap: int | None
    retry_ms: int


class LocalCeiling:
    """Per-process global ceiling, used when the shared store cannot answer: the same rule over
    one process's requests, so looser across processes. Entries older than the TTL age out."""

    def __init__(self) -> None:
        self._members: dict[str, int] = {}

    def admit(self, *, member: str, cap: int | None, ttl_ms: int, retry_ms: int, enforce: bool,
              now_ms: int) -> GlobalVerdict:
        cutoff = now_ms - ttl_ms
        for m in [m for m, started in self._members.items() if started <= cutoff]:
            self._members.pop(m)
        in_flight = len(self._members) + 1
        ok = cap is None or in_flight <= cap
        admitted = ok or not enforce
        if admitted:
            self._members[member] = now_ms
        return GlobalVerdict(admitted, ok, in_flight, cap, 0 if ok else retry_ms)

    def release(self, member: str) -> None:
        self._members.pop(member, None)

    def __len__(self) -> int:
        return len(self._members)


@dataclass
class KeyCache:
    """Valid key ids -> `Caller`, for `ttl_s`. Bounded LRU; a miss means the key is unknown."""

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


# ---- the blocklist contract (`rl:blocklist`) --------------------------------------------------
class InvalidBlocklist(ValueError):
    pass


def valid_entry_value(kind: str, value: str) -> bool:
    if kind == "key_hash":
        return bool(_KEY_HASH.fullmatch(value))
    if kind == "org_id":
        return bool(_ORG_ID.fullmatch(value))
    return False


def _utc(raw: object, name: str) -> datetime:
    if not isinstance(raw, str):
        raise InvalidBlocklist(f"{name}: not a string")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        raise InvalidBlocklist(f"{name}: not ISO 8601") from None
    if parsed.tzinfo is None:
        raise InvalidBlocklist(f"{name}: no UTC offset")
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class BlockEntry:
    kind: MatchType
    value: str
    reason: str
    expires_at: float  # epoch seconds
    approved_by: str


@dataclass(frozen=True)
class Blocklist:
    version: int
    updated_at: str
    entries: tuple[BlockEntry, ...]
    _index: dict[tuple[str, str], BlockEntry] = field(default_factory=dict, compare=False, repr=False)

    @classmethod
    def build(cls, version: int, updated_at: str, entries: tuple[BlockEntry, ...]) -> Blocklist:
        index: dict[tuple[str, str], BlockEntry] = {}
        for e in entries:
            held = index.get((e.kind, e.value))
            if held is None or e.expires_at > held.expires_at:
                index[(e.kind, e.value)] = e
        return cls(version, updated_at, entries, index)

    def match(self, kind: MatchType, value: str, *, now: float) -> BlockEntry | None:
        entry = self._index.get((kind, value))
        return entry if entry is not None and entry.expires_at > now else None

    def active(self, *, now: float) -> int:
        return sum(1 for e in self._index.values() if e.expires_at > now)


def parse_blocklist(raw: str) -> Blocklist:
    """`rl:blocklist`, schema 1:
    `{"schema_version": 1, "version": <int>, "updated_at": <ISO 8601 UTC>,
      "entries": [{"type": "key_hash"|"org_id", "value": <sha256 hex|org id>, "reason": <text>,
                   "expires_at": <ISO 8601 UTC>, "approved_by": <name>}]}`.
    Anything else raises; a caller keeps its last good list, never an empty one."""
    try:
        doc = json.loads(raw)
    except ValueError:
        raise InvalidBlocklist("not JSON") from None
    if not isinstance(doc, dict):
        raise InvalidBlocklist("not an object")
    if doc.get("schema_version") != BLOCKLIST_SCHEMA_VERSION:
        raise InvalidBlocklist(f"unknown schema_version {doc.get('schema_version')!r}")
    version = doc.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise InvalidBlocklist("version: must be a positive integer")
    updated_at = doc.get("updated_at")
    _utc(updated_at, "updated_at")
    entries = doc.get("entries")
    if not isinstance(entries, list) or len(entries) > MAX_BLOCKLIST_ENTRIES:
        raise InvalidBlocklist("entries: must be a list of at most %d" % MAX_BLOCKLIST_ENTRIES)
    out = []
    for i, e in enumerate(entries):
        if not isinstance(e, dict):
            raise InvalidBlocklist(f"entries[{i}]: not an object")
        kind, value = e.get("type"), e.get("value")
        if kind not in BLOCKLIST_REASONS or not isinstance(value, str) or not valid_entry_value(kind, value):
            raise InvalidBlocklist(f"entries[{i}]: bad type or value")
        reason, approver = e.get("reason"), e.get("approved_by")
        if not isinstance(reason, str) or not isinstance(approver, str):
            raise InvalidBlocklist(f"entries[{i}]: reason and approved_by must be strings")
        expires = _utc(e.get("expires_at"), f"entries[{i}].expires_at").timestamp()
        out.append(BlockEntry(kind, value, reason, expires, approver))
    return Blocklist.build(version, updated_at, tuple(out))


def retry_seconds(retry_ms: int) -> int:
    return max(1, math.ceil(retry_ms / 1000))
