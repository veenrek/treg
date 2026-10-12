---
title: Request admission — blocklist, overload cap, global ceiling, surge signals (batch 1)
status: built; blocklist log_only, global ceiling shadow, overload cap off by default
sources:
  - src/treg/domain/ratelimit/__init__.py
  - src/treg/domain/ratelimit/policy.py
  - src/treg/application/ratelimit/__init__.py
  - src/treg/application/ratelimit/limiter.py
  - src/treg/application/ratelimit/config_state.py
  - src/treg/application/ratelimit/blocklist_state.py
  - src/treg/application/ratelimit/background.py
  - src/treg/application/ratelimit/metrics.py
  - src/treg/application/ratelimit/signals.py
  - src/treg/application/ratelimit/signals_flush.py
  - src/treg/application/ratelimit/inflight.py
  - src/treg/application/ratelimit/admin.py
  - src/treg/application/ratelimit/blocklist_admin.py
  - src/treg/application/ratelimit/receipts.py
  - src/treg/routers/admin_rate_limit.py
  - src/treg/bootstrap_ratelimit.py
  - src/treg/infra/request_scope.py
  - src/treg/infra/kv.py
  - src/treg/infra/db.py
  - src/treg/config.py
  - src/treg/domain/identity/access.py
  - src/treg/alembic/versions/0069_rate_limit_config_version.py
  - tests/test_rate_limit_policy.py
  - tests/test_rate_limit_config.py
  - tests/test_rate_limit_middleware.py
  - tests/test_rate_limit_admin.py
  - tests/test_rate_limit_overload.py
related:
  - architecture/import-boundaries.md
  - architecture/money.md
  - ops/capacity.md
---

# Request admission

A flood through many valid keys exhausts **in-flight concurrency** before request rate. treg has
no reverse proxy, so admission lives in the app, as the outermost middleware
(`bootstrap_ratelimit.RateLimitMiddleware`, added last in `bootstrap.create_app`), before auth, any
database session and money admission. Decisions are `application.ratelimit.limiter.RateLimiter`;
rules are `domain.ratelimit.policy`. Per-key, per-org, tier and IP layers are a later batch.

Order per request:

1. **Overload cap** (`overload_cap_enabled`, off by default): an in-process `asyncio.Semaphore` of
   `overload_cap_size`, no shared store. When it is full (`locked()`) the request gets **503**,
   `Retry-After`, `reason: overload_cap` (`X-Treg-Overload-Reason`), at once; it never queues. The
   permit is held until the app returns, which for ASGI is after the last streamed chunk, a client
   disconnect, an exception or a cancellation. Health checks and `/admin/*` are not counted. MCP
   streams (`GET /mcp...`, or an `/mcp` request accepting `text/event-stream`) never take a main
   permit: they have a separate `overload_cap_stream_size` semaphore, refused as
   `overload_cap_stream`.
   Distinct from the database pool's `503 treg_saturated`. The size is provisional: measured
   busy-hour concurrency is above it, so it is set from `inflight_gauge` before the flag is on.
   Every request is counted in flight (`inflight`) whether or not the cap is on;
   `background.inflight_loop` samples that and the DB pools' checked-out connections every second
   and emits `inflight_gauge` (pid, current and peak in flight, per-pool checked out, peak and
   capacity) every `inflight_gauge_emit_s`, as a log line and a metric. Counter reads only.
2. **Blocklist by key hash**, before auth (SHA-256 of the presented token, the `ApiKey.key_hash`
   spelling), and by org id when the key's org is already in the key cache.
3. **Global concurrency ceiling** (below), last of the middleware's checks.
4. **Blocklist by org id after auth**: the middleware puts `check_org` in the request's scope slot
   and `access.require_member` calls it once it knows the org (`_refuse_blocked_org`), so a blocked
   org is refused even on a key's first request in a process. Auth publishes the key's org first,
   so from the key's next request the refusal comes from the key cache, before any session opens.
   The cache holds the key-to-org mapping, not the verdict: an unblock applies at the next sync.
   An MCP client's Bearer is cached through the alias its in-process `/call/` teaches.

Every refusing layer has its own label: `overload_cap`, `treg_blocklist.key_hash`,
`treg_blocklist.org_id`, `treg_rl.global_concurrency`.

## Blocklist

Mode `blocklist_mode`: `off`, `log_only` (the default: match, log `rate_limit_blocklist_match`,
serve), `enforce_403` (refuse with **403**, `X-Treg-Block-Reason`, the entry's reason and the
blocklist version, so clients do not retry). The env accepts only `off` or `log_only`; `enforce_403`
is an audited policy write.

**Source of truth:** `BlocklistEntry` (one row per target, `expires_at` always set, `revoked_at` for
an unblock) and `BlocklistAudit` (one row per call, append-only; its id is the published
version). Migrations live in this repo only.

**Distribution:** `rl:blocklist`, one JSON string overwritten whole:

```json
{"schema_version": 1, "version": <audit id>, "updated_at": "<ISO 8601 UTC>",
 "entries": [{"type": "key_hash" | "org_id", "value": "<sha256 hex | org id>",
              "reason": "<text>", "expires_at": "<ISO 8601 UTC>", "approved_by": "<name>"}]}
```

`policy.parse_blocklist` validates it; readers ignore expired entries. Each process reads it every
`rate_limit_blocklist_refresh_s` in `background.blocklist_loop` (`blocklist_state.refresh_once`),
never on the request path. An unreadable store or a missing key keeps the last good list; a payload
that does not parse or has an unknown `schema_version` keeps it too and alerts
(`rate_limit_blocklist_invalid`). **Missing is never empty**: before a first good read a process has
no list, reported as `blocklist_loaded: false`.

**Writer:** `POST /admin/blocklist` (`blocklist_admin.block`), authorized by
`blocklist_admin_token`, a credential that opens the blocklist and status endpoints only
(`require_blocklist_writer`; a super-admin also passes). Guards, each a **400** naming the failure,
and one bad target refuses the whole call:

- every target resolves to an org (a key hash through `ApiKey` or `Membership.token_hash`; a signed
  Default key has no stored hash and is blocked through its org);
- the org has **never paid** (no completed Stripe top-up; treg records no refund amount) and was
  created inside `blocklist_new_org_max_age_s`;
- at most `blocklist_max_entries_per_call` targets; every entry expires, `ttl_s` defaults to
  `blocklist_default_ttl_s` (24 h) and may not exceed `blocklist_max_ttl_s`;
- reason, approver and non-empty evidence are required.

The call is budgeted (`blocklist_writes_per_hour`, a shared-store window that fails closed, 429).
Order: entries and the audit row commit, then the whole active list is published to
`rl:blocklist` by a compare-and-set that never replaces a newer version. A failed publish reports
`published: false`. After the write the server posts a receipt (entries, TTL, version, audit id) to
Slack (`receipts`, `blocklist_receipt_slack_token`/`_channel`) in a task: best-effort, counted on
failure (`blocklist_receipt_failures`), never delaying or undoing the write. `POST
/admin/blocklist/{id}/unblock` is the one-action unblock. `GET /admin/blocklist/status?version=N` is
the readback: `live` once the store and every process with a fresh heartbeat (`rl:live:<instance>`)
serve at least N.

The window, per-call cap and write budget defaults are placeholders, to be set from surge signals.

## Global concurrency ceiling

Mode `off`, `shadow` (default; logs `rate_limit_would_block`) or `enforce` (**429**, `Retry-After`).
One Lua script (`kv._RL_ADMIT_GLOBAL`) over a sorted set of request ids scored by start time;
entries older than `concurrency_ttl_s` (at least `call_timeout_s`) age out; the middleware's
`finally` removes the request. `global_paid_reserve` slots are usable by paid orgs only
(`RateLimitConfig.global_cap`). A key not yet in the key cache (every key's first request after a
deploy) is counted but never refused: refused before auth it would never be learned. The figure is
unset by default; it comes from measured peak in-flight concurrency and p95 latency. A store fault
fails open to `policy.LocalCeiling` per process, with a short cooldown.

The key cache (`KeyCache`, `request_scope.key_id`) learns a key's org, paid status and age from
`access.require_member` when the middleware asks (`want_caller`), one indexed read per key per TTL.

## Policy

`RateLimitConfig` (mode, blocklist mode, global figures). **Env** holds defaults (mode `off` or
`shadow`, blocklist `off` or `log_only`). **Postgres** `RateLimitConfigVersion` is the audited
source (`PUT /admin/rate-limit/config`, super-admin; range checked; `enforce` needs
`enforce_approval`; `revert-to-shadow` is one audited action). **`rl:config`** is the copy processes
read every `rate_limit_config_refresh_s` in the background. A bad, missing or unreadable value
keeps the last good policy for at most `rate_limit_config_max_age_s`; past that `enforce` is served
as `shadow` and `rate_limit_config_stale` alerts. With nothing good, env defaults serve and
`rate_limit_config_env_fallback` alerts. Every version change is logged.

**Eviction repair:** the store evicts by LRU. When either key is missing, `background.maybe_restore`
republishes it from Postgres on the dedicated `ratelimit` pool, at most once per
`rate_limit_republish_interval_s` across processes (a store claim). The request path never reads
Postgres (import contract).

## Surge signals

Record-only. `signals` aggregates in process memory per IP, per org and per (IP, org): requests,
call requests, unknown keys, 401/403/429/5xx, blocklist matches, distinct orgs and keys, peak in
flight; bounded by `surge_max_subjects`. `signals_flush` writes one `SurgeSignal` row per subject
per `surge_flush_s` on the `ratelimit` pool, with the org's `created_at` and paid total, and prunes
past `surge_retention_days`. The client IP is the ASGI peer; the middleware never reads a forwarded-for header. `python -m
treg` starts uvicorn with its defaults: `proxy_headers` on, `forwarded_allow_ips` from
`FORWARDED_ALLOW_IPS` or loopback only. So a forwarded-for header is applied only from a trusted
peer, and behind a load balancer whose address is not trusted the peer is that hop. Trusting
exactly the platform's hop is a deployment setting (`FORWARDED_ALLOW_IPS`), never `*`.

## Telemetry

`ratelimit_decision` rows by layer, reason, result, tier, paid, config version and mode;
`ratelimit_gauge` per process with its config and blocklist versions and modes, peak global
concurrency, store latency, `rl:` memory sample and the counters above.
