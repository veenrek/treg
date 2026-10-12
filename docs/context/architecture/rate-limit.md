---
title: Request rate limiting — layered, measured in shadow before it refuses anything
status: built; env default mode is shadow, enforce needs an audited admin write
sources:
  - src/treg/domain/ratelimit/__init__.py
  - src/treg/domain/ratelimit/policy.py
  - src/treg/application/ratelimit/__init__.py
  - src/treg/application/ratelimit/limiter.py
  - src/treg/application/ratelimit/config_state.py
  - src/treg/application/ratelimit/background.py
  - src/treg/application/ratelimit/metrics.py
  - src/treg/application/ratelimit/admin.py
  - src/treg/routers/admin_rate_limit.py
  - src/treg/bootstrap_ratelimit.py
  - src/treg/infra/request_scope.py
  - src/treg/infra/kv.py
  - src/treg/config.py
  - src/treg/domain/identity/access.py
  - src/treg/alembic/versions/0069_rate_limit_config_version.py
  - tests/test_rate_limit_policy.py
  - tests/test_rate_limit_config.py
  - tests/test_rate_limit_middleware.py
  - tests/test_rate_limit_admin.py
  - tests/test_rate_limit_redis.py
related:
  - architecture/import-boundaries.md
  - architecture/money.md
  - ops/capacity.md
---

# Request rate limiting

A flood through many valid keys exhausts **in-flight concurrency** before it exhausts request
rate: long-held requests occupy workers and database connections. treg has no reverse proxy in
front of it, so the protection lives in the app, as the outermost middleware
(`bootstrap_ratelimit.RateLimitMiddleware`, added last in `bootstrap.create_app`). It runs before
auth, any database session and money admission. Every decision is
`application.ratelimit.limiter.RateLimiter`; the rules are `domain.ratelimit.policy`.

## Layers

Evaluated in `policy.LAYERS` order; each has its own `reason` (`policy.REASONS`, `treg_rl.<layer>`)
so logs and metrics say which layer, ours or any other mitigation's, refused a request.

1. **Per key** — a token bucket (`key_rate_per_s`, `key_burst`) and a concurrency cap.
2. **Per org** — the same pair for the whole team, keyed by org slug. `org_overrides` replaces the
   org layer's figures for one slug, whatever the tier.
3. **Tier** — `paid` or `unpaid` thresholds. Paid = the team has a `purchased` `CreditBlock` with a
   Stripe payment intent (`access._org_has_paid`). Account age is the secondary signal (below).
4. **Per IP** — no volume cap. A HyperLogLog counts distinct known orgs per IP per `ip_window_s`
   window. Past `ip_distinct_orgs_threshold`, an **unpaid org younger than `new_org_age_s`** behind
   that IP gets the `tightened` thresholds instead of `unpaid`; nobody else changes. The IP layer
   also has a concurrency cap.
5. **Global** — a concurrency ceiling, evaluated **last**: a request another layer refuses never
   holds a global slot. `global_paid_reserve` slots are usable by paid orgs only (an unpaid org sees
   `global_concurrency - global_paid_reserve`), so unpaid traffic is shed first.

The client IP is the ASGI peer (`scope["client"]`). The middleware never reads a forwarded-for
header. Whether the peer is the real client or the load balancer's address is a deployment fact
that shadow data answers (`distinct_ips` in the gauge) before the IP layer may enforce.

A key is known only through `KeyCache`, a per-process LRU of key hashes (`request_scope.key_id`,
the SHA-256 of the token and the `X-Treg-Org` header) with a short TTL. A miss sets `want_caller`
in the request's scope slot; `access.require_member` then publishes the org, its paid status and
age into the slot, and `RateLimiter.finish` caches it. So an **unknown or invalid key counts only at
the IP layer** and never creates a per-key, per-org or global counter. The cost is a cold start after
each deploy, counted as `unknown_key_requests`.

Exempt: `rate_limit_exempt_paths` (health, the Stripe webhooks), requests carrying a server-side
credential (`admin_token`, the house-team tokens), and treg's own in-process requests, which
`request_scope.internal_app` marks in the ASGI scope (no network client can set a scope key). MCP
and hub checks reach `/call/` that way: the outer request was already counted, and the inner
request's auth also teaches the cache the outer token (`alias`).

## Shared store

One Lua script per request (`kv._RL_ADMIT`): phase one reads every layer, phase two takes a token
from each bucket and adds the request to each concurrency set only when every layer allowed it, or
the mode is not `enforce`. `rl_release` removes it in the middleware's `finally`, whatever the app
raised. Keys are `rl:`-prefixed. Per-second request counters live two seconds; a bucket lives until
it would be full again; a concurrency set is a sorted set of request ids scored by start time, and
entries older than `concurrency_ttl_s` (validated to be at least `call_timeout_s`) are dropped, so a
release lost to a crash overcounts for at most that long. `rl_memory` samples what `rl:` keys
occupy next to the store's total, because the store evicts by LRU and also holds money-admission
leases.

**Fail open.** A store fault (`kv.Unavailable`) is counted (`store_errors`), starts a short cooldown
(`rate_limit_store_cooldown_s`) so an outage does not add a timeout to every request, and the
decision falls back to `policy.LocalLimiter`: the same plan per process, so looser across
processes, and without IP tightening. Without `TREG_KV_URL` the limiter always runs locally.

## Policy: env defaults, an audited table, a cached copy

- **Env** (`Settings.rate_limit_*`) holds the defaults, validated against the same schema at boot.
  `rate_limit_mode` accepts only `off` or `shadow`. An unset threshold measures its layer and
  refuses nothing; no capacity figure is written in code. Enforce figures are derived from shadow
  data: capacity from measured peak in-flight concurrency, rate from that concurrency over p95
  latency.
- **Postgres** `RateLimitConfigVersion` is the source of truth: one audited row per write (actor,
  action, mode, note, the full document, `enforce_approval`). Only `application.ratelimit.admin`
  writes it, only through `/admin/rate-limit/config` (`require_superadmin`). Every value is range
  checked first (`RateLimitConfig`, extra fields forbidden); `enforce` needs `enforce_approval`;
  `base_version` turns a stale write into a 409. `revert-to-shadow` writes the current thresholds
  in shadow mode as its own audited row. The row commits **before** the store is written.
- **`rl:config`** in the shared store is the copy processes read, written after the commit by a
  compare-and-set that never replaces a newer version (`republish` forces it, the remedy when the
  store evicted the key or a publish failed).
- **Processes** read `rl:config` only in `background.run`, every `rate_limit_config_refresh_s`
  (`config_state.refresh_once`). The request path reads the in-memory `config_state.current()` and
  never the store or the table (the second import contract). A bad or missing value keeps the last
  good policy; with none, the env defaults serve and `rate_limit_config_env_fallback` is logged at
  error level and sent as `ratelimit_config_fallback`, and every gauge carries
  `config_fallback: true`. Every change of version is logged (`rate_limit_config_changed`).

## Modes and responses

`off` skips the middleware's work entirely. `shadow` never refuses: each layer that would have
refused logs `rate_limit_would_block` (layer, reason, tier, paid, key-hash prefix, org, IP, value,
cap, config version). `enforce` answers **429** with `Retry-After` (the bucket's wait, or
`concurrency_retry_after_s`), `X-Treg-RateLimit-Layer`, `X-Treg-RateLimit-Reason`, and a body
naming the layer, reason and config version. Lines are bounded per window
(`rate_limit_log_max_per_window`), except a paid org's, which is never dropped.

## Telemetry

Drained once per `rate_limit_metrics_emit_s` by the background task (`background.emit`), as
analytics events and log lines:

- `ratelimit_decision` — counts by layer, reason, result (`allow`, `shadow_reject`, `reject`),
  tier (`paid`, `unpaid`, `tightened`, `unknown`), paid and config version. A paid row with a
  `reject` or `shadow_reject` result is also logged at warning level: the hook for "a paid org was
  refused" alerting.
- `ratelimit_gauge` — p50/p95/p99/max of each key's, org's and IP's peak rate and concurrency in
  the window, distinct orgs per IP, global concurrency, store latency, store and release errors,
  local decisions, unknown-key requests, exempt requests, key-cache size, `rl:` memory sample, and
  the config version, source and fallback flag.
