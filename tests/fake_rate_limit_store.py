"""An in-memory shared store for rate-limit tests that do not need a real Redis.

It holds the `rl:` documents and counts every call, so a test can prove which code path reads
what. The ceiling raises `Unavailable` unless a test sets `admit_ok`, which sends decisions to
`LocalCeiling`; the Lua scripts run against a real Redis in `test_rate_limit_redis.py`.
"""

from __future__ import annotations

import json
from collections import Counter

from treg.infra import kv


class FakeRateLimitStore:
    def __init__(self) -> None:
        self.docs: dict[str, str] = {}
        self.claims: set[str] = set()
        self.live: dict[str, str] = {}
        self.calls: Counter = Counter()
        self.down = False
        self.windows: Counter = Counter()

    def _check(self, op: str) -> None:
        self.calls[op] += 1
        if self.down:
            raise kv.Unavailable("ConnectionError")

    async def rl_admit_global(self, member, cap, ttl_ms, enforce):
        self._check("rl_admit_global")
        raise kv.Unavailable("no admission in the fake store")

    async def rl_release(self, member):
        self._check("rl_release")

    async def rl_get(self, key):
        self._check(f"rl_get:{key}")
        return self.docs.get(key)

    async def rl_publish(self, key, value, version, *, force=False):
        self._check(f"rl_publish:{key}")
        held = self.docs.get(key)
        if held and not force and json.loads(held).get("version", 0) > version:
            return False
        self.docs[key] = value
        return True

    async def rl_claim(self, key, ttl_s):
        self._check("rl_claim")
        if key in self.claims:
            return False
        self.claims.add(key)
        return True

    async def rl_heartbeat(self, key, value, ttl_s):
        self._check("rl_heartbeat")
        self.live[key] = value

    async def rl_live(self):
        self._check("rl_live")
        return list(self.live.values())

    async def rl_memory(self, max_keys):
        self._check("rl_memory")
        return {"rl_keys_sampled": 0, "rl_bytes_sampled": 0, "rl_sample_truncated": False,
                "kv_used_memory": 0}

    async def take(self, key, limit, ttl_s):
        if self.down:
            return False
        self.windows[key] += 1
        return self.windows[key] <= limit

    async def ping(self):
        return not self.down

    async def aclose(self):
        pass


def install(monkeypatch) -> FakeRateLimitStore:
    store = FakeRateLimitStore()
    monkeypatch.setattr(kv, "configured", lambda: True)
    monkeypatch.setattr(kv, "_store", store)
    return store
