"""Bounded in-process rate-limit telemetry, drained once per window by the background task.

Two shapes, both fixed-cardinality: `ratelimit_decision` rows counted by
(layer, reason, result, tier, paid, config_version), and one `ratelimit_gauge` with p50/p95/p99/max
of each subject's peak rate and concurrency in the window. Subject identities (key hash, org, IP)
appear only in the rate-limited `would_block`/`reject` log lines, never in a metric.
"""

from __future__ import annotations

import json
import logging
import math
import threading
from collections import Counter

log = logging.getLogger("treg.ratelimit")

SCOPES = {"key_rate": "key", "key_concurrency": "key", "org_rate": "org",
          "org_concurrency": "org", "ip_concurrency": "ip", "global_concurrency": "global"}
_MAX_SUBJECTS = 5_000
_MAX_LATENCIES = 4_096
_lock = threading.Lock()


class _Window:
    def __init__(self) -> None:
        self.decisions: Counter = Counter()
        # (scope, metric) -> {subject: peak}
        self.peaks: dict[tuple[str, str], dict[str, int]] = {}
        self.subjects_dropped = 0
        self.latencies_ms: list[float] = []
        self.counts: Counter = Counter()
        self.logs = 0
        self.logs_dropped = 0
        self.distinct_ips: set[str] = set()


_w = _Window()


def decision(*, layer: str, reason: str, result: str, tier: str, paid: bool, version: int) -> None:
    with _lock:
        _w.decisions[(layer, reason, result, tier, paid, version)] += 1


def count(name: str, n: int = 1) -> None:
    with _lock:
        _w.counts[name] += n


def latency(ms: float) -> None:
    with _lock:
        if len(_w.latencies_ms) < _MAX_LATENCIES:
            _w.latencies_ms.append(ms)


def peak(layer: str, metric: str, subject: str, value: int) -> None:
    with _lock:
        table = _w.peaks.setdefault((SCOPES[layer], metric), {})
        if subject in table:
            table[subject] = max(table[subject], value)
        elif len(table) < _MAX_SUBJECTS:
            table[subject] = value
        else:
            _w.subjects_dropped += 1


def ip_seen(ip: str) -> None:
    with _lock:
        if len(_w.distinct_ips) < _MAX_SUBJECTS:
            _w.distinct_ips.add(ip)


def event_log(level: int, name: str, fields: dict, *, budget: int, always: bool = False) -> None:
    """A per-request line, bounded per window so a flood cannot become a log flood."""
    with _lock:
        if not always and _w.logs >= budget:
            _w.logs_dropped += 1
            return
        _w.logs += 1
    log.log(level, "%s %s", name, json.dumps({"event": name, **fields}, separators=(",", ":"),
                                             default=str))


def _pct(values: list, q: float):
    if not values:
        return None
    ordered = sorted(values)  # nearest rank
    return ordered[max(0, math.ceil(q * len(ordered)) - 1)]


def drain() -> tuple[list[dict], dict]:
    global _w
    with _lock:
        w, _w = _w, _Window()
    rows = [{"layer": layer, "reason": reason, "result": result, "tier": tier, "paid": paid,
             "config_version": version, "count": n}
            for (layer, reason, result, tier, paid, version), n in sorted(w.decisions.items(), key=str)]
    gauge: dict = {"subjects_dropped": w.subjects_dropped, "log_lines": w.logs,
                   "log_lines_dropped": w.logs_dropped, "distinct_ips": len(w.distinct_ips),
                   **dict(w.counts)}
    for (scope, metric), table in sorted(w.peaks.items()):
        values = list(table.values())
        gauge[f"{scope}_{metric}_subjects"] = len(values)
        for label, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
            gauge[f"{scope}_{metric}_{label}"] = _pct(values, q)
        gauge[f"{scope}_{metric}_max"] = max(values) if values else None
    for label, q in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99)):
        gauge[f"store_latency_ms_{label}"] = _pct(w.latencies_ms, q)
    gauge["store_latency_ms_max"] = max(w.latencies_ms) if w.latencies_ms else None
    return rows, gauge
