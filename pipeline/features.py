"""
features.py
───────────
Derives 23 features from raw BETH events using sliding windows,
process tree analysis, and sequence statistics.

All features are computed incrementally — state is maintained in
rolling buffers keyed by (host_id, pid).
"""

import time
import math
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, Deque, List, Optional

import numpy as np


# ── Configuration ─────────────────────────────────────────────────────────────

WINDOW_SHORT  = 30   # seconds
WINDOW_LONG   = 60   # seconds
WINDOW_DNS    = 60   # seconds
WINDOW_SLOW   = 300  # seconds (host baseline)

FEATURE_NAMES = [
    "syscall_entropy",
    "syscall_entropy_60",
    "unique_syscalls",
    "event_rate",
    "event_rate_60",
    "parent_anomaly_score",
    "uid_switch",
    "namespace_delta",
    "failed_syscall_ratio",
    "argsNum_mean",
    "argsNum_std",
    "arg_fingerprint",
    "execve_rate",
    "clone_rate",
    "openat_rate",
    "dns_rate",
    "dns_entropy",
    "pid_depth",
    "siblings_count",
    "inter_event_mean",
    "inter_event_std",
    "inter_event_cv",
    "host_anomaly_baseline",
]


# ── Internal state buffers ─────────────────────────────────────────────────────

@dataclass
class ProcessState:
    """Per-process rolling state."""
    pid:          int
    ppid:         int
    host:         str
    uid:          int
    namespace:    int

    events_short: Deque = field(default_factory=lambda: deque())  # (ts, syscall, args_n, retval)
    events_long:  Deque = field(default_factory=lambda: deque())
    dns_events:   Deque = field(default_factory=lambda: deque())  # (ts, domain)
    timestamps:   Deque = field(default_factory=lambda: deque())  # for inter-event time

    if_score:     float = 0.0   # updated by detector after each inference


class FeatureStore:
    """
    Global state store. Maintains rolling buffers per (host, pid).
    Thread-safe for single-consumer use; wrap with locks for multi-threaded.
    """

    def __init__(self):
        self._procs:          Dict[str, ProcessState]  = {}
        self._host_scores:    Dict[str, Deque]         = defaultdict(lambda: deque())
        self._host_ppid_map:  Dict[str, Dict[int, List[int]]] = defaultdict(lambda: defaultdict(list))
        self._pid_depth:      Dict[str, Dict[int, int]] = defaultdict(dict)

    def _key(self, host: str, pid: int) -> str:
        return f"{host}:{pid}"

    def get_or_create(self, event: dict) -> ProcessState:
        key = self._key(event["hostName"], event["processId"])
        if key not in self._procs:
            self._procs[key] = ProcessState(
                pid=event["processId"],
                ppid=event["parentProcessId"],
                host=event["hostName"],
                uid=event["userId"],
                namespace=event["mountNamespace"],
            )
            # Track sibling relationships
            ppid_map = self._host_ppid_map[event["hostName"]]
            ppid_map[event["parentProcessId"]].append(event["processId"])

            # Compute pid depth
            depth_map = self._pid_depth[event["hostName"]]
            parent_depth = depth_map.get(event["parentProcessId"], 0)
            depth_map[event["processId"]] = parent_depth + 1

        return self._procs[key]

    def update_host_baseline(self, host: str, if_score: float, ts: float):
        buf = self._host_scores[host]
        buf.append((ts, if_score))
        cutoff = ts - WINDOW_SLOW
        while buf and buf[0][0] < cutoff:
            buf.popleft()

    def host_anomaly_baseline(self, host: str) -> float:
        buf = self._host_scores[host]
        if not buf:
            return 0.0
        return float(np.mean([s for _, s in buf]))

    def siblings_count(self, host: str, ppid: int) -> int:
        return len(self._host_ppid_map[host].get(ppid, []))

    def pid_depth(self, host: str, pid: int) -> int:
        return self._pid_depth[host].get(pid, 0)

    def parent_if_score(self, host: str, ppid: int) -> float:
        key = self._key(host, ppid)
        if key in self._procs:
            return self._procs[key].if_score
        return 0.0


# ── Feature computation ───────────────────────────────────────────────────────

def _shannon_entropy(events: Deque, ts_now: float, window: float) -> float:
    """Shannon entropy of syscall names within [ts_now - window, ts_now]."""
    cutoff = ts_now - window
    counts: Dict[str, int] = defaultdict(int)
    total = 0
    for ts, syscall, *_ in events:
        if ts >= cutoff:
            counts[syscall] += 1
            total += 1
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _event_rate(events: Deque, ts_now: float, window: float) -> float:
    cutoff = ts_now - window
    count = sum(1 for ts, *_ in events if ts >= cutoff)
    return count / window


def _syscall_rate(events: Deque, ts_now: float, window: float, name: str) -> float:
    cutoff = ts_now - window
    count = sum(1 for ts, syscall, *_ in events if ts >= cutoff and syscall == name)
    return count / window


def _failed_ratio(events: Deque, ts_now: float, window: float) -> float:
    cutoff = ts_now - window
    subset = [(ts, args_n, retval) for ts, _, args_n, retval in events if ts >= cutoff]
    if not subset:
        return 0.0
    failed = sum(1 for *_, retval in subset if retval < 0)
    return failed / len(subset)


def _argsnum_stats(events: Deque, ts_now: float, window: float):
    cutoff = ts_now - window
    vals = [args_n for ts, _, args_n, _ in events if ts >= cutoff]
    if not vals:
        return 0.0, 0.0
    arr = np.array(vals, dtype=float)
    return float(arr.mean()), float(arr.std())


def _arg_fingerprint(args: str) -> int:
    parts = tuple(sorted(args.split(","))) if args else ("",)
    h = hashlib.md5(",".join(parts).encode()).hexdigest()
    return int(h[:8], 16)


def _inter_event_stats(timestamps: Deque):
    ts_list = list(timestamps)
    if len(ts_list) < 2:
        return 0.0, 0.0, 0.0
    diffs = np.diff(ts_list)
    mean  = float(diffs.mean())
    std   = float(diffs.std())
    cv    = std / mean if mean > 0 else 0.0
    return mean, std, cv


def _dns_entropy(dns_events: Deque, ts_now: float) -> float:
    cutoff = ts_now - WINDOW_DNS
    domains = [d for ts, d in dns_events if ts >= cutoff]
    if not domains:
        return 0.0
    counts: Dict[str, int] = defaultdict(int)
    for d in domains:
        counts[d] += 1
    total = len(domains)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _dns_rate(dns_events: Deque, ts_now: float) -> float:
    cutoff = ts_now - WINDOW_DNS
    count = sum(1 for ts, _ in dns_events if ts >= cutoff)
    return count / WINDOW_DNS


# ── Public API ────────────────────────────────────────────────────────────────

_store = FeatureStore()


def extract(event: dict, parent_if_score: Optional[float] = None) -> dict:
    """
    Compute all 23 features for a single BETH event dict.

    Parameters
    ----------
    event : dict
        Raw BETH event (one row from the CSV, delivered via Kafka).
    parent_if_score : float, optional
        Anomaly score of the parent process (injected by detector after inference).

    Returns
    -------
    dict with keys matching FEATURE_NAMES, plus the original event fields.
    """
    ts       = float(event.get("timestamp", time.time()))
    syscall  = str(event.get("eventName", "unknown"))
    args     = str(event.get("args", ""))
    args_n   = int(event.get("argsNum", 0))
    retval   = int(event.get("returnValue", 0))
    host     = str(event.get("hostName", "unknown"))
    pid      = int(event.get("processId", 0))
    ppid     = int(event.get("parentProcessId", 0))
    uid      = int(event.get("userId", 0))
    ns       = int(event.get("mountNamespace", 0))

    proc = _store.get_or_create(event)

    # Update rolling buffers
    entry = (ts, syscall, args_n, retval)
    proc.events_short.append(entry)
    proc.events_long.append(entry)
    proc.timestamps.append(ts)

    # Trim old entries
    cutoff_short = ts - WINDOW_SHORT
    cutoff_long  = ts - WINDOW_LONG
    while proc.events_short and proc.events_short[0][0] < cutoff_short:
        proc.events_short.popleft()
    while proc.events_long and proc.events_long[0][0] < cutoff_long:
        proc.events_long.popleft()
    while len(proc.timestamps) > 500:
        proc.timestamps.popleft()

    # DNS events (host-level)
    if syscall in ("connect", "sendto") and "." in args:
        _store._host_scores[host]   # touch
        proc.dns_events.append((ts, args.split(",")[0] if args else ""))
        while proc.dns_events and proc.dns_events[0][0] < ts - WINDOW_DNS:
            proc.dns_events.popleft()

    # Compute features
    argsnum_mean, argsnum_std = _argsnum_stats(proc.events_short, ts, WINDOW_SHORT)
    inter_mean, inter_std, inter_cv = _inter_event_stats(proc.timestamps)

    parent_score = (
        parent_if_score
        if parent_if_score is not None
        else _store.parent_if_score(host, ppid)
    )

    unique_syscalls = len(set(s for _, s, *_ in proc.events_short))

    features = {
        "syscall_entropy":       _shannon_entropy(proc.events_short, ts, WINDOW_SHORT),
        "syscall_entropy_60":    _shannon_entropy(proc.events_long,  ts, WINDOW_LONG),
        "unique_syscalls":       unique_syscalls,
        "event_rate":            _event_rate(proc.events_short, ts, WINDOW_SHORT),
        "event_rate_60":         _event_rate(proc.events_long,  ts, WINDOW_LONG),
        "parent_anomaly_score":  parent_score,
        "uid_switch":            float(uid != proc.uid),
        "namespace_delta":       float(ns != proc.namespace),
        "failed_syscall_ratio":  _failed_ratio(proc.events_short, ts, WINDOW_SHORT),
        "argsNum_mean":          argsnum_mean,
        "argsNum_std":           argsnum_std,
        "arg_fingerprint":       _arg_fingerprint(args),
        "execve_rate":           _syscall_rate(proc.events_short, ts, WINDOW_SHORT, "execve"),
        "clone_rate":            _syscall_rate(proc.events_short, ts, WINDOW_SHORT, "clone"),
        "openat_rate":           _syscall_rate(proc.events_short, ts, WINDOW_SHORT, "openat"),
        "dns_rate":              _dns_rate(proc.dns_events, ts),
        "dns_entropy":           _dns_entropy(proc.dns_events, ts),
        "pid_depth":             _store.pid_depth(host, pid),
        "siblings_count":        _store.siblings_count(host, ppid),
        "inter_event_mean":      inter_mean,
        "inter_event_std":       inter_std,
        "inter_event_cv":        inter_cv,
        "host_anomaly_baseline": _store.host_anomaly_baseline(host),
    }

    return {**event, **features}


def update_if_score(host: str, pid: int, if_score: float, ts: float):
    """Called by detector after Isolation Forest inference to propagate scores."""
    key = _store._key(host, pid)
    if key in _store._procs:
        _store._procs[key].if_score = if_score
    _store.update_host_baseline(host, if_score, ts)
