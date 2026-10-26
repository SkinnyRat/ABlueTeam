"""Detector framework (Tier 0 — deterministic, no LLM).

A detector consumes the normalized Event stream and emits Findings. Most AD
detections are *rate/behaviour* based (many TGS requests, broad LDAP searches,
many ports from one source), so the base class gives a per-key sliding time
window: feed it events, it tells you what's currently inside the window.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import defaultdict, deque
from collections.abc import Iterable

from ..models import Event, Finding


class SlidingWindow:
    """Per-key deque of (ts, item); evicts entries older than `window` seconds."""

    def __init__(self, window: float) -> None:
        self.window = window
        self._buckets: dict[object, deque] = defaultdict(deque)

    def add(self, key: object, ts: float, item: object) -> deque:
        dq = self._buckets[key]
        dq.append((ts, item))
        cutoff = ts - self.window
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        if not dq:
            self._buckets.pop(key, None)
        return dq


class Detector(ABC):
    name: str = "detector"

    @abstractmethod
    def feed(self, ev: Event) -> Iterable[Finding]:
        """Consume one event; yield zero or more Findings."""
        raise NotImplementedError
