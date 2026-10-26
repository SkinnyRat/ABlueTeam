"""Glue: tail -> normalize -> dedup -> detect -> triage -> emit Findings.

  batch  — read both landing files once, merge by timestamp (backtesting).
  follow — tail both files live, interleaving records as they arrive.

Triage is gated by severity so the LLM backends (API/local) only run on findings
worth the call; the free heuristic backend runs on everything.
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Iterator

from .dedup import Deduper
from .detectors.base import Detector
from .detectors.kerberoast import KerberoastDetector
from .detectors.ldap_recon import LdapReconDetector
from .detectors.scan_recon import ScanReconDetector
from .models import Event, Finding
from .tailer import SURICATA_NDJSON, ZEEK_NDJSON, follow, read_batch
from .triage import TriageBackend, get_backend

_SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_detectors() -> list[Detector]:
    return [ScanReconDetector(), LdapReconDetector(), KerberoastDetector()]


class Pipeline:
    def __init__(self, backend: TriageBackend | None = None,
                 min_triage_severity: str = "info") -> None:
        self.deduper = Deduper()
        self.detectors = build_detectors()
        self.backend = backend or get_backend("heuristic")
        self.min_rank = _SEV_RANK.get(min_triage_severity, 0)

    def _process(self, ev: Event) -> Iterator[Finding]:
        if self.deduper.is_duplicate(ev):
            return
        for det in self.detectors:
            for finding in det.feed(ev):
                if _SEV_RANK.get(finding.severity, 0) >= self.min_rank:
                    finding.triage = self.backend.triage(finding)
                yield finding

    def run_batch(self, limit: int | None = None) -> Iterator[Finding]:
        events = list(read_batch(SURICATA_NDJSON, "suricata"))
        events += list(read_batch(ZEEK_NDJSON, "zeek"))
        events.sort(key=lambda e: e.ts)
        if limit:
            events = events[-limit:]
        for ev in events:
            yield from self._process(ev)

    def run_follow(self) -> Iterator[Finding]:
        q: queue.Queue[Event] = queue.Queue(maxsize=10_000)

        def pump(path, source):
            for ev in follow(path, source):
                q.put(ev)

        for path, source in ((SURICATA_NDJSON, "suricata"), (ZEEK_NDJSON, "zeek")):
            threading.Thread(target=pump, args=(path, source), daemon=True).start()

        while True:
            ev = q.get()
            yield from self._process(ev)
