"""LDAP enumeration (BloodHound / SharpHound / ldapsearch).

AD directory recon shows up as a burst of LDAP search_requests from one source
to the DC, often with broad filters ((objectClass=*), objectCategory sweeps).
Signals:
  * Suricata ldap : request.operation == "search_request".
  * Zeek ldap_search / ldap : one record per search.
Fire when one source issues >= THRESHOLD searches in the window, with higher
severity if broad "catch-all" filters appear (hallmark of mass collection).

ATT&CK: T1087.002 (Account Discovery: Domain Account),
        T1069.002 (Permission Groups Discovery: Domain Groups).
"""

from __future__ import annotations

from collections.abc import Iterable

from ..models import Event, Finding
from .base import Detector, SlidingWindow

WINDOW = 60.0
SEARCH_THRESHOLD = 20
_BROAD = ("objectclass", "objectcategory", "samaccountname", "(&", "(|")


class LdapReconDetector(Detector):
    name = "ldap_recon"

    def __init__(self) -> None:
        self._searches = SlidingWindow(WINDOW)
        self._fired: dict[str | None, float] = {}  # src -> last fire ts (debounce)

    def _is_search(self, ev: Event) -> tuple[bool, str]:
        if ev.source == "suricata" and ev.kind == "ldap":
            req = ev.raw.get("ldap", {}).get("request", {})
            if req.get("operation") == "search_request":
                f = str(req.get("search_request", {}).get("filter", "")).lower()
                return True, f
        if ev.source == "zeek" and ev.kind in ("ldap_search", "ldap"):
            return True, str(ev.raw.get("filter", "")).lower()
        return False, ""

    def feed(self, ev: Event) -> Iterable[Finding]:
        is_search, filt = self._is_search(ev)
        if not is_search:
            return
        dq = self._searches.add(ev.src_ip, ev.ts, filt)
        if len(dq) < SEARCH_THRESHOLD:
            return
        # debounce: at most one finding per source per window
        if ev.ts - self._fired.get(ev.src_ip, 0.0) < WINDOW:
            return
        self._fired[ev.src_ip] = ev.ts
        broad = any(any(b in f for b in _BROAD) for _, f in dq)
        yield Finding(
            ts=ev.ts, detector=self.name,
            severity="high" if broad else "medium",
            title="LDAP enumeration against the directory",
            attack=["T1087.002", "T1069.002"], src_ip=ev.src_ip, dst_ip=ev.dst_ip,
            summary=(f"{ev.src_ip} issued {len(dq)} LDAP searches in {int(WINDOW)}s"
                     + (" incl. broad catch-all filters (BloodHound-style)" if broad else "")),
            evidence=[ev.raw],
        )
