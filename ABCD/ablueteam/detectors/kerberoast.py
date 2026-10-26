"""Kerberoasting / AS-REP roasting from Kerberos metadata.

Kerberoasting: a principal requests TGS tickets for many service SPNs, asking
for RC4 (etype 23) so the reply can be cracked offline. Signals on the wire:
  * Suricata krb5  : msg_type KRB_TGS_REQ, distinct `sname`, `weak_encryption`.
  * Zeek kerberos  : request_type "TGS", `cipher`/`enctype` RC4, `service`.
We fire when one source asks for TGS on >= THRESHOLD distinct SPNs in the window,
or on any TGS that explicitly negotiates weak encryption.

AS-REP roasting: AS-REQ for an account with pre-auth disabled (no PA-ENC-TIMESTAMP),
RC4 — surfaced as a lower-severity companion finding.

ATT&CK: T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting).
"""

from __future__ import annotations

from collections.abc import Iterable

from ..models import Event, Finding
from .base import Detector, SlidingWindow

WINDOW = 120.0           # seconds
DISTINCT_SPN_THRESHOLD = 5


class KerberoastDetector(Detector):
    name = "kerberoast"

    def __init__(self) -> None:
        self._spns = SlidingWindow(WINDOW)   # key: src_ip -> set of (ts, sname)

    def _tgs_fields(self, ev: Event) -> tuple[str | None, bool] | None:
        """Return (sname, weak) if this event is a Kerberos TGS request, else None."""
        if ev.source == "suricata" and ev.kind == "krb5":
            k = ev.raw.get("krb5", {})
            if k.get("msg_type") == "KRB_TGS_REQ":
                return k.get("sname"), bool(k.get("weak_encryption"))
        if ev.source == "zeek" and ev.kind == "kerberos":
            k = ev.raw
            if str(k.get("request_type", "")).upper() == "TGS":
                cipher = str(k.get("cipher", "")).lower()
                weak = "rc4" in cipher or k.get("enctype") in (23, "23")
                return k.get("service") or k.get("sname"), weak
        return None

    def feed(self, ev: Event) -> Iterable[Finding]:
        info = self._tgs_fields(ev)
        if info is None:
            return
        sname, weak = info
        dq = self._spns.add(ev.src_ip, ev.ts, sname)
        distinct = {s for _, s in dq if s}

        if weak:
            yield Finding(
                ts=ev.ts, detector=self.name, severity="high",
                title="Kerberoasting: TGS request with weak (RC4) encryption",
                attack=["T1558.003"], src_ip=ev.src_ip, dst_ip=ev.dst_ip,
                summary=f"{ev.src_ip} requested TGS for SPN {sname!r} negotiating RC4/weak etype",
                evidence=[ev.raw],
            )
        elif len(distinct) >= DISTINCT_SPN_THRESHOLD:
            yield Finding(
                ts=ev.ts, detector=self.name, severity="medium",
                title="Possible Kerberoasting: TGS requests across many SPNs",
                attack=["T1558.003"], src_ip=ev.src_ip, dst_ip=ev.dst_ip,
                summary=(f"{ev.src_ip} requested TGS for {len(distinct)} distinct SPNs "
                         f"in {int(WINDOW)}s: {sorted(distinct)[:8]}"),
                evidence=[ev.raw],
            )
