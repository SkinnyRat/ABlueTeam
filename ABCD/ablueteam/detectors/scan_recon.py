"""Network scanning / discovery from Suricata alerts + port fan-out.

Two sources of signal:
  * Suricata ET SCAN alerts (Nmap UA, RDP scan, "Behavioral Unusual Port ...").
    These are already-labelled, so we pass them straight through as Findings.
  * Port fan-out: one source touching many distinct dst ports on one host in a
    short window (horizontal/vertical scan) even when no ET rule fired.

Known-benign noise is dropped (see cyber-range-gotchas): CVE-2020-11899 fires on
ordinary IPv6 multicast from the GOAD VMs and is not an attack.

ATT&CK: T1046 (Network Service Discovery), T1595 (Active Scanning).
"""

from __future__ import annotations

from collections.abc import Iterable

from ..models import Event, Finding
from .base import Detector, SlidingWindow

WINDOW = 30.0
PORT_FANOUT_THRESHOLD = 15
# Once a (src,dst) pair looks like a scan, stay quiet about it for this long so a
# sustained sweep doesn't re-fire every window. TODO: aggregate to one
# "scan campaign" finding per source across all targets instead of per pair.
SUPPRESS_SECONDS = 600.0

_BENIGN_SIG_SUBSTR = ("CVE-2020-11899",)  # benign IPv6 multicast noise


class ScanReconDetector(Detector):
    name = "scan_recon"

    def __init__(self) -> None:
        self._ports = SlidingWindow(WINDOW)       # key: (src_ip,dst_ip) -> ports
        self._fired: dict[tuple, float] = {}

    def feed(self, ev: Event) -> Iterable[Finding]:
        # (1) pass-through of labelled ET SCAN alerts
        if ev.source == "suricata" and ev.kind == "alert":
            alert = ev.raw.get("alert", {})
            sig = alert.get("signature", "")
            if any(s in sig for s in _BENIGN_SIG_SUBSTR):
                return
            cat = alert.get("category", "")
            if "SCAN" in sig.upper() or cat == "Detection of a Network Scan":
                yield Finding(
                    ts=ev.ts, detector=self.name, severity="low",
                    title=f"Network scan signature: {sig}",
                    attack=["T1046", "T1595"], src_ip=ev.src_ip, dst_ip=ev.dst_ip,
                    summary=f"{ev.src_ip} -> {ev.dst_ip}:{ev.dst_port} — {sig}",
                    evidence=[ev.raw],
                )
            return

        # (2) behavioural port fan-out across flow records
        if ev.kind in ("flow", "conn") and ev.dst_port:
            key = (ev.src_ip, ev.dst_ip)
            dq = self._ports.add(key, ev.ts, ev.dst_port)
            ports = {p for _, p in dq}
            if len(ports) >= PORT_FANOUT_THRESHOLD and ev.ts - self._fired.get(key, 0.0) >= SUPPRESS_SECONDS:
                self._fired[key] = ev.ts
                yield Finding(
                    ts=ev.ts, detector=self.name, severity="medium",
                    title="Port scan (fan-out)",
                    attack=["T1046"], src_ip=ev.src_ip, dst_ip=ev.dst_ip,
                    summary=(f"{ev.src_ip} touched {len(ports)} distinct ports on "
                             f"{ev.dst_ip} in {int(WINDOW)}s"),
                    evidence=[ev.raw],
                )
