"""Network scanning / discovery from Suricata alerts + port fan-out.

Two sources of signal:
  * Suricata ET SCAN alerts (Nmap UA, RDP scan, "Behavioral Unusual Port ...").
    These are already-labelled, so we pass them straight through as Findings.
  * Port fan-out: one source touching many distinct dst ports/hosts in a short
    window (horizontal/vertical scan) even when no ET rule fired.

Rather than one finding per (src,dst) pair, the behavioural path aggregates all
of a source's probes into a single **scan campaign** per source across every
target it touched in the window. The campaign is classified by shape:
  * vertical   — many ports on one (few) host(s): port sweep.
  * horizontal — few ports across many hosts: service/subnet sweep.
  * block      — many ports AND many hosts: broad block scan.
The campaign finding carries an `enrichment` block (breadth, per-host port sets,
distinct ports, corroborating ET signatures) so triage reasons over the whole
sweep, not a single flow record.

Known-benign noise is dropped (see cyber-range-gotchas): CVE-2020-11899 fires on
ordinary IPv6 multicast from the GOAD VMs and is not an attack.

ATT&CK: T1046 (Network Service Discovery), T1595 (Active Scanning).
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable

from ..models import Event, Finding
from .base import Detector, SlidingWindow

WINDOW = 30.0
PORT_FANOUT_THRESHOLD = 15    # distinct ports on a single host -> vertical sweep
HOST_FANOUT_THRESHOLD = 10    # distinct hosts touched       -> horizontal sweep
# Once a source looks like a scan campaign, stay quiet about it for this long so a
# sustained sweep doesn't re-fire every window; the next finding (after the quiet
# period) reflects the campaign's updated, wider scope.
SUPPRESS_SECONDS = 600.0
_SAMPLE_RAWS = 3              # raw records kept per source as concrete evidence
_CAP = 40                    # cap list sizes in the enrichment block

_BENIGN_SIG_SUBSTR = ("CVE-2020-11899",)  # benign IPv6 multicast noise


class ScanReconDetector(Detector):
    name = "scan_recon"

    def __init__(self) -> None:
        self._probes = SlidingWindow(WINDOW)      # src_ip -> (dst_ip, dst_port)
        self._sigs = SlidingWindow(WINDOW)        # src_ip -> (dst_ip, et_signature)
        self._samples: dict[str | None, deque] = defaultdict(lambda: deque(maxlen=_SAMPLE_RAWS))
        self._fired: dict[str | None, float] = {}  # src_ip -> last campaign fire ts

    def feed(self, ev: Event) -> Iterable[Finding]:
        # (1) pass-through of labelled ET SCAN alerts; also feed the campaign tracker
        # so a concurrent behavioural campaign can cite the corroborating signature.
        if ev.source == "suricata" and ev.kind == "alert":
            alert = ev.raw.get("alert", {})
            sig = alert.get("signature", "")
            if any(s in sig for s in _BENIGN_SIG_SUBSTR):
                return
            cat = alert.get("category", "")
            if "SCAN" in sig.upper() or cat == "Detection of a Network Scan":
                self._sigs.add(ev.src_ip, ev.ts, (ev.dst_ip, sig))
                yield Finding(
                    ts=ev.ts, detector=self.name, severity="low",
                    title=f"Network scan signature: {sig}",
                    attack=["T1046", "T1595"], src_ip=ev.src_ip, dst_ip=ev.dst_ip,
                    summary=f"{ev.src_ip} -> {ev.dst_ip}:{ev.dst_port} — {sig}",
                    evidence=[ev.raw],
                )
            return

        # (2) behavioural port fan-out across flow records -> per-source campaign
        if ev.kind in ("flow", "conn") and ev.dst_port:
            dq = self._probes.add(ev.src_ip, ev.ts, (ev.dst_ip, ev.dst_port))
            self._samples[ev.src_ip].append(ev.raw)

            by_host: dict[str | None, set] = defaultdict(set)
            for _, (dst, port) in dq:
                by_host[dst].add(port)
            max_ports = max((len(p) for p in by_host.values()), default=0)
            n_hosts = len(by_host)

            vertical = max_ports >= PORT_FANOUT_THRESHOLD
            horizontal = n_hosts >= HOST_FANOUT_THRESHOLD
            if not (vertical or horizontal):
                return
            if ev.ts - self._fired.get(ev.src_ip, 0.0) < SUPPRESS_SECONDS:
                return
            self._fired[ev.src_ip] = ev.ts
            yield self._campaign(ev, by_host, vertical, horizontal)

    def _campaign(self, ev: Event, by_host: dict[str | None, set],
                  vertical: bool, horizontal: bool) -> Finding:
        shape = "block" if vertical and horizontal else "horizontal" if horizontal else "vertical"
        all_ports = sorted({p for ports in by_host.values() for p in ports})
        total_probes = sum(len(p) for p in by_host.values())
        # hosts worst-first, so the enrichment leads with the most-probed targets
        ranked = sorted(by_host.items(), key=lambda kv: len(kv[1]), reverse=True)
        et_sigs = sorted({s for _, (_, s) in self._sigs.current(ev.src_ip, ev.ts) if s})

        enrichment = {
            "campaign": {
                "src_ip": ev.src_ip,
                "scan_shape": shape,
                "window_seconds": WINDOW,
                "target_count": len(by_host),
                "targets": sorted(h for h in by_host if h)[:_CAP],
                "port_count": len(all_ports),
                "distinct_ports": all_ports[:_CAP],
                "max_ports_on_one_host": max((len(p) for p in by_host.values()), default=0),
                "total_probes": total_probes,
                "top_targets": [
                    {"dst_ip": h, "port_count": len(ports), "ports": sorted(ports)[:_CAP]}
                    for h, ports in ranked[:5]
                ],
                "corroborating_et_signatures": et_sigs,
            }
        }

        if shape == "horizontal":
            what = (f"{ev.src_ip} swept {len(by_host)} hosts "
                    f"(ports {all_ports[:8]}) in {int(WINDOW)}s")
        elif shape == "vertical":
            top = ranked[0]
            what = (f"{ev.src_ip} touched {len(top[1])} distinct ports on "
                    f"{top[0]} in {int(WINDOW)}s")
        else:
            what = (f"{ev.src_ip} probed {len(all_ports)} ports across "
                    f"{len(by_host)} hosts in {int(WINDOW)}s")
        if et_sigs:
            what += f"; corroborated by ET SCAN ({len(et_sigs)} sig(s))"

        # broad sweeps and ET-corroborated scans rate higher than a lone vertical probe
        severity = "high" if shape == "block" or et_sigs else "medium"
        # a single-target campaign keeps its dst; a multi-target sweep has no one dst
        dst = next(iter(by_host)) if len(by_host) == 1 else None
        return Finding(
            ts=ev.ts, detector=self.name, severity=severity,
            title=f"Scan campaign ({shape})",
            attack=["T1046", "T1595"], src_ip=ev.src_ip, dst_ip=dst,
            summary=what,
            evidence=list(self._samples[ev.src_ip]),
            enrichment=enrichment,
        )
