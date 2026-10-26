"""Normalized event + finding types shared across the pipeline.

Suricata eve records and Zeek JSON logs have different shapes; everything
downstream (dedup, detectors, triage) works on the normalized `Event` so a
detector never has to care which sensor a record came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _parse_suricata_ts(ts: str) -> float:
    # Suricata: ISO8601 with offset, e.g. "2026-10-26T19:11:05.123456+0000".
    # 3.11+ fromisoformat handles the offset; fall back to naive-UTC on odd input.
    try:
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return datetime.now(timezone.utc).timestamp()


@dataclass(slots=True)
class Event:
    """A single sensor record, flattened to a common shape."""

    ts: float                       # epoch seconds (UTC)
    source: str                     # 'suricata' | 'zeek'
    kind: str                       # 'alert','krb5','ldap','smb','rdp' | zeek log basename
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    proto: str | None = None
    iface: str | None = None        # Suricata in_iface (wg0 / vboxnet0); None for Zeek
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_suricata(cls, d: dict[str, Any]) -> "Event":
        return cls(
            ts=_parse_suricata_ts(d.get("timestamp", "")),
            source="suricata",
            kind=d.get("event_type", "?"),
            src_ip=d.get("src_ip"),
            src_port=d.get("src_port"),
            dst_ip=d.get("dest_ip"),
            dst_port=d.get("dest_port"),
            proto=(d.get("proto") or "").upper() or None,
            iface=d.get("in_iface"),
            raw=d,
        )

    @classmethod
    def from_zeek(cls, d: dict[str, Any]) -> "Event":
        path = d.get("log_path", "") or d.get("_path", "")
        kind = path.rsplit("/", 1)[-1].removesuffix(".log") or "?"
        return cls(
            ts=float(d.get("ts", 0.0) or 0.0),
            source="zeek",
            kind=kind,
            src_ip=d.get("id.orig_h"),
            src_port=d.get("id.orig_p"),
            dst_ip=d.get("id.resp_h"),
            dst_port=d.get("id.resp_p"),
            proto=(d.get("proto") or "").upper() or None,
            iface=None,
            raw=d,
        )


@dataclass(slots=True)
class Finding:
    """A detector's verdict. Tier-0 (rules) fills everything but `triage`;
    the triage layer attaches the LLM narrative/confidence afterwards."""

    ts: float
    detector: str                   # detector name that fired
    severity: str                   # 'info' | 'low' | 'medium' | 'high' | 'critical'
    title: str
    attack: list[str] = field(default_factory=list)   # ATT&CK technique IDs, e.g. ['T1558.003']
    src_ip: str | None = None
    dst_ip: str | None = None
    summary: str = ""               # rule-generated one-liner (no LLM)
    evidence: list[dict[str, Any]] = field(default_factory=list)  # raw records that justify it
    triage: dict[str, Any] | None = None   # filled by the triage layer

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "detector": self.detector,
            "severity": self.severity,
            "title": self.title,
            "attack": self.attack,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "summary": self.summary,
            "evidence_count": len(self.evidence),
            "evidence": self.evidence,
            "triage": self.triage,
        }
