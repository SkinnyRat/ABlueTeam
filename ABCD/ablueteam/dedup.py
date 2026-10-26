"""Collapse the dual-interface GOAD double-count.

With both wg0 and vboxnet0 up, each GOAD packet alerts twice: pre-NAT on wg0
(src=10.13.0.3) and post-NAT on vboxnet0 (src=192.168.56.1). So `src_ip` and
`flow_id` DIFFER between the two copies and can't be the dedup key. What stays
stable across the NAT is the destination + service + signature, so we key on
(kind, signature, dst_ip, dst_port, proto) within a short time window and keep
the first copy seen.

NOTE: if `community_id` is enabled in suricata.yaml later, prefer it as the key
(it also links Suricata<->Zeek records for the same flow). It is currently off.
"""

from __future__ import annotations

from collections import OrderedDict

from .models import Event

WINDOW_SECONDS = 5.0
_MAX_KEYS = 50_000  # bound memory for the live stream


def _sig(ev: Event) -> str:
    if ev.kind == "alert":
        return ev.raw.get("alert", {}).get("signature", "")
    return ev.kind


class Deduper:
    def __init__(self, window: float = WINDOW_SECONDS) -> None:
        self.window = window
        self._seen: OrderedDict[tuple, float] = OrderedDict()

    def is_duplicate(self, ev: Event) -> bool:
        # Only alert-type events are double-counted across ifaces; pass others through.
        if ev.source != "suricata" or ev.kind != "alert":
            return False
        key = (ev.kind, _sig(ev), ev.dst_ip, ev.dst_port, ev.proto)
        prev = self._seen.get(key)
        if prev is not None and (ev.ts - prev) <= self.window:
            self._seen[key] = ev.ts  # slide the window
            self._seen.move_to_end(key)
            return True
        self._seen[key] = ev.ts
        self._seen.move_to_end(key)
        if len(self._seen) > _MAX_KEYS:
            self._seen.popitem(last=False)
        return False
