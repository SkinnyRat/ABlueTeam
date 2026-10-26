"""Read NDJSON landing files as a stream of normalized Events.

Two modes:
  * batch  — read the whole file once (for backtesting against captured data)
  * follow — seek to EOF and yield new lines as they land (live), handling the
             file being rotated/truncated by Fluent Bit.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterator
from pathlib import Path

from .models import Event

# Default landing files written by the Fluent Bit receiver on yi (.2).
SURICATA_NDJSON = Path("/data/suricata/eve.ndjson")
ZEEK_NDJSON = Path("/data/zeek/zeek.ndjson")


def _to_event(line: str, source: str) -> Event | None:
    line = line.strip()
    if not line:
        return None
    try:
        d = json.loads(line)
    except json.JSONDecodeError:
        return None
    # Fluent Bit may wrap the record; unwrap a single nested payload if present.
    if source == "suricata" and "event_type" not in d and "log" in d:
        try:
            d = json.loads(d["log"])
        except (json.JSONDecodeError, TypeError):
            pass
    return Event.from_suricata(d) if source == "suricata" else Event.from_zeek(d)


def read_batch(path: Path, source: str) -> Iterator[Event]:
    """Yield every record currently in the file (one pass)."""
    with path.open("r", errors="replace") as fh:
        for line in fh:
            ev = _to_event(line, source)
            if ev is not None:
                yield ev


def follow(path: Path, source: str, poll: float = 0.5) -> Iterator[Event]:
    """Tail -f the file from EOF, surviving truncation/rotation."""
    with path.open("r", errors="replace") as fh:
        fh.seek(0, 2)  # EOF
        inode = path.stat().st_ino
        while True:
            line = fh.readline()
            if line:
                ev = _to_event(line, source)
                if ev is not None:
                    yield ev
                continue
            time.sleep(poll)
            # Detect rotation (new inode) or truncation (file shrank).
            try:
                st = path.stat()
            except FileNotFoundError:
                continue
            if st.st_ino != inode or st.st_size < fh.tell():
                fh.close()
                fh = path.open("r", errors="replace")
                inode = st.st_ino
