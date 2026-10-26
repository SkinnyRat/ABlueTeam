"""ablueteam — AI NDR layer for the ABlueTeam cyber range.

Tier 0 (rules: Suricata/Zeek + detectors here) detect; the LLM (triage.py) only
classifies/explains/scores. Reads the NDJSON that Fluent Bit lands in /data.
"""

from .models import Event, Finding
from .pipeline import Pipeline

__all__ = ["Event", "Finding", "Pipeline"]
__version__ = "0.1.0"
