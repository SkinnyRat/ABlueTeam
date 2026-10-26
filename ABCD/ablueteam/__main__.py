"""CLI:  python -m ablueteam [--follow] [--backend heuristic|anthropic|ollama]

Examples:
  python -m ablueteam                     # backtest /data once, heuristic triage
  python -m ablueteam --limit 200000      # only the last N merged events
  python -m ablueteam --backend anthropic --min-severity medium
  python -m ablueteam --follow            # live tail
"""

from __future__ import annotations

import argparse
import json
import sys

from .pipeline import Pipeline
from .triage import get_backend


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ablueteam")
    p.add_argument("--follow", action="store_true", help="tail live instead of batch")
    p.add_argument("--backend", default="heuristic",
                   choices=["heuristic", "anthropic", "ollama", "llamacpp"])
    p.add_argument("--model", default=None, help="override backend model id")
    p.add_argument("--min-severity", default="info",
                   choices=["info", "low", "medium", "high", "critical"],
                   help="only run the LLM backend on findings at/above this severity")
    p.add_argument("--limit", type=int, default=None, help="batch: last N events only")
    args = p.parse_args(argv)

    kw = {"model": args.model} if args.model else {}
    backend = get_backend(args.backend, **kw)
    pipe = Pipeline(backend=backend, min_triage_severity=args.min_severity)

    stream = pipe.run_follow() if args.follow else pipe.run_batch(limit=args.limit)
    count = 0
    try:
        for finding in stream:
            count += 1
            print(json.dumps(finding.to_dict(), default=str))
            sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    if not args.follow:
        print(f"# {count} findings", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
