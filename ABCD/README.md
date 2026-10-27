# ablueteam — AI NDR layer

The AI half of ABlueTeam. Tails the NDJSON that Fluent Bit lands in `/data`
(Suricata `eve.ndjson` + Zeek `zeek.ndjson`), runs deterministic detectors, and
hands each finding to an LLM for triage.

> **This is NDR, not EDR.** It sees only the wire (via the `.1` gateway). On-host
> tradecraft — LSASS dumping, local privesc, forged tickets — is invisible until a
> host agent (Sysmon/Wazuh) is added on the GOAD VMs. See
> [../IDS_monitoring.md](../IDS_monitoring.md) for the full visibility matrix.

## Design: rules detect, the LLM triages

The model is **never** in the detection decision and never in a long agent loop —
that's where small/local models fail. Suricata+Zeek do the protocol perception;
the detectors here make the call; the LLM only classifies, explains, maps to
ATT&CK, scores confidence, and recommends a next step from the structured evidence.

| Tier | Job | Backend |
|---|---|---|
| 0 | Detection | Suricata/Zeek + `detectors/` — no LLM |
| 1 | Per-finding triage (bulk) | `anthropic` (Claude Haiku) *or* `ollama` (Qwen2.5-7B) |
| 2 | Incident assembly / novel patterns | `anthropic` (Opus/Sonnet) |

Backends are pluggable (`triage.py`); the default `heuristic` backend needs no
key and runs today.

## Run

```bash
cd ABCD
PYTHONPATH=. python3 -m ablueteam                      # backtest /data, heuristic triage
PYTHONPATH=. python3 -m ablueteam --follow             # live tail
PYTHONPATH=. python3 -m ablueteam --backend anthropic --min-severity medium
PYTHONPATH=. python3 -m ablueteam --backend ollama --model qwen2.5:7b-instruct
```

`--min-severity` gates which findings reach the LLM backend (keeps API/CPU cost
on the ones that matter); the free heuristic verdict is attached to all of them.
Output is one JSON finding per line.

## Layout

```
ablueteam/
  models.py            normalized Event + Finding
  tailer.py            batch / follow NDJSON readers
  dedup.py             collapses the dual-iface GOAD double-count
  detectors/
    base.py            Detector ABC + per-key SlidingWindow
    scan_recon.py      scan campaign aggregation (per src) (T1046, T1595)
    ldap_recon.py      BloodHound-style LDAP enumeration   (T1087.002, T1069.002)
    kerberoast.py      Kerberoasting / AS-REP roasting     (T1558.003/.004)
  triage.py            LLM triage interface + heuristic/anthropic/ollama backends
  pipeline.py          tail -> dedup -> detect -> triage
  __main__.py          CLI
```

## Detectors implemented / planned

Implemented (Tier 0): scan/recon, LDAP enumeration, Kerberoasting/AS-REP.

The scan detector aggregates per source into one **scan campaign** across all
targets (vertical / horizontal / block shape) and attaches an enrichment block
(breadth, per-host port sets, corroborating ET signatures) that triage reasons
over — see `detectors/scan_recon.py`.

Next up: SMB enumeration (tree connects to ADMIN$/C$/IPC$), DCE-RPC lateral
movement (PsExec/svcctl via Zeek `dce_rpc`), and password-spray (AS-REQ→KRB_ERROR
fan-out).

## Known gaps / TODO

- `community_id` is **off** in `suricata.yaml`; enabling it gives a clean dedup
  key and links Suricata↔Zeek records for the same flow.
- Zeek is **wg0-only**, so AD *replies* aren't Zeek-logged; add vboxnet to
  `node.cfg` for both directions (needed for stream reassembly on some detectors).
